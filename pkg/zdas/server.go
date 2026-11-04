package zdas

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// Server is the top-level ZDAS instance. It wires together config, key
// management, provider discovery, session storage, and HTTP serving.
type Server struct {
	cfg        Config
	registry   *ProviderRegistry
	store      *memStore // nil with WithStore; ZDAS stops only a store it created
	discovery  *signerDiscovery
	reconciler *fallbackReconciler // nil when fallback is disabled
	handlers   *endpoints
	logger     *slog.Logger

	// runCtx scopes background work (discovery and reconciler polling) and
	// the initial discovery poll; Shutdown cancels it.
	runCtx    context.Context
	cancelRun context.CancelFunc

	mu       sync.Mutex
	stopping bool         // Shutdown has been called
	httpSrv  *http.Server // nil until Start begins serving
	chalSrv  *http.Server // ACME challenge listener (if separate from main)
}

// NewServer creates a fully-wired Server. Call Start to begin serving. cfg
// must have its defaults applied, by LoadConfig or Config.ApplyDefaults;
// NewServer fails if a setting it cannot do without is unset.
func NewServer(cfg Config, logger *slog.Logger, opts ...Option) (srv *Server, retErr error) {
	if err := cfg.checkRequired(); err != nil {
		return nil, fmt.Errorf("config: %w (was ApplyDefaults called?)", err)
	}
	cfg.Controller.APIURL = controllerRoot(cfg.Controller.APIURL)
	var sopts serverOptions
	for _, o := range opts {
		o(&sopts)
	}
	if sopts.err != nil {
		return nil, sopts.err
	}

	keys := sopts.keys
	if keys == nil {
		var err error
		keys, err = GenerateKeySet()
		if err != nil {
			return nil, fmt.Errorf("generate key set: %w", err)
		}
		logger.Info("generated signing key", "kid", keys.KID())
	} else {
		verifyKIDs := make([]string, len(sopts.verifyKeys))
		for i, ks := range sopts.verifyKeys {
			verifyKIDs[i] = ks.KID()
		}
		logger.Info("using injected signing key", "kid", keys.KID(), "verify_only_kids", verifyKIDs)
	}

	registry := NewProviderRegistry()
	store := sopts.store
	var owned *memStore // the store ZDAS created, and so stops
	if store == nil {
		owned = newMemStore(cfg.Session.Timeout, cfg.Session.CodeExpiry, storeSweepInterval)
		owned.logger = logger
		store = owned
		// Stop the store's sweep goroutine if NewServer fails partway
		// through; on success the returned Server owns it.
		defer func() {
			if retErr != nil {
				owned.stop()
			}
		}()
	}

	// Register directly-configured providers (those defined in ZDAS config
	// rather than discovered from the controller).
	configuredNames := make(map[string]struct{}, len(cfg.Providers))
	for _, pc := range cfg.Providers {
		configuredNames[pc.Name] = struct{}{}
		switch pc.Type {
		case ProviderTypeGitHub:
			gh := NewGitHubProvider(pc)
			if sopts.upstream != nil {
				gh.client = sopts.upstream
			}
			if err := registry.Register(gh); err != nil {
				return nil, fmt.Errorf("register provider %q: %w", pc.Name, err)
			}
			logger.Info("registered configured provider", "name", pc.Name, "type", pc.Type)
		case ProviderTypeOIDC:
			// Bound the OIDC discovery call so an unresponsive IdP can't
			// hang startup indefinitely.
			discoCtx, cancel := context.WithTimeout(context.Background(), providerSetupTimeout)
			oidcProv, err := NewOIDCProvider(discoCtx, OIDCProviderConfig{
				Name:                pc.Name,
				Issuer:              pc.OIDCIssuerURL,
				ClientID:            pc.ClientID,
				ClientSecret:        pc.ClientSecret,
				Scopes:              pc.Scopes,
				FetchUserInfo:       pc.FetchUserInfo,
				RequireUserInfo:     pc.RequireUserInfo,
				AllowedEmailDomains: pc.AllowedEmailDomains,
				RequiredClaims:      pc.RequiredClaims,
				HTTPClient:          sopts.upstream,
				Logger:              logger,
			})
			cancel()
			if err != nil {
				return nil, fmt.Errorf("register oidc provider %q: %w", pc.Name, err)
			}
			if err := registry.Register(oidcProv); err != nil {
				return nil, fmt.Errorf("register provider %q: %w", pc.Name, err)
			}
			logger.Info("registered configured provider", "name", pc.Name, "type", pc.Type)
		default:
			return nil, fmt.Errorf("provider %q: unknown type %q (config not validated?)", pc.Name, pc.Type)
		}
	}

	var id *parsedIdentity
	if cfg.Controller.IdentityFile != "" {
		var err error
		if id, err = loadIdentityFile(cfg.Controller.IdentityFile); err != nil {
			return nil, err
		}
	}
	ctrlClient, err := controllerClient(cfg.Controller, id)
	if err != nil {
		return nil, fmt.Errorf("create controller client: %w", err)
	}
	disc := newSignerDiscovery(cfg.Controller, ctrlClient, sopts.upstream, registry, configuredNames, logger)

	var reconciler *fallbackReconciler
	if cfg.Fallback.Enabled && id != nil {
		mgmtClient := managementClientFromIdentity(id)
		apiURL := cfg.Controller.APIURL
		if id.APIURL != "" {
			apiURL = id.APIURL
		}
		reconciler = newFallbackReconciler(cfg.Fallback, cfg.Claims, mgmtClient, apiURL, logger)
		logger.Info("fallback reconciler enabled", "poll_interval", cfg.Fallback.PollInterval)
	} else if cfg.Fallback.Enabled {
		logger.Info("fallback enrollment enabled without reconciler (no identity_file)")
	}

	if cfg.LegacyCallback {
		logger.Warn("legacy_callback is deprecated and will be removed: register <external_url>/callback/<provider name> with each IdP, then turn it off")
	}

	handlers := newEndpoints(cfg, keys, sopts.verifyKeys, registry, store, disc, reconciler, sopts.provisioner, logger)

	runCtx, cancelRun := context.WithCancel(context.Background())
	return &Server{
		cfg:        cfg,
		registry:   registry,
		store:      owned,
		discovery:  disc,
		reconciler: reconciler,
		handlers:   handlers,
		logger:     logger,
		runCtx:     runCtx,
		cancelRun:  cancelRun,
	}, nil
}

// Handler wraps an http.Handler with a Stop method for clean shutdown of
// background goroutines (discovery polling, session cleanup).
type Handler struct {
	http.Handler
	srv *Server
}

// Stop halts background goroutines started by NewHandler. Call this when the
// embedding application is shutting down.
func (h *Handler) Stop() {
	h.srv.cancelRun()
	h.srv.discovery.stop()
	if h.srv.reconciler != nil {
		h.srv.reconciler.stop()
	}
	h.srv.stopStore()
}

// CompleteProvision finishes an enrollment that the provisioner sent to an
// interactive page with ProvisionResult.RedirectURL. The embedding
// application calls it from its own handler for that page, with the
// enrollment's pending ID and the outcome of its provisioning: the claims
// to mint, or an error, which follows the same rules as an error from
// Provision and takes precedence over claims. It consumes the pending
// provision and redirects the browser back to the tunneler, or responds 400
// when the pending provision is missing or expired.
//
// Both the claims and the pending ID must come from the application's own
// state, never from the request. Pass the ProvisionRequest.PendingID the
// provisioner recorded for the user it authenticated, not the pending_id
// query parameter: the user enrolling can change the URL, and could
// otherwise send someone else's pending ID, or choose claims for any
// identity.
func (h *Handler) CompleteProvision(w http.ResponseWriter, r *http.Request, pendingID string, claims map[string]any, err error) {
	h.srv.handlers.completeProvision(w, r, pendingID, claims, err)
}

// NewHandler returns a Handler for embedding ZDAS in another application.
// It performs initial discovery but does not start an HTTP server. The caller
// is responsible for serving the returned handler and calling Stop on shutdown.
func NewHandler(cfg Config, logger *slog.Logger, opts ...Option) (*Handler, error) {
	srv, err := NewServer(cfg, logger, opts...)
	if err != nil {
		return nil, err
	}
	if err := srv.discovery.start(srv.runCtx); err != nil {
		srv.cancelRun()
		srv.stopStore()
		return nil, fmt.Errorf("start discovery: %w", err)
	}
	if srv.reconciler != nil {
		srv.reconciler.start(srv.runCtx)
	}
	return &Handler{Handler: srv.handlers.mux(), srv: srv}, nil
}

// Start performs initial discovery and begins serving HTTP(S). It blocks until
// the server stops, and returns nil when that is because Shutdown was called,
// including before or during startup.
//
// ctx bounds startup only: canceling it during initial discovery stops the
// server as Shutdown would, and Start returns nil without serving. Once
// serving, background polling runs until Shutdown. Callers always call
// Shutdown, including after Start returns an error.
func (s *Server) Start(ctx context.Context) error {
	stopOnCancel := context.AfterFunc(ctx, s.cancelRun)
	err := s.discovery.start(s.runCtx)
	stopOnCancel()
	if s.runCtx.Err() != nil {
		return nil
	}
	if err != nil {
		return fmt.Errorf("start discovery: %w", err)
	}
	if s.reconciler != nil {
		s.reconciler.start(s.runCtx)
	}

	srv := newHTTPServer(s.cfg.Listen, s.handlers.mux())
	s.mu.Lock()
	if s.stopping {
		s.mu.Unlock()
		// Shutdown may have run before the background work above started.
		s.discovery.stop()
		if s.reconciler != nil {
			s.reconciler.stop()
		}
		return nil
	}
	s.httpSrv = srv
	s.mu.Unlock()

	s.logger.Info("starting zdas",
		"listen", s.cfg.Listen,
		"external_url", s.cfg.ExternalURL,
		"tls_mode", s.cfg.TLS.Mode,
		"providers", s.registry.Len(),
	)

	switch s.cfg.TLS.Mode {
	case TLSModeNone:
		err = srv.ListenAndServe()
	case TLSModeStatic:
		err = srv.ListenAndServeTLS(s.cfg.TLS.CertFile, s.cfg.TLS.KeyFile)
	case TLSModeACME:
		err = s.listenACME(srv)
	default:
		err = fmt.Errorf("unknown tls mode: %s", s.cfg.TLS.Mode)
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Timeouts and limits for ZDAS's HTTP servers.
const (
	serverReadTimeout  = 15 * time.Second
	serverWriteTimeout = 15 * time.Second
	serverIdleTimeout  = 60 * time.Second
	// serverMaxHeaderBytes caps the request line and headers, which Go
	// otherwise allows up to 1 MB. An /authorize request is well under
	// 4 KB.
	serverMaxHeaderBytes = 32 << 10
)

// newHTTPServer returns a server for addr with ZDAS's timeouts and limits.
func newHTTPServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:           addr,
		Handler:        h,
		ReadTimeout:    serverReadTimeout,
		WriteTimeout:   serverWriteTimeout,
		IdleTimeout:    serverIdleTimeout,
		MaxHeaderBytes: serverMaxHeaderBytes,
	}
}

// Shutdown gracefully shuts down the server: it cancels background work,
// including an initial discovery poll still running, stops accepting
// connections, waits for in-flight requests until ctx is done, then waits
// for the background work to stop. It may be called more than once, and
// before or during Start.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	s.stopping = true
	httpSrv, chalSrv := s.httpSrv, s.chalSrv
	s.mu.Unlock()
	s.cancelRun()

	var errs []error
	if chalSrv != nil {
		errs = append(errs, chalSrv.Shutdown(ctx))
	}
	if httpSrv != nil {
		errs = append(errs, httpSrv.Shutdown(ctx))
	}
	s.discovery.stop()
	if s.reconciler != nil {
		s.reconciler.stop()
	}
	s.stopStore()
	return errors.Join(errs...)
}

// stopStore stops the session store cleanup goroutine if ZDAS created the
// store. A Store passed to WithStore belongs to the caller and is left alone.
func (s *Server) stopStore() {
	if s.store != nil {
		s.store.stop()
	}
}
