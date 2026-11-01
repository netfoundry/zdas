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
	keys       *KeySet
	registry   *ProviderRegistry
	store      *SessionStore // nil with WithStore; ZDAS stops only a store it created
	discovery  *Discovery
	reconciler *Reconciler // nil when fallback is disabled
	handlers   *Handlers
	logger     *slog.Logger

	mu       sync.Mutex
	stopping bool         // Shutdown has been called
	httpSrv  *http.Server // nil until Start begins serving
	chalSrv  *http.Server // ACME challenge listener (if separate from main)
}

// NewServer creates a fully-wired Server. Call Start to begin serving.
func NewServer(cfg Config, logger *slog.Logger, opts ...Option) (srv *Server, retErr error) {
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
	var memStore *SessionStore
	if store == nil {
		memStore = NewSessionStore(cfg.Session.Timeout, cfg.Session.CodeExpiry)
		store = sessionStoreAdapter{memStore}
		// Stop the session store cleanup goroutine if NewServer fails
		// partway through; on success the returned Server owns it.
		defer func() {
			if retErr != nil {
				memStore.Stop()
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
				Name:            pc.Name,
				Issuer:          pc.OIDCIssuerURL,
				ClientID:        pc.ClientID,
				ClientSecret:    pc.ClientSecret,
				Scopes:          pc.Scopes,
				FetchUserInfo:   pc.FetchUserInfo,
				RequireUserInfo: pc.RequireUserInfo,
				HTTPClient:      sopts.upstream,
				Logger:          logger,
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

	disc, err := NewDiscovery(cfg.Controller, registry, configuredNames, logger)
	if err != nil {
		return nil, fmt.Errorf("create discovery: %w", err)
	}
	disc.upstreamClient = sopts.upstream

	var reconciler *Reconciler
	if cfg.Fallback.Enabled && cfg.Controller.IdentityFile != "" {
		id, err := loadIdentityFile(cfg.Controller.IdentityFile)
		if err != nil {
			return nil, fmt.Errorf("load identity file for reconciler: %w", err)
		}
		mgmtClient := managementClientFromIdentity(id)
		apiURL := cfg.Controller.APIURL
		if id.APIURL != "" {
			apiURL = id.APIURL
		}
		reconciler = NewReconciler(cfg.Fallback, cfg.Claims, mgmtClient, apiURL, logger)
		logger.Info("fallback reconciler enabled", "poll_interval", cfg.Fallback.PollInterval)
	} else if cfg.Fallback.Enabled {
		logger.Info("fallback enrollment enabled without reconciler (no identity_file)")
	}

	handlers := newHandlers(cfg, keys, sopts.verifyKeys, registry, store, disc, reconciler, sopts.provisioner, logger)

	return &Server{
		cfg:        cfg,
		keys:       keys,
		registry:   registry,
		store:      memStore,
		discovery:  disc,
		reconciler: reconciler,
		handlers:   handlers,
		logger:     logger,
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
	h.srv.discovery.Stop()
	if h.srv.reconciler != nil {
		h.srv.reconciler.Stop()
	}
	h.srv.stopStore()
}

// CompleteProvision finishes an enrollment that the provisioner sent to an
// interactive page. See [Handlers.CompleteProvision].
func (h *Handler) CompleteProvision(w http.ResponseWriter, r *http.Request, pendingID string, claims map[string]any, err error) {
	h.srv.handlers.CompleteProvision(w, r, pendingID, claims, err)
}

// NewHandler returns a Handler for embedding ZDAS in another application.
// It performs initial discovery but does not start an HTTP server. The caller
// is responsible for serving the returned handler and calling Stop on shutdown.
func NewHandler(cfg Config, logger *slog.Logger, opts ...Option) (*Handler, error) {
	srv, err := NewServer(cfg, logger, opts...)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	if err := srv.discovery.Start(ctx); err != nil {
		srv.stopStore()
		return nil, fmt.Errorf("start discovery: %w", err)
	}
	if srv.reconciler != nil {
		srv.reconciler.Start(ctx)
	}
	return &Handler{Handler: srv.handlers.Mux(), srv: srv}, nil
}

// Start performs initial discovery and begins serving HTTP(S). It blocks until
// the server stops, and returns nil when that is because Shutdown was called,
// including before serving began. A ctx canceled during initial discovery
// also makes it return nil without serving; the caller still calls Shutdown.
func (s *Server) Start(ctx context.Context) error {
	if err := s.discovery.Start(ctx); err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("start discovery: %w", err)
	}
	if s.reconciler != nil {
		s.reconciler.Start(ctx)
	}

	srv := newHTTPServer(s.cfg.Listen, s.handlers.Mux())
	s.mu.Lock()
	if s.stopping {
		s.mu.Unlock()
		// Shutdown may have run before the background work above started.
		s.discovery.Stop()
		if s.reconciler != nil {
			s.reconciler.Stop()
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

	var err error
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

// newHTTPServer returns a server for addr with ZDAS's timeouts.
func newHTTPServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:         addr,
		Handler:      h,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
}

// Shutdown gracefully shuts down the server: it stops accepting connections,
// waits for in-flight requests until ctx is done, then stops background
// work. It may be called more than once, and before or during Start.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	s.stopping = true
	httpSrv, chalSrv := s.httpSrv, s.chalSrv
	s.mu.Unlock()

	var errs []error
	if chalSrv != nil {
		errs = append(errs, chalSrv.Shutdown(ctx))
	}
	if httpSrv != nil {
		errs = append(errs, httpSrv.Shutdown(ctx))
	}
	s.discovery.Stop()
	if s.reconciler != nil {
		s.reconciler.Stop()
	}
	s.stopStore()
	return errors.Join(errs...)
}

// stopStore stops the session store cleanup goroutine if ZDAS created the
// store. A Store passed to WithStore belongs to the caller and is left alone.
func (s *Server) stopStore() {
	if s.store != nil {
		s.store.Stop()
	}
}
