package zdas

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestNewServerRegistersConfiguredOIDCProvider verifies that an OIDC provider
// declared in ProviderConfig is created and registered during NewServer.
func TestNewServerRegistersConfiguredOIDCProvider(t *testing.T) {
	// Mock OIDC issuer that serves /.well-known/openid-configuration so
	// NewOIDCProvider's discovery call succeeds.
	idpServer, _ := mockOIDCServer(t, map[string]interface{}{"sub": "test"})

	// Mock controller (returns no signers - we're testing the configured path).
	ctrlMux := http.NewServeMux()
	ctrlMux.HandleFunc("/edge/client/v1/external-jwt-signers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(signerResponse{Data: []signerEntry{}})
	})
	ctrlServer := httptest.NewServer(ctrlMux)
	t.Cleanup(ctrlServer.Close)

	cfg := Config{
		Listen:      ":0",
		ExternalURL: "https://zdas.test",
		TLS:         TLSConfig{Mode: TLSModeNone},
		Controller: ControllerConfig{
			APIURL:       ctrlServer.URL,
			PollInterval: 0,
			SelfIssuer:   "https://zdas.test",
		},
		Providers: []ProviderConfig{
			{
				Type:          ProviderTypeOIDC,
				Name:          "my-keycloak",
				ClientID:      "test-client",
				OIDCIssuerURL: idpServer.URL,
			},
		},
		Claims: ClaimsConfig{
			UsernameClaim:     "preferred_username",
			NameTemplate:      "{username}-{device_name}",
			IdentityNameClaim: "device_identity_name",
			ExternalIDClaim:   "device_external_id",
		},
		Token: TokenConfig{
			Issuer:   "https://zdas.test",
			Audience: "ziti-enroll",
			Expiry:   5 * time.Minute,
		},
		Session: SessionConfig{
			Timeout:    10 * time.Minute,
			CodeExpiry: 60 * time.Second,
		},
	}

	srv, err := NewServer(cfg, slog.Default())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { srv.store.Stop() })

	// The configured OIDC provider should be in the registry.
	got, err := srv.registry.Resolve("my-keycloak")
	if err != nil {
		t.Fatalf("expected my-keycloak in registry: %v", err)
	}
	if _, ok := got.(*OIDCProvider); !ok {
		t.Errorf("expected *OIDCProvider, got %T", got)
	}
	if got.Name() != "my-keycloak" {
		t.Errorf("Name() = %q", got.Name())
	}
	if got.Issuer() != idpServer.URL {
		t.Errorf("Issuer() = %q, want %q", got.Issuer(), idpServer.URL)
	}
}

// TestNewServerRegistersConfiguredOIDCProviderWithSecret verifies that a
// configured OIDC provider with a ClientSecret set (e.g. Google Web client)
// lands in the registry with the secret threaded through to the provider.
func TestNewServerRegistersConfiguredOIDCProviderWithSecret(t *testing.T) {
	idpServer, _ := mockOIDCServer(t, map[string]interface{}{"sub": "test"})

	ctrlMux := http.NewServeMux()
	ctrlMux.HandleFunc("/edge/client/v1/external-jwt-signers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(signerResponse{Data: []signerEntry{}})
	})
	ctrlServer := httptest.NewServer(ctrlMux)
	t.Cleanup(ctrlServer.Close)

	cfg := Config{
		Listen:      ":0",
		ExternalURL: "https://zdas.test",
		TLS:         TLSConfig{Mode: TLSModeNone},
		Controller: ControllerConfig{
			APIURL:       ctrlServer.URL,
			PollInterval: 0,
			SelfIssuer:   "https://zdas.test",
		},
		Providers: []ProviderConfig{
			{
				Type:          ProviderTypeOIDC,
				Name:          "google",
				ClientID:      "gcid",
				ClientSecret:  "gcsecret",
				OIDCIssuerURL: idpServer.URL,
			},
		},
		Claims: ClaimsConfig{
			UsernameClaim:     "preferred_username",
			NameTemplate:      "{username}-{device_name}",
			IdentityNameClaim: "device_identity_name",
			ExternalIDClaim:   "device_external_id",
		},
		Token: TokenConfig{
			Issuer:   "https://zdas.test",
			Audience: "ziti-enroll",
			Expiry:   5 * time.Minute,
		},
		Session: SessionConfig{
			Timeout:    10 * time.Minute,
			CodeExpiry: 60 * time.Second,
		},
	}

	srv, err := NewServer(cfg, slog.Default())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { srv.store.Stop() })

	got, err := srv.registry.Resolve("google")
	if err != nil {
		t.Fatalf("expected google in registry: %v", err)
	}
	oidcProv, ok := got.(*OIDCProvider)
	if !ok {
		t.Fatalf("expected *OIDCProvider, got %T", got)
	}
	if oidcProv.clientSecret != "gcsecret" {
		t.Errorf("clientSecret = %q, want gcsecret", oidcProv.clientSecret)
	}
}

// TestNewServerOIDCProviderDiscoveryFailure verifies that a configured OIDC
// provider with an unreachable issuer fails NewServer at startup (fail-fast).
func TestNewServerOIDCProviderDiscoveryFailure(t *testing.T) {
	ctrlMux := http.NewServeMux()
	ctrlMux.HandleFunc("/edge/client/v1/external-jwt-signers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(signerResponse{Data: []signerEntry{}})
	})
	ctrlServer := httptest.NewServer(ctrlMux)
	t.Cleanup(ctrlServer.Close)

	cfg := Config{
		Listen:      ":0",
		ExternalURL: "https://zdas.test",
		TLS:         TLSConfig{Mode: TLSModeNone},
		Controller: ControllerConfig{
			APIURL:       ctrlServer.URL,
			PollInterval: 0,
			SelfIssuer:   "https://zdas.test",
		},
		Providers: []ProviderConfig{
			{
				Type:          ProviderTypeOIDC,
				Name:          "broken",
				ClientID:      "c",
				OIDCIssuerURL: "http://127.0.0.1:1", // unreachable
			},
		},
		Claims: ClaimsConfig{
			UsernameClaim:     "preferred_username",
			NameTemplate:      "{username}-{device_name}",
			IdentityNameClaim: "device_identity_name",
			ExternalIDClaim:   "device_external_id",
		},
		Token: TokenConfig{
			Issuer:   "https://zdas.test",
			Audience: "ziti-enroll",
			Expiry:   5 * time.Minute,
		},
		Session: SessionConfig{
			Timeout:    10 * time.Minute,
			CodeExpiry: 60 * time.Second,
		},
	}

	_, err := NewServer(cfg, slog.Default())
	if err == nil {
		t.Fatal("expected NewServer to fail when configured OIDC provider is unreachable")
	}
}

// TestNewServerKeyOptions verifies that NewServer generates and logs a key
// when WithKeySet is absent, and uses and logs the injected key otherwise.
func TestNewServerKeyOptions(t *testing.T) {
	cfg := replicaConfig(t)

	var buf bytes.Buffer
	srv, err := NewServer(cfg, slog.New(slog.NewTextHandler(&buf, nil)))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { srv.Shutdown(context.Background()) })
	if !strings.Contains(buf.String(), `msg="generated signing key" kid=`+srv.keys.KID()) {
		t.Errorf("default path log = %q, want generated signing key", buf.String())
	}

	active, err := GenerateKeySet()
	if err != nil {
		t.Fatalf("GenerateKeySet: %v", err)
	}
	verify, err := GenerateKeySet()
	if err != nil {
		t.Fatalf("GenerateKeySet: %v", err)
	}
	buf.Reset()
	injected, err := NewServer(cfg, slog.New(slog.NewTextHandler(&buf, nil)), WithKeySet(active, verify))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { injected.Shutdown(context.Background()) })
	if injected.keys != active {
		t.Error("NewServer did not use the injected key")
	}
	if got := buf.String(); strings.Contains(got, "generated signing key") ||
		!strings.Contains(got, `msg="using injected signing key" kid=`+active.KID()) ||
		!strings.Contains(got, verify.KID()) {
		t.Errorf("injected path log = %q, want injected kid and verify-only kid", got)
	}
}

// TestNewServerRejectsNilOptions verifies that a nil key or store fails
// NewServer rather than silently falling back to a per-process default,
// which would break a multi-replica deployment without any error.
func TestNewServerRejectsNilOptions(t *testing.T) {
	cfg := replicaConfig(t)
	ks, err := GenerateKeySet()
	if err != nil {
		t.Fatalf("GenerateKeySet: %v", err)
	}
	for name, opt := range map[string]Option{
		"nil active":      WithKeySet(nil),
		"nil verify-only": WithKeySet(ks, nil),
		"nil store":       WithStore(nil),
		"nil client":      WithUpstreamHTTPClient(nil),
	} {
		if srv, err := NewServer(cfg, slog.Default(), opt); err == nil {
			srv.Shutdown(context.Background())
			t.Errorf("%s: NewServer succeeded, want error", name)
		}
	}
}

// TestNewServerInjectedStoreNotOwned verifies that a server given a Store
// does not create, and so never stops, a SessionStore of its own.
func TestNewServerInjectedStoreNotOwned(t *testing.T) {
	cfg := replicaConfig(t)
	srv, err := NewServer(cfg, slog.Default(), WithStore(newJSONStore()))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if srv.store != nil {
		t.Error("server created a SessionStore despite WithStore")
	}
	if err := srv.Shutdown(context.Background()); err != nil {
		t.Errorf("Shutdown: %v", err)
	}
	h := &Handler{srv: srv}
	h.Stop() // must not panic on the nil store
}

// TestServerStartShutdown verifies that Start returns nil, not an error,
// when Shutdown stops it, and that Shutdown can be called again.
func TestServerStartShutdown(t *testing.T) {
	srv, err := NewServer(replicaConfig(t), slog.Default())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	started := make(chan error, 1)
	go func() { started <- srv.Start(context.Background()) }()

	// Wait until Start has its HTTP server, then stop it.
	deadline := time.Now().Add(5 * time.Second)
	for {
		srv.mu.Lock()
		serving := srv.httpSrv != nil
		srv.mu.Unlock()
		if serving {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Start did not begin serving")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := srv.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	select {
	case err := <-started:
		if err != nil {
			t.Errorf("Start after Shutdown = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return after Shutdown")
	}
	if err := srv.Shutdown(context.Background()); err != nil {
		t.Errorf("second Shutdown: %v", err)
	}
}

// TestServerShutdownBeforeStart verifies that a Shutdown that arrives
// before Start begins serving, such as a signal during startup, keeps Start
// from serving instead of being lost.
func TestServerShutdownBeforeStart(t *testing.T) {
	srv, err := NewServer(replicaConfig(t), slog.Default())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := srv.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Start(context.Background()) }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Start = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Start served after Shutdown")
	}
}

// TestServerStartCanceledDuringDiscovery verifies that a ctx canceled
// before serving makes Start return nil rather than a discovery error.
func TestServerStartCanceledDuringDiscovery(t *testing.T) {
	srv, err := NewServer(replicaConfig(t), slog.Default())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { srv.Shutdown(context.Background()) })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := srv.Start(ctx); err != nil {
		t.Errorf("Start with canceled ctx = %v, want nil", err)
	}
}

func TestHandlerStopTwice(t *testing.T) {
	h, err := NewHandler(replicaConfig(t), slog.Default())
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	h.Stop()
	h.Stop()
}
