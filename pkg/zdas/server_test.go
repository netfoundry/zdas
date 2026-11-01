package zdas

import (
	"bytes"
	"context"
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
	idpServer, _ := mockOIDCServer(t, map[string]any{"sub": "test"})

	cfg := replicaConfig(t)
	cfg.Providers = []ProviderConfig{
		{
			Type:          ProviderTypeOIDC,
			Name:          "my-keycloak",
			ClientID:      "test-client",
			OIDCIssuerURL: idpServer.URL,
		},
	}

	srv, err := NewServer(cfg, slog.Default())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { srv.Shutdown(context.Background()) })

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
	idpServer, _ := mockOIDCServer(t, map[string]any{"sub": "test"})

	cfg := replicaConfig(t)
	cfg.Providers = []ProviderConfig{
		{
			Type:          ProviderTypeOIDC,
			Name:          "google",
			ClientID:      "gcid",
			ClientSecret:  "gcsecret",
			OIDCIssuerURL: idpServer.URL,
		},
	}

	srv, err := NewServer(cfg, slog.Default())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { srv.Shutdown(context.Background()) })

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
	cfg := replicaConfig(t)
	cfg.Providers = []ProviderConfig{
		{
			Type:          ProviderTypeOIDC,
			Name:          "broken",
			ClientID:      "c",
			OIDCIssuerURL: "http://127.0.0.1:1", // unreachable
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
	if !strings.Contains(buf.String(), `msg="generated signing key" kid=`+srv.handlers.keys.KID()) {
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
	if injected.handlers.keys != active {
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
		"nil provisioner": WithProvisioner(nil),
	} {
		if srv, err := NewServer(cfg, slog.Default(), opt); err == nil {
			srv.Shutdown(context.Background())
			t.Errorf("%s: NewServer succeeded, want error", name)
		}
	}
}

// TestNewServerInjectedStoreNotOwned verifies that a server given a Store
// does not create, and so never stops, an in-memory store of its own.
func TestNewServerInjectedStoreNotOwned(t *testing.T) {
	cfg := replicaConfig(t)
	srv, err := NewServer(cfg, slog.Default(), WithStore(newJSONStore()))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if srv.store != nil {
		t.Error("server created an in-memory store despite WithStore")
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

// TestServerShutdownCancelsInitialPoll verifies that Shutdown during the
// initial discovery poll ends it, rather than waiting for the controller.
func TestServerShutdownCancelsInitialPoll(t *testing.T) {
	requested := make(chan struct{})
	release := make(chan struct{})
	ctrl := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(requested)
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	t.Cleanup(ctrl.Close)
	t.Cleanup(func() { close(release) })
	cfg := replicaConfig(t)
	cfg.Controller.APIURL = ctrl.URL

	srv, err := NewServer(cfg, slog.Default())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Start(context.Background()) }()
	<-requested
	if err := srv.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Start = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Start still in its initial poll after Shutdown")
	}
}
