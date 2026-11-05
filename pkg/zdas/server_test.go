package zdas

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
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
			AllowAnyUser:  true,
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
			AllowAnyUser:  true,
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
			AllowAnyUser:  true,
		},
	}

	_, err := NewServer(cfg, slog.Default())
	if err == nil || !strings.Contains(err.Error(), "oidc discovery") {
		t.Fatalf("NewServer = %v, want an oidc discovery error for an unreachable provider", err)
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

// TestHTTPServerLimitsHeaderSize verifies that ZDAS's server refuses a
// request line and headers far larger than any real request.
func TestHTTPServerLimitsHeaderSize(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := newHTTPServer(ln.Addr().String(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	resp, err := http.Get("http://" + ln.Addr().String() + "/authorize?state=" + strings.Repeat("s", 2*serverMaxHeaderBytes))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Errorf("status = %d, want 431", resp.StatusCode)
	}
}

// TestNewServerControllerURLs verifies that NewServer reaches the client API
// from the controller's root when api_url is a client API URL, and gives the
// reconciler the management API of the identity file's controller.
func TestNewServerControllerURLs(t *testing.T) {
	cfg := replicaConfig(t)
	cfg.Controller.APIURL = "https://ctrl.example.com/edge/client/v1/"
	cfg.Controller.IdentityFile = generateTestIdentityFile(t, "https://mgmt.example.com:1280/edge/client/v1")
	cfg.Fallback = FallbackConfig{Enabled: true, PollInterval: time.Minute, Timeout: time.Hour}

	srv, err := NewServer(cfg, slog.Default())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { srv.Shutdown(context.Background()) })
	if got := srv.discovery.cfg.APIURL; got != "https://ctrl.example.com" {
		t.Errorf("discovery controller URL = %q, want https://ctrl.example.com", got)
	}
	if srv.reconciler == nil {
		t.Fatal("no reconciler")
	}
	if got := srv.reconciler.mgmtURL; got != "https://mgmt.example.com:1280/edge/management/v1" {
		t.Errorf("reconciler management URL = %q", got)
	}
}

// TestNewServerWiresPolicyAndStoreLogger verifies that NewServer passes a
// configured OIDC provider's policy through, and gives the built-in store
// a logger for eviction warnings.
func TestNewServerWiresPolicyAndStoreLogger(t *testing.T) {
	idp, _ := mockOIDCServer(t, map[string]any{"sub": "u"})
	cfg := replicaConfig(t)
	cfg.Providers = []ProviderConfig{{
		Type: ProviderTypeOIDC, Name: "corp", ClientID: "c", OIDCIssuerURL: idp.URL,
		AllowedEmailDomains: []string{"corp.example"}, RequiredClaims: map[string][]string{"groups": {"ziti"}},
	}}
	srv, err := NewServer(cfg, slog.Default())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { srv.Shutdown(context.Background()) })

	p, err := srv.registry.Resolve("corp")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	op := p.(*OIDCProvider)
	if !slices.Equal(op.emailDomains, []string{"corp.example"}) || !slices.Equal(op.requiredClaims["groups"], []string{"ziti"}) {
		t.Errorf("policy = %v, %v", op.emailDomains, op.requiredClaims)
	}
	if srv.store.logger == nil {
		t.Error("built-in store has no logger")
	}
}

// TestNewServerChecksProviders verifies that NewServer refuses a configured
// provider Validate would refuse, so a Config built in code without
// Validate fails closed.
func TestNewServerChecksProviders(t *testing.T) {
	cases := []struct {
		name string
		pc   ProviderConfig
		want string
	}{
		{"github without a policy", ProviderConfig{Type: ProviderTypeGitHub, Name: "gh", ClientID: "c", ClientSecret: "s"}, "anyone who can sign in"},
		{"oidc without a policy", ProviderConfig{Type: ProviderTypeOIDC, Name: "kc", ClientID: "c", OIDCIssuerURL: "https://idp.invalid"}, "anyone who can sign in"},
		{"github with an oidc policy", ProviderConfig{Type: ProviderTypeGitHub, Name: "gh", ClientID: "c", ClientSecret: "s", AllowedEmailDomains: []string{"corp.example"}}, "allowed_email_domains and required_claims are for oidc"},
		{"oidc with a github policy", ProviderConfig{Type: ProviderTypeOIDC, Name: "kc", ClientID: "c", OIDCIssuerURL: "https://idp.invalid", AllowedOrgs: []string{"acme"}}, "allowed_orgs is for github"},
		{"policy and allow_any_user", ProviderConfig{Type: ProviderTypeGitHub, Name: "gh", ClientID: "c", ClientSecret: "s", AllowedOrgs: []string{"acme"}, AllowAnyUser: true}, "conflicts"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := replicaConfig(t)
			cfg.Providers = []ProviderConfig{tc.pc}
			_, err := NewServer(cfg, slog.Default())
			if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), tc.pc.Name) {
				t.Errorf("NewServer = %v, want an error naming %q and containing %q", err, tc.pc.Name, tc.want)
			}
		})
	}
}

// TestNewServerNilLogger verifies that NewServer works with a nil logger,
// as the provider constructors do.
func TestNewServerNilLogger(t *testing.T) {
	srv, err := NewServer(replicaConfig(t), nil)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	srv.Shutdown(context.Background())
}
