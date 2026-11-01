package zdas

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

var errRefused = errors.New("refused by the test transport")

// recordingTransport records each request it is given, and either sends it
// on or refuses it.
type recordingTransport struct {
	refuse bool

	mu   sync.Mutex
	urls []string // host + path
}

func (rt *recordingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	rt.mu.Lock()
	rt.urls = append(rt.urls, r.URL.Host+r.URL.Path)
	rt.mu.Unlock()
	if rt.refuse {
		return nil, errRefused
	}
	return http.DefaultTransport.RoundTrip(r)
}

func (rt *recordingTransport) seen() []string {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return slices.Clone(rt.urls)
}

// TestOIDCProviderSendsEveryRequestThroughHTTPClient verifies that discovery,
// the signing keys, the token exchange and userinfo all use
// OIDCProviderConfig.HTTPClient, so an embedder controls every request the
// provider makes to the issuer.
func TestOIDCProviderSendsEveryRequestThroughHTTPClient(t *testing.T) {
	server, _ := mockOIDCServerWithUserInfo(t, map[string]any{"sub": "user-42"},
		jsonUserInfo(t, map[string]any{"sub": "user-42", "groups": []string{"eng"}}))
	rt := &recordingTransport{}
	ctx := context.Background()
	p, err := NewOIDCProvider(ctx, OIDCProviderConfig{
		Name:            "test-idp",
		Issuer:          server.URL,
		ClientID:        "test-client",
		FetchUserInfo:   true,
		RequireUserInfo: true,
		HTTPClient:      &http.Client{Transport: rt},
	})
	if err != nil {
		t.Fatalf("NewOIDCProvider: %v", err)
	}
	if _, err := p.ExchangeAndIdentify(ctx, "fake-code", server.URL+"/callback"); err != nil {
		t.Fatalf("ExchangeAndIdentify: %v", err)
	}
	host := server.Listener.Addr().String()
	seen := rt.seen()
	for _, path := range []string{"/.well-known/openid-configuration", "/jwks", "/token", "/userinfo"} {
		if !slices.Contains(seen, host+path) {
			t.Errorf("%s did not go through HTTPClient; it saw %v", path, seen)
		}
	}
}

// TestOIDCProviderHTTPClientRefusal verifies that a client refusing every
// request stops the provider at discovery, rather than discovery falling
// back to another client.
func TestOIDCProviderHTTPClientRefusal(t *testing.T) {
	server, _ := mockOIDCServer(t, map[string]any{"sub": "user-42"})
	_, err := NewOIDCProvider(context.Background(), OIDCProviderConfig{
		Name:       "test-idp",
		Issuer:     server.URL,
		ClientID:   "test-client",
		HTTPClient: &http.Client{Transport: &recordingTransport{refuse: true}},
	})
	if !errors.Is(err, errRefused) {
		t.Fatalf("NewOIDCProvider error = %v, want the client's refusal", err)
	}
}

// TestGitHubProviderSendsEveryRequestThroughItsClient verifies that the
// GitHub provider's token exchange and API calls use its client, the one
// WithUpstreamHTTPClient sets.
func TestGitHubProviderSendsEveryRequestThroughItsClient(t *testing.T) {
	server := mockGitHubServer(t,
		map[string]any{"id": float64(12345), "login": "jsmith"},
		[]map[string]any{{"login": "acme"}},
		[]map[string]any{{"email": "j@example.com", "primary": true, "verified": true}})
	p := newTestGitHubProvider(t, server, []string{"acme"})
	rt := &recordingTransport{}
	p.client = &http.Client{Transport: rt}
	if _, err := p.ExchangeAndIdentify(context.Background(), "fake-code", "https://zdas/callback"); err != nil {
		t.Fatalf("ExchangeAndIdentify: %v", err)
	}
	host := server.Listener.Addr().String()
	seen := rt.seen()
	for _, path := range []string{"/login/oauth/access_token", "/user", "/user/emails", "/user/orgs"} {
		if !slices.Contains(seen, host+path) {
			t.Errorf("%s did not go through the client; it saw %v", path, seen)
		}
	}
}

// TestTokenError verifies that a refused token exchange reports its status
// and reply separately, with the message it has always had.
func TestTokenError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	t.Cleanup(srv.Close)
	_, err := oidcTokenExchange(context.Background(), srv.Client(), srv.URL, url.Values{})
	var te *TokenError
	if !errors.As(err, &te) {
		t.Fatalf("error = %v, want a *TokenError", err)
	}
	if te.StatusCode != http.StatusBadRequest || string(te.Body) != `{"error":"invalid_grant"}` {
		t.Errorf("TokenError = %d %q", te.StatusCode, te.Body)
	}
	if want := `token endpoint returned 400: {"error":"invalid_grant"}`; err.Error() != want {
		t.Errorf("Error() = %q, want %q", err.Error(), want)
	}
}

// upstreamClientConfig is a server config with a configured OIDC provider at
// configured, a GitHub provider, and a controller that lists one signer whose
// issuer is signer.
func upstreamClientConfig(t *testing.T, configured, signer string) Config {
	t.Helper()
	ctrlMux := http.NewServeMux()
	ctrlMux.HandleFunc("/edge/client/v1/external-jwt-signers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(signerResponse{Data: []signerEntry{
			{Name: "discovered", Issuer: signer, ClientID: "test-client", EnrollToCertEnabled: true},
		}})
	})
	ctrlServer := httptest.NewServer(ctrlMux)
	t.Cleanup(ctrlServer.Close)
	return Config{
		Listen:      ":0",
		ExternalURL: "https://zdas.test",
		TLS:         TLSConfig{Mode: TLSModeNone},
		Controller:  ControllerConfig{APIURL: ctrlServer.URL, SelfIssuer: "https://zdas.test"},
		Providers: []ProviderConfig{
			{Type: ProviderTypeOIDC, Name: "configured", ClientID: "test-client", OIDCIssuerURL: configured},
			{Type: ProviderTypeGitHub, Name: "github", ClientID: "gh-client", ClientSecret: "gh-secret"},
		},
		Claims:  defaultClaimsConfig(),
		Token:   TokenConfig{Issuer: "https://zdas.test", Audience: "ziti-enroll", Expiry: 5 * time.Minute},
		Session: SessionConfig{Timeout: 10 * time.Minute, CodeExpiry: 60 * time.Second},
	}
}

// TestWithUpstreamHTTPClient verifies that the option reaches every kind of
// upstream provider: configured OIDC, discovered from the controller's
// signers, and GitHub.
func TestWithUpstreamHTTPClient(t *testing.T) {
	configured, _ := mockOIDCServer(t, map[string]any{"sub": "a"})
	discovered, _ := mockOIDCServer(t, map[string]any{"sub": "b"})
	cfg := upstreamClientConfig(t, configured.URL, discovered.URL)

	rt := &recordingTransport{}
	client := &http.Client{Transport: rt}
	srv, err := NewServer(cfg, slog.Default(), WithUpstreamHTTPClient(client))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { srv.Shutdown(context.Background()) })
	if err := srv.discovery.runOnce(context.Background()); err != nil {
		t.Fatalf("discovery: %v", err)
	}
	seen := rt.seen()
	for _, s := range []*httptest.Server{configured, discovered} {
		if want := s.Listener.Addr().String() + "/.well-known/openid-configuration"; !slices.Contains(seen, want) {
			t.Errorf("discovery at %s did not go through the client; it saw %v", s.URL, seen)
		}
	}
	if _, err := srv.registry.Resolve("discovered"); err != nil {
		t.Errorf("discovered provider not registered: %v", err)
	}
	gh, err := srv.registry.Resolve("github")
	if err != nil {
		t.Fatalf("github provider: %v", err)
	}
	if gh.(*GitHubProvider).client != client {
		t.Error("the GitHub provider does not use the client")
	}

	// A client that refuses everything stops the configured provider, so
	// nothing fell back to another client.
	refuse := &http.Client{Transport: &recordingTransport{refuse: true}}
	if srv, err := NewServer(cfg, slog.Default(), WithUpstreamHTTPClient(refuse)); !errors.Is(err, errRefused) {
		if err == nil {
			srv.Shutdown(context.Background())
		}
		t.Errorf("NewServer with a refusing client: %v, want the client's refusal", err)
	}
}

// TestDiscoveredProviderUsesUpstreamClient verifies that a provider built
// from a controller signer is refused by a refusing upstream client, rather
// than reaching its issuer with another client.
func TestDiscoveredProviderUsesUpstreamClient(t *testing.T) {
	discovered, _ := mockOIDCServer(t, map[string]any{"sub": "b"})
	cfg := upstreamClientConfig(t, "", discovered.URL)
	cfg.Providers = nil
	srv, err := NewServer(cfg, slog.Default(), WithUpstreamHTTPClient(&http.Client{Transport: &recordingTransport{refuse: true}}))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { srv.Shutdown(context.Background()) })
	if err := srv.discovery.runOnce(context.Background()); err != nil {
		t.Fatalf("discovery: %v", err)
	}
	if _, err := srv.registry.Resolve("discovered"); err == nil {
		t.Error("the discovered provider was registered past a refusing client")
	}
}

// TestHTTPClientCapsResponseBody verifies that ZDAS's own client truncates
// response bodies, which protects readers that have no cap of their own.
func TestHTTPClientCapsResponseBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(bytes.Repeat([]byte("x"), maxResponseBytes+1<<20))
	}))
	t.Cleanup(srv.Close)

	resp, err := httpClient.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) != maxResponseBytes {
		t.Errorf("read %d bytes, want %d", len(body), maxResponseBytes)
	}
}

// TestOIDCProviderDefaultClientCapsDiscovery verifies that, without
// OIDCProviderConfig.HTTPClient, discovery goes through ZDAS's own client
// rather than http.DefaultClient: an oversized discovery document is
// truncated and rejected instead of read whole.
func TestOIDCProviderDefaultClientCapsDiscovery(t *testing.T) {
	var issuer string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"padding":                strings.Repeat("x", maxResponseBytes),
			"issuer":                 issuer,
			"authorization_endpoint": issuer + "/authorize",
			"token_endpoint":         issuer + "/token",
			"jwks_uri":               issuer + "/jwks",
		})
	}))
	t.Cleanup(srv.Close)
	issuer = srv.URL

	_, err := NewOIDCProvider(context.Background(), OIDCProviderConfig{Name: "big", Issuer: issuer, ClientID: "c"})
	if err == nil {
		t.Fatal("oversized discovery document accepted")
	}
}

func TestTokenErrorTruncatesBody(t *testing.T) {
	err := &TokenError{StatusCode: 400, Body: bytes.Repeat([]byte("x"), maxErrorBody+100)}
	if n := len(err.Error()); n > maxErrorBody+64 {
		t.Errorf("error message is %d bytes, want the body cut to about %d", n, maxErrorBody)
	}
}
