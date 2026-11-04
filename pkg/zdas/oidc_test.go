package zdas

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// mockOIDCServer stands up an httptest.Server that serves:
//   - /.well-known/openid-configuration
//   - /jwks
//   - /token  (returns a signed id_token)
//
// It returns the server and the signing key.
func mockOIDCServer(t *testing.T, claims map[string]any) (*httptest.Server, jwk.Key) {
	t.Helper()
	return mockOIDCServerWithUserInfo(t, claims, nil)
}

// mockOIDCServerWithUserInfo is mockOIDCServer plus a /userinfo endpoint
// served by userInfo. When userInfo is nil the discovery document omits
// userinfo_endpoint, matching an issuer that does not offer one.
func mockOIDCServerWithUserInfo(t *testing.T, claims map[string]any, userInfo http.HandlerFunc) (*httptest.Server, jwk.Key) {
	t.Helper()
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	privJWK, err := jwk.Import(privKey)
	if err != nil {
		t.Fatalf("wrap private key: %v", err)
	}
	_ = privJWK.Set(jwk.KeyIDKey, "test-kid")
	_ = privJWK.Set(jwk.AlgorithmKey, jwa.ES256())

	pubJWK, err := jwk.Import(privKey.Public())
	if err != nil {
		t.Fatalf("wrap public key: %v", err)
	}
	_ = pubJWK.Set(jwk.KeyIDKey, "test-kid")
	_ = pubJWK.Set(jwk.AlgorithmKey, jwa.ES256())

	// We need a mux that knows its own URL, which is a chicken-and-egg problem
	// with httptest. We'll use a handler that reads the Host header.
	var server *httptest.Server
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		baseURL := server.URL
		doc := map[string]any{
			"issuer":                                baseURL,
			"authorization_endpoint":                baseURL + "/authorize",
			"token_endpoint":                        baseURL + "/token",
			"jwks_uri":                              baseURL + "/jwks",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"ES256"},
		}
		if userInfo != nil {
			doc["userinfo_endpoint"] = baseURL + "/userinfo"
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	})

	if userInfo != nil {
		mux.HandleFunc("/userinfo", userInfo)
	}

	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		set := jwk.NewSet()
		_ = set.AddKey(pubJWK)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(set)
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		// Build and sign an ID token with the test claims.
		tok := jwt.New()
		_ = tok.Set(jwt.IssuerKey, server.URL)
		_ = tok.Set(jwt.AudienceKey, "test-client")
		_ = tok.Set(jwt.IssuedAtKey, time.Now())
		_ = tok.Set(jwt.ExpirationKey, time.Now().Add(5*time.Minute))
		for k, v := range claims {
			_ = tok.Set(k, v)
		}

		signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), privJWK))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		resp := map[string]any{
			"access_token": "opaque-at",
			"id_token":     string(signed),
			"token_type":   "Bearer",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	server = httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server, privJWK
}

func TestOIDCProviderAuthorizeURL(t *testing.T) {
	server, _ := mockOIDCServer(t, map[string]any{"sub": "u123"})

	ctx := context.Background()
	p, err := NewOIDCProvider(ctx, OIDCProviderConfig{
		Name:     "test-idp",
		Issuer:   server.URL,
		ClientID: "test-client",
	})
	if err != nil {
		t.Fatalf("NewOIDCProvider: %v", err)
	}

	authURL := p.AuthorizeURL("state-abc", "https://zdas/callback")
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("parse authorize URL: %v", err)
	}
	if !strings.HasPrefix(authURL, server.URL+"/authorize") {
		t.Errorf("authorize URL prefix wrong: %s", authURL)
	}
	if u.Query().Get("client_id") != "test-client" {
		t.Errorf("client_id = %q", u.Query().Get("client_id"))
	}
	if u.Query().Get("state") != "state-abc" {
		t.Errorf("state = %q", u.Query().Get("state"))
	}
	if u.Query().Get("redirect_uri") != "https://zdas/callback" {
		t.Errorf("redirect_uri = %q", u.Query().Get("redirect_uri"))
	}
}

func TestOIDCProviderAuthorizeURLWithPKCE(t *testing.T) {
	server, _ := mockOIDCServer(t, map[string]any{"sub": "u123"})

	ctx := context.Background()
	p, err := NewOIDCProvider(ctx, OIDCProviderConfig{
		Name:     "test-idp",
		Issuer:   server.URL,
		ClientID: "test-client",
	})
	if err != nil {
		t.Fatalf("NewOIDCProvider: %v", err)
	}

	authURL, verifier, err := p.AuthorizeURLWithPKCE("state-abc", "https://zdas/callback")
	if err != nil {
		t.Fatalf("AuthorizeURLWithPKCE: %v", err)
	}
	if verifier == "" {
		t.Error("verifier is empty")
	}

	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("parse authorize URL: %v", err)
	}
	if u.Query().Get("code_challenge") == "" {
		t.Error("missing code_challenge")
	}
	if u.Query().Get("code_challenge_method") != "S256" {
		t.Errorf("code_challenge_method = %q", u.Query().Get("code_challenge_method"))
	}
}

func TestOIDCProviderExchangeAndIdentify(t *testing.T) {
	claims := map[string]any{
		"sub":                "user-42",
		"preferred_username": "jsmith",
		"name":               "John Smith",
		"email":              "jsmith@example.com",
		"email_verified":     true,
	}
	server, _ := mockOIDCServer(t, claims)

	ctx := context.Background()
	p, err := NewOIDCProvider(ctx, OIDCProviderConfig{
		Name:     "test-idp",
		Issuer:   server.URL,
		ClientID: "test-client",
	})
	if err != nil {
		t.Fatalf("NewOIDCProvider: %v", err)
	}

	identity, err := p.ExchangeAndIdentify(ctx, "fake-code", server.URL+"/callback")
	if err != nil {
		t.Fatalf("ExchangeAndIdentify: %v", err)
	}
	if identity.Subject != "user-42" {
		t.Errorf("Subject = %q", identity.Subject)
	}
	if identity.Username != "jsmith" {
		t.Errorf("Username = %q, want jsmith", identity.Username)
	}
	if identity.Email != "jsmith@example.com" {
		t.Errorf("Email = %q, want jsmith@example.com", identity.Email)
	}
	if identity.Issuer != server.URL {
		t.Errorf("Issuer = %q", identity.Issuer)
	}
}

func TestOIDCProviderUnverifiedEmailDropped(t *testing.T) {
	cases := []struct {
		name   string
		claims map[string]any
	}{
		{
			name: "email_verified false",
			claims: map[string]any{
				"sub":            "u1",
				"email":          "attacker@example.com",
				"email_verified": false,
			},
		},
		{
			name: "email_verified missing",
			claims: map[string]any{
				"sub":   "u1",
				"email": "attacker@example.com",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, _ := mockOIDCServer(t, tc.claims)
			ctx := context.Background()
			p, err := NewOIDCProvider(ctx, OIDCProviderConfig{
				Name:     "test-idp",
				Issuer:   server.URL,
				ClientID: "test-client",
			})
			if err != nil {
				t.Fatalf("NewOIDCProvider: %v", err)
			}
			identity, err := p.ExchangeAndIdentify(ctx, "fake-code", server.URL+"/callback")
			if err != nil {
				t.Fatalf("ExchangeAndIdentify: %v", err)
			}
			if identity.Email != "" {
				t.Errorf("Email = %q, want empty (unverified should be dropped)", identity.Email)
			}
			// Other fields should still work.
			if identity.Subject != "u1" {
				t.Errorf("Subject = %q", identity.Subject)
			}
		})
	}
}

func TestOIDCProviderUsernameFallback(t *testing.T) {
	// No preferred_username - should fall back to name.
	claims := map[string]any{
		"sub":  "user-99",
		"name": "Fallback Name",
	}
	server, _ := mockOIDCServer(t, claims)

	ctx := context.Background()
	p, err := NewOIDCProvider(ctx, OIDCProviderConfig{
		Name:     "test-idp",
		Issuer:   server.URL,
		ClientID: "test-client",
	})
	if err != nil {
		t.Fatalf("NewOIDCProvider: %v", err)
	}

	identity, err := p.ExchangeAndIdentify(ctx, "fake-code", server.URL+"/callback")
	if err != nil {
		t.Fatalf("ExchangeAndIdentify: %v", err)
	}
	if identity.Username != "Fallback Name" {
		t.Errorf("Username = %q, want 'Fallback Name'", identity.Username)
	}
}

// jsonUserInfo returns a /userinfo handler that checks the bearer token
// matches the mock token endpoint's access token and replies with body.
func jsonUserInfo(t *testing.T, body map[string]any) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer opaque-at" {
			t.Errorf("userinfo Authorization = %q, want Bearer opaque-at", got)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(body)
	}
}

func TestOIDCFetchUserInfoMergesClaims(t *testing.T) {
	idClaims := map[string]any{
		"sub":   "user-42",
		"email": "id@example.com",
	}
	server, _ := mockOIDCServerWithUserInfo(t, idClaims, jsonUserInfo(t, map[string]any{
		"sub":    "user-42",
		"email":  "userinfo@example.com", // conflicts with id_token; id_token must win
		"groups": []any{"admins", "devs"},
	}))

	p, err := NewOIDCProvider(context.Background(), OIDCProviderConfig{
		Name:          "okta",
		Issuer:        server.URL,
		ClientID:      "test-client",
		FetchUserInfo: true,
	})
	if err != nil {
		t.Fatalf("NewOIDCProvider: %v", err)
	}

	identity, err := p.ExchangeAndIdentify(context.Background(), "code", server.URL+"/callback")
	if err != nil {
		t.Fatalf("ExchangeAndIdentify: %v", err)
	}
	groups, ok := identity.Raw["groups"].([]any)
	if !ok || len(groups) != 2 || groups[0] != "admins" {
		t.Errorf("Raw[groups] = %v, want [admins devs]", identity.Raw["groups"])
	}
	if got := identity.Raw["email"]; got != "id@example.com" {
		t.Errorf("Raw[email] = %v, want id_token value to win on conflict", got)
	}
}

func TestOIDCFetchUserInfoOffByDefault(t *testing.T) {
	server, _ := mockOIDCServerWithUserInfo(t, map[string]any{"sub": "u1"}, func(w http.ResponseWriter, r *http.Request) {
		t.Error("userinfo endpoint called without FetchUserInfo")
		http.Error(w, "unexpected", http.StatusInternalServerError)
	})

	p, err := NewOIDCProvider(context.Background(), OIDCProviderConfig{
		Name:     "idp",
		Issuer:   server.URL,
		ClientID: "test-client",
	})
	if err != nil {
		t.Fatalf("NewOIDCProvider: %v", err)
	}
	identity, err := p.ExchangeAndIdentify(context.Background(), "code", server.URL+"/callback")
	if err != nil {
		t.Fatalf("ExchangeAndIdentify: %v", err)
	}
	if _, present := identity.Raw["groups"]; present {
		t.Error("Raw should only contain id_token claims")
	}
}

func TestOIDCFetchUserInfoFailureNonFatal(t *testing.T) {
	cases := []struct {
		name     string
		userInfo http.HandlerFunc
	}{
		{"http error", func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "boom", http.StatusInternalServerError)
		}},
		{"sub mismatch", jsonUserInfo(t, map[string]any{"sub": "someone-else", "groups": []any{"admins"}})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, _ := mockOIDCServerWithUserInfo(t, map[string]any{"sub": "u1", "name": "n"}, tc.userInfo)
			p, err := NewOIDCProvider(context.Background(), OIDCProviderConfig{
				Name:          "idp",
				Issuer:        server.URL,
				ClientID:      "test-client",
				FetchUserInfo: true,
			})
			if err != nil {
				t.Fatalf("NewOIDCProvider: %v", err)
			}
			identity, err := p.ExchangeAndIdentify(context.Background(), "code", server.URL+"/callback")
			if err != nil {
				t.Fatalf("ExchangeAndIdentify should succeed without RequireUserInfo: %v", err)
			}
			if identity.Subject != "u1" {
				t.Errorf("Subject = %q", identity.Subject)
			}
			if _, present := identity.Raw["groups"]; present {
				t.Error("claims from a rejected userinfo response must not be merged")
			}
		})
	}
}

func TestOIDCRequireUserInfoFailureIsFatal(t *testing.T) {
	cases := []struct {
		name     string
		userInfo http.HandlerFunc
	}{
		{"http error", func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "boom", http.StatusInternalServerError)
		}},
		{"sub mismatch", jsonUserInfo(t, map[string]any{"sub": "someone-else"})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, _ := mockOIDCServerWithUserInfo(t, map[string]any{"sub": "u1"}, tc.userInfo)
			p, err := NewOIDCProvider(context.Background(), OIDCProviderConfig{
				Name:            "idp",
				Issuer:          server.URL,
				ClientID:        "test-client",
				FetchUserInfo:   true,
				RequireUserInfo: true,
			})
			if err != nil {
				t.Fatalf("NewOIDCProvider: %v", err)
			}
			if _, err := p.ExchangeAndIdentify(context.Background(), "code", server.URL+"/callback"); err == nil {
				t.Fatal("expected error with RequireUserInfo")
			}
		})
	}
}

func TestOIDCUserInfoWithoutEndpoint(t *testing.T) {
	// Discovery document has no userinfo_endpoint.
	server, _ := mockOIDCServer(t, map[string]any{"sub": "u1"})

	p, err := NewOIDCProvider(context.Background(), OIDCProviderConfig{
		Name:          "idp",
		Issuer:        server.URL,
		ClientID:      "test-client",
		FetchUserInfo: true,
	})
	if err != nil {
		t.Fatalf("FetchUserInfo without endpoint should construct: %v", err)
	}
	if p.fetchUserInfo {
		t.Error("fetchUserInfo should be disabled when the issuer has no userinfo_endpoint")
	}
	if _, err := p.ExchangeAndIdentify(context.Background(), "code", server.URL+"/callback"); err != nil {
		t.Errorf("ExchangeAndIdentify: %v", err)
	}

	_, err = NewOIDCProvider(context.Background(), OIDCProviderConfig{
		Name:            "idp",
		Issuer:          server.URL,
		ClientID:        "test-client",
		FetchUserInfo:   true,
		RequireUserInfo: true,
	})
	if err == nil || !strings.Contains(err.Error(), "userinfo_endpoint") {
		t.Errorf("RequireUserInfo without endpoint should fail construction, got %v", err)
	}
}

func TestNewOIDCProviderStoresClientSecret(t *testing.T) {
	server, _ := mockOIDCServer(t, map[string]any{"sub": "u1"})

	p, err := NewOIDCProvider(context.Background(), OIDCProviderConfig{
		Name:         "confidential",
		Issuer:       server.URL,
		ClientID:     "client-id",
		ClientSecret: "shhh",
	})
	if err != nil {
		t.Fatalf("NewOIDCProvider: %v", err)
	}
	if p.clientSecret != "shhh" {
		t.Errorf("clientSecret = %q, want %q", p.clientSecret, "shhh")
	}
}

// recordTokenRequest makes p's token exchange record the form it posts and
// fail with errTestRecorded, so a test can check what was sent.
func recordTokenRequest(t *testing.T, p *OIDCProvider) *url.Values {
	t.Helper()
	var recorded url.Values
	p.client = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse token request: %v", err)
		}
		recorded = r.PostForm
		return nil, errTestRecorded
	})}
	return &recorded
}

// roundTripFunc adapts a function to http.RoundTripper.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

var errTestRecorded = errors.New("test-recorded")

func TestOIDCTokenExchangeIncludesClientSecret(t *testing.T) {
	server, _ := mockOIDCServer(t, map[string]any{"sub": "u1"})
	p, err := NewOIDCProvider(context.Background(), OIDCProviderConfig{
		Name:         "confidential",
		Issuer:       server.URL,
		ClientID:     "client-id",
		ClientSecret: "topsecret",
	})
	if err != nil {
		t.Fatalf("NewOIDCProvider: %v", err)
	}

	recorded := recordTokenRequest(t, p)
	if _, err := p.ExchangeAndIdentifyWithPKCE(context.Background(), "code", "https://zdas/cb", "verifier"); !errors.Is(err, errTestRecorded) {
		t.Fatalf("ExchangeAndIdentifyWithPKCE = %v, want the recording transport's error", err)
	}

	if got := recorded.Get("client_secret"); got != "topsecret" {
		t.Errorf("client_secret = %q, want topsecret", got)
	}
	if got := recorded.Get("code_verifier"); got != "verifier" {
		t.Errorf("code_verifier = %q, want verifier (PKCE must still apply)", got)
	}
	if got := recorded.Get("client_id"); got != "client-id" {
		t.Errorf("client_id = %q", got)
	}
}

func TestOIDCTokenExchangeOmitsClientSecretWhenUnset(t *testing.T) {
	server, _ := mockOIDCServer(t, map[string]any{"sub": "u1"})
	p, err := NewOIDCProvider(context.Background(), OIDCProviderConfig{
		Name:     "public",
		Issuer:   server.URL,
		ClientID: "client-id",
		// ClientSecret deliberately empty.
	})
	if err != nil {
		t.Fatalf("NewOIDCProvider: %v", err)
	}

	recorded := recordTokenRequest(t, p)
	if _, err := p.ExchangeAndIdentifyWithPKCE(context.Background(), "code", "https://zdas/cb", "verifier"); !errors.Is(err, errTestRecorded) {
		t.Fatalf("ExchangeAndIdentifyWithPKCE = %v, want the recording transport's error", err)
	}

	if _, present := (*recorded)["client_secret"]; present {
		t.Errorf("client_secret should not be in params, got %q", recorded.Get("client_secret"))
	}
	if got := recorded.Get("code_verifier"); got != "verifier" {
		t.Errorf("code_verifier = %q", got)
	}
}

func TestGeneratePKCE(t *testing.T) {
	v1, c1, err := generatePKCE()
	if err != nil {
		t.Fatalf("generatePKCE: %v", err)
	}
	v2, c2, err := generatePKCE()
	if err != nil {
		t.Fatalf("generatePKCE: %v", err)
	}
	if v1 == v2 {
		t.Error("two PKCE verifiers should differ")
	}
	if c1 == c2 {
		t.Error("two PKCE challenges should differ")
	}
	if len(v1) < 40 {
		t.Errorf("verifier too short: %d chars", len(v1))
	}
}

// TestOIDCProviderRejectsMissingSub verifies that an ID token without a sub
// is rejected, since every such user would otherwise share one external ID.
func TestOIDCProviderRejectsMissingSub(t *testing.T) {
	server, _ := mockOIDCServer(t, map[string]any{"preferred_username": "nobody"})
	p, err := NewOIDCProvider(context.Background(), OIDCProviderConfig{Name: "idp", Issuer: server.URL, ClientID: "test-client"})
	if err != nil {
		t.Fatalf("NewOIDCProvider: %v", err)
	}
	if id, err := p.ExchangeAndIdentify(context.Background(), "code", server.URL+"/callback"); err == nil {
		t.Errorf("accepted an id_token without sub, subject %q", id.Subject)
	}
}

// TestOIDCProviderPolicy verifies that AllowedEmailDomains and
// RequiredClaims refuse users with ErrAccessDenied, through a real token
// exchange.
func TestOIDCProviderPolicy(t *testing.T) {
	claims := map[string]any{
		"sub":            "user-42",
		"email":          "jsmith@Example.com",
		"email_verified": true,
		"groups":         []any{"staff", "ziti-users"},
		"tenant":         "acme",
		"mfa":            true,
		"level":          float64(3),
		"profile":        map[string]any{"team": "a"},
		"roles":          []any{[]any{"admin"}},
	}
	unverified := map[string]any{"sub": "user-43", "email": "x@example.com", "email_verified": false}
	cases := []struct {
		name    string
		claims  map[string]any
		domains []string
		require map[string][]string
		allowed bool
	}{
		{"domain matches ignoring case", claims, []string{"example.COM"}, nil, true},
		{"other domain", claims, []string{"example.org"}, nil, false},
		{"parent domain is not enough", map[string]any{"sub": "u", "email": "a@sub.example.com", "email_verified": true}, []string{"example.com"}, nil, false},
		{"unverified email", unverified, []string{"example.com"}, nil, false},
		{"group in list", claims, nil, map[string][]string{"groups": {"admins", "ziti-users"}}, true},
		{"group not in list", claims, nil, map[string][]string{"groups": {"admins"}}, false},
		{"string claim", claims, nil, map[string][]string{"tenant": {"acme"}}, true},
		{"bool claim", claims, nil, map[string][]string{"mfa": {"true"}}, true},
		{"number claim", claims, nil, map[string][]string{"level": {"3"}}, true},
		{"missing claim", claims, nil, map[string][]string{"dept": {"eng"}}, false},
		{"object claim", claims, nil, map[string][]string{"profile": {"a"}}, false},
		{"nested list claim", claims, nil, map[string][]string{"roles": {"admin"}}, false},
		{"every claim must match", claims, nil, map[string][]string{"tenant": {"acme"}, "mfa": {"false"}}, false},
		{"domain and claims", claims, []string{"example.com"}, map[string][]string{"tenant": {"acme"}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, _ := mockOIDCServer(t, tc.claims)
			p, err := NewOIDCProvider(t.Context(), OIDCProviderConfig{
				Name: "idp", Issuer: server.URL, ClientID: "test-client",
				AllowedEmailDomains: tc.domains, RequiredClaims: tc.require,
			})
			if err != nil {
				t.Fatalf("NewOIDCProvider: %v", err)
			}
			_, err = p.ExchangeAndIdentify(t.Context(), "code", server.URL+"/callback")
			if tc.allowed && err != nil {
				t.Errorf("refused: %v", err)
			}
			if !tc.allowed && !errors.Is(err, ErrAccessDenied) {
				t.Errorf("err = %v, want ErrAccessDenied", err)
			}
		})
	}
}

func TestOIDCProviderCheckResponseIssuer(t *testing.T) {
	cases := []struct {
		sendsIss bool
		iss      string
		ok       bool
	}{
		{false, "", true},
		{false, "https://idp", true},
		{false, "https://evil", false},
		{true, "https://idp", true},
		{true, "", false},
		{true, "https://idp/", false},
	}
	for _, tc := range cases {
		p := &OIDCProvider{issuer: "https://idp", sendsIss: tc.sendsIss}
		if err := p.checkResponseIssuer(tc.iss); (err == nil) != tc.ok {
			t.Errorf("sendsIss=%v iss=%q: err = %v, want ok=%v", tc.sendsIss, tc.iss, err, tc.ok)
		}
	}
}

// TestOIDCProviderReadsIssParameterSupport verifies that NewOIDCProvider
// reads authorization_response_iss_parameter_supported from discovery.
func TestOIDCProviderReadsIssParameterSupport(t *testing.T) {
	for _, supported := range []bool{false, true} {
		var srv *httptest.Server
		srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]any{
				"issuer": srv.URL, "authorization_endpoint": srv.URL + "/authorize", "token_endpoint": srv.URL + "/token",
				"jwks_uri": srv.URL + "/jwks", "authorization_response_iss_parameter_supported": supported,
			})
		}))
		p, err := NewOIDCProvider(t.Context(), OIDCProviderConfig{Name: "idp", Issuer: srv.URL, ClientID: "c"})
		srv.Close()
		if err != nil {
			t.Fatalf("NewOIDCProvider: %v", err)
		}
		if p.sendsIss != supported {
			t.Errorf("sendsIss = %v, want %v", p.sendsIss, supported)
		}
	}
}
