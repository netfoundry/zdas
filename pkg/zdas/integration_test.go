package zdas

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// TestIntegrationOIDCFlow tests the complete authorize -> callback -> token
// flow using a mock Ziti controller and a mock OIDC provider.
func TestIntegrationOIDCFlow(t *testing.T) {
	// 1. Stand up a mock OIDC IdP.
	idpClaims := map[string]any{
		"sub":                "oidc-user-42",
		"preferred_username": "alice",
		"name":               "Alice Smith",
	}
	idpServer, _ := mockOIDCServer(t, idpClaims)

	// 2. Stand up a mock Ziti controller that returns the IdP as a signer.
	ctrlMux := http.NewServeMux()
	ctrlMux.HandleFunc("/edge/client/v1/external-jwt-signers", func(w http.ResponseWriter, r *http.Request) {
		resp := signerResponse{Data: []signerEntry{
			{
				Name:                "test-keycloak",
				ClientID:            "test-client",
				ExternalAuthURL:     idpServer.URL,
				EnrollToCertEnabled: true,
			},
		}}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})
	ctrlServer := httptest.NewServer(ctrlMux)
	t.Cleanup(ctrlServer.Close)

	// 3. Build a ZDAS server with this config.
	cfg := Config{
		Listen:      ":0",
		ExternalURL: "https://zdas.test",
		TLS:         TLSConfig{Mode: TLSModeNone},
		Controller: ControllerConfig{
			APIURL:       ctrlServer.URL,
			PollInterval: 0,
			SelfIssuer:   "https://zdas.test",
		},
		Claims: ClaimsConfig{
			UsernameClaim:     "preferred_username",
			NameTemplate:      "{username}-{device_name}",
			IdentityNameClaim: "device_identity_name",
			ExternalIDClaim:   "device_external_id",
		},
		Token: TokenConfig{
			Issuer:   "https://zdas.test",
			Audience: "ziti-enrolltocert",
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
	// Run initial discovery (discovers the OIDC provider).
	if err := srv.discovery.poll(t.Context()); err != nil {
		t.Fatalf("discovery: %v", err)
	}
	t.Cleanup(func() {
		srv.store.stop()
	})

	mux := srv.handlers.mux()

	// 4. Tunneler sends /authorize.
	verifier, challenge := generateTestPKCE(t)
	authReq := "/authorize?" + url.Values{
		"redirect_uri":          {"http://localhost:20314/auth/callback"},
		"response_type":         {"code"},
		"state":                 {"tunneler-state-abc"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"device_name":           {"macbook-pro"},
		"client_id":             {"ziti-enrolltocert"},
	}.Encode()

	w := authorizeAndConsent(t, mux, authReq, "")

	if w.Code != http.StatusSeeOther {
		t.Fatalf("authorize: status = %d, body = %s", w.Code, w.Body.String())
	}
	upstreamRedirect, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse upstream redirect: %v", err)
	}
	if !strings.HasPrefix(upstreamRedirect.String(), idpServer.URL+"/authorize") {
		t.Fatalf("expected redirect to IdP, got %s", upstreamRedirect)
	}
	sessionState := upstreamRedirect.Query().Get("state")
	if sessionState == "" {
		t.Fatal("no state in upstream redirect")
	}

	// 5. Simulate the upstream IdP calling back with an authorization code.
	callbackReq := "/callback/test-keycloak?" + url.Values{
		"code":  {"upstream-auth-code"},
		"state": {sessionState},
	}.Encode()

	req := browserRequest(w, callbackReq)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("callback: status = %d, body = %s", w.Code, w.Body.String())
	}
	tunnelerRedirect, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse tunneler redirect: %v", err)
	}
	if tunnelerRedirect.Query().Get("state") != "tunneler-state-abc" {
		t.Errorf("tunneler state = %q", tunnelerRedirect.Query().Get("state"))
	}
	zdasCode := tunnelerRedirect.Query().Get("code")
	if zdasCode == "" {
		t.Fatal("no zdas code in tunneler redirect")
	}

	// 6. Tunneler exchanges the code at /token.
	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {zdasCode},
		"redirect_uri":  {"http://localhost:20314/auth/callback"},
		"code_verifier": {verifier},
		"client_id":     {"ziti-enrolltocert"},
	}
	tokenReq := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(tokenForm.Encode()))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, tokenReq)

	if w.Code != http.StatusOK {
		t.Fatalf("token: status = %d, body = %s", w.Code, w.Body.String())
	}

	var tokenResp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &tokenResp); err != nil {
		t.Fatalf("unmarshal token response: %v", err)
	}
	if tokenResp["token_type"] != "Bearer" {
		t.Errorf("token_type = %v", tokenResp["token_type"])
	}

	// 7. Verify the JWT.
	rawJWT := tokenResp["id_token"].(string)
	jwksBytes, _ := JWKS(srv.handlers.keys)
	pubSet, _ := jwk.Parse(jwksBytes)
	tok, err := jwt.Parse([]byte(rawJWT), jwt.WithKeySet(pubSet, jws.WithInferAlgorithmFromKey(true)))
	if err != nil {
		t.Fatalf("verify jwt: %v", err)
	}

	if stringClaim(tok, "iss") != "https://zdas.test" {
		t.Errorf("issuer = %q", stringClaim(tok, "iss"))
	}
	idName := claim(tok, "device_identity_name")
	if idName != "alice-macbook-pro" {
		t.Errorf("device_identity_name = %v", idName)
	}
	extID := claim(tok, "device_external_id")
	if extID == nil || extID == "" {
		t.Error("device_external_id missing")
	}
	if stringClaim(tok, "sub") != extID {
		t.Errorf("sub (%q) should equal device_external_id (%q)", stringClaim(tok, "sub"), extID)
	}
	devName := claim(tok, "device_name")
	if devName != "macbook-pro" {
		t.Errorf("device_name = %v", devName)
	}
}

// TestIntegrationGitHubFlow tests the flow with a GitHub provider.
func TestIntegrationGitHubFlow(t *testing.T) {
	// Mock GitHub API.
	githubUser := map[string]any{
		"id":    float64(77777),
		"login": "bobdev",
		"name":  "Bob Developer",
	}
	ghServer := mockGitHubServer(t, githubUser, nil, nil)

	// Mock controller with no OIDC signers (only GitHub configured directly).
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
				Type:          ProviderTypeGitHub,
				Name:          "github",
				ClientID:      "test-gh-client",
				ClientSecret:  "test-gh-secret",
				UsernameField: "login",
				UserIDField:   "id",
				AllowAnyUser:  true,
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
			Audience: "ziti-enrolltocert",
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
	if err := srv.discovery.poll(t.Context()); err != nil {
		t.Fatalf("discovery: %v", err)
	}
	t.Cleanup(func() { srv.store.stop() })

	// Point the GitHub provider at our mock server.
	ghProv, err := srv.registry.Resolve("github")
	if err != nil {
		t.Fatalf("resolve github: %v", err)
	}
	ghp := ghProv.(*GitHubProvider)
	ghp.authBaseURL = ghServer.URL + "/login/oauth/authorize"
	ghp.tokenBaseURL = ghServer.URL + "/login/oauth/access_token"
	ghp.userURL = ghServer.URL + "/user"

	mux := srv.handlers.mux()

	// Tunneler sends /authorize.
	verifier, challenge := generateTestPKCE(t)
	authReq := "/authorize?" + url.Values{
		"redirect_uri":          {"http://localhost:20314/auth/callback"},
		"response_type":         {"code"},
		"state":                 {"gh-state"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"device_name":           {"linux-desktop"},
		"client_id":             {"ziti-enrolltocert"},
	}.Encode()

	w := authorizeAndConsent(t, mux, authReq, "")
	if w.Code != http.StatusSeeOther {
		t.Fatalf("authorize: status = %d", w.Code)
	}
	upstreamRedirect, _ := url.Parse(w.Header().Get("Location"))
	sessionState := upstreamRedirect.Query().Get("state")

	// Simulate GitHub callback.
	req := browserRequest(w, "/callback/github?code=gh-code&state="+sessionState)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		t.Fatalf("callback: status = %d, body = %s", w.Code, w.Body.String())
	}
	tunnelerRedirect, _ := url.Parse(w.Header().Get("Location"))
	zdasCode := tunnelerRedirect.Query().Get("code")

	// Token exchange.
	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {zdasCode},
		"redirect_uri":  {"http://localhost:20314/auth/callback"},
		"code_verifier": {verifier},
	}
	tokenReq := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(tokenForm.Encode()))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, tokenReq)
	if w.Code != http.StatusOK {
		t.Fatalf("token: status = %d, body = %s", w.Code, w.Body.String())
	}

	var tokenResp map[string]any
	json.Unmarshal(w.Body.Bytes(), &tokenResp)
	rawJWT := tokenResp["id_token"].(string)

	jwksBytes, _ := JWKS(srv.handlers.keys)
	pubSet, _ := jwk.Parse(jwksBytes)
	tok, err := jwt.Parse([]byte(rawJWT), jwt.WithKeySet(pubSet, jws.WithInferAlgorithmFromKey(true)))
	if err != nil {
		t.Fatalf("verify jwt: %v", err)
	}

	idName := claim(tok, "device_identity_name")
	if idName != "bobdev-linux-desktop" {
		t.Errorf("device_identity_name = %v, want bobdev-linux-desktop", idName)
	}
	upSub := claim(tok, "upstream_sub")
	if upSub != "77777" {
		t.Errorf("upstream_sub = %v, want 77777", upSub)
	}
}

// TestIntegrationFallbackFlow tests enrollment without device_name when
// fallback is enabled. The JWT should have a pending-style name and
// nonce-based external ID.
func TestIntegrationFallbackFlow(t *testing.T) {
	idpClaims := map[string]any{
		"sub":                "fallback-user",
		"preferred_username": "charlie",
	}
	idpServer, _ := mockOIDCServer(t, idpClaims)

	ctrlMux := http.NewServeMux()
	ctrlMux.HandleFunc("/edge/client/v1/external-jwt-signers", func(w http.ResponseWriter, r *http.Request) {
		resp := signerResponse{Data: []signerEntry{
			{
				Name:                "test-kc",
				ClientID:            "test-client",
				ExternalAuthURL:     idpServer.URL,
				EnrollToCertEnabled: true,
			},
		}}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
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
		Fallback: FallbackConfig{
			Enabled:          true,
			PollInterval:     10 * time.Second,
			TempNameTemplate: "{username}-pending-{nonce_short}",
			Timeout:          1 * time.Hour,
		},
		Claims: ClaimsConfig{
			UsernameClaim:     "preferred_username",
			NameTemplate:      "{username}-{device_name}",
			IdentityNameClaim: "device_identity_name",
			ExternalIDClaim:   "device_external_id",
		},
		Token: TokenConfig{
			Issuer:   "https://zdas.test",
			Audience: "ziti-enrolltocert",
			Expiry:   5 * time.Minute,
		},
		Session: SessionConfig{
			Timeout:    10 * time.Minute,
			CodeExpiry: 60 * time.Second,
		},
	}

	// Build server components manually (no identity file needed for this test).
	keys, _ := GenerateKeySet()
	registry := NewProviderRegistry()
	store := newMemStore(cfg.Session.Timeout, cfg.Session.CodeExpiry, storeSweepInterval)
	t.Cleanup(store.stop)

	disc := newSignerDiscovery(cfg.Controller, http.DefaultClient, nil, registry, nil, slog.Default())
	if err := disc.poll(t.Context()); err != nil {
		t.Fatalf("discovery: %v", err)
	}

	// No reconciler in this test (no identity file), but fallback is enabled.
	h := newTestEndpoints(cfg, keys, registry, store, nil)
	mux := h.mux()

	// Tunneler sends /authorize WITHOUT device_name.
	verifier, challenge := generateTestPKCE(t)
	authReq := "/authorize?" + url.Values{
		"redirect_uri":          {"http://localhost:20314/auth/callback"},
		"response_type":         {"code"},
		"state":                 {"fb-state"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"client_id":             {"ziti-enrolltocert"},
	}.Encode()

	w := authorizeAndConsent(t, mux, authReq, "")
	if w.Code != http.StatusSeeOther {
		t.Fatalf("authorize: status = %d, body = %s", w.Code, w.Body.String())
	}
	upstreamRedirect, _ := url.Parse(w.Header().Get("Location"))
	if strings.Contains(upstreamRedirect.String(), "error=") {
		t.Fatalf("expected upstream redirect, got error: %s", upstreamRedirect)
	}
	sessionState := upstreamRedirect.Query().Get("state")

	// Simulate upstream callback.
	req := browserRequest(w, "/callback/test-kc?code=upstream-code&state="+sessionState)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		t.Fatalf("callback: status = %d, body = %s", w.Code, w.Body.String())
	}
	tunnelerRedirect, _ := url.Parse(w.Header().Get("Location"))
	zdasCode := tunnelerRedirect.Query().Get("code")

	// Token exchange.
	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {zdasCode},
		"redirect_uri":  {"http://localhost:20314/auth/callback"},
		"code_verifier": {verifier},
	}
	tokenReq := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(tokenForm.Encode()))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, tokenReq)
	if w.Code != http.StatusOK {
		t.Fatalf("token: status = %d, body = %s", w.Code, w.Body.String())
	}

	var tokenResp map[string]any
	json.Unmarshal(w.Body.Bytes(), &tokenResp)
	rawJWT := tokenResp["id_token"].(string)

	jwksBytes, _ := JWKS(keys)
	pubSet, _ := jwk.Parse(jwksBytes)
	tok, err := jwt.Parse([]byte(rawJWT), jwt.WithKeySet(pubSet, jws.WithInferAlgorithmFromKey(true)))
	if err != nil {
		t.Fatalf("verify jwt: %v", err)
	}

	// Verify fallback claims.
	idName := claim(tok, "device_identity_name")
	name := idName.(string)
	if !strings.HasPrefix(name, "charlie-pending-") {
		t.Errorf("device_identity_name = %q, want charlie-pending-*", name)
	}
	extID := claim(tok, "device_external_id")
	if extID == nil || extID == "" {
		t.Error("device_external_id missing")
	}
	devName := claim(tok, "device_name")
	if devName != "" {
		t.Errorf("device_name should be empty for fallback, got %v", devName)
	}
}

// replicaConfig returns a Config for NewServer backed by a mock controller
// that advertises no signers, so tests register providers directly.
func replicaConfig(t *testing.T) Config {
	t.Helper()
	ctrlMux := http.NewServeMux()
	ctrlMux.HandleFunc("/edge/client/v1/external-jwt-signers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(signerResponse{Data: []signerEntry{}})
	})
	ctrlServer := httptest.NewServer(ctrlMux)
	t.Cleanup(ctrlServer.Close)
	return Config{
		Listen:      ":0",
		ExternalURL: "https://zdas.test",
		TLS:         TLSConfig{Mode: TLSModeNone},
		Controller: ControllerConfig{
			APIURL:     ctrlServer.URL,
			SelfIssuer: "https://zdas.test",
		},
		Claims: defaultClaimsConfig(),
		Token: TokenConfig{
			Issuer:   "https://zdas.test",
			Audience: "ziti-enrolltocert",
			Expiry:   5 * time.Minute,
		},
		Session: SessionConfig{
			Timeout:    10 * time.Minute,
			CodeExpiry: 60 * time.Second,
		},
	}
}

// newReplica builds a Server with opts and a mock upstream provider, and
// returns its mux.
func newReplica(t *testing.T, cfg Config, opts ...Option) (*Server, http.Handler) {
	t.Helper()
	srv, err := NewServer(cfg, slog.Default(), opts...)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { srv.Shutdown(context.Background()) })
	if err := srv.registry.Register(&callbackProvider{
		name:   "mock-idp",
		issuer: "https://mock-idp",
		identity: &UpstreamIdentity{
			Subject:  "u42",
			Username: "alice",
			Issuer:   "https://mock-idp",
			Raw:      map[string]any{"preferred_username": "alice"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	return srv, srv.handlers.mux()
}

// enrollAcross runs GET /authorize on start, the consent post and /callback
// on callback, and /token on token, and returns the minted JWT.
func enrollAcross(t *testing.T, start, callback, token http.Handler) string {
	t.Helper()
	verifier, challenge := generateTestPKCE(t)
	authReq := "/authorize?" + url.Values{
		"redirect_uri":          {"http://localhost:20314/auth/callback"},
		"response_type":         {"code"},
		"state":                 {"tunneler-state"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"device_name":           {"laptop"},
	}.Encode()
	page := httptest.NewRecorder()
	start.ServeHTTP(page, httptest.NewRequest(http.MethodGet, authReq, nil))
	w := consent(t, callback, page, "")
	if w.Code != http.StatusSeeOther {
		t.Fatalf("authorize: status = %d, body = %s", w.Code, w.Body.String())
	}
	upstream, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse upstream redirect: %v", err)
	}

	callbackReq := "/callback/mock-idp?" + url.Values{
		"code":  {"upstream-code"},
		"state": {upstream.Query().Get("state")},
	}.Encode()
	req := browserRequest(w, callbackReq)
	w = httptest.NewRecorder()
	callback.ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		t.Fatalf("callback: status = %d, body = %s", w.Code, w.Body.String())
	}
	tunneler, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse tunneler redirect: %v", err)
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {tunneler.Query().Get("code")},
		"redirect_uri":  {"http://localhost:20314/auth/callback"},
		"code_verifier": {verifier},
	}
	req = httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	token.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("token: status = %d, body = %s", w.Code, w.Body.String())
	}
	var resp struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal token response: %v", err)
	}
	return resp.IDToken
}

// verifyWithJWKSFrom verifies rawJWT against the JWKS served by mux, as the
// controller would when it reaches that replica.
func verifyWithJWKSFrom(t *testing.T, mux http.Handler, rawJWT string) jwt.Token {
	t.Helper()
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("jwks: status = %d", w.Code)
	}
	set, err := jwk.Parse(w.Body.Bytes())
	if err != nil {
		t.Fatalf("parse jwks: %v", err)
	}
	tok, err := jwt.Parse([]byte(rawJWT), jwt.WithKeySet(set))
	if err != nil {
		t.Fatalf("verify jwt: %v", err)
	}
	return tok
}

// TestIntegrationMultiReplicaFlow runs one enrollment across two replicas
// that share an injected key and store: /authorize on the first, /callback
// on the second, /token on the first, and the token is verified against the
// second's JWKS.
func TestIntegrationMultiReplicaFlow(t *testing.T) {
	ks, err := GenerateKeySet()
	if err != nil {
		t.Fatalf("GenerateKeySet: %v", err)
	}
	store := newJSONStore()
	cfg := replicaConfig(t)
	_, a := newReplica(t, cfg, WithKeySet(ks), WithStore(store))
	_, b := newReplica(t, cfg, WithKeySet(ks), WithStore(store))

	rawJWT := enrollAcross(t, a, b, a)
	tok := verifyWithJWKSFrom(t, b, rawJWT)
	if name := claim(tok, "device_identity_name"); name != "alice-laptop" {
		t.Errorf("device_identity_name = %v", name)
	}
}

// TestIntegrationMultiReplicaRotationOverlap covers step 2 of the rotation
// documented on WithKeySet: one replica already signs with the new key while
// another still signs with the old one, and each verifies the other's tokens.
func TestIntegrationMultiReplicaRotationOverlap(t *testing.T) {
	oldKey, err := GenerateKeySet()
	if err != nil {
		t.Fatalf("GenerateKeySet: %v", err)
	}
	newKey, err := GenerateKeySet()
	if err != nil {
		t.Fatalf("GenerateKeySet: %v", err)
	}
	store := newJSONStore()
	cfg := replicaConfig(t)
	_, rotated := newReplica(t, cfg, WithKeySet(newKey, oldKey), WithStore(store))
	_, lagging := newReplica(t, cfg, WithKeySet(oldKey, newKey), WithStore(store))

	verifyWithJWKSFrom(t, lagging, enrollAcross(t, rotated, rotated, rotated))
	verifyWithJWKSFrom(t, rotated, enrollAcross(t, lagging, lagging, lagging))
}

// TestIntegrationProvisionCompleteAcrossReplicas runs an interactive
// provisioning detour across two replicas sharing a store: the picker
// redirect comes from one, and the embedder's handler finishes the flow
// through the other's Handler. The token carries the embedder's claims.
func TestIntegrationProvisionCompleteAcrossReplicas(t *testing.T) {
	ks, err := GenerateKeySet()
	if err != nil {
		t.Fatalf("GenerateKeySet: %v", err)
	}
	store := newJSONStore()
	cfg := replicaConfig(t)
	picker := WithProvisioner(&interactiveProvisioner{redirectURL: "https://embedder.example.com/pick?enroll_id=e1"})
	_, a := newReplica(t, cfg, WithKeySet(ks), WithStore(store), picker)
	srvB, b := newReplica(t, cfg, WithKeySet(ks), WithStore(store), picker)
	handlerB := &Handler{Handler: b, srv: srvB}

	verifier, challenge := generateTestPKCE(t)
	redirectURI := "http://localhost:20314/auth/callback"
	w := authorizeAndConsent(t, a, "/authorize?"+url.Values{
		"redirect_uri":          {redirectURI},
		"state":                 {"tstate"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"device_name":           {"laptop"},
	}.Encode(), "")
	upstream, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse upstream redirect: %v", err)
	}
	cb := httptest.NewRecorder()
	a.ServeHTTP(cb, browserRequest(w, "/callback/mock-idp?code=x&state="+upstream.Query().Get("state")))
	pick, err := url.Parse(cb.Header().Get("Location"))
	if err != nil || pick.Host != "embedder.example.com" {
		t.Fatalf("callback: status = %d, Location = %q; want picker redirect", cb.Code, cb.Header().Get("Location"))
	}
	if pick.Query().Get("enroll_id") != "e1" {
		t.Errorf("picker redirect lost the provisioner's query: %s", pick)
	}

	claims := map[string]any{
		"sub":                  "ext-from-embedder",
		"device_external_id":   "ext-from-embedder",
		"device_identity_name": "alice-laptop",
	}
	done := httptest.NewRecorder()
	handlerB.CompleteProvision(done, httptest.NewRequest(http.MethodPost, "/pick", nil), pick.Query().Get("pending_id"), claims, nil)
	tunneler, err := url.Parse(done.Header().Get("Location"))
	if err != nil || done.Code != http.StatusFound {
		t.Fatalf("CompleteProvision: status = %d, body = %s", done.Code, done.Body.String())
	}
	if tunneler.Query().Get("state") != "tstate" {
		t.Errorf("state = %q, want tstate", tunneler.Query().Get("state"))
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {tunneler.Query().Get("code")},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tw := httptest.NewRecorder()
	a.ServeHTTP(tw, req)
	if tw.Code != http.StatusOK {
		t.Fatalf("token: status = %d, body = %s", tw.Code, tw.Body.String())
	}
	var resp struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(tw.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal token response: %v", err)
	}
	tok := verifyWithJWKSFrom(t, b, resp.IDToken)
	if ext := claim(tok, "device_external_id"); ext != "ext-from-embedder" {
		t.Errorf("device_external_id = %v, want ext-from-embedder", ext)
	}
}
