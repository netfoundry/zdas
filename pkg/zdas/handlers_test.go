package zdas

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// newTestEndpoints returns endpoints over store, keyed as NewServer keys
// them, with entries expiring by the store's TTLs.
func newTestEndpoints(cfg Config, keys *KeySet, reg *ProviderRegistry, store *memStore, p EnrollmentProvisioner) *endpoints {
	cfg.Session.Timeout, cfg.Session.CodeExpiry = store.sessionTTL, store.codeTTL
	return newEndpoints(cfg, keys, nil, reg, store, nil, nil, p, slog.Default())
}

// seedSession stores sess as /authorize would, but without binding it to a
// browser, so that a /callback without a cookie finds it. It returns the
// session ID.
func seedSession(t *testing.T, h *endpoints, sess *AuthSession) string {
	t.Helper()
	id, err := h.createSession(context.Background(), sess, "")
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}
	return id
}

// seedPendingProvision stores pp as a provisioner redirect would, and
// returns its pending ID.
func seedPendingProvision(t *testing.T, h *endpoints, pp *PendingProvision) string {
	t.Helper()
	id, err := h.createPendingProvision(context.Background(), pp)
	if err != nil {
		t.Fatalf("createPendingProvision: %v", err)
	}
	return id
}

func setupHandlers(t *testing.T) (*endpoints, *stubProvider) {
	t.Helper()
	ks, err := GenerateKeySet()
	if err != nil {
		t.Fatalf("GenerateKeySet: %v", err)
	}
	reg := NewProviderRegistry()
	sp := &stubProvider{name: "test-idp", issuer: "https://test-idp"}
	if err := reg.Register(sp); err != nil {
		t.Fatal(err)
	}
	store := newMemStore(10*time.Minute, 60*time.Second, storeSweepInterval)
	t.Cleanup(store.stop)

	cfg := Config{
		ExternalURL: "https://zdas.example.com",
		Claims:      defaultClaimsConfig(),
		Token: TokenConfig{
			Issuer:   "https://zdas.example.com",
			Audience: "ziti-enrolltocert",
			Expiry:   5 * time.Minute,
		},
	}
	h := newTestEndpoints(cfg, ks, reg, store, nil)
	return h, sp
}

// generateTestPKCE returns a verifier and its S256 challenge for tests.
func generateTestPKCE(t *testing.T) (verifier, challenge string) {
	t.Helper()
	v, c, err := generatePKCE()
	if err != nil {
		t.Fatalf("generatePKCE: %v", err)
	}
	return v, c
}

func TestHandleDiscovery(t *testing.T) {
	h, _ := setupHandlers(t)
	mux := h.mux()

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var doc map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if doc["issuer"] != "https://zdas.example.com" {
		t.Errorf("issuer = %v", doc["issuer"])
	}
	if doc["jwks_uri"] != "https://zdas.example.com/.well-known/jwks.json" {
		t.Errorf("jwks_uri = %v", doc["jwks_uri"])
	}

	// The advertised issuer is the one tokens carry, which may differ from
	// the external URL.
	h.cfg.Token.Issuer = "https://issuer.example.com"
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if doc["issuer"] != "https://issuer.example.com" {
		t.Errorf("issuer = %v, want the token issuer", doc["issuer"])
	}
}

func TestHandleJWKS(t *testing.T) {
	h, _ := setupHandlers(t)
	mux := h.mux()

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var doc struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(doc.Keys) != 1 {
		t.Errorf("keys count = %d", len(doc.Keys))
	}
}

func TestHandleNetworkJWTsNotCached(t *testing.T) {
	h, _ := setupHandlers(t)
	mux := h.mux()

	req := httptest.NewRequest(http.MethodGet, "/network-jwts", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	// No discovery set (nil) - should return 503.
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", w.Code)
	}
}

func TestHandleExtJWTSignersNotCached(t *testing.T) {
	h, _ := setupHandlers(t)
	mux := h.mux()

	req := httptest.NewRequest(http.MethodGet, "/edge/client/v1/external-jwt-signers", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	// No discovery set (nil) - should return 503.
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", w.Code)
	}
}

func TestHandleAuthorizeMissingDeviceNameFallbackDisabled(t *testing.T) {
	h, _ := setupHandlers(t)
	mux := h.mux()
	_, challenge := generateTestPKCE(t)

	reqURL := "/authorize?redirect_uri=http://localhost:20314/auth/callback&response_type=code&state=s1" +
		"&code_challenge=" + challenge + "&code_challenge_method=S256"
	req := httptest.NewRequest(http.MethodGet, reqURL, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "error=invalid_request") || !strings.Contains(loc, "device_name") {
		t.Errorf("expected device_name error redirect, got %s", loc)
	}
}

func TestHandleAuthorizeFallbackEnabled(t *testing.T) {
	// Same as setupHandlers but with fallback enabled.
	ks, _ := GenerateKeySet()
	reg := NewProviderRegistry()
	sp := &stubProvider{name: "test-idp", issuer: "https://test-idp"}
	_ = reg.Register(sp)
	store := newMemStore(10*time.Minute, 60*time.Second, storeSweepInterval)
	t.Cleanup(store.stop)

	cfg := Config{
		ExternalURL: "https://zdas.example.com",
		Fallback:    FallbackConfig{Enabled: true, TempNameTemplate: "{username}-pending-{nonce_short}"},
		Claims:      defaultClaimsConfig(),
		Token: TokenConfig{
			Issuer:   "https://zdas.example.com",
			Audience: "ziti-enrolltocert",
			Expiry:   5 * time.Minute,
		},
	}
	h := newTestEndpoints(cfg, ks, reg, store, nil)
	mux := h.mux()

	_, challenge := generateTestPKCE(t)
	reqURL := "/authorize?redirect_uri=http://localhost:20314/auth/callback&response_type=code&state=s1" +
		"&code_challenge=" + challenge + "&code_challenge_method=S256"
	req := httptest.NewRequest(http.MethodGet, reqURL, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	// Should redirect to upstream (not error), even without device_name.
	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", w.Code)
	}
	loc := w.Header().Get("Location")
	if strings.Contains(loc, "error=") {
		t.Errorf("expected upstream redirect, got error: %s", loc)
	}
	if !strings.HasPrefix(loc, "https://stub/test-idp") {
		t.Errorf("expected redirect to stub provider, got %s", loc)
	}
}

func TestHandleAuthorizeIDPSelector(t *testing.T) {
	ks, _ := GenerateKeySet()
	reg := NewProviderRegistry()
	_ = reg.Register(&stubProvider{name: "keycloak", issuer: "https://kc"})
	_ = reg.Register(&stubProvider{name: "github", issuer: "https://github.com"})
	store := newMemStore(10*time.Minute, 60*time.Second, storeSweepInterval)
	t.Cleanup(store.stop)

	cfg := Config{
		ExternalURL: "https://zdas.example.com",
		Claims:      defaultClaimsConfig(),
		Token:       TokenConfig{Issuer: "https://zdas.example.com", Audience: "ziti-enrolltocert", Expiry: 5 * time.Minute},
	}
	h := newTestEndpoints(cfg, ks, reg, store, nil)
	mux := h.mux()

	_, challenge := generateTestPKCE(t)
	// Multiple providers, no selection yet - should show selector page.
	reqURL := "/authorize?redirect_uri=http://localhost:20314/auth/callback&response_type=code&state=s1" +
		"&code_challenge=" + challenge + "&code_challenge_method=S256&device_name=laptop"
	req := httptest.NewRequest(http.MethodGet, reqURL, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Select") {
		t.Error("expected selector page title")
	}
	if !strings.Contains(body, "keycloak") || !strings.Contains(body, "github") {
		t.Errorf("expected both provider names in page, got: %s", body)
	}
	// Each link should carry forward the original query params.
	if !strings.Contains(body, "device_name=laptop") {
		t.Error("expected device_name in selector links")
	}
	if !strings.Contains(body, "idp=keycloak") || !strings.Contains(body, "idp=github") {
		t.Error("expected idp param in selector links")
	}
	// Links must be relative so the browser resolves them against the
	// current /authorize URL, regardless of how the embedding app mounts
	// ZDAS (e.g., at /zdas). An absolute "/authorize?..." would 404 when
	// ZDAS is mounted under a prefix via http.StripPrefix.
	if !strings.Contains(body, `href="?`) {
		t.Errorf("expected relative href=\"?...\" in selector, got: %s", body)
	}
	if strings.Contains(body, `href="/authorize`) {
		t.Errorf("selector must not use absolute /authorize path; got: %s", body)
	}
}

// idpSelectorHandlers sets up endpoints with multiple providers and an
// optional IDPSelectorURL. Returns the mux for sending requests.
func idpSelectorHandlers(t *testing.T, selectorURL string) *http.ServeMux {
	t.Helper()
	ks, _ := GenerateKeySet()
	reg := NewProviderRegistry()
	_ = reg.Register(&stubProvider{name: "github", issuer: "https://github.com"})
	_ = reg.Register(&stubProvider{name: "keycloak", issuer: "https://kc"})
	store := newMemStore(10*time.Minute, 60*time.Second, storeSweepInterval)
	t.Cleanup(store.stop)

	cfg := Config{
		ExternalURL:    "https://zdas.example.com",
		IDPSelectorURL: selectorURL,
		Claims:         defaultClaimsConfig(),
		Token:          TokenConfig{Issuer: "https://zdas.example.com", Audience: "ziti-enroll", Expiry: 5 * time.Minute},
	}
	h := newTestEndpoints(cfg, ks, reg, store, nil)
	return h.mux()
}

func TestIDPSelectorURLUnsetRendersBuiltinPicker(t *testing.T) {
	// Existing behavior: no IDPSelectorURL, multiple providers, no idp
	// param -> built-in picker page rendered inline.
	mux := idpSelectorHandlers(t, "")
	_, challenge := generateTestPKCE(t)
	reqURL := "/authorize?redirect_uri=http://localhost:20314/auth/callback&response_type=code&state=s1" +
		"&code_challenge=" + challenge + "&code_challenge_method=S256&device_name=laptop"
	req := httptest.NewRequest(http.MethodGet, reqURL, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (built-in picker)", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Select an identity provider") {
		t.Error("expected built-in picker page to be rendered")
	}
}

func TestIDPSelectorURLRedirectsWithProvidersAndQuery(t *testing.T) {
	mux := idpSelectorHandlers(t, "https://app.example.com/pick-idp")
	_, challenge := generateTestPKCE(t)
	reqURL := "/authorize?redirect_uri=http://localhost:20314/auth/callback&response_type=code&state=s1" +
		"&code_challenge=" + challenge + "&code_challenge_method=S256&device_name=laptop"
	req := httptest.NewRequest(http.MethodGet, reqURL, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", w.Code)
	}
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}
	if loc.Scheme != "https" || loc.Host != "app.example.com" || loc.Path != "/pick-idp" {
		t.Errorf("redirect target = %q", loc.String())
	}
	// Providers list must be sorted and comma-separated.
	if got := loc.Query().Get("providers"); got != "github,keycloak" {
		t.Errorf("providers = %q, want github,keycloak", got)
	}
	// Original query params must be preserved.
	if loc.Query().Get("state") != "s1" {
		t.Errorf("state = %q", loc.Query().Get("state"))
	}
	if loc.Query().Get("device_name") != "laptop" {
		t.Errorf("device_name = %q", loc.Query().Get("device_name"))
	}
	if loc.Query().Get("redirect_uri") != "http://localhost:20314/auth/callback" {
		t.Errorf("redirect_uri = %q", loc.Query().Get("redirect_uri"))
	}
}

func TestIDPSelectorURLSingleProviderSkipsPicker(t *testing.T) {
	// With IDPSelectorURL set but only one provider registered, ZDAS must
	// still bypass the picker entirely and go straight to the upstream.
	ks, _ := GenerateKeySet()
	reg := NewProviderRegistry()
	_ = reg.Register(&stubProvider{name: "only-one", issuer: "https://only"})
	store := newMemStore(10*time.Minute, 60*time.Second, storeSweepInterval)
	t.Cleanup(store.stop)

	cfg := Config{
		ExternalURL:    "https://zdas.example.com",
		IDPSelectorURL: "https://app.example.com/pick-idp",
		Claims:         defaultClaimsConfig(),
		Token:          TokenConfig{Issuer: "https://zdas.example.com", Audience: "ziti-enroll", Expiry: 5 * time.Minute},
	}
	h := newTestEndpoints(cfg, ks, reg, store, nil)
	mux := h.mux()

	_, challenge := generateTestPKCE(t)
	reqURL := "/authorize?redirect_uri=http://localhost:20314/auth/callback&response_type=code&state=s1" +
		"&code_challenge=" + challenge + "&code_challenge_method=S256&device_name=laptop"
	req := httptest.NewRequest(http.MethodGet, reqURL, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", w.Code)
	}
	// Must redirect to the stub upstream, NOT the picker URL.
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://stub/only-one") {
		t.Errorf("expected redirect to upstream, got %s", loc)
	}
}

func TestIDPSelectorURLIDPSuppliedSkipsPicker(t *testing.T) {
	// With IDPSelectorURL set, multiple providers, AND an idp hint,
	// ZDAS must skip the picker and go straight to the chosen upstream.
	mux := idpSelectorHandlers(t, "https://app.example.com/pick-idp")
	_, challenge := generateTestPKCE(t)
	reqURL := "/authorize?redirect_uri=http://localhost:20314/auth/callback&response_type=code&state=s1" +
		"&code_challenge=" + challenge + "&code_challenge_method=S256&device_name=laptop&idp=github"
	req := httptest.NewRequest(http.MethodGet, reqURL, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://stub/github") {
		t.Errorf("expected redirect to stub github, got %s", loc)
	}
}

func TestIDPSelectorURLAppendsToExistingQuery(t *testing.T) {
	// The configured picker URL already has a query string. The original
	// /authorize params must be appended with "&", producing exactly one "?".
	mux := idpSelectorHandlers(t, "https://app.example.com/pick-idp?source=zdas")
	_, challenge := generateTestPKCE(t)
	reqURL := "/authorize?redirect_uri=http://localhost:20314/auth/callback&response_type=code&state=s1" +
		"&code_challenge=" + challenge + "&code_challenge_method=S256&device_name=laptop"
	req := httptest.NewRequest(http.MethodGet, reqURL, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", w.Code)
	}
	location := w.Header().Get("Location")
	if strings.Count(location, "?") != 1 {
		t.Errorf("expected exactly one '?' in redirect, got %q", location)
	}
	loc, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}
	// Both the original picker query and our additions must be present.
	if loc.Query().Get("source") != "zdas" {
		t.Errorf("source param lost: %q", loc.Query().Get("source"))
	}
	if loc.Query().Get("providers") != "github,keycloak" {
		t.Errorf("providers = %q", loc.Query().Get("providers"))
	}
	if loc.Query().Get("state") != "s1" {
		t.Errorf("state = %q", loc.Query().Get("state"))
	}
}

func TestHandleAuthorizeMissingPKCE(t *testing.T) {
	h, _ := setupHandlers(t)
	mux := h.mux()

	reqURL := "/authorize?redirect_uri=http://localhost:20314/auth/callback&response_type=code&state=s1&device_name=laptop"
	req := httptest.NewRequest(http.MethodGet, reqURL, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "error=invalid_request") || !strings.Contains(loc, "PKCE") {
		t.Errorf("expected PKCE error redirect, got %s", loc)
	}
}

func TestHandleAuthorizeRedirects(t *testing.T) {
	h, _ := setupHandlers(t)
	mux := h.mux()
	_, challenge := generateTestPKCE(t)

	reqURL := "/authorize?redirect_uri=http://localhost:20314/auth/callback&response_type=code&state=s1" +
		"&code_challenge=" + challenge + "&code_challenge_method=S256&device_name=laptop"
	req := httptest.NewRequest(http.MethodGet, reqURL, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://stub/test-idp") {
		t.Errorf("expected redirect to stub provider, got %s", loc)
	}
}

func TestTokenEndpointFullFlow(t *testing.T) {
	// This tests the /token endpoint directly by pre-populating an auth code
	// in the session store (simulating what /callback would have done).
	h, _ := setupHandlers(t)
	mux := h.mux()

	verifier, challenge := generateTestPKCE(t)

	claims := ComposeClaims(defaultClaimsConfig(), FallbackConfig{}, &UpstreamIdentity{
		Subject:  "user1",
		Username: "alice",
		Issuer:   "https://test-idp",
		Raw:      map[string]any{"preferred_username": "alice"},
	}, &DeviceInfo{DeviceName: "macbook"}, "")

	code, err := h.createCode(t.Context(), &AuthCode{
		Claims:              claims,
		RedirectURI:         "http://localhost:20314/auth/callback",
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatalf("CreateCode: %v", err)
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"http://localhost:20314/auth/callback"},
		"code_verifier": {verifier},
		"client_id":     {"ziti-enrolltocert"},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp["token_type"] != "Bearer" {
		t.Errorf("token_type = %v", resp["token_type"])
	}
	if resp["access_token"] == nil || resp["access_token"] == "" {
		t.Error("access_token is empty")
	}
	if resp["id_token"] == nil || resp["id_token"] == "" {
		t.Error("id_token is empty")
	}
}

func TestTokenEndpointRejectsReplay(t *testing.T) {
	h, _ := setupHandlers(t)
	mux := h.mux()
	verifier, challenge := generateTestPKCE(t)

	code, _ := h.createCode(t.Context(), &AuthCode{
		Claims:              map[string]any{"sub": "x"},
		RedirectURI:         "http://localhost:20314/auth/callback",
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	})

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"http://localhost:20314/auth/callback"},
		"code_verifier": {verifier},
	}

	// First exchange.
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("first exchange: status = %d", w.Code)
	}

	// Second exchange (replay) should fail.
	req = httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("replay: status = %d, want 400", w.Code)
	}
	var errResp map[string]string
	json.Unmarshal(w.Body.Bytes(), &errResp)
	if errResp["error"] != "invalid_grant" {
		t.Errorf("error = %q", errResp["error"])
	}
}

func TestTokenEndpointBadPKCE(t *testing.T) {
	h, _ := setupHandlers(t)
	mux := h.mux()
	_, challenge := generateTestPKCE(t)

	code, _ := h.createCode(t.Context(), &AuthCode{
		Claims:              map[string]any{"sub": "x"},
		RedirectURI:         "http://localhost:20314/auth/callback",
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	})

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"http://localhost:20314/auth/callback"},
		"code_verifier": {"wrong-verifier"},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", w.Code)
	}
	var errResp map[string]string
	json.Unmarshal(w.Body.Bytes(), &errResp)
	if errResp["error"] != "invalid_grant" {
		t.Errorf("error = %q", errResp["error"])
	}
}

func TestVerifyPKCE(t *testing.T) {
	verifier, challenge := generateTestPKCE(t)
	if !verifyPKCE(challenge, "S256", verifier) {
		t.Error("valid PKCE should pass")
	}
	if verifyPKCE(challenge, "S256", "wrong") {
		t.Error("wrong verifier should fail")
	}
	if verifyPKCE(challenge, "plain", verifier) {
		t.Error("non-S256 method should fail")
	}
}

// callbackProvider implements UpstreamProvider for handler callback tests,
// returning a canned identity on ExchangeAndIdentify.
type callbackProvider struct {
	name     string
	issuer   string
	identity *UpstreamIdentity
	err      error // returned by ExchangeAndIdentify when set
}

func (p *callbackProvider) Name() string   { return p.name }
func (p *callbackProvider) Issuer() string { return p.issuer }
func (p *callbackProvider) AuthorizeURL(state, redirectURI string) string {
	return "https://idp/authorize?state=" + state
}
func (p *callbackProvider) ExchangeAndIdentify(_ context.Context, code, redirectURI string) (*UpstreamIdentity, error) {
	if p.err != nil {
		return nil, p.err
	}
	return p.identity, nil
}

func TestCallbackToTokenFullFlow(t *testing.T) {
	ks, _ := GenerateKeySet()
	reg := NewProviderRegistry()
	cp := &callbackProvider{
		name:   "mock-idp",
		issuer: "https://mock-idp",
		identity: &UpstreamIdentity{
			Subject:  "u42",
			Username: "jsmith",
			Issuer:   "https://mock-idp",
			Raw:      map[string]any{"preferred_username": "jsmith"},
		},
	}
	_ = reg.Register(cp)
	store := newMemStore(10*time.Minute, 60*time.Second, storeSweepInterval)
	t.Cleanup(store.stop)

	cfg := Config{
		ExternalURL: "https://zdas.example.com",
		Claims:      defaultClaimsConfig(),
		Token: TokenConfig{
			Issuer:   "https://zdas.example.com",
			Audience: "ziti-enrolltocert",
			Expiry:   5 * time.Minute,
		},
	}
	h := newTestEndpoints(cfg, ks, reg, store, nil)
	mux := h.mux()

	// Pre-create a session as if /authorize had run.
	verifier, challenge := generateTestPKCE(t)
	sessID := seedSession(t, h, &AuthSession{
		TunnelerRedirectURI:         "http://localhost:20314/auth/callback",
		TunnelerState:               "tstate",
		TunnelerCodeChallenge:       challenge,
		TunnelerCodeChallengeMethod: "S256",
		DeviceInfo:                  &DeviceInfo{DeviceName: "macbook"},
		UpstreamProviderName:        "mock-idp",
	})

	// Simulate /callback from upstream.
	callbackURL := "/callback?code=upstream-code&state=" + sessID
	req := httptest.NewRequest(http.MethodGet, callbackURL, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("callback status = %d, body = %s", w.Code, w.Body.String())
	}
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}
	if loc.Query().Get("state") != "tstate" {
		t.Errorf("state = %q", loc.Query().Get("state"))
	}
	zdasCode := loc.Query().Get("code")
	if zdasCode == "" {
		t.Fatal("no zdas code in callback redirect")
	}

	// Exchange the ZDAS code at /token.
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {zdasCode},
		"redirect_uri":  {"http://localhost:20314/auth/callback"},
		"code_verifier": {verifier},
	}
	req = httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("token status = %d, body = %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["access_token"] == nil || resp["access_token"] == "" {
		t.Error("missing access_token")
	}
}

// provisionerFunc adapts a function to EnrollmentProvisioner.
type provisionerFunc func(context.Context, ProvisionRequest) (*ProvisionResult, error)

func (f provisionerFunc) Provision(ctx context.Context, req ProvisionRequest) (*ProvisionResult, error) {
	return f(ctx, req)
}

// TestCallbackErrorMapping verifies the error the tunneler gets for each way
// /callback can fail after the session is found.
func TestCallbackErrorMapping(t *testing.T) {
	identity := &UpstreamIdentity{Subject: "u1", Username: "alice", Issuer: "https://mock-idp"}
	cases := []struct {
		name        string
		query       string
		err         error
		provisioner EnrollmentProvisioner
		wantError   string
	}{
		{"not permitted upstream", "code=c", fmt.Errorf("%w: not in org", ErrAccessDenied), nil, "access_denied"},
		{"upstream failure", "code=c", errors.New("token endpoint down"), nil, "server_error"},
		{"upstream access_denied", "error=access_denied", nil, nil, "access_denied"},
		{"upstream login_required", "error=login_required", nil, nil, "login_required"},
		{"upstream unknown error", "error=%3Cscript%3E", nil, nil, "server_error"},
		{"no code", "", nil, nil, "server_error"},
		{"provisioner returns nil", "code=c", nil, provisionerFunc(func(context.Context, ProvisionRequest) (*ProvisionResult, error) {
			return nil, nil
		}), "server_error"},
		{"provisioner returns nothing", "code=c", nil, provisionerFunc(func(context.Context, ProvisionRequest) (*ProvisionResult, error) {
			return &ProvisionResult{}, nil
		}), "server_error"},
		{"provisioner returns a mistyped claim", "code=c", nil, provisionerFunc(func(context.Context, ProvisionRequest) (*ProvisionResult, error) {
			return &ProvisionResult{Claims: map[string]any{"sub": 123}}, nil
		}), "server_error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ks, _ := GenerateKeySet()
			reg := NewProviderRegistry()
			_ = reg.Register(&callbackProvider{name: "mock-idp", issuer: "https://mock-idp", identity: identity, err: tc.err})
			store := newMemStore(10*time.Minute, time.Minute, storeSweepInterval)
			t.Cleanup(store.stop)
			cfg := Config{
				ExternalURL: "https://zdas.test",
				Claims:      defaultClaimsConfig(),
				Token:       TokenConfig{Issuer: "https://zdas.test", Audience: "ziti-enroll", Expiry: 5 * time.Minute},
			}
			h := newTestEndpoints(cfg, ks, reg, store, tc.provisioner)
			sessID := seedSession(t, h, &AuthSession{
				TunnelerRedirectURI:  "http://localhost:20314/auth/callback",
				TunnelerState:        "tstate",
				DeviceInfo:           &DeviceInfo{DeviceName: "laptop"},
				UpstreamProviderName: "mock-idp",
			})

			target := "/callback?state=" + sessID
			if tc.query != "" {
				target += "&" + tc.query
			}
			w := httptest.NewRecorder()
			h.mux().ServeHTTP(w, httptest.NewRequest(http.MethodGet, target, nil))
			loc, err := url.Parse(w.Header().Get("Location"))
			if err != nil || w.Code != http.StatusFound {
				t.Fatalf("status = %d, Location = %q", w.Code, w.Header().Get("Location"))
			}
			if got := loc.Query().Get("error"); got != tc.wantError {
				t.Errorf("error = %q, want %q", got, tc.wantError)
			}
			if loc.Query().Has("code") {
				t.Error("code issued on a failed callback")
			}
		})
	}
}

// TestRedirectKeepsExistingQuery verifies that a code is appended to a
// redirect URI that already has a query, rather than starting a second one.
func TestRedirectKeepsExistingQuery(t *testing.T) {
	cases := []struct{ in, want string }{
		{"http://localhost:1/cb", "http://localhost:1/cb?code=c"},
		{"http://localhost:1/cb?x=1", "http://localhost:1/cb?x=1&code=c"},
		{"http://localhost:1/cb?x=1#frag", "http://localhost:1/cb?x=1&code=c#frag"},
	}
	for _, tc := range cases {
		if got := withQuery(tc.in, url.Values{"code": {"c"}}); got != tc.want {
			t.Errorf("withQuery(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
