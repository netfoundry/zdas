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
	"unsafe"
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
	id := mustID(t)
	if err := h.createPendingProvision(context.Background(), id, pp); err != nil {
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

	// Should redirect to upstream (not error), even without device_name,
	// after a page naming the device by its hostname.
	page := httptest.NewRecorder()
	mux.ServeHTTP(page, httptest.NewRequest(http.MethodGet, authorizeURL(t, url.Values{"device_name": nil, "hostname": {"build-box"}}), nil))
	if !strings.Contains(page.Body.String(), "<strong>build-box</strong>") {
		t.Errorf("fallback page doesn't name the device by hostname: %s", page.Body)
	}
	w := consent(t, mux, page, "")
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", w.Code)
	}
	loc := w.Header().Get("Location")
	if strings.Contains(loc, "error=") {
		t.Errorf("expected upstream redirect, got error: %s", loc)
	}
	if !strings.HasPrefix(loc, "https://stub/test-idp") {
		t.Errorf("expected redirect to stub provider, got %s", loc)
	}
}

// TestHandleAuthorizeFallbackRefusedForTokenEnrollment verifies that
// fallback logins are refused while ZDAS's signer allows enroll-to-token,
// and served again once it doesn't.
func TestHandleAuthorizeFallbackRefusedForTokenEnrollment(t *testing.T) {
	ks, _ := GenerateKeySet()
	reg := NewProviderRegistry()
	_ = reg.Register(&stubProvider{name: "test-idp", issuer: "https://test-idp"})
	store := newMemStore(10*time.Minute, 60*time.Second, storeSweepInterval)
	t.Cleanup(store.stop)
	cfg := Config{
		ExternalURL: "https://zdas.example.com",
		Fallback:    FallbackConfig{Enabled: true, TempNameTemplate: "{username}-pending-{nonce_short}"},
		Claims:      defaultClaimsConfig(),
		Token:       TokenConfig{Issuer: "https://zdas.example.com", Audience: "ziti-enroll", Expiry: 5 * time.Minute},
	}
	h := newTestEndpoints(cfg, ks, reg, store, nil)
	h.discovery = &signerDiscovery{}
	mux := h.mux()
	noDevice := authorizeURL(t, url.Values{"device_name": nil})

	h.discovery.selfToToken.Store(true)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, noDevice, nil))
	if loc := w.Header().Get("Location"); w.Code != http.StatusFound || !strings.Contains(loc, "error=invalid_request") || !strings.Contains(loc, "enroll-to-cert") {
		t.Errorf("fallback with token enrollment allowed: %d %s", w.Code, loc)
	}
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, authorizeURL(t, nil), nil))
	if w.Code != http.StatusOK {
		t.Errorf("login with device_name refused: %d %s", w.Code, w.Header().Get("Location"))
	}

	h.discovery.selfToToken.Store(false)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, noDevice, nil))
	if w.Code != http.StatusOK {
		t.Errorf("fallback with cert-only signer refused: %d %s", w.Code, w.Header().Get("Location"))
	}
}

// TestHandleAuthorizeIDPSelector verifies that with several providers
// /authorize shows a consent page with a button for each, that goes nowhere
// until the user picks one, and that the page is safe to show: escaped, not
// frameable, not cached.
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

	page := httptest.NewRecorder()
	mux.ServeHTTP(page, httptest.NewRequest(http.MethodGet, authorizeURL(t, url.Values{
		"device_name": {"<b>laptop</b>"}, "os": {"darwin"}, "arch": {"arm64"},
	}), nil))
	if page.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", page.Code)
	}
	body := page.Body.String()
	for _, want := range []string{
		`value="github">Continue with github`, `value="keycloak">Continue with keycloak`,
		"&lt;b&gt;laptop&lt;/b&gt;", "(darwin arm64)", "localhost:20314", `<form method="post">`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q: %s", want, body)
		}
	}
	if strings.Contains(body, "<b>laptop") {
		t.Error("device name not escaped")
	}
	for k, want := range map[string]string{
		"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'",
		"X-Frame-Options":         "DENY",
		"Cache-Control":           "no-store",
		"X-Content-Type-Options":  "nosniff",
		"Referrer-Policy":         "no-referrer",
	} {
		if got := page.Header().Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}

	w := consent(t, mux, page, "github")
	if w.Code != http.StatusSeeOther || !strings.HasPrefix(w.Header().Get("Location"), "https://stub/github") {
		t.Errorf("consent: %d %s, want 303 to github", w.Code, w.Header().Get("Location"))
	}
}

// TestConsentRequiresBindingCookie verifies that the consent form only
// works from the browser that got the page, once, and only for a session
// that is waiting for consent.
func TestConsentRequiresBindingCookie(t *testing.T) {
	mux := bindingHandlers(t, "https://zdas.example.com")
	post := func(form url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/authorize", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for _, c := range cookies {
			req.AddCookie(c)
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		return w
	}

	page := httptest.NewRecorder()
	mux.ServeHTTP(page, httptest.NewRequest(http.MethodGet, authorizeURL(t, nil), nil))
	id := consentFieldRe.FindStringSubmatch(page.Body.String())[1]
	cookie := liveCookie(t, page, id)
	form := url.Values{"consent": {id}, "idp": {"mock-idp"}}

	// A cross-site form post carries no SameSite=Lax cookie.
	if w := post(form); w.Code != http.StatusBadRequest || w.Header().Get("Location") != "" {
		t.Errorf("without cookie: %d %q, want 400", w.Code, w.Header().Get("Location"))
	}
	// The fields are read from the form only, not the URL.
	inQuery := httptest.NewRequest(http.MethodPost, "/authorize?"+form.Encode(), strings.NewReader(""))
	inQuery.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	inQuery.AddCookie(cookie)
	qw := httptest.NewRecorder()
	mux.ServeHTTP(qw, inQuery)
	if qw.Code != http.StatusBadRequest {
		t.Errorf("fields in the query: %d, want 400", qw.Code)
	}
	if w := post(url.Values{"consent": {id}, "idp": {strings.Repeat("x", maxConsentRequestBytes)}}, cookie); w.Code != http.StatusBadRequest {
		t.Errorf("oversized form: %d, want 400", w.Code)
	}
	w := post(form, cookie)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("with cookie: %d %s", w.Code, w.Body)
	}
	if w := post(form, cookie); w.Code != http.StatusBadRequest {
		t.Errorf("second post: %d, want 400", w.Code)
	}

	// A session waiting for /callback can't be consented to again.
	started, upstream := startAuthorize(t, mux)
	if w := post(url.Values{"consent": {upstream}, "idp": {"mock-idp"}}, liveCookie(t, started, upstream)); w.Code != http.StatusBadRequest {
		t.Errorf("consent to an upstream session: %d, want 400", w.Code)
	}
}

// TestCallbackRejectsConsentSession verifies that a session still waiting
// for consent can't be completed at /callback, even from its own browser.
func TestCallbackRejectsConsentSession(t *testing.T) {
	h, _ := setupHandlers(t)
	mux := h.mux()
	page := httptest.NewRecorder()
	mux.ServeHTTP(page, httptest.NewRequest(http.MethodGet, authorizeURL(t, nil), nil))
	id := consentFieldRe.FindStringSubmatch(page.Body.String())[1]

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, browserRequest(page, "/callback?code=c&state="+id))
	if w.Code != http.StatusBadRequest || w.Header().Get("Location") != "" {
		t.Errorf("callback for a consent session: %d %q, want 400", w.Code, w.Header().Get("Location"))
	}
}

// TestConsentUnknownProvider verifies that a post naming no registered
// provider returns the error to the tunneler.
func TestConsentUnknownProvider(t *testing.T) {
	h, _ := setupHandlers(t)
	mux := h.mux()
	w := authorizeAndConsent(t, mux, authorizeURL(t, nil), "nope")
	if loc := w.Header().Get("Location"); w.Code != http.StatusFound || !strings.HasPrefix(loc, "http://localhost:20314/auth/callback?") || !strings.Contains(loc, "error=invalid_request") {
		t.Errorf("unknown idp: %d %s", w.Code, loc)
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
	// No IDPSelectorURL, multiple providers, no idp param: ZDAS's own
	// consent page offers every provider.
	mux := idpSelectorHandlers(t, "")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, authorizeURL(t, nil), nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (built-in picker)", w.Code)
	}
	if n := len(consentButtonRe.FindAllString(w.Body.String(), -1)); n != 2 {
		t.Errorf("page offers %d providers, want 2", n)
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

	// The host picker posts consent back from the same browser.
	form := url.Values{"consent": {loc.Query().Get("consent")}, "idp": {"keycloak"}}
	post := httptest.NewRequest(http.MethodPost, "/authorize", strings.NewReader(form.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range w.Result().Cookies() {
		post.AddCookie(c)
	}
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, post)
	if got := w.Header().Get("Location"); w.Code != http.StatusSeeOther || !strings.HasPrefix(got, "https://stub/keycloak") {
		t.Errorf("host picker consent: %d %s, want 303 to keycloak", w.Code, got)
	}
}

func TestIDPSelectorURLSingleProviderSkipsPicker(t *testing.T) {
	// With IDPSelectorURL set but only one provider registered, ZDAS
	// skips the host picker and asks for consent on its own page.
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
	w := authorizeAndConsent(t, h.mux(), authorizeURL(t, nil), "")
	if loc := w.Header().Get("Location"); w.Code != http.StatusSeeOther || !strings.HasPrefix(loc, "https://stub/only-one") {
		t.Errorf("consent: %d %s, want 303 to the upstream", w.Code, loc)
	}
}

func TestIDPSelectorURLIDPSuppliedSkipsPicker(t *testing.T) {
	// With IDPSelectorURL set, multiple providers, AND an idp hint, as a
	// host picker that links back sends, ZDAS skips the host picker and
	// asks for consent to that provider only.
	mux := idpSelectorHandlers(t, "https://app.example.com/pick-idp")
	w := authorizeAndConsent(t, mux, authorizeURL(t, url.Values{"idp": {"github"}}), "")
	if loc := w.Header().Get("Location"); w.Code != http.StatusSeeOther || !strings.HasPrefix(loc, "https://stub/github") {
		t.Errorf("consent: %d %s, want 303 to github", w.Code, loc)
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
	w := authorizeAndConsent(t, h.mux(), authorizeURL(t, nil), "")
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d", w.Code)
	}
	if loc := w.Header().Get("Location"); !strings.HasPrefix(loc, "https://stub/test-idp") {
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

	exchangedWith string // the redirect URI ExchangeAndIdentify last got
}

func (p *callbackProvider) Name() string   { return p.name }
func (p *callbackProvider) Issuer() string { return p.issuer }
func (p *callbackProvider) AuthorizeURL(state, redirectURI string) string {
	return "https://idp/authorize?" + url.Values{"state": {state}, "redirect_uri": {redirectURI}}.Encode()
}
func (p *callbackProvider) ExchangeAndIdentify(_ context.Context, code, redirectURI string) (*UpstreamIdentity, error) {
	p.exchangedWith = redirectURI
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

// authorizeURL returns an /authorize URL with valid parameters, overridden
// by over.
func authorizeURL(t *testing.T, over url.Values) string {
	t.Helper()
	_, challenge := generateTestPKCE(t)
	q := url.Values{
		"redirect_uri":          {"http://localhost:20314/auth/callback"},
		"state":                 {"s1"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"device_name":           {"laptop"},
	}
	for k, v := range over {
		q[k] = v
	}
	return "/authorize?" + q.Encode()
}

// TestAuthorizeRejectsOversizedParams verifies that /authorize refuses a
// state or redirect_uri too large to keep in a session, without creating
// one, and accepts values at the limit.
func TestAuthorizeRejectsOversizedParams(t *testing.T) {
	h, _ := setupHandlers(t)
	cases := []struct {
		name string
		over url.Values
		want int
	}{
		{"huge state", url.Values{"state": {strings.Repeat("s", 900_000)}}, http.StatusBadRequest},
		{"state over the limit", url.Values{"state": {strings.Repeat("s", maxStateLength+1)}}, http.StatusBadRequest},
		{"state at the limit", url.Values{"state": {strings.Repeat("s", maxStateLength)}}, http.StatusOK},
		{"redirect_uri over the limit", url.Values{"redirect_uri": {"http://localhost:1/" + strings.Repeat("p", maxRedirectURILength)}}, http.StatusBadRequest},
		{"nonce over the limit", url.Values{"nonce": {strings.Repeat("n", maxNonceLength+1)}}, http.StatusBadRequest},
		{"nonce at the limit", url.Values{"nonce": {strings.Repeat("n", maxNonceLength)}}, http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.mux().ServeHTTP(w, httptest.NewRequest(http.MethodGet, authorizeURL(t, tc.over), nil))
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d", w.Code, tc.want)
			}
			if tc.want == http.StatusBadRequest && (w.Header().Get("Location") != "" || len(w.Result().Cookies()) != 0) {
				t.Error("rejected request redirected or started a session")
			}
		})
	}
}

// TestAuthorizeRejectsMalformedChallenge verifies that a code_challenge that
// is not a canonical S256 digest is refused before the user signs in.
func TestAuthorizeRejectsMalformedChallenge(t *testing.T) {
	h, _ := setupHandlers(t)
	_, valid := generateTestPKCE(t)
	for name, challenge := range map[string]string{
		"too short":         "abc",
		"padded":            valid + "=",
		"standard alphabet": "+" + valid[1:],
		"non-canonical":     valid[:42] + "B",
		"too long":          valid + "A",
	} {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.mux().ServeHTTP(w, httptest.NewRequest(http.MethodGet, authorizeURL(t, url.Values{"code_challenge": {challenge}}), nil))
			loc, err := url.Parse(w.Header().Get("Location"))
			if err != nil || loc.Query().Get("error") != "invalid_request" {
				t.Errorf("status = %d, Location = %q; want an invalid_request redirect", w.Code, w.Header().Get("Location"))
			}
			if len(w.Result().Cookies()) != 0 {
				t.Error("session started for a malformed challenge")
			}
		})
	}
}

// TestAuthorizeSessionDoesNotKeepRequest verifies that the session's strings
// are copies, not slices of the request's query string, which would keep
// the whole request line in memory for the life of the session.
func TestAuthorizeSessionDoesNotKeepRequest(t *testing.T) {
	h, _ := setupHandlers(t)
	req := httptest.NewRequest(http.MethodGet, authorizeURL(t, url.Values{
		"hostname":          {strings.Repeat("h", 10_000)},
		"os":                {"linux"},
		"enrollment_method": {"enrollToCert"},
		"client_type":       {"tunneler"},
		"nonce":             {"n-1"},
	}), nil)
	raw := req.URL.RawQuery
	w := httptest.NewRecorder()
	h.mux().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}

	mem := h.store.(*memStore)
	mem.mu.Lock()
	sess := mem.sessions.order.Front().Value.(*entry[*AuthSession]).value
	mem.mu.Unlock()
	start := uintptr(unsafe.Pointer(unsafe.StringData(raw)))
	end := start + uintptr(len(raw))
	for name, v := range map[string]string{
		"redirect_uri":      sess.TunnelerRedirectURI,
		"state":             sess.TunnelerState,
		"code_challenge":    sess.TunnelerCodeChallenge,
		"method":            sess.TunnelerCodeChallengeMethod,
		"device_name":       sess.DeviceInfo.DeviceName,
		"hostname":          sess.DeviceInfo.Hostname,
		"os":                sess.DeviceInfo.OS,
		"enrollment_method": sess.EnrollmentMethod,
		"client_type":       sess.ClientType,
		"nonce":             sess.TunnelerNonce,
	} {
		if p := uintptr(unsafe.Pointer(unsafe.StringData(v))); v != "" && p >= start && p < end {
			t.Errorf("session %s shares memory with the request's query string", name)
		}
	}
	if sess.TunnelerNonce != "n-1" {
		t.Errorf("TunnelerNonce = %q, want n-1", sess.TunnelerNonce)
	}
	if len(sess.DeviceInfo.Hostname) != 255 {
		t.Errorf("hostname length = %d, want 255", len(sess.DeviceInfo.Hostname))
	}
}

// TestTokenRejectsOversizedBody verifies that /token stops reading a body
// far larger than any real token request.
func TestTokenRejectsOversizedBody(t *testing.T) {
	h, _ := setupHandlers(t)
	body := "grant_type=authorization_code&code=" + strings.Repeat("c", 1<<20)
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.mux().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest || tokenErrorCode(t, w) != "invalid_request" {
		t.Errorf("status = %d, body = %s; want 400 invalid_request", w.Code, w.Body.String())
	}
}

// TestCallbackMustMatchProvider verifies that each provider gets its own
// callback URL, used for the token exchange too, and that a response at
// another provider's callback, or the shared one, is refused (an IdP
// mix-up). With LegacyCallback it is the other way round.
func TestCallbackMustMatchProvider(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprintf("legacy=%v", legacy), func(t *testing.T) {
			ks, _ := GenerateKeySet()
			reg := NewProviderRegistry()
			providers := map[string]*callbackProvider{}
			for _, name := range []string{"honest", "evil"} {
				providers[name] = &callbackProvider{name: name, issuer: "https://" + name, identity: &UpstreamIdentity{Subject: "u1", Username: "jsmith", Issuer: "https://" + name}}
				_ = reg.Register(providers[name])
			}
			store := newMemStore(10*time.Minute, 60*time.Second, storeSweepInterval)
			t.Cleanup(store.stop)
			cfg := Config{
				ExternalURL:    "https://zdas.example.com",
				LegacyCallback: legacy,
				Claims:         defaultClaimsConfig(),
				Token:          TokenConfig{Issuer: "https://zdas.example.com", Audience: "ziti-enroll", Expiry: 5 * time.Minute},
			}
			mux := newTestEndpoints(cfg, ks, reg, store, nil).mux()

			own, other := "https://zdas.example.com/callback/evil", "https://zdas.example.com/callback"
			if legacy {
				own, other = other, "https://zdas.example.com/callback/honest"
			}
			for _, tc := range []struct {
				callback string
				ok       bool
			}{{other, false}, {"https://zdas.example.com/callback/honest", false}, {own, true}} {
				started := authorizeAndConsent(t, mux, authorizeURL(t, nil), "evil")
				loc, _ := url.Parse(started.Header().Get("Location"))
				if got := loc.Query().Get("redirect_uri"); got != own {
					t.Fatalf("redirect_uri sent upstream = %q, want %q", got, own)
				}
				path := strings.TrimPrefix(tc.callback, "https://zdas.example.com")
				w := httptest.NewRecorder()
				mux.ServeHTTP(w, browserRequest(started, path+"?code=c&state="+loc.Query().Get("state")))
				got := w.Header().Get("Location")
				if tc.ok != !strings.Contains(got, "error=") {
					t.Errorf("callback at %s: Location %s, want ok=%v", path, got, tc.ok)
				}
				if tc.ok && providers["evil"].exchangedWith != own {
					t.Errorf("token exchange redirect_uri = %q, want %q", providers["evil"].exchangedWith, own)
				}
			}
		})
	}
}

// TestCallbackChecksResponseIssuer verifies that an authorization response
// whose iss names another issuer is refused before its code is exchanged.
func TestCallbackChecksResponseIssuer(t *testing.T) {
	idp, _ := mockOIDCServer(t, map[string]any{"sub": "u1", "preferred_username": "jsmith"})
	p, err := NewOIDCProvider(t.Context(), OIDCProviderConfig{Name: "kc", Issuer: idp.URL, ClientID: "test-client"})
	if err != nil {
		t.Fatalf("NewOIDCProvider: %v", err)
	}
	ks, _ := GenerateKeySet()
	reg := NewProviderRegistry()
	_ = reg.Register(p)
	store := newMemStore(10*time.Minute, 60*time.Second, storeSweepInterval)
	t.Cleanup(store.stop)
	cfg := Config{
		ExternalURL: "https://zdas.example.com",
		Claims:      defaultClaimsConfig(),
		Token:       TokenConfig{Issuer: "https://zdas.example.com", Audience: "ziti-enroll", Expiry: 5 * time.Minute},
	}
	mux := newTestEndpoints(cfg, ks, reg, store, nil).mux()

	for _, tc := range []struct {
		iss string
		ok  bool
	}{{"https://evil.example.com", false}, {idp.URL, true}, {"", true}} {
		started := authorizeAndConsent(t, mux, authorizeURL(t, nil), "")
		loc, _ := url.Parse(started.Header().Get("Location"))
		q := url.Values{"code": {"c"}, "state": {loc.Query().Get("state")}}
		if tc.iss != "" {
			q.Set("iss", tc.iss)
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, browserRequest(started, "/callback/kc?"+q.Encode()))
		got := w.Header().Get("Location")
		if tc.ok != (strings.Contains(got, "code=") && !strings.Contains(got, "error=")) {
			t.Errorf("iss %q: Location %s, want ok=%v", tc.iss, got, tc.ok)
		}
	}
}

// TestAuthorizeResponseType verifies that /authorize refuses any flow but
// the code flow, and still takes a request that names none.
func TestAuthorizeResponseType(t *testing.T) {
	h, _ := setupHandlers(t)
	for _, tc := range []struct {
		rt   []string
		want string
	}{{[]string{"code"}, ""}, {nil, ""}, {[]string{"token"}, "unsupported_response_type"}, {[]string{"code id_token"}, "unsupported_response_type"}} {
		w := httptest.NewRecorder()
		h.mux().ServeHTTP(w, httptest.NewRequest(http.MethodGet, authorizeURL(t, url.Values{"response_type": tc.rt}), nil))
		loc := w.Header().Get("Location")
		if tc.want == "" && w.Code != http.StatusOK {
			t.Errorf("response_type %v: %d %s, want the consent page", tc.rt, w.Code, loc)
		}
		if tc.want != "" && !strings.Contains(loc, "error="+tc.want) {
			t.Errorf("response_type %v: %d %s, want %s", tc.rt, w.Code, loc, tc.want)
		}
	}
}
