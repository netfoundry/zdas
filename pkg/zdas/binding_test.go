package zdas

import (
	"bytes"
	"html"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

// browserRequest returns a GET for target carrying the cookies prev set, as
// the browser that received prev would send them.
func browserRequest(prev *httptest.ResponseRecorder, target string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	for _, c := range prev.Result().Cookies() {
		req.AddCookie(c)
	}
	return req
}

// consentFieldRe and consentButtonRe find the consent page's form fields.
var (
	consentFieldRe  = regexp.MustCompile(`name="consent" value="([^"]*)"`)
	consentButtonRe = regexp.MustCompile(`name="idp" value="([^"]*)"`)
)

// consent submits the consent page in page, a response from GET /authorize,
// as the browser that got it would, choosing idp, or the page's only
// provider when idp is empty. It returns the response, which redirects
// upstream and sets the binding cookie /callback needs.
func consent(t *testing.T, h http.Handler, page *httptest.ResponseRecorder, idp string) *httptest.ResponseRecorder {
	t.Helper()
	if page.Code != http.StatusOK {
		t.Fatalf("authorize: status = %d, want the consent page; Location %q, body %s", page.Code, page.Header().Get("Location"), page.Body)
	}
	body := page.Body.String()
	field := consentFieldRe.FindStringSubmatch(body)
	if field == nil {
		t.Fatalf("no consent field in page: %s", body)
	}
	if idp == "" {
		buttons := consentButtonRe.FindAllStringSubmatch(body, -1)
		if len(buttons) != 1 {
			t.Fatalf("consent page offers %d providers, want 1", len(buttons))
		}
		idp = html.UnescapeString(buttons[0][1])
	}
	form := url.Values{"consent": {field[1]}, "idp": {idp}}
	req := httptest.NewRequest(http.MethodPost, "/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range page.Result().Cookies() {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// authorizeAndConsent runs GET /authorize for target and then consents, as
// consent does.
func authorizeAndConsent(t *testing.T, h http.Handler, target, idp string) *httptest.ResponseRecorder {
	t.Helper()
	page := httptest.NewRecorder()
	h.ServeHTTP(page, httptest.NewRequest(http.MethodGet, target, nil))
	return consent(t, h, page, idp)
}

// bindingHandlers returns a mux for a deployment mounted at externalURL with
// a provider whose callback always succeeds.
func bindingHandlers(t *testing.T, externalURL string) http.Handler {
	t.Helper()
	return bindingEndpoints(t, externalURL).mux()
}

// bindingEndpoints returns the endpoints bindingHandlers serves.
func bindingEndpoints(t *testing.T, externalURL string) *endpoints {
	t.Helper()
	ks, err := GenerateKeySet()
	if err != nil {
		t.Fatalf("GenerateKeySet: %v", err)
	}
	reg := NewProviderRegistry()
	if err := reg.Register(&callbackProvider{
		name:     "mock-idp",
		issuer:   "https://mock-idp",
		identity: &UpstreamIdentity{Subject: "u1", Username: "jsmith", Issuer: "https://mock-idp"},
	}); err != nil {
		t.Fatal(err)
	}
	store := newMemStore(10*time.Minute, 60*time.Second, storeSweepInterval)
	t.Cleanup(store.stop)
	cfg := Config{
		ExternalURL: externalURL,
		Claims:      defaultClaimsConfig(),
		Token:       TokenConfig{Issuer: externalURL, Audience: "ziti-enrolltocert", Expiry: 5 * time.Minute},
	}
	return newTestEndpoints(cfg, ks, reg, store, nil)
}

// startAuthorize runs /authorize and consents, and returns the consent
// response and the session ID it sent to the IdP.
func startAuthorize(t *testing.T, mux http.Handler) (*httptest.ResponseRecorder, string) {
	t.Helper()
	_, challenge := generateTestPKCE(t)
	reqURL := "/authorize?" + url.Values{
		"redirect_uri":          {"http://localhost:20314/auth/callback"},
		"response_type":         {"code"},
		"state":                 {"tstate"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"device_name":           {"laptop"},
	}.Encode()
	w := authorizeAndConsent(t, mux, reqURL, "")
	if w.Code != http.StatusSeeOther {
		t.Fatalf("consent: status = %d, body = %s", w.Code, w.Body.String())
	}
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	return w, loc.Query().Get("state")
}

// liveCookie returns the cookie w sets for session ID sessID.
func liveCookie(t *testing.T, w *httptest.ResponseRecorder, sessID string) *http.Cookie {
	t.Helper()
	for _, c := range w.Result().Cookies() {
		if c.Name == bindingCookieName(sessID) && c.MaxAge > 0 {
			return c
		}
	}
	t.Fatalf("no binding cookie for session %s", sessID)
	return nil
}

func TestAuthorizeSetsBindingCookie(t *testing.T) {
	cases := []struct {
		externalURL string
		wantPath    string
		wantSecure  bool
	}{
		{"https://zdas.example.com", "/", true},
		{"https://app.example.com/enroll", "/enroll", true},
		{"http://localhost:8080", "/", false},
	}
	for _, tc := range cases {
		t.Run(tc.externalURL, func(t *testing.T) {
			w, sessID := startAuthorize(t, bindingHandlers(t, tc.externalURL))
			c := liveCookie(t, w, sessID)
			for _, other := range w.Result().Cookies() {
				if other.Name != c.Name && other.MaxAge >= 0 {
					t.Errorf("cookie %s set as well as the session's", other.Name)
				}
			}
			if want := "zdas_bind_" + sessID[:8]; c.Name != want {
				t.Errorf("Name = %q, want %q", c.Name, want)
			}
			if !validID(c.Value) || c.Value == sessID {
				t.Errorf("Value = %q, want a 32-char hex nonce distinct from the session ID", c.Value)
			}
			if c.Path != tc.wantPath {
				t.Errorf("Path = %q, want %q", c.Path, tc.wantPath)
			}
			if c.Secure != tc.wantSecure {
				t.Errorf("Secure = %v, want %v", c.Secure, tc.wantSecure)
			}
			if !c.HttpOnly {
				t.Error("HttpOnly not set")
			}
			if c.SameSite != http.SameSiteLaxMode {
				t.Errorf("SameSite = %v, want Lax", c.SameSite)
			}
			if c.MaxAge != int((10 * time.Minute).Seconds()) {
				t.Errorf("MaxAge = %d, want session timeout", c.MaxAge)
			}
		})
	}
}

// TestCallbackRequiresBindingCookie verifies that /callback from a browser
// without the session's binding cookie is refused and cancels the sign-in,
// so the browser that started it can't finish it afterwards either.
func TestCallbackRequiresBindingCookie(t *testing.T) {
	cases := []struct {
		name   string
		cookie func(sessID string, other *http.Cookie) *http.Cookie
	}{
		{"no cookie", func(string, *http.Cookie) *http.Cookie { return nil }},
		{"wrong value", func(sessID string, _ *http.Cookie) *http.Cookie {
			return &http.Cookie{Name: bindingCookieName(sessID), Value: strings.Repeat("0", 32)}
		}},
		{"malformed value", func(sessID string, _ *http.Cookie) *http.Cookie {
			return &http.Cookie{Name: bindingCookieName(sessID), Value: "x"}
		}},
		{"another session's cookie", func(_ string, other *http.Cookie) *http.Cookie { return other }},
		{"another session's nonce under this name", func(sessID string, other *http.Cookie) *http.Cookie {
			return &http.Cookie{Name: bindingCookieName(sessID), Value: other.Value}
		}},
	}
	for _, tc := range cases {
		for _, query := range []string{"code=c", "error=access_denied"} {
			t.Run(tc.name+"/"+query, func(t *testing.T) {
				mux := bindingHandlers(t, "https://zdas.example.com")
				started, sessID := startAuthorize(t, mux)
				// An attacker can start their own flow and hold its cookie.
				attacker, attackerID := startAuthorize(t, mux)

				target := "/callback/mock-idp?" + query + "&state=" + sessID
				req := httptest.NewRequest(http.MethodGet, target, nil)
				if c := tc.cookie(sessID, liveCookie(t, attacker, attackerID)); c != nil {
					req.AddCookie(c)
				}
				w := httptest.NewRecorder()
				mux.ServeHTTP(w, req)
				if w.Code != http.StatusBadRequest || w.Body.String() != sessionOtherBrowser+"\n" {
					t.Fatalf("wrong browser: status = %d, body = %s; want 400 and the warning", w.Code, w.Body.String())
				}
				if loc := w.Header().Get("Location"); loc != "" {
					t.Errorf("wrong browser: Location = %q, want none", loc)
				}

				// The sign-in is gone, for the browser that started it too.
				w = httptest.NewRecorder()
				mux.ServeHTTP(w, browserRequest(started, target))
				if w.Code != http.StatusBadRequest || w.Body.String() != sessionMissing+"\n" {
					t.Errorf("right browser afterwards: status = %d, body = %s; want 400 not found", w.Code, w.Body.String())
				}
				if loc := w.Header().Get("Location"); loc != "" {
					t.Errorf("right browser afterwards: Location = %q, want none", loc)
				}
			})
		}
	}
}

// TestCallbackSkippingConsentIsCancelled walks the phish that skips the
// consent page: the attacker consents in their own browser and sends the
// victim the IdP's address. An IdP that approves without asking sends the
// victim's browser to /callback, which cancels the sign-in, so when the
// victim sends that address back, the attacker's browser can't finish it.
func TestCallbackSkippingConsentIsCancelled(t *testing.T) {
	h := bindingEndpoints(t, "https://zdas.example.com")
	var logs bytes.Buffer
	h.logger = slog.New(slog.NewTextHandler(&logs, nil))
	mux := h.mux()
	attacker, sessID := startAuthorize(t, mux)
	callback := "/callback/mock-idp?code=c&state=" + sessID

	victim := httptest.NewRecorder()
	mux.ServeHTTP(victim, httptest.NewRequest(http.MethodGet, callback, nil))
	if victim.Code != http.StatusBadRequest || !strings.Contains(victim.Body.String(), "don't") {
		t.Fatalf("victim's browser: status = %d, body = %s; want 400 and the warning", victim.Code, victim.Body.String())
	}
	if !strings.Contains(logs.String(), "did not start the sign-in") {
		t.Errorf("cancelled sign-in not logged: %s", logs.String())
	}

	pasted := httptest.NewRecorder()
	mux.ServeHTTP(pasted, browserRequest(attacker, callback))
	if pasted.Code == http.StatusFound || pasted.Header().Get("Location") != "" {
		t.Fatalf("attacker's browser finished the sign-in: %d %s", pasted.Code, pasted.Header().Get("Location"))
	}
}

// TestCallbackFromRightBrowser verifies that the browser with the binding
// cookie completes the sign-in and has the cookie expired.
func TestCallbackFromRightBrowser(t *testing.T) {
	mux := bindingHandlers(t, "https://zdas.example.com")
	started, sessID := startAuthorize(t, mux)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, browserRequest(started, "/callback/mock-idp?code=c&state="+sessID))
	if w.Code != http.StatusFound || !strings.HasPrefix(w.Header().Get("Location"), "http://localhost:20314/auth/callback?") {
		t.Fatalf("status = %d, Location = %q; want 302 to the tunneler callback", w.Code, w.Header().Get("Location"))
	}
	cleared := false
	for _, c := range w.Result().Cookies() {
		if c.Name == bindingCookieName(sessID) && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Error("binding cookie not expired after the session was consumed")
	}
}

// TestLegacyBoundSession verifies that a session stored the way v0.15.0 and
// earlier stored it, under its ID and nonce together, is still consumed by
// the browser with that nonce, and by no other.
func TestLegacyBoundSession(t *testing.T) {
	h, _ := setupHandlers(t)
	ctx := t.Context()
	id, nonce := mustID(t), mustID(t)
	sess := &AuthSession{DeviceInfo: &DeviceInfo{}, UpstreamProviderName: "x", CreatedAt: time.Now()}
	if err := h.store.CreateSession(ctx, h.storeKey(kindSession, id+"."+nonce), sess); err != nil {
		t.Fatal(err)
	}
	if sess, other, err := h.consumeSession(ctx, id, ""); sess != nil || other || err != nil {
		t.Errorf("without the nonce: %v, %v, %v; want a miss", sess, other, err)
	}
	if sess, other, err := h.consumeSession(ctx, id, nonce); sess == nil || other || err != nil {
		t.Errorf("with the nonce: %v, %v, %v; want the session", sess, other, err)
	}
}

func TestBindingCookieScope(t *testing.T) {
	cases := []struct {
		externalURL string
		wantPath    string
		wantSecure  bool
	}{
		{"https://zdas.example.com", "/", true},
		{"https://zdas.example.com/", "/", true},
		{"https://app.example.com/enroll", "/enroll", true},
		{"http://localhost:8080/a/b", "/a/b", false},
		{"", "/", false},
		{"://bad", "/", false},
	}
	for _, tc := range cases {
		path, secure := bindingCookieScope(tc.externalURL)
		if path != tc.wantPath || secure != tc.wantSecure {
			t.Errorf("bindingCookieScope(%q) = %q, %v; want %q, %v", tc.externalURL, path, secure, tc.wantPath, tc.wantSecure)
		}
	}
}

// TestSignInLastsOneSessionTimeout verifies that consent does not restart
// the session's clock: a sign-in has the session timeout in all, from
// /authorize to /callback.
func TestSignInLastsOneSessionTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mux := bindingHandlers(t, "https://zdas.example.com")
		page := httptest.NewRecorder()
		mux.ServeHTTP(page, httptest.NewRequest(http.MethodGet, authorizeURL(t, nil), nil))
		time.Sleep(9 * time.Minute)
		consented := consent(t, mux, page, "")
		if consented.Code != http.StatusSeeOther {
			t.Fatalf("consent: %d", consented.Code)
		}
		loc, err := url.Parse(consented.Header().Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		state := loc.Query().Get("state")
		time.Sleep(2 * time.Minute)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, browserRequest(consented, "/callback/mock-idp?code=c&state="+state))
		if w.Code != http.StatusBadRequest || w.Body.String() != sessionMissing+"\n" {
			t.Errorf("callback 11 minutes after /authorize: %d %s, want 400 not found", w.Code, w.Body.String())
		}
	})
}
