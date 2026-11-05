package zdas

import (
	"bytes"
	"html"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
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
				if w.Code != http.StatusBadRequest || w.Body.String() != sessionWarning+"\n" {
					t.Fatalf("wrong browser: status = %d, body = %s; want 400 and the warning", w.Code, w.Body.String())
				}
				if loc := w.Header().Get("Location"); loc != "" {
					t.Errorf("wrong browser: Location = %q, want none", loc)
				}

				// The sign-in is gone, for the browser that started it too.
				w = httptest.NewRecorder()
				mux.ServeHTTP(w, browserRequest(started, target))
				if w.Code != http.StatusBadRequest || w.Body.String() != sessionWarning+"\n" {
					t.Errorf("right browser afterwards: status = %d, body = %s; want 400 and the warning", w.Code, w.Body.String())
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

// TestOldSessionKeysAreNotRead verifies that sessions stored the way v0.15.0
// stored them, under kind "session" with the ID alone or the ID and nonce
// together, are never consumed, from any browser. Reading them would let a
// sign-in started before an upgrade finish without the binding check.
func TestOldSessionKeysAreNotRead(t *testing.T) {
	h, _ := setupHandlers(t)
	ctx := t.Context()
	id, nonce := mustID(t), mustID(t)
	issuer := h.cfg.Token.Issuer
	for _, key := range []string{hashStoreKey("session", issuer, id), hashStoreKey("session", issuer, id+"."+nonce)} {
		sess := &AuthSession{DeviceInfo: &DeviceInfo{}, UpstreamProviderName: "x", CreatedAt: time.Now()}
		if err := h.store.CreateSession(ctx, key, sess); err != nil {
			t.Fatal(err)
		}
	}
	for _, n := range []string{"", nonce} {
		if sess, other, err := h.consumeSession(ctx, id, n); sess != nil || other || err != nil {
			t.Errorf("nonce %q: %v, %v, %v; want a miss", n, sess, other, err)
		}
	}

	// And the other way: a session stored now is not under the key a
	// v0.15.0 replica computes for a request without a cookie, so such a
	// replica, sharing the Store, can't take it from any browser.
	newID, err := h.createSession(ctx, &AuthSession{DeviceInfo: &DeviceInfo{}}, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := h.store.ConsumeSession(ctx, hashStoreKey("session", issuer, newID)); got != nil || err != nil {
		t.Errorf("new session found under v0.15.0's key: %v, %v", got, err)
	}
}

// TestSessionWithoutBindingHashIsRefused verifies that a session that comes
// back from the Store without its BindingHash, as from a Store that
// predates the field, is treated as missing for every browser, rather than
// matching a request with no cookie.
func TestSessionWithoutBindingHashIsRefused(t *testing.T) {
	h, _ := setupHandlers(t)
	var logs strings.Builder
	h.logger = slog.New(slog.NewTextHandler(&logs, nil))
	for _, nonce := range []string{"", testBindingNonce} {
		id := mustID(t)
		sess := &AuthSession{DeviceInfo: &DeviceInfo{}, UpstreamProviderName: "x", CreatedAt: time.Now()}
		if err := h.store.CreateSession(t.Context(), h.storeKey(kindSession, id), sess); err != nil {
			t.Fatal(err)
		}
		if got, other, err := h.consumeSession(t.Context(), id, nonce); got != nil || other || err != nil {
			t.Errorf("nonce %q: %v, %v, %v; want a miss", nonce, got, other, err)
		}
	}
	if !strings.Contains(logs.String(), "without BindingHash") {
		t.Errorf("store fault not logged: %s", logs.String())
	}
	if _, err := h.createSession(t.Context(), &AuthSession{DeviceInfo: &DeviceInfo{}}, ""); err == nil {
		t.Error("createSession accepted an empty binding nonce")
	}
}

// TestCallbackMissWarns verifies that a /callback with a code or an error
// that names no session waiting for one warns against sending the address
// on. That covers a phisher who edits state in the IdP's address before
// sending it, so that the victim's browser cancels nothing.
func TestCallbackMissWarns(t *testing.T) {
	mux := bindingHandlers(t, "https://zdas.example.com")
	attacker, sessID := startAuthorize(t, mux)
	for _, target := range []string{
		"/callback/mock-idp?code=c",
		"/callback/mock-idp?code=c&state=" + mustID(t),
		"/callback/mock-idp?code=c&state=garbage",
		"/callback/mock-idp?error=access_denied&state=" + mustID(t),
	} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, target, nil))
		if w.Code != http.StatusBadRequest || w.Body.String() != sessionWarning+"\n" {
			t.Errorf("%s: %d %s, want 400 and the warning", target, w.Code, w.Body.String())
		}
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/callback/mock-idp?state="+mustID(t), nil))
	if w.Body.String() != sessionMissing+"\n" {
		t.Errorf("miss with neither code nor error: %s, want the plain message", w.Body.String())
	}
	// The attacker's own session is untouched by the edited addresses: the
	// binding can't tie the victim's code to it, so the warning is what is
	// left.
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, browserRequest(attacker, "/callback/mock-idp?code=c&state="+sessID))
	if w.Code != http.StatusFound {
		t.Errorf("attacker's session after edited callbacks: %d, want it still live", w.Code)
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
		if w.Code != http.StatusBadRequest || w.Body.String() != sessionWarning+"\n" {
			t.Errorf("callback 11 minutes after /authorize: %d %s, want 400 and the warning", w.Code, w.Body.String())
		}
	})
}

// jarBrowser drives a handler the way a browser does: a cookie jar decides
// which cookies each request carries, by domain, path, Secure and expiry,
// rather than a test replaying every cookie it was sent.
type jarBrowser struct {
	h   http.Handler
	jar *cookiejar.Jar
}

func newJarBrowser(t *testing.T, h http.Handler) *jarBrowser {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &jarBrowser{h: h, jar: jar}
}

func (b *jarBrowser) do(req *http.Request) *httptest.ResponseRecorder {
	for _, c := range b.jar.Cookies(req.URL) {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	b.h.ServeHTTP(w, req)
	b.jar.SetCookies(req.URL, w.Result().Cookies())
	return w
}

func (b *jarBrowser) get(target string) *httptest.ResponseRecorder {
	return b.do(httptest.NewRequest(http.MethodGet, target, nil))
}

func (b *jarBrowser) post(target string, form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return b.do(req)
}

// TestBindingWithBrowserCookies runs a sign-in under a mount prefix over
// https, with browsers whose cookie jars choose what they send. The binding
// cookie must reach consent and /callback under the prefix, the expired one
// from /authorize must be gone, and a second browser must not finish it.
func TestBindingWithBrowserCookies(t *testing.T) {
	const base = "https://zdas.example.com/enroll"
	mux := http.StripPrefix("/enroll", bindingHandlers(t, base))
	_, challenge := generateTestPKCE(t)
	authorize := base + "/authorize?" + url.Values{
		"redirect_uri":          {"http://localhost:20314/auth/callback"},
		"response_type":         {"code"},
		"state":                 {"tstate"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"device_name":           {"laptop"},
	}.Encode()
	start := func(b *jarBrowser) string {
		t.Helper()
		page := b.get(authorize)
		field := consentFieldRe.FindStringSubmatch(page.Body.String())
		if page.Code != http.StatusOK || field == nil {
			t.Fatalf("authorize: %d %s", page.Code, page.Body)
		}
		w := b.post(base+"/authorize", url.Values{"consent": {field[1]}, "idp": {"mock-idp"}})
		loc, err := url.Parse(w.Header().Get("Location"))
		if w.Code != http.StatusSeeOther || err != nil {
			t.Fatalf("consent: %d %s", w.Code, w.Body)
		}
		return loc.Query().Get("state")
	}

	user := newJarBrowser(t, mux)
	state := start(user)
	u, _ := url.Parse(base + "/callback/mock-idp")
	if n := len(user.jar.Cookies(u)); n != 1 {
		t.Errorf("cookies for /callback = %d, want only the live binding cookie", n)
	}
	if outside, _ := url.Parse("https://zdas.example.com/callback/mock-idp"); len(user.jar.Cookies(outside)) != 0 {
		t.Error("the binding cookie is sent outside the mount prefix")
	}
	if insecure, _ := url.Parse("http://zdas.example.com/enroll/callback/mock-idp"); len(user.jar.Cookies(insecure)) != 0 {
		t.Error("the binding cookie is sent over plain http")
	}
	w := user.get(base + "/callback/mock-idp?code=c&state=" + state)
	if w.Code != http.StatusFound || !strings.HasPrefix(w.Header().Get("Location"), "http://localhost:20314/auth/callback?") {
		t.Fatalf("callback from the user's browser: %d %s", w.Code, w.Header().Get("Location"))
	}

	attacker := newJarBrowser(t, mux)
	state = start(attacker)
	victim := newJarBrowser(t, mux)
	if w := victim.get(base + "/callback/mock-idp?code=c&state=" + state); w.Code != http.StatusBadRequest || w.Body.String() != sessionWarning+"\n" {
		t.Errorf("callback from another browser: %d %s, want 400 and the warning", w.Code, w.Body)
	}
	if w := attacker.get(base + "/callback/mock-idp?code=c&state=" + state); w.Code == http.StatusFound {
		t.Errorf("the browser that started the sign-in finished it after another browser cancelled it")
	}
}
