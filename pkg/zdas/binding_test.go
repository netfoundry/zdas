package zdas

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
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

// bindingHandlers returns a mux for a deployment mounted at externalURL with
// a provider whose callback always succeeds.
func bindingHandlers(t *testing.T, externalURL string) http.Handler {
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
	return newTestEndpoints(cfg, ks, reg, store, nil).mux()
}

// startAuthorize runs /authorize and returns its response and the session
// ID it sent to the IdP.
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
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, reqURL, nil))
	if w.Code != http.StatusFound {
		t.Fatalf("authorize: status = %d, body = %s", w.Code, w.Body.String())
	}
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	return w, loc.Query().Get("state")
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
			cookies := w.Result().Cookies()
			if len(cookies) != 1 {
				t.Fatalf("got %d cookies, want 1", len(cookies))
			}
			c := cookies[0]
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
				attacker, _ := startAuthorize(t, mux)

				target := "/callback?" + query + "&state=" + sessID
				req := httptest.NewRequest(http.MethodGet, target, nil)
				if c := tc.cookie(sessID, attacker.Result().Cookies()[0]); c != nil {
					req.AddCookie(c)
				}
				w := httptest.NewRecorder()
				mux.ServeHTTP(w, req)
				if w.Code != http.StatusBadRequest {
					t.Fatalf("wrong browser: status = %d, want 400, body = %s", w.Code, w.Body.String())
				}
				if loc := w.Header().Get("Location"); loc != "" {
					t.Errorf("wrong browser: Location = %q, want none", loc)
				}

				// The session is still there for the browser that started it.
				w = httptest.NewRecorder()
				mux.ServeHTTP(w, browserRequest(started, target))
				if w.Code != http.StatusFound {
					t.Fatalf("right browser: status = %d, want 302, body = %s", w.Code, w.Body.String())
				}
				if !strings.HasPrefix(w.Header().Get("Location"), "http://localhost:20314/auth/callback?") {
					t.Errorf("right browser: Location = %q, want the tunneler callback", w.Header().Get("Location"))
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
			})
		}
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
