package zdas

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// allowed runs raw through the same checks /authorize applies.
func allowed(raw string, allowList []string) bool {
	u, err := parseRedirectURI(raw)
	return err == nil && redirectAllowed(u, parseAllowList(allowList, slog.Default()))
}

func TestRedirectAllowedLoopbackDefault(t *testing.T) {
	accept := []string{
		"http://localhost:20314/auth/callback",
		"http://LOCALHOST:1/cb",
		"http://127.0.0.1:1/cb",
		"http://127.5.6.7:1/cb",
		"http://[::1]:1/cb",
		"https://localhost:1/cb",
		"http://localhost/cb",
	}
	reject := []string{
		"http://localhost:@evil.example/cb",
		`http://evil.example\@localhost/cb`,
		"http://localhost.evil.example/cb",
		"http://localhost./cb",
		"http://evil.example/cb",
		"http://10.0.0.1:1/cb",
		"http://127.1/cb",
		"http://0x7f000001/cb",
		"http://[::1%25lo0]:1/cb",
		"ftp://localhost/cb",
		"localhost:1/cb",
		"//localhost:1/cb",
		"",
	}
	for _, raw := range accept {
		if !allowed(raw, nil) {
			t.Errorf("%q rejected, want accepted", raw)
		}
	}
	for _, raw := range reject {
		if allowed(raw, nil) {
			t.Errorf("%q accepted, want rejected", raw)
		}
	}
}

func TestRedirectAllowedAllowList(t *testing.T) {
	allowList := []string{
		"https://app.example.com/cb",
		"http://localhost",
		"http://127.0.0.1:20314",
	}
	cases := []struct {
		raw  string
		want bool
	}{
		{"https://app.example.com/cb", true},
		{"https://APP.example.com:443/cb", true},
		{"https://app.example.com/cb?x=1", true},
		{"https://app.example.com/other", false},
		{"https://app.example.com/cb/more", false},
		{"https://app.example.com:8443/cb", false},
		{"http://app.example.com/cb", false},
		{"https://app.example.com.evil.example/cb", false},
		{"https://app.example.com@evil.example/cb", false},
		{"http://localhost:5555/any/path", true},
		{"http://localhost/cb", true},
		{"http://127.0.0.1:20314/cb", true},
		{"http://127.0.0.1:20315/cb", false},
		// A non-empty list replaces the loopback default.
		{"http://[::1]:1/cb", false},
	}
	for _, tc := range cases {
		if got := allowed(tc.raw, allowList); got != tc.want {
			t.Errorf("allowed(%q) = %v, want %v", tc.raw, got, tc.want)
		}
	}
}

// TestRedirectAllowedLegacyPrefixEntry checks that the entries the config
// doc used to recommend as prefixes keep working, and no longer let a
// userinfo trick through.
func TestRedirectAllowedLegacyPrefixEntry(t *testing.T) {
	allowList := []string{"http://localhost:", "http://127.0.0.1:"}
	if !allowed("http://localhost:20314/auth/callback", allowList) {
		t.Error("loopback callback rejected by legacy entry")
	}
	if !allowed("http://127.0.0.1:1/cb", allowList) {
		t.Error("loopback IP callback rejected by legacy entry")
	}
	if allowed("http://localhost:@evil.example/cb", allowList) {
		t.Error("userinfo redirect accepted by legacy entry")
	}
}

func TestValidateAllowedRedirectURIs(t *testing.T) {
	cases := []struct {
		entry   string
		wantErr bool
	}{
		{"https://app.example.com/cb", false},
		{"http://localhost:", false},
		{"http://[::1]", false},
		{"app.example.com", true},
		{"ftp://app.example.com", true},
		{"https://user@app.example.com", true},
		{"https://", true},
		{"", true},
	}
	for _, tc := range cases {
		cfg := &Config{
			ExternalURL:         "https://das.example.com",
			Controller:          ControllerConfig{APIURL: "https://c"},
			AllowedRedirectURIs: []string{tc.entry},
		}
		cfg.ApplyDefaults()
		if err := cfg.Validate(); (err != nil) != tc.wantErr {
			t.Errorf("Validate with entry %q: err = %v, wantErr %v", tc.entry, err, tc.wantErr)
		}
	}
}

func TestAuthorizeRejectsRemoteRedirect(t *testing.T) {
	h, _ := setupHandlers(t)
	mux := h.Mux()
	_, challenge := generateTestPKCE(t)

	for _, redirect := range []string{
		"https://evil.example/cb",
		"http://localhost:@evil.example/cb",
	} {
		reqURL := "/authorize?" + url.Values{
			"redirect_uri":          {redirect},
			"response_type":         {"code"},
			"state":                 {"s1"},
			"code_challenge":        {challenge},
			"code_challenge_method": {"S256"},
			"device_name":           {"laptop"},
		}.Encode()
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, reqURL, nil))

		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", redirect, w.Code)
		}
		// No Location means neither an error redirect to the attacker's
		// URL nor a redirect on to the IdP.
		if loc := w.Header().Get("Location"); loc != "" {
			t.Errorf("%s: Location = %q, want none", redirect, loc)
		}
		if c := w.Result().Cookies(); len(c) != 0 {
			t.Errorf("%s: set %d cookies, want none", redirect, len(c))
		}
	}
}

// TestRedirectAllowListAllInvalid verifies that a list whose entries all
// fail to parse allows nothing, rather than falling back to the loopback
// default an empty list gets.
func TestRedirectAllowListAllInvalid(t *testing.T) {
	if allowed("http://localhost:20314/auth/callback", []string{"not a url", "ftp://x"}) {
		t.Error("loopback callback accepted under an allow list with no valid entries")
	}
}

func TestAuthorizeRejectsColonInDeviceName(t *testing.T) {
	h, _ := setupHandlers(t)
	_, challenge := generateTestPKCE(t)
	reqURL := "/authorize?" + url.Values{
		"redirect_uri":          {"http://localhost:20314/auth/callback"},
		"state":                 {"s1"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"device_name":           {"1:laptop"},
	}.Encode()
	w := httptest.NewRecorder()
	h.Mux().ServeHTTP(w, httptest.NewRequest(http.MethodGet, reqURL, nil))

	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil || loc.Query().Get("error") != "invalid_request" {
		t.Errorf("status = %d, Location = %q; want an invalid_request redirect", w.Code, w.Header().Get("Location"))
	}
	if len(w.Result().Cookies()) != 0 {
		t.Error("session started for a device_name containing ':'")
	}
}
