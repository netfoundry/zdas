package zdas

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// brandedEndpoints returns endpoints with the providers named, branded by
// branding, logging to logs.
func brandedEndpoints(t *testing.T, branding func(*http.Request) PageBranding, logs *logBuffer, providers ...string) *endpoints {
	t.Helper()
	ks, _ := GenerateKeySet()
	reg := NewProviderRegistry()
	for _, name := range providers {
		if err := reg.Register(&stubProvider{name: name, issuer: "https://" + name}); err != nil {
			t.Fatal(err)
		}
	}
	store := newMemStore(10*time.Minute, 60*time.Second, storeSweepInterval)
	t.Cleanup(store.stop)
	cfg := Config{
		ExternalURL: "https://zdas.example.com",
		Claims:      defaultClaimsConfig(),
		Token:       TokenConfig{Issuer: "https://zdas.example.com", Audience: "ziti-enroll", Expiry: 5 * time.Minute},
	}
	h := newTestEndpoints(t, cfg, ks, reg, store, nil)
	h.logger = slog.New(slog.NewTextHandler(logs, nil))
	h.branding = branding
	return h
}

// consentPage returns the consent page /authorize shows on h.
func consentPage(t *testing.T, h *endpoints) string {
	t.Helper()
	w := httptest.NewRecorder()
	h.mux().ServeHTTP(w, httptest.NewRequest(http.MethodGet, authorizeURL(t, nil), nil))
	if w.Code != http.StatusOK {
		t.Fatalf("authorize: status = %d, want the consent page", w.Code)
	}
	return w.Body.String()
}

// consentWarning is the start of the consent page's fixed warning.
const consentWarning = "<strong>Continue only if you started this yourself"

// browserAccept is the Accept header a browser sends for a page.
const browserAccept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"

func TestConsentPageDefaults(t *testing.T) {
	var logs logBuffer
	body := consentPage(t, brandedEndpoints(t, nil, &logs, "github"))
	for _, want := range []string{
		"<title>Sign in to OpenZiti</title>", "<h1>Sign in to OpenZiti</h1>",
		"<p>An app asked to sign you in to an OpenZiti network.</p>",
		`value="github">Continue with github`, consentWarning, "prefers-color-scheme: dark",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q: %s", want, body)
		}
	}
	for _, unwanted := range []string{"<img", "color: #fff"} {
		if strings.Contains(body, unwanted) {
			t.Errorf("unbranded page has %q", unwanted)
		}
	}
	if logs.String() != "" {
		t.Errorf("unexpected log: %s", logs.String())
	}
}

func TestConsentPageBranding(t *testing.T) {
	var logs logBuffer
	h := brandedEndpoints(t, func(*http.Request) PageBranding {
		return PageBranding{
			Title:             "Enroll this machine as a host for <Acme>",
			Intro:             "Acme's hosts sign in here.",
			ProviderLabels:    map[string]string{"acme": "Acme Corp"},
			Logo:              "data:image/svg+xml;base64,PHN2Zy8+",
			LogoDark:          "/admin/static/logo-reverse.svg",
			PrimaryColor:      "#0066FF",
			PrimaryHoverColor: "#0052cc",
		}
	}, &logs, "acme", "github")
	body := consentPage(t, h)
	for _, want := range []string{
		"<title>Enroll this machine as a host for &lt;Acme&gt;</title>",
		"<h1>Enroll this machine as a host for &lt;Acme&gt;</h1>",
		"<p>Acme&#39;s hosts sign in here.</p>",
		`value="acme">Continue with Acme Corp`,
		`value="github">Continue with github`,
		// html/template writes + as &#43; in an attribute, which the browser
		// reads back as +.
		`<img class="logo logo-light" src="data:image/svg&#43;xml;base64,PHN2Zy8&#43;" alt="">`,
		`<img class="logo logo-dark" src="/admin/static/logo-reverse.svg" alt="">`,
		"button { background: #0066FF; border-color: #0066FF; color: #fff; }",
		"button:hover { background: #0052cc; border-color: #0052cc; }",
		consentWarning,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q: %s", want, body)
		}
	}
	if !strings.Contains(body[strings.Index(body, consentWarning):], "<button") {
		t.Error("the warning doesn't come before the buttons")
	}
	if logs.String() != "" {
		t.Errorf("unexpected log: %s", logs.String())
	}
}

// TestConsentPageBrandingPerRequest verifies that branding is chosen for
// each request, as for an embedder with several tenants.
func TestConsentPageBrandingPerRequest(t *testing.T) {
	var logs logBuffer
	h := brandedEndpoints(t, func(r *http.Request) PageBranding {
		return PageBranding{Title: "Sign in to " + r.Host}
	}, &logs, "github")
	for _, host := range []string{"a.example.com", "b.example.com"} {
		req := httptest.NewRequest(http.MethodGet, authorizeURL(t, nil), nil)
		req.Host = host
		w := httptest.NewRecorder()
		h.mux().ServeHTTP(w, req)
		if want := "<h1>Sign in to " + host + "</h1>"; !strings.Contains(w.Body.String(), want) {
			t.Errorf("page for %s lacks %q", host, want)
		}
	}
}

// TestConsentPageBrandingRefused verifies that branding that isn't valid
// is left out, with one warning for each bad logo or color however many
// pages show it, and that text is cleaned and cut.
func TestConsentPageBrandingRefused(t *testing.T) {
	var logs logBuffer
	h := brandedEndpoints(t, func(*http.Request) PageBranding {
		return PageBranding{
			Title:          "\u202eA\x00cme " + strings.Repeat("x", maxPageTitleRunes),
			Intro:          "\u200b",
			ProviderLabels: map[string]string{"acme": "\x01", "github": strings.Repeat("y", maxProviderLabelRunes+1)},
			Logo:           "javascript:alert(1)",
			LogoDark:       "data:text/html,<script>alert(1)</script>",
			PrimaryColor:   "red; } body { display: none",
		}
	}, &logs, "acme", "github")
	body := consentPage(t, h)
	consentPage(t, h)
	title := "Acme " + strings.Repeat("x", maxPageTitleRunes-5) + "…"
	for _, want := range []string{
		"<h1>" + title + "</h1>", "<p>An app asked to sign you in to an OpenZiti network.</p>", `value="acme">Continue with acme`,
		`value="github">Continue with ` + strings.Repeat("y", maxProviderLabelRunes) + "…",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q: %s", want, body)
		}
	}
	for _, unwanted := range []string{"<img", "javascript", "<script", "body { display", "\u202e"} {
		if strings.Contains(body, unwanted) {
			t.Errorf("page has %q: %s", unwanted, body)
		}
	}
	for _, field := range []string{"field=Logo ", "field=LogoDark ", "field=PrimaryColor "} {
		if n := strings.Count(logs.String(), field+"host=example.com"); n != 1 {
			t.Errorf("%d warnings naming the host for %s, want 1: %s", n, field, logs.String())
		}
	}
}

// TestPageBrandingPartial verifies the combinations that leave a field
// without its partner.
func TestPageBrandingPartial(t *testing.T) {
	for _, tc := range []struct {
		name     string
		branding PageBranding
		want     []string
		unwanted []string
		warn     string
	}{
		{
			name:     "dark logo alone",
			branding: PageBranding{LogoDark: "/d.svg"},
			want:     []string{`<img class="logo logo-dark" src="/d.svg" alt="">`},
			unwanted: []string{`class="logo logo-light"`, `<img class="logo" `},
		},
		{
			name:     "light logo with a bad dark one",
			branding: PageBranding{Logo: "/l.svg", LogoDark: "javascript:x"},
			want:     []string{`<img class="logo" src="/l.svg" alt="">`},
			unwanted: []string{`class="logo logo-light"`, `<img class="logo logo-dark"`},
			warn:     "field=LogoDark",
		},
		{
			name:     "hover color alone",
			branding: PageBranding{PrimaryHoverColor: "#000"},
			unwanted: []string{"color: #fff", "#000"},
			warn:     "field=PrimaryHoverColor",
		},
		{
			name:     "primary with a bad hover",
			branding: PageBranding{PrimaryColor: "#0066FF", PrimaryHoverColor: "red"},
			want:     []string{"button:hover { background: #0066FF; border-color: #0066FF; }"},
			warn:     "field=PrimaryHoverColor",
		},
		{
			name:     "primary alone",
			branding: PageBranding{PrimaryColor: "#0066FF"},
			want:     []string{"button:hover { background: #0066FF; border-color: #0066FF; }"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logs logBuffer
			h := brandedEndpoints(t, func(*http.Request) PageBranding { return tc.branding }, &logs, "github")
			body := consentPage(t, h)
			for _, want := range tc.want {
				if !strings.Contains(body, want) {
					t.Errorf("page lacks %q: %s", want, body)
				}
			}
			for _, unwanted := range tc.unwanted {
				if strings.Contains(body, unwanted) {
					t.Errorf("page has %q: %s", unwanted, body)
				}
			}
			if got := logs.String(); (tc.warn == "") != (got == "") || !strings.Contains(got, tc.warn) {
				t.Errorf("log = %q, want a warning for %q", got, tc.warn)
			}
		})
	}
}

func TestLogoURL(t *testing.T) {
	const prefix = "data:image/png;base64,"
	for _, tc := range []struct {
		logo string
		ok   bool
	}{
		{"/static/logo.svg", true},
		{"/" + strings.Repeat("a", maxRedirectURILength-1), true},
		{"/" + strings.Repeat("a", maxRedirectURILength), false},
		{"data:image/png;base64,iVBORw0KGgo=", true},
		{"data:image/jpeg;base64,/9j/", true},
		{"data:image/gif;base64,R0lG", true},
		{"data:image/webp;base64,UklG", true},
		{"data:image/svg+xml,%3Csvg/%3E", true},
		{"data:image/svg+xml;utf8,<svg/>", true},
		{prefix + strings.Repeat("A", maxLogoBytes-len(prefix)), true},
		{prefix + strings.Repeat("A", maxLogoBytes-len(prefix)+1), false},
		{"data:image/svgxml,x", false},
		{"data:image/png", false},
		{"data:text/html,x", false},
		{"DATA:image/png;base64,x", false},
		{"https://cdn.example.com/logo.svg", false},
		{"//evil.example/logo.svg", false},
		{"/\\evil.example/logo.svg", false},
		{"/static/logo.svg?v=2", false},
		{"/authorize?redirect_uri=x", false},
		{"/static/logo.svg#x", false},
		{"/static/logo .svg", false},
		{"/static/\nlogo.svg", false},
		{"static/logo.svg", false},
		{"javascript:alert(1)", false},
	} {
		got, problem := logoURL(tc.logo)
		if (got != "") != tc.ok || (problem == "") != tc.ok {
			t.Errorf("logoURL(%.40q) = %q, %q; want accepted %v", tc.logo, got, problem, tc.ok)
		}
	}
	if got, problem := logoURL(""); got != "" || problem != "" {
		t.Errorf(`logoURL("") = %q, %q; want neither`, got, problem)
	}
}

func TestCSSColor(t *testing.T) {
	for _, tc := range []struct {
		color string
		ok    bool
	}{
		{"#0066FF", true},
		{"#0052cc", true},
		{"#fff", true},
		{"#ffff", false},
		{"#0066FF0", false},
		{"0066FF", false},
		{"#gggggg", false},
		{"red", false},
		{"#fff; color: red", false},
	} {
		got, problem := cssColor(tc.color)
		if (got != "") != tc.ok || (problem == "") != tc.ok {
			t.Errorf("cssColor(%q) = %q, %q; want accepted %v", tc.color, got, problem, tc.ok)
		}
	}
	if got, problem := cssColor(""); got != "" || problem != "" {
		t.Errorf(`cssColor("") = %q, %q; want neither`, got, problem)
	}
}

// TestPageBrandingPanic verifies that a branding function that panics
// leaves the page in ZDAS's own look and is logged once.
func TestPageBrandingPanic(t *testing.T) {
	var logs logBuffer
	h := brandedEndpoints(t, func(*http.Request) PageBranding { panic("tenant lookup failed") }, &logs, "github")
	for range 2 {
		if body := consentPage(t, h); !strings.Contains(body, "<h1>Sign in to OpenZiti</h1>") || !strings.Contains(body, consentWarning) {
			t.Errorf("page after a panic: %s", body)
		}
	}
	if n := strings.Count(logs.String(), "page branding function panicked"); n != 1 || !strings.Contains(logs.String(), "tenant lookup failed") {
		t.Errorf("%d panic log lines, want 1 with the panic: %s", n, logs.String())
	}

	// http.ErrAbortHandler is how a handler asks net/http to abort the
	// response, so it isn't swallowed.
	h.branding = func(*http.Request) PageBranding { panic(http.ErrAbortHandler) }
	defer func() {
		if v := recover(); v != http.ErrAbortHandler {
			t.Errorf("recovered %v, want http.ErrAbortHandler", v)
		}
	}()
	consentPage(t, h)
}

func TestOnceSet(t *testing.T) {
	var o onceSet
	if !o.first("a") || o.first("a") {
		t.Error("first doesn't report a key once")
	}
	for i := 1; i < maxBrandingWarnings; i++ {
		o.first(strings.Repeat("k", i))
	}
	if o.first("one too many") {
		t.Errorf("first recorded more than %d keys", maxBrandingWarnings)
	}
}

// TestPageBrandingConcurrent renders pages from many requests at once with
// one shared PageBranding, which ZDAS must only read.
func TestPageBrandingConcurrent(t *testing.T) {
	var logs logBuffer
	shared := PageBranding{Title: "Acme", ProviderLabels: map[string]string{"github": "GitHub"}, PrimaryColor: "bad"}
	h := brandedEndpoints(t, func(*http.Request) PageBranding { return shared }, &logs, "github")
	mux := h.mux()
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, authorizeURL(t, nil), nil))
			if !strings.Contains(w.Body.String(), "Continue with GitHub") {
				t.Errorf("page lacks the label: %s", w.Body.String())
			}
		})
	}
	wg.Wait()
	if n := strings.Count(logs.String(), "field=PrimaryColor"); n != 1 {
		t.Errorf("%d warnings for the shared bad color, want 1", n)
	}
}

func TestAcceptsHTML(t *testing.T) {
	for accept, want := range map[string]bool{
		browserAccept:      true,
		"Text/HTML":        true,
		"":                 false,
		"*/*":              false,
		"application/json": false,
	} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Accept", accept)
		if got := acceptsHTML(r); got != want {
			t.Errorf("acceptsHTML(Accept: %q) = %v, want %v", accept, got, want)
		}
	}
}

// TestPageError verifies that an error a browser asks for as a page comes
// as a branded page with the same status, and that any other request gets
// exactly what http.Error sends, without calling the branding function.
func TestPageError(t *testing.T) {
	var calls atomic.Int32
	branding := func(*http.Request) PageBranding {
		calls.Add(1)
		return PageBranding{Title: "Acme sign-in", Logo: "/static/logo.svg"}
	}
	var logs logBuffer
	h := brandedEndpoints(t, branding, &logs, "github")
	empty := brandedEndpoints(t, branding, &logs)
	failing := newJSONStore()
	broken := setupStoreHandlers(t, failing, "https://zdas.example.com")
	broken.branding = branding
	failing.failWith(errors.New("database unavailable"))
	id := mustID(t)

	for _, tc := range []struct {
		name, method, target, body string
		h                          *endpoints
		status                     int
		want                       string
	}{
		{"callback without a session", http.MethodGet, "/callback/github?state=" + id + "&code=c", "", h, http.StatusBadRequest, sessionWarning},
		{"stray callback", http.MethodPost, "/callback/github/x", "state=" + id, h, http.StatusBadRequest, sessionWarning},
		{"consent without a session", http.MethodPost, "/authorize", "consent=" + id + "&idp=github", h, http.StatusBadRequest, consentMissing},
		{"consent for an unknown provider", http.MethodPost, "/authorize", "consent=" + id + "&idp=nope", h, http.StatusBadRequest, "unknown or missing sign-in provider; go back and choose one"},
		{"consent with no providers", http.MethodPost, "/authorize", "consent=" + id + "&idp=github", empty, http.StatusServiceUnavailable, "no sign-in providers are available; try again later"},
		{"consent body too large", http.MethodPost, "/authorize", "consent=" + strings.Repeat("x", maxConsentRequestBytes), h, http.StatusBadRequest, "malformed form body"},
		{"authorize without redirect_uri", http.MethodGet, "/authorize", "", h, http.StatusBadRequest, "redirect_uri is required"},
		{"authorize with a redirect_uri not allowed", http.MethodGet, "/authorize?redirect_uri=https://evil.example/cb", "", h, http.StatusBadRequest, "redirect_uri is not allowed"},
		{"store failure", http.MethodGet, "/callback/mock-idp?code=x&state=" + id, "", broken, http.StatusInternalServerError, "internal error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			send := func(method, accept string) *httptest.ResponseRecorder {
				req := httptest.NewRequest(method, tc.target, strings.NewReader(tc.body))
				if tc.body != "" {
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				}
				if accept != "" {
					req.Header.Set("Accept", accept)
				}
				w := httptest.NewRecorder()
				tc.h.mux().ServeHTTP(w, req)
				return w
			}

			calls.Store(0)
			for _, accept := range []string{"", "*/*", "application/json"} {
				text := send(tc.method, accept)
				hdr := text.Header()
				if text.Code != tc.status || text.Body.String() != tc.want+"\n" ||
					hdr.Get("Content-Type") != "text/plain; charset=utf-8" || hdr.Get("X-Content-Type-Options") != "nosniff" ||
					hdr.Get("Content-Security-Policy") != "" || hdr.Get("Vary") != "Accept" {
					t.Errorf("Accept %q: %d %q %v, want %d and exactly http.Error's %q with Vary: Accept", accept, text.Code, text.Body.String(), hdr, tc.status, tc.want)
				}
			}
			if n := calls.Load(); n != 0 {
				t.Errorf("branding function called %d times for requests that don't accept HTML", n)
			}

			page := send(tc.method, browserAccept)
			if page.Code != tc.status {
				t.Errorf("status = %d, want %d", page.Code, tc.status)
			}
			body := page.Body.String()
			for _, want := range []string{"<h1>Acme sign-in</h1>", `src="/static/logo.svg"`, "<p>" + strings.ReplaceAll(tc.want, "'", "&#39;")} {
				if !strings.Contains(body, want) {
					t.Errorf("page lacks %q: %s", want, body)
				}
			}
			for k, want := range map[string]string{
				"Content-Type":            "text/html; charset=utf-8",
				"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'",
				"X-Frame-Options":         "DENY",
				"Cache-Control":           "no-store",
				"Vary":                    "Accept",
			} {
				if got := page.Header().Get(k); got != want {
					t.Errorf("%s = %q, want %q", k, got, want)
				}
			}
		})
	}
}

// TestWritePageDropsContentLength verifies that a page doesn't keep a
// Content-Length set before it, which would no longer match its body.
func TestWritePageDropsContentLength(t *testing.T) {
	var logs logBuffer
	h := brandedEndpoints(t, nil, &logs, "github")
	w := httptest.NewRecorder()
	w.Header().Set("Content-Length", "3")
	r := httptest.NewRequest(http.MethodGet, "/callback", nil)
	r.Header.Set("Accept", browserAccept)
	h.pageError(w, r, consentMissing, http.StatusBadRequest)
	if got := w.Header().Get("Content-Length"); got != "" {
		t.Errorf("Content-Length = %q, want none", got)
	}
}

// TestPageErrorHead verifies that HEAD gets an error page's status and
// headers.
func TestPageErrorHead(t *testing.T) {
	var logs logBuffer
	h := brandedEndpoints(t, nil, &logs, "github")
	srv := httptest.NewServer(h.mux())
	t.Cleanup(srv.Close)
	req, err := http.NewRequest(http.MethodHead, srv.URL+"/callback/github?state="+mustID(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", browserAccept)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || resp.Header.Get("Content-Type") != "text/html; charset=utf-8" {
		t.Errorf("HEAD: %d %s, want 400 text/html", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
}

// TestPageErrorAfterConsumedSession verifies the error page a sign-in gets
// when its callback reaches another browser, after ZDAS has consumed and
// cancelled the session.
func TestPageErrorAfterConsumedSession(t *testing.T) {
	h := bindingEndpoints(t, "https://zdas.example.com")
	h.branding = func(*http.Request) PageBranding { return PageBranding{Title: "Acme sign-in"} }
	mux := h.mux()
	_, sessID := startAuthorize(t, mux)

	req := httptest.NewRequest(http.MethodGet, "/callback/mock-idp?code=c&state="+sessID, nil)
	req.Header.Set("Accept", browserAccept)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if body := w.Body.String(); w.Code != http.StatusBadRequest || !strings.Contains(body, "<h1>Acme sign-in</h1>") ||
		!strings.Contains(body, "This sign-in can&#39;t be finished here.") {
		t.Errorf("callback from another browser: %d %s, want the 400 warning page", w.Code, body)
	}
	if loc := w.Header().Get("Location"); loc != "" {
		t.Errorf("Location = %q, want none", loc)
	}
}

// TestNewServerPageBranding verifies that WithPageBranding reaches the pages
// a Server shows.
func TestNewServerPageBranding(t *testing.T) {
	srv, err := NewServer(replicaConfig(t), slog.Default(), WithPageBranding(func(*http.Request) PageBranding {
		return PageBranding{Title: "Acme sign-in"}
	}))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { srv.Shutdown(context.Background()) })
	req := httptest.NewRequest(http.MethodGet, "/callback?state=unknown", nil)
	req.Header.Set("Accept", "text/html")
	w := httptest.NewRecorder()
	srv.handlers.mux().ServeHTTP(w, req)
	if !strings.Contains(w.Body.String(), "<h1>Acme sign-in</h1>") {
		t.Errorf("page isn't branded: %s", w.Body.String())
	}
}

// TestCompleteProvisionPageError verifies that CompleteProvision answers a
// browser with an error page too.
func TestCompleteProvisionPageError(t *testing.T) {
	var logs logBuffer
	h := brandedEndpoints(t, func(*http.Request) PageBranding { return PageBranding{Title: "Acme sign-in"} }, &logs, "github")
	req := httptest.NewRequest(http.MethodGet, "/enroll/pick", nil)
	req.Header.Set("Accept", "text/html")
	w := httptest.NewRecorder()
	h.completeProvision(w, req, "unknown", map[string]any{"sub": "u"}, nil)
	if body := w.Body.String(); w.Code != http.StatusBadRequest || !strings.Contains(body, "<h1>Acme sign-in</h1>") {
		t.Errorf("CompleteProvision: %d %s, want a 400 error page", w.Code, body)
	}
}
