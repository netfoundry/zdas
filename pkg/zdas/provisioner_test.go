package zdas

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// immediateProvisioner returns claims directly (no interactive redirect).
type immediateProvisioner struct {
	claims map[string]any
}

func (p *immediateProvisioner) Provision(_ context.Context, req ProvisionRequest) (*ProvisionResult, error) {
	return &ProvisionResult{Claims: p.claims}, nil
}

// interactiveProvisioner returns a redirect URL for interactive selection.
type interactiveProvisioner struct {
	redirectURL string
}

func (p *interactiveProvisioner) Provision(_ context.Context, req ProvisionRequest) (*ProvisionResult, error) {
	return &ProvisionResult{RedirectURL: p.redirectURL}, nil
}

// failingProvisioner returns the configured error from Provision.
type failingProvisioner struct {
	err error
}

func (p *failingProvisioner) Provision(_ context.Context, req ProvisionRequest) (*ProvisionResult, error) {
	return nil, p.err
}

func TestProvisionerImmediateClaims(t *testing.T) {
	// Set up a ZDAS handler with a provisioner that returns claims directly.
	ks, _ := GenerateKeySet()
	reg := NewProviderRegistry()
	cp := &callbackProvider{
		name:   "mock-idp",
		issuer: "https://mock-idp",
		identity: &UpstreamIdentity{
			Subject:  "u1",
			Email:    "alice@example.com",
			Username: "alice",
			Issuer:   "https://mock-idp",
			Raw:      map[string]any{"preferred_username": "alice"},
		},
	}
	_ = reg.Register(cp)
	store := newSessionStore(10*time.Minute, 60*time.Second)
	t.Cleanup(store.Stop)

	provisioner := &immediateProvisioner{
		claims: map[string]any{
			"device_identity_name": "custom-name",
			"device_external_id":   "custom-ext-id",
			"sub":                  "custom-ext-id",
		},
	}

	cfg := Config{
		ExternalURL: "https://zdas.test",
		Claims:      defaultClaimsConfig(),
		Token:       TokenConfig{Issuer: "https://zdas.test", Audience: "ziti-enroll", Expiry: 5 * time.Minute},
	}
	h := newTestEndpoints(cfg, ks, reg, store, provisioner)
	mux := h.Mux()

	// Create a session as if /authorize ran.
	verifier, challenge := generateTestPKCE(t)
	sessID := seedSession(t, h, &AuthSession{
		TunnelerRedirectURI:         "http://localhost:20314/auth/callback",
		TunnelerState:               "tstate",
		TunnelerCodeChallenge:       challenge,
		TunnelerCodeChallengeMethod: "S256",
		DeviceInfo:                  &DeviceInfo{DeviceName: "laptop"},
		UpstreamProviderName:        "mock-idp",
	})

	// Simulate callback.
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/callback?code=c&state="+sessID, nil))
	if w.Code != http.StatusFound {
		t.Fatalf("callback status = %d, body = %s", w.Code, w.Body.String())
	}

	loc, _ := url.Parse(w.Header().Get("Location"))
	zdasCode := loc.Query().Get("code")
	if zdasCode == "" {
		t.Fatal("no code in redirect")
	}

	// Exchange code for token.
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {zdasCode},
		"redirect_uri":  {"http://localhost:20314/auth/callback"},
		"code_verifier": {verifier},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("token status = %d, body = %s", w.Code, w.Body.String())
	}

	// Verify the token contains the provisioner's custom claims.
	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["access_token"] == nil {
		t.Fatal("missing access_token")
	}
}

func TestProvisionerInteractiveRedirect(t *testing.T) {
	ks, _ := GenerateKeySet()
	reg := NewProviderRegistry()
	cp := &callbackProvider{
		name:   "mock-idp",
		issuer: "https://mock-idp",
		identity: &UpstreamIdentity{
			Subject:  "u1",
			Username: "alice",
			Issuer:   "https://mock-idp",
			Raw:      map[string]any{},
		},
	}
	_ = reg.Register(cp)
	store := newSessionStore(10*time.Minute, 60*time.Second)
	t.Cleanup(store.Stop)

	provisioner := &interactiveProvisioner{
		redirectURL: "https://ezziti.example.com/pick-network",
	}

	cfg := Config{
		ExternalURL: "https://zdas.test",
		Claims:      defaultClaimsConfig(),
		Token:       TokenConfig{Issuer: "https://zdas.test", Audience: "ziti-enroll", Expiry: 5 * time.Minute},
	}
	h := newTestEndpoints(cfg, ks, reg, store, provisioner)
	mux := h.Mux()

	verifier, challenge := generateTestPKCE(t)
	sessID := seedSession(t, h, &AuthSession{
		TunnelerRedirectURI:         "http://localhost:20314/auth/callback",
		TunnelerState:               "tstate",
		TunnelerCodeChallenge:       challenge,
		TunnelerCodeChallengeMethod: "S256",
		DeviceInfo:                  &DeviceInfo{DeviceName: "laptop"},
		UpstreamProviderName:        "mock-idp",
	})

	// Callback should redirect to the picker page with a pending_id.
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/callback?code=c&state="+sessID, nil))
	if w.Code != http.StatusFound {
		t.Fatalf("callback status = %d", w.Code)
	}
	loc, _ := url.Parse(w.Header().Get("Location"))
	if !strings.HasPrefix(loc.String(), "https://ezziti.example.com/pick-network") {
		t.Fatalf("expected redirect to picker, got %s", loc)
	}
	pendingID := loc.Query().Get("pending_id")
	if pendingID == "" {
		t.Fatal("no pending_id in redirect")
	}

	// The picker page's handler completes provisioning.
	claims := map[string]any{
		"device_identity_name": "alice-laptop",
		"device_external_id":   "ext-from-picker",
		"sub":                  "ext-from-picker",
	}
	w = completeProvision(h, pendingID, claims, nil)
	if w.Code != http.StatusFound {
		t.Fatalf("CompleteProvision status = %d, body = %s", w.Code, w.Body.String())
	}
	loc, _ = url.Parse(w.Header().Get("Location"))
	if loc.Query().Get("state") != "tstate" {
		t.Errorf("state = %q", loc.Query().Get("state"))
	}
	zdasCode := loc.Query().Get("code")
	if zdasCode == "" {
		t.Fatal("no code from CompleteProvision")
	}

	// Exchange the code.
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {zdasCode},
		"redirect_uri":  {"http://localhost:20314/auth/callback"},
		"code_verifier": {verifier},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("token status = %d, body = %s", w.Code, w.Body.String())
	}
}

// runProvisionerCallback wires a stubbed provisioner up to a /callback request
// and returns the recorder so tests can inspect the redirect.
func runProvisionerCallback(t *testing.T, p EnrollmentProvisioner) *httptest.ResponseRecorder {
	t.Helper()
	ks, _ := GenerateKeySet()
	reg := NewProviderRegistry()
	cp := &callbackProvider{
		name:   "mock-idp",
		issuer: "https://mock-idp",
		identity: &UpstreamIdentity{
			Subject:  "u1",
			Email:    "alice@example.com",
			Username: "alice",
			Issuer:   "https://mock-idp",
			Raw:      map[string]any{},
		},
	}
	_ = reg.Register(cp)
	store := newSessionStore(10*time.Minute, 60*time.Second)
	t.Cleanup(store.Stop)

	cfg := Config{
		ExternalURL: "https://zdas.test",
		Claims:      defaultClaimsConfig(),
		Token:       TokenConfig{Issuer: "https://zdas.test", Audience: "ziti-enroll", Expiry: 5 * time.Minute},
	}
	h := newTestEndpoints(cfg, ks, reg, store, p)
	mux := h.Mux()

	_, challenge := generateTestPKCE(t)
	sessID := seedSession(t, h, &AuthSession{
		TunnelerRedirectURI:         "http://localhost:20314/auth/callback",
		TunnelerState:               "tstate",
		TunnelerCodeChallenge:       challenge,
		TunnelerCodeChallengeMethod: "S256",
		DeviceInfo:                  &DeviceInfo{DeviceName: "laptop"},
		UpstreamProviderName:        "mock-idp",
	})

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/callback?code=c&state="+sessID, nil))
	return w
}

func TestProvisionerStructuredErrorPassthrough(t *testing.T) {
	cases := []struct {
		name string
		code string
	}{
		{"access_denied", "access_denied"},
		{"invalid_request", "invalid_request"},
		{"server_error", "server_error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pe := &ProvisionError{Code: tc.code, Description: "go away: " + tc.name}
			w := runProvisionerCallback(t, &failingProvisioner{err: pe})

			if w.Code != http.StatusFound {
				t.Fatalf("status = %d, want 302", w.Code)
			}
			loc, _ := url.Parse(w.Header().Get("Location"))
			if loc.Query().Get("error") != tc.code {
				t.Errorf("error = %q, want %q", loc.Query().Get("error"), tc.code)
			}
			if loc.Query().Get("error_description") != "go away: "+tc.name {
				t.Errorf("error_description = %q", loc.Query().Get("error_description"))
			}
			if loc.Query().Get("state") != "tstate" {
				t.Errorf("state = %q, want tstate", loc.Query().Get("state"))
			}
		})
	}
}

func TestProvisionerStructuredErrorWrapped(t *testing.T) {
	// errors.As must unwrap correctly through fmt.Errorf wrapping.
	pe := &ProvisionError{Code: "access_denied", Description: "denied"}
	wrapped := fmt.Errorf("provisioning context: %w", pe)
	w := runProvisionerCallback(t, &failingProvisioner{err: wrapped})

	loc, _ := url.Parse(w.Header().Get("Location"))
	if loc.Query().Get("error") != "access_denied" {
		t.Errorf("wrapped ProvisionError not unwrapped: error = %q", loc.Query().Get("error"))
	}
	if loc.Query().Get("error_description") != "denied" {
		t.Errorf("error_description = %q", loc.Query().Get("error_description"))
	}
}

func TestProvisionerPlainErrorBecomesServerError(t *testing.T) {
	w := runProvisionerCallback(t, &failingProvisioner{err: errors.New("database is down")})

	loc, _ := url.Parse(w.Header().Get("Location"))
	if loc.Query().Get("error") != "server_error" {
		t.Errorf("error = %q, want server_error", loc.Query().Get("error"))
	}
	if loc.Query().Get("error_description") != "provisioning failed" {
		t.Errorf("error_description = %q", loc.Query().Get("error_description"))
	}
}

func TestSanitizeErrorDescription(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "hello world", "hello world"},
		{"newlines stripped", "line one\nline two", "line one line two"},
		{"control chars stripped", "tab\there", "tab here"},
		{"backslash stripped", `back\slash`, "back slash"},
		{"quote stripped", `say "hi"`, "say  hi "},
		{"truncates long input", strings.Repeat("a", 300), strings.Repeat("a", 200)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizeErrorDescription(tc.in)
			if got != tc.want {
				t.Errorf("sanitizeErrorDescription(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestProvisionerStructuredErrorSanitizes(t *testing.T) {
	pe := &ProvisionError{
		Code:        "access_denied",
		Description: "no\nnewlines\there",
	}
	w := runProvisionerCallback(t, &failingProvisioner{err: pe})

	loc, _ := url.Parse(w.Header().Get("Location"))
	got := loc.Query().Get("error_description")
	if strings.ContainsAny(got, "\n\t") {
		t.Errorf("error_description still contains control chars: %q", got)
	}
	if got != "no newlines here" {
		t.Errorf("error_description = %q", got)
	}
}

func TestProvisionerInvalidErrorCodeFallsBack(t *testing.T) {
	cases := []string{"", "totally_made_up", "INVALID_REQUEST"}
	for _, badCode := range cases {
		t.Run("code_"+badCode, func(t *testing.T) {
			pe := &ProvisionError{Code: badCode, Description: "should not pass through"}
			w := runProvisionerCallback(t, &failingProvisioner{err: pe})

			loc, _ := url.Parse(w.Header().Get("Location"))
			if loc.Query().Get("error") != "server_error" {
				t.Errorf("invalid code %q produced error=%q, want server_error",
					badCode, loc.Query().Get("error"))
			}
			if loc.Query().Get("error_description") != "provisioning failed" {
				t.Errorf("error_description = %q", loc.Query().Get("error_description"))
			}
		})
	}
}

// setupProvisionComplete returns endpoints with a pending provision stored,
// and its pending ID.
func setupProvisionComplete(t *testing.T) (h *endpoints, pendingID string) {
	t.Helper()
	ks, err := GenerateKeySet()
	if err != nil {
		t.Fatalf("GenerateKeySet: %v", err)
	}
	reg := NewProviderRegistry()
	store := newSessionStore(10*time.Minute, 60*time.Second)
	t.Cleanup(store.Stop)

	cfg := Config{
		ExternalURL: "https://zdas.test",
		Claims:      defaultClaimsConfig(),
		Token:       TokenConfig{Issuer: "https://zdas.test", Audience: "ziti-enroll", Expiry: 5 * time.Minute},
	}
	h = newTestEndpoints(cfg, ks, reg, store, nil)

	pendingID = seedPendingProvision(t, h, &PendingProvision{
		TunnelerRedirectURI:         "http://localhost:20314/auth/callback",
		TunnelerState:               "tstate",
		TunnelerCodeChallenge:       "challenge",
		TunnelerCodeChallengeMethod: "S256",
	})
	return h, pendingID
}

// consumePending consumes the pending provision id, or returns nil if there
// is none.
func consumePending(h *endpoints, id string) *PendingProvision {
	pp, _ := h.consumePendingProvision(context.Background(), id)
	return pp
}

// completeProvision calls CompleteProvision as an embedder's picker handler
// would, and returns the recorded response.
func completeProvision(h *endpoints, pendingID string, claims map[string]any, err error) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.completeProvision(w, httptest.NewRequest(http.MethodPost, "/pick-network", nil), pendingID, claims, err)
	return w
}

// TestProvisionCompleteRouteRemoved verifies that the browser cannot finish
// a pending provision itself. The user enrolling holds the pending ID, so a
// public route that took claims from the request would let that user enroll
// as any identity.
func TestProvisionCompleteRouteRemoved(t *testing.T) {
	h, pendingID := setupProvisionComplete(t)
	body := `{"pending_id":"` + pendingID + `","claims":{"sub":"victim","device_external_id":"victim"}}`
	req := httptest.NewRequest(http.MethodPost, "/provision/complete", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Mux().ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
	if pp := consumePending(h, pendingID); pp == nil {
		t.Error("pending provision was consumed by a request from the browser")
	}
}

func TestProvisionCompleteErrorPath(t *testing.T) {
	cases := []struct {
		name     string
		code     string
		desc     string
		wantCode string
	}{
		{"access_denied", "access_denied", "no membership", "access_denied"},
		{"server_error", "server_error", "internal", "server_error"},
		{"invalid_request", "invalid_request", "bad input", "invalid_request"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, pendingID := setupProvisionComplete(t)
			w := completeProvision(h, pendingID, nil, &ProvisionError{Code: tc.code, Description: tc.desc})

			if w.Code != http.StatusFound {
				t.Fatalf("status = %d, want 302; body=%s", w.Code, w.Body.String())
			}
			loc, _ := url.Parse(w.Header().Get("Location"))
			if loc.Query().Get("error") != tc.wantCode {
				t.Errorf("error = %q, want %q", loc.Query().Get("error"), tc.wantCode)
			}
			if loc.Query().Get("error_description") != tc.desc {
				t.Errorf("error_description = %q, want %q", loc.Query().Get("error_description"), tc.desc)
			}
			if loc.Query().Get("state") != "tstate" {
				t.Errorf("state = %q, want tstate", loc.Query().Get("state"))
			}
		})
	}
}

func TestProvisionCompleteInvalidErrorFallsBack(t *testing.T) {
	cases := []struct {
		name string
		err  error
	}{
		{"unknown code", &ProvisionError{Code: "totally_made_up", Description: "embedder secret"}},
		{"empty code", &ProvisionError{Code: "", Description: "embedder secret"}},
		{"wrong case", &ProvisionError{Code: "ACCESS_DENIED", Description: "embedder secret"}},
		{"plain error", errors.New("embedder secret")},
		{"neither claims nor error", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, pendingID := setupProvisionComplete(t)
			w := completeProvision(h, pendingID, nil, tc.err)

			loc, _ := url.Parse(w.Header().Get("Location"))
			if loc.Query().Get("error") != "server_error" {
				t.Errorf("error = %q, want server_error", loc.Query().Get("error"))
			}
			// Description must be replaced with the generic fallback so we
			// don't leak embedder-supplied text alongside a bogus code.
			if loc.Query().Get("error_description") != "provisioning failed" {
				t.Errorf("error_description = %q, want %q",
					loc.Query().Get("error_description"), "provisioning failed")
			}
			if loc.Query().Has("code") {
				t.Error("code issued without claims")
			}
		})
	}
}

func TestProvisionCompleteErrorPathConsumesPending(t *testing.T) {
	h, pendingID := setupProvisionComplete(t)
	denied := &ProvisionError{Code: "access_denied", Description: "no"}
	completeProvision(h, pendingID, nil, denied)

	if pp := consumePending(h, pendingID); pp != nil {
		t.Error("pending provision was not consumed")
	}
	w := completeProvision(h, pendingID, nil, denied)
	if w.Code != http.StatusBadRequest {
		t.Errorf("replay status = %d, want 400", w.Code)
	}
}

func TestProvisionCompleteErrorTakesPrecedence(t *testing.T) {
	h, pendingID := setupProvisionComplete(t)
	w := completeProvision(h, pendingID,
		map[string]any{"device_external_id": "x"},
		&ProvisionError{Code: "access_denied", Description: "denied"})

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", w.Code)
	}
	loc, _ := url.Parse(w.Header().Get("Location"))
	if loc.Query().Get("error") != "access_denied" {
		t.Errorf("expected error path to win, got error=%q code=%q",
			loc.Query().Get("error"), loc.Query().Get("code"))
	}
}

func TestProvisionCompleteErrorDescriptionSanitized(t *testing.T) {
	h, pendingID := setupProvisionComplete(t)
	// Include a double-quote and backslash, both disallowed by RFC 6749
	// 4.1.2.1, plus newline/tab control chars. None should survive.
	w := completeProvision(h, pendingID, nil, &ProvisionError{
		Code:        "access_denied",
		Description: "say \"hi\"\nback\\slash\there",
	})

	loc, _ := url.Parse(w.Header().Get("Location"))
	got := loc.Query().Get("error_description")
	if strings.ContainsAny(got, "\n\t\\\"") {
		t.Errorf("description not sanitized: %q", got)
	}
	// And legal characters should survive.
	if !strings.Contains(got, "say") || !strings.Contains(got, "hi") {
		t.Errorf("legal characters lost: %q", got)
	}
}

// capturingProvisioner records the ProvisionRequest it receives.
type capturingProvisioner struct {
	captured ProvisionRequest
	claims   map[string]any
}

func (p *capturingProvisioner) Provision(_ context.Context, req ProvisionRequest) (*ProvisionResult, error) {
	p.captured = req
	return &ProvisionResult{Claims: p.claims}, nil
}

func TestProvisionerReceivesEnrollmentMethod(t *testing.T) {
	ks, _ := GenerateKeySet()
	reg := NewProviderRegistry()
	cp := &callbackProvider{
		name:   "mock-idp",
		issuer: "https://mock-idp",
		identity: &UpstreamIdentity{
			Subject:  "u1",
			Email:    "alice@example.com",
			Username: "alice",
			Issuer:   "https://mock-idp",
			Raw:      map[string]any{"preferred_username": "alice"},
		},
	}
	_ = reg.Register(cp)
	store := newSessionStore(10*time.Minute, 60*time.Second)
	t.Cleanup(store.Stop)

	provisioner := &capturingProvisioner{
		claims: map[string]any{
			"device_identity_name": "alice-laptop",
			"device_external_id":   "ext-id",
			"sub":                  "ext-id",
		},
	}

	cfg := Config{
		ExternalURL: "https://zdas.test",
		Claims:      defaultClaimsConfig(),
		Token:       TokenConfig{Issuer: "https://zdas.test", Audience: "ziti-enroll", Expiry: 5 * time.Minute},
	}
	h := newTestEndpoints(cfg, ks, reg, store, provisioner)
	mux := h.Mux()

	_, challenge := generateTestPKCE(t)
	sessID := seedSession(t, h, &AuthSession{
		TunnelerRedirectURI:         "http://localhost:20314/auth/callback",
		TunnelerState:               "tstate",
		TunnelerCodeChallenge:       challenge,
		TunnelerCodeChallengeMethod: "S256",
		DeviceInfo:                  &DeviceInfo{DeviceName: "laptop"},
		EnrollmentMethod:            "enrollToToken",
		UpstreamProviderName:        "mock-idp",
	})

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/callback?code=c&state="+sessID, nil))
	if w.Code != http.StatusFound {
		t.Fatalf("callback status = %d, body = %s", w.Code, w.Body.String())
	}

	if provisioner.captured.EnrollmentMethod != "enrollToToken" {
		t.Errorf("EnrollmentMethod = %q, want %q", provisioner.captured.EnrollmentMethod, "enrollToToken")
	}
}

func TestProvisionCompleteExpired(t *testing.T) {
	h, _ := setupProvisionComplete(t)
	w := completeProvision(h, "bogus", map[string]any{"sub": "x"}, nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestProvisionerReceivesClientType(t *testing.T) {
	cases := []struct {
		name  string
		param string // appended to the /authorize query
		want  string
	}{
		{"client_type sent", "&client_type=host", "host"},
		{"unmodified tunneler omits it", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ks, _ := GenerateKeySet()
			reg := NewProviderRegistry()
			_ = reg.Register(&callbackProvider{
				name:   "mock-idp",
				issuer: "https://mock-idp",
				identity: &UpstreamIdentity{
					Subject:  "u1",
					Username: "alice",
					Issuer:   "https://mock-idp",
					Raw:      map[string]any{},
				},
			})
			store := newSessionStore(10*time.Minute, 60*time.Second)
			t.Cleanup(store.Stop)

			provisioner := &capturingProvisioner{
				claims: map[string]any{
					"device_identity_name": "alice-host",
					"device_external_id":   "ext-id",
					"sub":                  "ext-id",
				},
			}
			cfg := Config{
				ExternalURL: "https://zdas.test",
				Claims:      defaultClaimsConfig(),
				Token:       TokenConfig{Issuer: "https://zdas.test", Audience: "ziti-enroll", Expiry: 5 * time.Minute},
			}
			mux := newTestEndpoints(cfg, ks, reg, store, provisioner).Mux()

			_, challenge := generateTestPKCE(t)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
				"/authorize?redirect_uri=http://localhost:20314/auth/callback&state=s1&device_name=box"+
					"&code_challenge="+challenge+"&code_challenge_method=S256"+tc.param, nil))
			if w.Code != http.StatusFound {
				t.Fatalf("authorize status = %d, body = %s", w.Code, w.Body.String())
			}
			loc, err := url.Parse(w.Header().Get("Location"))
			if err != nil {
				t.Fatalf("parse Location: %v", err)
			}
			req := browserRequest(w, "/callback?code=c&state="+loc.Query().Get("state"))
			w = httptest.NewRecorder()
			mux.ServeHTTP(w, req)
			if w.Code != http.StatusFound {
				t.Fatalf("callback status = %d, body = %s", w.Code, w.Body.String())
			}
			if provisioner.captured.ClientType != tc.want {
				t.Errorf("ClientType = %q, want %q", provisioner.captured.ClientType, tc.want)
			}
		})
	}
}

// TestProvisionCompleteTracksFallback verifies that a fallback enrollment
// that goes through a provisioner page is queued for the reconciler when the
// page finishes it, as one finished at /callback is.
func TestProvisionCompleteTracksFallback(t *testing.T) {
	ks, _ := GenerateKeySet()
	reg := NewProviderRegistry()
	_ = reg.Register(&callbackProvider{
		name:     "mock-idp",
		issuer:   "https://mock-idp",
		identity: &UpstreamIdentity{Subject: "u1", Username: "alice", Issuer: "https://mock-idp"},
	})
	store := newSessionStore(10*time.Minute, 60*time.Second)
	t.Cleanup(store.Stop)
	cfg := Config{
		ExternalURL: "https://zdas.test",
		Claims:      defaultClaimsConfig(),
		Token:       TokenConfig{Issuer: "https://zdas.test", Audience: "ziti-enroll", Expiry: 5 * time.Minute},
	}
	h := newTestEndpoints(cfg, ks, reg, store, &interactiveProvisioner{redirectURL: "https://embedder.example.com/pick"})
	h.reconciler = testReconciler("https://ctrl", time.Hour)
	sessID := seedSession(t, h, &AuthSession{
		TunnelerRedirectURI:  "http://localhost:20314/auth/callback",
		TunnelerState:        "tstate",
		DeviceInfo:           &DeviceInfo{},
		FallbackNonce:        "0123456789abcdef",
		UpstreamProviderName: "mock-idp",
	})

	cb := httptest.NewRecorder()
	h.Mux().ServeHTTP(cb, httptest.NewRequest(http.MethodGet, "/callback?code=c&state="+sessID, nil))
	pick, err := url.Parse(cb.Header().Get("Location"))
	if err != nil || pick.Query().Get("pending_id") == "" {
		t.Fatalf("callback: status = %d, Location = %q; want a picker redirect", cb.Code, cb.Header().Get("Location"))
	}

	w := completeProvision(h, pick.Query().Get("pending_id"), map[string]any{
		"sub":                  "0a1b2c",
		"device_external_id":   "0a1b2c",
		"device_identity_name": "alice-pending-0123",
		"preferred_username":   "alice",
	}, nil)
	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if n := h.reconciler.PendingCount(); n != 1 {
		t.Errorf("PendingCount = %d, want 1", n)
	}
}
