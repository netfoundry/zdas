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
)

// mockGitHubServer returns a test server that simulates GitHub's OAuth and API
// endpoints. It accepts any code as valid and returns the provided user data.
// emails is optional - when non-nil, it's served from /user/emails.
func mockGitHubServer(t *testing.T, user map[string]any, orgs []map[string]any, emails []map[string]any) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"access_token": "test-token",
			"token_type":   "Bearer",
		})
	})

	mux.HandleFunc("/user/orgs", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(orgs)
	})

	mux.HandleFunc("/user/emails", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if emails != nil {
			json.NewEncoder(w).Encode(emails)
		} else {
			json.NewEncoder(w).Encode([]any{})
		}
	})

	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(user)
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

func newTestGitHubProvider(t *testing.T, server *httptest.Server, allowedOrgs []string) *GitHubProvider {
	t.Helper()
	p := NewGitHubProvider(ProviderConfig{
		Name:          "github-test",
		ClientID:      "test-client-id",
		ClientSecret:  "test-client-secret",
		UsernameField: "login",
		UserIDField:   "id",
		AllowedOrgs:   allowedOrgs,
	})
	p.authBaseURL = server.URL + "/login/oauth/authorize"
	p.tokenBaseURL = server.URL + "/login/oauth/access_token"
	p.userURL = server.URL + "/user"
	return p
}

func TestGitHubProviderName(t *testing.T) {
	p := NewGitHubProvider(ProviderConfig{Name: "gh", ClientID: "c", ClientSecret: "s"})
	if p.Name() != "gh" {
		t.Errorf("Name() = %q", p.Name())
	}
	if p.Issuer() != "https://github.com" {
		t.Errorf("Issuer() = %q", p.Issuer())
	}
}

func TestGitHubProviderAuthorizeURL(t *testing.T) {
	p := NewGitHubProvider(ProviderConfig{
		Name:         "gh",
		ClientID:     "my-client",
		ClientSecret: "s",
	})
	authURL := p.AuthorizeURL("mystate", "https://zdas/callback")
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if u.Query().Get("client_id") != "my-client" {
		t.Errorf("client_id = %q", u.Query().Get("client_id"))
	}
	if u.Query().Get("state") != "mystate" {
		t.Errorf("state = %q", u.Query().Get("state"))
	}
	if !strings.Contains(u.Query().Get("scope"), "read:user") {
		t.Errorf("scope missing read:user: %q", u.Query().Get("scope"))
	}
}

func TestGitHubProviderExchangeAndIdentify(t *testing.T) {
	user := map[string]any{
		"id":    float64(12345),
		"login": "jsmith",
		"name":  "John Smith",
		"email": "j@example.com",
	}
	// /user/emails must provide the primary+verified address - the /user
	// profile email is no longer trusted.
	emails := []map[string]any{
		{"email": "j@example.com", "primary": true, "verified": true},
	}
	server := mockGitHubServer(t, user, nil, emails)
	p := newTestGitHubProvider(t, server, nil)

	identity, err := p.ExchangeAndIdentify(context.Background(), "fake-code", "https://zdas/callback")
	if err != nil {
		t.Fatalf("ExchangeAndIdentify: %v", err)
	}
	if identity.Subject != "12345" {
		t.Errorf("Subject = %q, want 12345", identity.Subject)
	}
	if identity.Username != "jsmith" {
		t.Errorf("Username = %q, want jsmith", identity.Username)
	}
	if identity.Email != "j@example.com" {
		t.Errorf("Email = %q, want j@example.com", identity.Email)
	}
	if identity.Issuer != "https://github.com" {
		t.Errorf("Issuer = %q", identity.Issuer)
	}
}

func TestGitHubProviderUnverifiedProfileEmailDropped(t *testing.T) {
	// /user profile has a public email but /user/emails has no verified
	// entries (or none match this address). The profile email must not
	// leak through - Email should be empty.
	user := map[string]any{
		"id":    float64(99),
		"login": "attacker",
		"email": "victim@example.com", // attacker set this publicly but never verified
	}
	emails := []map[string]any{
		{"email": "victim@example.com", "primary": true, "verified": false},
	}
	server := mockGitHubServer(t, user, nil, emails)
	p := newTestGitHubProvider(t, server, nil)

	identity, err := p.ExchangeAndIdentify(context.Background(), "fake-code", "https://zdas/callback")
	if err != nil {
		t.Fatalf("ExchangeAndIdentify: %v", err)
	}
	if identity.Email != "" {
		t.Errorf("Email = %q, want empty (unverified profile email must not leak)", identity.Email)
	}
	if identity.Subject != "99" {
		t.Errorf("Subject = %q", identity.Subject)
	}
}

func TestGitHubProviderOrgCheckPass(t *testing.T) {
	user := map[string]any{
		"id":    float64(1),
		"login": "dev",
	}
	orgs := []map[string]any{
		{"login": "mycompany"},
		{"login": "other-org"},
	}
	server := mockGitHubServer(t, user, orgs, nil)
	p := newTestGitHubProvider(t, server, []string{"mycompany"})

	_, err := p.ExchangeAndIdentify(context.Background(), "code", "https://zdas/callback")
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
}

func TestGitHubProviderOrgCheckFail(t *testing.T) {
	user := map[string]any{
		"id":    float64(1),
		"login": "outsider",
	}
	orgs := []map[string]any{
		{"login": "some-other-org"},
	}
	server := mockGitHubServer(t, user, orgs, nil)
	p := newTestGitHubProvider(t, server, []string{"mycompany"})

	_, err := p.ExchangeAndIdentify(context.Background(), "code", "https://zdas/callback")
	if !errors.Is(err, ErrAccessDenied) {
		t.Errorf("expected an error wrapping ErrAccessDenied, got %v", err)
	}
}

// TestGitHubProviderOrgCheckPaginates verifies that an allowed organization
// on a later page of the user's organizations is found.
func TestGitHubProviderOrgCheckPaginates(t *testing.T) {
	var pages []string
	server := mockGitHubServer(t, map[string]any{"id": float64(1), "login": "member"}, nil, nil)
	orgs := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		pages = append(pages, page)
		var out []map[string]string
		if page == "1" {
			for i := range gitHubOrgsPageSize {
				out = append(out, map[string]string{"login": fmt.Sprintf("org-%d", i)})
			}
		} else {
			out = []map[string]string{{"login": "mycompany"}}
		}
		json.NewEncoder(w).Encode(out)
	})
	paged := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/user/orgs" {
			orgs(w, r)
			return
		}
		server.Config.Handler.ServeHTTP(w, r)
	}))
	t.Cleanup(paged.Close)
	p := newTestGitHubProvider(t, paged, []string{"mycompany"})

	if _, err := p.ExchangeAndIdentify(context.Background(), "code", "https://zdas/callback"); err != nil {
		t.Fatalf("ExchangeAndIdentify: %v", err)
	}
	if len(pages) != 2 {
		t.Errorf("read org pages %v, want 2", pages)
	}
}

// TestGitHubProviderRejectsMissingSubject verifies that a user whose ID
// field is missing, null or not a scalar is rejected, rather than sharing
// one subject, and so one device identity, with every such user.
func TestGitHubProviderRejectsMissingSubject(t *testing.T) {
	cases := map[string]map[string]any{
		"missing":    {"login": "no-id"},
		"null":       {"login": "null-id", "id": nil},
		"object":     {"login": "obj-id", "id": map[string]any{"v": 1}},
		"empty":      {"login": "empty-id", "id": ""},
		"null email": {"login": "private", "id": float64(1), "email": nil},
	}
	for name, user := range cases {
		t.Run(name, func(t *testing.T) {
			server := mockGitHubServer(t, user, nil, nil)
			p := newTestGitHubProvider(t, server, nil)
			if name == "null email" {
				p.userIDField = "email"
			}
			if id, err := p.ExchangeAndIdentify(context.Background(), "code", "https://zdas/callback"); err == nil {
				t.Errorf("accepted with subject %q", id.Subject)
			}
		})
	}
}

func TestGitHubProviderFieldMapping(t *testing.T) {
	user := map[string]any{
		"id":    float64(99),
		"login": "handle",
		"name":  "Full Name",
		"email": "me@example.com",
	}
	server := mockGitHubServer(t, user, nil, nil)

	// Use name instead of login for username.
	p := newTestGitHubProvider(t, server, nil)
	p.usernameField = "name"
	p.userIDField = "id"

	identity, err := p.ExchangeAndIdentify(context.Background(), "code", "https://zdas/callback")
	if err != nil {
		t.Fatalf("ExchangeAndIdentify: %v", err)
	}
	if identity.Username != "Full Name" {
		t.Errorf("Username = %q, want 'Full Name'", identity.Username)
	}
}

func TestGitHubProviderEmailFromUserEmails(t *testing.T) {
	// User profile has no public email - should fetch from /user/emails.
	user := map[string]any{
		"id":    float64(55),
		"login": "noemail",
	}
	emails := []map[string]any{
		{"email": "secondary@example.com", "primary": false, "verified": true},
		{"email": "primary@example.com", "primary": true, "verified": true},
	}
	server := mockGitHubServer(t, user, nil, emails)
	p := newTestGitHubProvider(t, server, nil)

	identity, err := p.ExchangeAndIdentify(context.Background(), "code", "https://zdas/callback")
	if err != nil {
		t.Fatalf("ExchangeAndIdentify: %v", err)
	}
	if identity.Email != "primary@example.com" {
		t.Errorf("Email = %q, want primary@example.com", identity.Email)
	}
}

func TestExtractField(t *testing.T) {
	data := map[string]any{
		"str":     "hello",
		"num":     float64(42),
		"missing": nil,
	}
	if got := extractField(data, "str"); got != "hello" {
		t.Errorf("str = %q", got)
	}
	if got := extractField(data, "num"); got != "42" {
		t.Errorf("num = %q", got)
	}
	if got := extractField(data, "nope"); got != "" {
		t.Errorf("nope = %q", got)
	}
}

// TestGitHubProviderOrgCheckIgnoresCase verifies that allowed_orgs matches
// organization names regardless of case, as GitHub does.
func TestGitHubProviderOrgCheckIgnoresCase(t *testing.T) {
	server := mockGitHubServer(t, map[string]any{"id": float64(1), "login": "member"}, []map[string]any{{"login": "NETFOUNDRY"}}, nil)
	p := newTestGitHubProvider(t, server, []string{"NetFoundry"})
	if _, err := p.ExchangeAndIdentify(context.Background(), "code", "https://zdas/callback"); err != nil {
		t.Errorf("member of netfoundry rejected for allowed_orgs [NetFoundry]: %v", err)
	}
}
