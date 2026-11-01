package zdas

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// mockManagementAPI simulates the Ziti controller management API for reconciler
// tests. It handles /authenticate, GET /identities (with filter), and PATCH
// /identities/{id}.
type mockManagementAPI struct {
	mu         sync.Mutex
	identities map[string]mockIdentity
	renamed    map[string]string // id -> new name
	rejectAll  bool              // answer identity calls with 401
}

type mockIdentity struct {
	ID         string
	ExternalID string
	Hostname   string // from envInfo
}

func newMockManagementAPI(identities []mockIdentity) *mockManagementAPI {
	m := &mockManagementAPI{
		identities: make(map[string]mockIdentity),
		renamed:    make(map[string]string),
	}
	for _, id := range identities {
		m.identities[id.ExternalID] = id
	}
	return m
}

func (m *mockManagementAPI) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/authenticate", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"token":             "mock-zt-session",
				"expirationSeconds": 1800,
			},
		})
	})
	mux.HandleFunc("/edge/management/v1/identities/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch {
			// Extract identity ID from path.
			parts := strings.Split(r.URL.Path, "/")
			identityID := parts[len(parts)-1]
			var body map[string]string
			json.NewDecoder(r.Body).Decode(&body)
			m.mu.Lock()
			m.renamed[identityID] = body["name"]
			m.mu.Unlock()
			w.WriteHeader(http.StatusOK)
			return
		}
		http.NotFound(w, r)
	})
	mux.HandleFunc("/edge/management/v1/identities", func(w http.ResponseWriter, r *http.Request) {
		filter := r.URL.Query().Get("filter")
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.rejectAll {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		var results []map[string]any
		for _, id := range m.identities {
			// Simple filter match: check if the externalId is in the filter string.
			if strings.Contains(filter, id.ExternalID) {
				entry := map[string]any{
					"id":         id.ID,
					"externalId": id.ExternalID,
				}
				if id.Hostname != "" {
					entry["envInfo"] = map[string]string{"hostname": id.Hostname}
				}
				results = append(results, entry)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"data": results})
	})
	return mux
}

func TestReconcilerTrack(t *testing.T) {
	r := newFallbackReconciler(
		FallbackConfig{PollInterval: 10 * time.Second, Timeout: 1 * time.Hour},
		defaultClaimsConfig(),
		http.DefaultClient,
		"https://ctrl",
		slog.Default(),
	)
	r.Track("ext-id-1", "alice", "abc123")
	if r.PendingCount() != 1 {
		t.Fatalf("PendingCount = %d, want 1", r.PendingCount())
	}
	r.Track("ext-id-2", "bob", "def456")
	if r.PendingCount() != 2 {
		t.Fatalf("PendingCount = %d, want 2", r.PendingCount())
	}
}

func TestReconcilerReconcileOneWithHostname(t *testing.T) {
	mock := newMockManagementAPI([]mockIdentity{
		{ID: "id-1", ExternalID: "ext-1", Hostname: "macbook-pro"},
	})
	server := httptest.NewServer(mock.handler())
	t.Cleanup(server.Close)

	r := newFallbackReconciler(
		FallbackConfig{PollInterval: 100 * time.Millisecond, Timeout: 1 * time.Hour},
		defaultClaimsConfig(),
		server.Client(),
		server.URL,
		slog.Default(),
	)
	r.sessionToken = "mock-zt-session"
	r.sessionExpires = time.Now().Add(30 * time.Minute)

	p := &pendingReconciliation{
		ExternalID: "ext-1",
		Username:   "jsmith",
		Nonce:      "abc123",
		TrackedAt:  time.Now(),
	}
	done, err := r.reconcileOne(t.Context(), p)
	if err != nil {
		t.Fatalf("reconcileOne: %v", err)
	}
	if !done {
		t.Error("expected done=true")
	}
	if mock.renamed["id-1"] != "jsmith-macbook-pro" {
		t.Errorf("renamed to %q, want jsmith-macbook-pro", mock.renamed["id-1"])
	}
}

func TestReconcilerReconcileOneNoHostname(t *testing.T) {
	mock := newMockManagementAPI([]mockIdentity{
		{ID: "id-1", ExternalID: "ext-1", Hostname: ""}, // no envInfo yet
	})
	server := httptest.NewServer(mock.handler())
	t.Cleanup(server.Close)

	r := newFallbackReconciler(
		FallbackConfig{PollInterval: 100 * time.Millisecond, Timeout: 1 * time.Hour},
		defaultClaimsConfig(),
		server.Client(),
		server.URL,
		slog.Default(),
	)
	r.sessionToken = "mock-zt-session"
	r.sessionExpires = time.Now().Add(30 * time.Minute)

	p := &pendingReconciliation{
		ExternalID: "ext-1",
		Username:   "jsmith",
		TrackedAt:  time.Now(),
	}
	done, err := r.reconcileOne(t.Context(), p)
	if err != nil {
		t.Fatalf("reconcileOne: %v", err)
	}
	if done {
		t.Error("expected done=false (no hostname yet)")
	}
}

func TestReconcilerReconcileOneNotFound(t *testing.T) {
	mock := newMockManagementAPI(nil) // no identities
	server := httptest.NewServer(mock.handler())
	t.Cleanup(server.Close)

	r := newFallbackReconciler(
		FallbackConfig{PollInterval: 100 * time.Millisecond, Timeout: 1 * time.Hour},
		defaultClaimsConfig(),
		server.Client(),
		server.URL,
		slog.Default(),
	)
	r.sessionToken = "mock-zt-session"
	r.sessionExpires = time.Now().Add(30 * time.Minute)

	p := &pendingReconciliation{
		ExternalID: "nonexistent",
		Username:   "jsmith",
		TrackedAt:  time.Now(),
	}
	done, err := r.reconcileOne(t.Context(), p)
	if err != nil {
		t.Fatalf("reconcileOne: %v", err)
	}
	if done {
		t.Error("expected done=false (not found)")
	}
}

func TestReconcilerTimeout(t *testing.T) {
	mock := newMockManagementAPI(nil)
	server := httptest.NewServer(mock.handler())
	t.Cleanup(server.Close)

	r := newFallbackReconciler(
		FallbackConfig{PollInterval: 50 * time.Millisecond, Timeout: 1 * time.Millisecond},
		defaultClaimsConfig(),
		server.Client(),
		server.URL,
		slog.Default(),
	)
	r.sessionToken = "mock-zt-session"
	r.sessionExpires = time.Now().Add(30 * time.Minute)

	r.Track("ext-timeout", "alice", "nonce")
	time.Sleep(5 * time.Millisecond)

	r.poll(t.Context())

	if r.PendingCount() != 0 {
		t.Errorf("expected timed-out entry to be removed, count = %d", r.PendingCount())
	}
}

func TestReconcilerSessionRefresh(t *testing.T) {
	mock := newMockManagementAPI(nil)
	server := httptest.NewServer(mock.handler())
	t.Cleanup(server.Close)

	r := newFallbackReconciler(
		FallbackConfig{PollInterval: 100 * time.Millisecond, Timeout: 1 * time.Hour},
		defaultClaimsConfig(),
		server.Client(),
		server.URL,
		slog.Default(),
	)
	// Session is expired.
	r.sessionExpires = time.Now().Add(-1 * time.Minute)

	r.Track("ext-1", "alice", "nonce")
	r.poll(t.Context()) // Should trigger refresh.

	if r.sessionToken != "mock-zt-session" {
		t.Errorf("session token not refreshed: %q", r.sessionToken)
	}
}

// testReconciler returns a reconciler against apiURL with the given timeout.
func testReconciler(apiURL string, timeout time.Duration) *fallbackReconciler {
	return newFallbackReconciler(
		FallbackConfig{PollInterval: 10 * time.Second, Timeout: timeout},
		defaultClaimsConfig(),
		http.DefaultClient,
		apiURL,
		slog.Default(),
	)
}

// TestReconcilerRefusesUnsupportedExternalID verifies that an external ID
// that could break out of the management API filter is never tracked.
func TestReconcilerRefusesUnsupportedExternalID(t *testing.T) {
	r := testReconciler("https://ctrl", time.Hour)
	for _, id := range []string{`x" or name = "edge-router-1`, "", "a b", "a\\b"} {
		r.Track(id, "alice", "n")
	}
	if n := r.PendingCount(); n != 0 {
		t.Errorf("PendingCount = %d, want 0", n)
	}
	r.Track("0123abcdef", "alice", "n")
	if n := r.PendingCount(); n != 1 {
		t.Errorf("PendingCount after a hex ID = %d, want 1", n)
	}
}

// TestReconcilerFindIdentityRequiresOneMatch verifies that the reconciler
// renames only an identity whose external ID is the one it asked for.
func TestReconcilerFindIdentityRequiresOneMatch(t *testing.T) {
	cases := []struct {
		name       string
		identities []mockIdentity
	}{
		{"different external ID", []mockIdentity{{ID: "id-1", ExternalID: "ext", Hostname: "h"}}},
		{"two matches", []mockIdentity{{ID: "id-1", ExternalID: "ext", Hostname: "h"}, {ID: "id-2", ExternalID: "xt-1", Hostname: "h"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			api := newMockManagementAPI(tc.identities)
			srv := httptest.NewServer(api.handler())
			t.Cleanup(srv.Close)
			r := testReconciler(srv.URL, time.Hour)

			if _, _, err := r.findIdentity(t.Context(), "ext-1"); err == nil {
				t.Error("findIdentity accepted a result that is not exactly the asked-for identity")
			}
		})
	}

	// Two identities with the asked-for external ID: neither is renamed.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"data":[{"id":"id-1","externalId":"ext-1"},{"id":"id-2","externalId":"ext-1"}]}`)
	}))
	t.Cleanup(srv.Close)
	if _, _, err := testReconciler(srv.URL, time.Hour).findIdentity(t.Context(), "ext-1"); err == nil {
		t.Error("findIdentity accepted two identities with one external ID")
	}
}

// TestReconcilerPrunesWhileControllerDown verifies that timed-out entries
// are dropped even when the reconciler cannot authenticate.
func TestReconcilerPrunesWhileControllerDown(t *testing.T) {
	r := testReconciler("http://127.0.0.1:1", time.Millisecond)
	r.Track("ext-1", "alice", "n")
	time.Sleep(5 * time.Millisecond)
	r.poll(t.Context())
	if n := r.PendingCount(); n != 0 {
		t.Errorf("PendingCount = %d, want 0", n)
	}
}

// TestReconcilerRefreshesRejectedSession verifies that a 401 from the
// management API makes the next poll authenticate again.
func TestReconcilerRefreshesRejectedSession(t *testing.T) {
	api := newMockManagementAPI([]mockIdentity{{ID: "id-1", ExternalID: "ext-1", Hostname: "h"}})
	api.rejectAll = true
	srv := httptest.NewServer(api.handler())
	t.Cleanup(srv.Close)
	r := testReconciler(srv.URL, time.Hour)
	r.Track("ext-1", "alice", "n")

	r.poll(t.Context())
	r.sessMu.RLock()
	expires := r.sessionExpires
	r.sessMu.RUnlock()
	if !expires.IsZero() {
		t.Errorf("session still valid until %v after a 401", expires)
	}
	if n := r.PendingCount(); n != 1 {
		t.Errorf("PendingCount = %d, want the entry kept for retry", n)
	}
}
