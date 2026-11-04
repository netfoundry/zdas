package zdas

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// jsonStore is a Store that behaves like an external database: entries are
// held as JSON keyed by kind and key, consume deletes them, and there is no
// expiry logic. Setting err makes every call fail with it.
type jsonStore struct {
	mu   sync.Mutex
	rows map[string][]byte
	err  error
}

func newJSONStore() *jsonStore {
	return &jsonStore{rows: make(map[string][]byte)}
}

func (s *jsonStore) failWith(err error) {
	s.mu.Lock()
	s.err = err
	s.mu.Unlock()
}

// keys returns the keys of every stored row.
func (s *jsonStore) keys() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for k := range s.rows {
		out = append(out, k[strings.IndexByte(k, '/')+1:])
	}
	return out
}

func (s *jsonStore) create(kind, key string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	s.rows[kind+"/"+key] = data
	return nil
}

// consume decodes and deletes the row into out, reporting whether it existed.
func (s *jsonStore) consume(kind, key string, out any) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return false, s.err
	}
	data, ok := s.rows[kind+"/"+key]
	if !ok {
		return false, nil
	}
	delete(s.rows, kind+"/"+key)
	return true, json.Unmarshal(data, out)
}

func (s *jsonStore) CreateSession(_ context.Context, key string, sess *AuthSession) error {
	return s.create(kindSession, key, sess)
}

func (s *jsonStore) ConsumeSession(_ context.Context, key string) (*AuthSession, error) {
	var sess AuthSession
	if ok, err := s.consume(kindSession, key, &sess); !ok || err != nil {
		return nil, err
	}
	return &sess, nil
}

func (s *jsonStore) CreateCode(_ context.Context, key string, ac *AuthCode) error {
	return s.create(kindCode, key, ac)
}

func (s *jsonStore) ConsumeCode(_ context.Context, key string) (*AuthCode, error) {
	var ac AuthCode
	if ok, err := s.consume(kindCode, key, &ac); !ok || err != nil {
		return nil, err
	}
	return &ac, nil
}

func (s *jsonStore) CreatePendingProvision(_ context.Context, key string, pp *PendingProvision) error {
	return s.create(kindProvision, key, pp)
}

func (s *jsonStore) ConsumePendingProvision(_ context.Context, key string) (*PendingProvision, error) {
	var pp PendingProvision
	if ok, err := s.consume(kindProvision, key, &pp); !ok || err != nil {
		return nil, err
	}
	return &pp, nil
}

// setupStoreHandlers returns handlers backed by store for issuer, wired the
// way NewServer wires an injected store.
func setupStoreHandlers(t *testing.T, store Store, issuer string) *endpoints {
	t.Helper()
	ks, err := GenerateKeySet()
	if err != nil {
		t.Fatalf("GenerateKeySet: %v", err)
	}
	reg := NewProviderRegistry()
	if err := reg.Register(&callbackProvider{
		name:     "mock-idp",
		issuer:   "https://mock-idp",
		identity: &UpstreamIdentity{Subject: "u42", Username: "jsmith", Issuer: "https://mock-idp"},
	}); err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		ExternalURL: issuer,
		Claims:      defaultClaimsConfig(),
		Token: TokenConfig{
			Issuer:   issuer,
			Audience: "ziti-enrolltocert",
			Expiry:   5 * time.Minute,
		},
		Session: SessionConfig{
			Timeout:    10 * time.Minute,
			CodeExpiry: 60 * time.Second,
		},
	}
	return newEndpoints(cfg, ks, nil, reg, store, nil, nil, nil, slog.Default())
}

// mustID returns a fresh ID in the form ZDAS generates.
func mustID(t *testing.T) string {
	t.Helper()
	id, err := randomID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func postToken(mux http.Handler, code string) *httptest.ResponseRecorder {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"http://localhost:20314/auth/callback"},
		"code_verifier": {"unused"},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	return w
}

func tokenErrorCode(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal token error: %v (body %s)", err, w.Body.String())
	}
	return body.Error
}

// TestStoreStaleEntriesAreMisses verifies that ZDAS enforces TTLs itself, so
// a store that hands back an expired entry, or one whose CreatedAt was lost
// or shifted, cannot extend its lifetime.
func TestStoreStaleEntriesAreMisses(t *testing.T) {
	for name, createdAt := range map[string]time.Time{
		"expired": time.Now().Add(-time.Hour),
		"zero":    {},
		"future":  time.Now().Add(5 * time.Hour),
	} {
		t.Run(name, func(t *testing.T) {
			store := newJSONStore()
			h := setupStoreHandlers(t, store, "https://zdas.example.com")
			mux := h.mux()
			ctx := t.Context()

			code := mustID(t)
			if err := store.CreateCode(ctx, h.storeKey(kindCode, code), &AuthCode{RedirectURI: "http://localhost:20314/auth/callback", CreatedAt: createdAt}); err != nil {
				t.Fatal(err)
			}
			w := postToken(mux, code)
			if w.Code != http.StatusBadRequest || tokenErrorCode(t, w) != "invalid_grant" {
				t.Errorf("code: status = %d, body = %s; want 400 invalid_grant", w.Code, w.Body.String())
			}

			sid := mustID(t)
			if err := store.CreateSession(ctx, h.storeKey(kindSession, sid), &AuthSession{DeviceInfo: &DeviceInfo{}, CreatedAt: createdAt}); err != nil {
				t.Fatal(err)
			}
			w = httptest.NewRecorder()
			mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/callback?code=x&state="+sid, nil))
			if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "session not found or expired") {
				t.Errorf("session: status = %d, body = %s; want 400 not found", w.Code, w.Body.String())
			}

			pid := mustID(t)
			if err := store.CreatePendingProvision(ctx, h.storeKey(kindProvision, pid), &PendingProvision{CreatedAt: createdAt}); err != nil {
				t.Fatal(err)
			}
			w = httptest.NewRecorder()
			h.completeProvision(w, httptest.NewRequest(http.MethodPost, "/pick", nil), pid, map[string]any{"sub": "x"}, nil)
			if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "pending provision not found or expired") {
				t.Errorf("provision: status = %d, body = %s; want 400 not found", w.Code, w.Body.String())
			}
		})
	}
}

// TestStoreFailureIsServerError verifies that a backend failure on consume
// is reported as a server error rather than as a missing or invalid entry.
func TestStoreFailureIsServerError(t *testing.T) {
	store := newJSONStore()
	h := setupStoreHandlers(t, store, "https://zdas.example.com")
	mux := h.mux()
	store.failWith(errors.New("database unavailable"))
	id := mustID(t)

	w := postToken(mux, id)
	if got := tokenErrorCode(t, w); got != "server_error" || w.Code != http.StatusInternalServerError {
		t.Errorf("token: error = %q, status %d; want server_error, 500", got, w.Code)
	}

	for _, target := range []string{
		"/callback?code=x&state=" + id,
		"/callback?error=access_denied&state=" + id,
	} {
		w = httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, target, nil))
		if w.Code != http.StatusInternalServerError {
			t.Errorf("%s: status = %d, want 500", target, w.Code)
		}
	}

	w = httptest.NewRecorder()
	h.completeProvision(w, httptest.NewRequest(http.MethodPost, "/pick", nil), id, map[string]any{"sub": "x"}, nil)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("provision complete: status = %d, want 500", w.Code)
	}
}

// TestStoreMalformedIDSkipsStore verifies that an ID ZDAS could not have
// issued is a miss without a store lookup: with a failing store, a lookup
// would turn it into a server error.
func TestStoreMalformedIDSkipsStore(t *testing.T) {
	store := newJSONStore()
	h := setupStoreHandlers(t, store, "https://zdas.example.com")
	mux := h.mux()
	store.failWith(errors.New("database unavailable"))

	for _, id := range []string{"", "short", strings.Repeat("A", 32), strings.Repeat("0", 31) + "g", strings.Repeat("0", 33)} {
		if w := postToken(mux, id); id != "" && tokenErrorCode(t, w) != "invalid_grant" {
			t.Errorf("token %q: body = %s; want invalid_grant", id, w.Body.String())
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/callback?code=x&state="+url.QueryEscape(id), nil))
		if w.Code != http.StatusBadRequest {
			t.Errorf("callback %q: status = %d, want 400", id, w.Code)
		}
	}
}

// TestStoreKeysAreHashedAndStamped verifies that the store sees only the
// derived key, never the ID handed to the client, and that ZDAS stamps
// CreatedAt before storing.
func TestStoreKeysAreHashedAndStamped(t *testing.T) {
	store := newJSONStore()
	h := setupStoreHandlers(t, store, "https://zdas.example.com")
	mux := h.mux()
	_, challenge := generateTestPKCE(t)

	reqURL := "/authorize?redirect_uri=http://localhost:20314/auth/callback&response_type=code&state=s1" +
		"&code_challenge=" + challenge + "&code_challenge_method=S256&device_name=laptop"
	w := authorizeAndConsent(t, mux, reqURL, "")
	if w.Code != http.StatusSeeOther {
		t.Fatalf("authorize: status = %d, body = %s", w.Code, w.Body.String())
	}
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	state := loc.Query().Get("state")
	nonce := liveCookie(t, w, state).Value

	keys := store.keys()
	want := hashStoreKey(kindSession, "https://zdas.example.com", state+"."+nonce)
	if len(keys) != 1 || keys[0] != want {
		t.Fatalf("store keys = %v, want [%s]", keys, want)
	}
	sess, err := store.ConsumeSession(t.Context(), want)
	if err != nil || sess == nil {
		t.Fatalf("ConsumeSession = %v, %v", sess, err)
	}
	if time.Since(sess.CreatedAt) > time.Minute {
		t.Errorf("session CreatedAt = %v, want now", sess.CreatedAt)
	}
}

// TestStoreEntriesBoundToIssuer verifies that a Store shared by two ZDAS
// configurations does not let an entry created under one be consumed under
// the other.
func TestStoreEntriesBoundToIssuer(t *testing.T) {
	store := newJSONStore()
	a := setupStoreHandlers(t, store, "https://tenant-a.example.com")
	b := setupStoreHandlers(t, store, "https://tenant-b.example.com")

	code, err := a.createCode(t.Context(), &AuthCode{RedirectURI: "http://localhost:20314/auth/callback"})
	if err != nil {
		t.Fatal(err)
	}
	if ac, err := b.consumeCode(t.Context(), code); err != nil || ac != nil {
		t.Errorf("consume on other issuer = %v, %v; want miss", ac, err)
	}
	if ac, err := a.consumeCode(t.Context(), code); err != nil || ac == nil {
		t.Errorf("consume on own issuer = %v, %v; want entry", ac, err)
	}
}
