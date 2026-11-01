package zdas

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// AuthSession holds state for an in-flight authorization flow between the
// /authorize call and the /callback.
type AuthSession struct {
	TunnelerRedirectURI         string
	TunnelerState               string
	TunnelerCodeChallenge       string
	TunnelerCodeChallengeMethod string
	DeviceInfo                  *DeviceInfo // always populated; DeviceName may be empty on fallback path
	FallbackNonce               string      // populated only on fallback path
	EnrollmentMethod            string      // from tunneler's enrollment_method param (e.g. "enrollToCert", "enrollToToken")
	ClientType                  string      // from the client_type param; empty for unmodified tunnelers
	ZDASCodeVerifier            string      // ZDAS's own PKCE verifier for upstream (empty for non-PKCE providers)
	UpstreamProviderName        string
	CreatedAt                   time.Time

	// Deprecated: ZDAS no longer sets or reads this. The browser binding
	// is part of the session's store key instead, so a callback from
	// another browser cannot find, and so cannot use up, the session.
	BrowserBindingHash string
}

// AuthCode holds composed claims alongside the metadata needed to validate the
// tunneler's code exchange request.
type AuthCode struct {
	Claims              map[string]interface{}
	RedirectURI         string
	CodeChallenge       string
	CodeChallengeMethod string
	IsFallback          bool // true if enrolled via fallback path
	CreatedAt           time.Time
	Used                bool
}

// PendingProvision holds state for an interactive provisioning detour.
// Created when a provisioner returns a RedirectURL, consumed by
// CompleteProvision.
type PendingProvision struct {
	TunnelerRedirectURI         string
	TunnelerState               string
	TunnelerCodeChallenge       string
	TunnelerCodeChallengeMethod string
	IsFallback                  bool
	CreatedAt                   time.Time
}

// maxStoreEntries is a per-map capacity cap to prevent memory exhaustion from
// a flood of /authorize requests. 10,000 concurrent in-flight sessions is far
// beyond any realistic enrollment volume.
const maxStoreEntries = 10_000

// SessionStore is an in-memory store for auth sessions, authorization codes,
// and pending provisions with automatic expiration. It is safe for concurrent
// use.
type SessionStore struct {
	sessionTTL time.Duration
	codeTTL    time.Duration

	mu         sync.Mutex
	sessions   map[string]*AuthSession
	codes      map[string]*AuthCode
	provisions map[string]*PendingProvision

	stopCleanup chan struct{}
	stopOnce    sync.Once
}

// NewSessionStore creates a store with the given TTLs and starts a background
// cleanup goroutine.
func NewSessionStore(sessionTTL, codeTTL time.Duration) *SessionStore {
	s := &SessionStore{
		sessionTTL:  sessionTTL,
		codeTTL:     codeTTL,
		sessions:    make(map[string]*AuthSession),
		codes:       make(map[string]*AuthCode),
		provisions:  make(map[string]*PendingProvision),
		stopCleanup: make(chan struct{}),
	}
	go s.cleanupLoop()
	return s
}

// Stop halts the background cleanup goroutine. It may be called more than
// once.
func (s *SessionStore) Stop() {
	s.stopOnce.Do(func() { close(s.stopCleanup) })
}

// CreateSession stores a new auth session and returns its ID.
func (s *SessionStore) CreateSession(sess *AuthSession) (string, error) {
	id, err := randomID()
	if err != nil {
		return "", err
	}
	sess.CreatedAt = time.Now()
	s.putSession(id, sess)
	return id, nil
}

// putSession stores sess under id as given, without stamping CreatedAt. When
// the store is full it evicts the oldest session rather than refusing the new
// one: sessions are created before anyone authenticates, so refusing them
// would let anonymous /authorize requests lock every user out.
func (s *SessionStore) putSession(id string, sess *AuthSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.sessions) >= maxStoreEntries {
		s.evictOldestSession()
	}
	s.sessions[id] = sess
}

// evictOldestSession removes the session with the earliest CreatedAt. s.mu
// must be held. It scans every session, which happens only while the store
// is full.
func (s *SessionStore) evictOldestSession() {
	var oldestID string
	var oldest time.Time
	for id, sess := range s.sessions {
		if oldestID == "" || sess.CreatedAt.Before(oldest) {
			oldestID, oldest = id, sess.CreatedAt
		}
	}
	delete(s.sessions, oldestID)
}

// GetSession retrieves and deletes (consumes) an auth session by ID. Returns
// nil if expired or not found.
func (s *SessionStore) GetSession(id string) *AuthSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return nil
	}
	delete(s.sessions, id)
	if time.Since(sess.CreatedAt) > s.sessionTTL {
		return nil
	}
	return sess
}

// CreateCode stores composed claims under a new authorization code and returns
// the code string.
func (s *SessionStore) CreateCode(ac *AuthCode) (string, error) {
	code, err := randomID()
	if err != nil {
		return "", err
	}
	ac.CreatedAt = time.Now()
	if err := s.putCode(code, ac); err != nil {
		return "", err
	}
	return code, nil
}

// putCode stores ac under code as given, without stamping CreatedAt.
func (s *SessionStore) putCode(code string, ac *AuthCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.codes) >= maxStoreEntries {
		return fmt.Errorf("code store full (%d entries)", maxStoreEntries)
	}
	s.codes[code] = ac
	return nil
}

// ConsumeCode retrieves and marks an authorization code as used. Returns nil if
// the code is expired, already used, or not found.
func (s *SessionStore) ConsumeCode(code string) *AuthCode {
	s.mu.Lock()
	defer s.mu.Unlock()
	ac, ok := s.codes[code]
	if !ok {
		return nil
	}
	if ac.Used || time.Since(ac.CreatedAt) > s.codeTTL {
		delete(s.codes, code)
		return nil
	}
	ac.Used = true
	return ac
}

// CreatePendingProvision stores state for an interactive provisioning detour
// and returns the pending ID.
func (s *SessionStore) CreatePendingProvision(pp *PendingProvision) (string, error) {
	id, err := randomID()
	if err != nil {
		return "", err
	}
	pp.CreatedAt = time.Now()
	if err := s.putPendingProvision(id, pp); err != nil {
		return "", err
	}
	return id, nil
}

// putPendingProvision stores pp under id as given, without stamping
// CreatedAt.
func (s *SessionStore) putPendingProvision(id string, pp *PendingProvision) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.provisions) >= maxStoreEntries {
		return fmt.Errorf("provision store full (%d entries)", maxStoreEntries)
	}
	s.provisions[id] = pp
	return nil
}

// ConsumePendingProvision retrieves and deletes a pending provision. Returns
// nil if expired or not found.
func (s *SessionStore) ConsumePendingProvision(id string) *PendingProvision {
	s.mu.Lock()
	defer s.mu.Unlock()
	pp, ok := s.provisions[id]
	if !ok {
		return nil
	}
	delete(s.provisions, id)
	if time.Since(pp.CreatedAt) > s.sessionTTL {
		return nil
	}
	return pp
}

func (s *SessionStore) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopCleanup:
			return
		case <-ticker.C:
			s.cleanup()
		}
	}
}

func (s *SessionStore) cleanup() {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, sess := range s.sessions {
		if now.Sub(sess.CreatedAt) > s.sessionTTL {
			delete(s.sessions, id)
		}
	}
	for code, ac := range s.codes {
		if ac.Used || now.Sub(ac.CreatedAt) > s.codeTTL {
			delete(s.codes, code)
		}
	}
	for id, pp := range s.provisions {
		if now.Sub(pp.CreatedAt) > s.sessionTTL {
			delete(s.provisions, id)
		}
	}
}

func randomID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate random id: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// generateShortNonce returns a 16-character hex nonce for fallback enrollments.
// 8 bytes of entropy pushes the birthday-collision bound to ~4 billion, which
// is safe for any realistic volume of concurrent fallback enrollments.
func generateShortNonce() (string, error) {
	b := make([]byte, 8) // 8 bytes = 16 hex chars
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	return hex.EncodeToString(b), nil
}
