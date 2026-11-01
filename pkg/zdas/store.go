package zdas

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// Store holds the short-lived state of in-flight enrollments: auth sessions
// between /authorize and /callback, authorization codes between /callback and
// /token, and pending provisions between a provisioner redirect and
// CompleteProvision. By default ZDAS keeps this state in memory; an
// embedder running several replicas supplies a shared Store with WithStore.
//
// ZDAS generates every ID itself and never passes one to a Store. Each entry
// is stored under a key derived from its ID with SHA-256, so the store never
// holds a live session ID, authorization code or pending provision ID, and
// reading the store does not let anyone redeem its entries. Keys are 64
// lowercase hex characters and fresh for every Create call. The derivation
// also binds the entry's kind and the configured token issuer, so an entry
// can only be consumed as the kind and by the ZDAS configuration that
// created it, and, for an auth session, the nonce in the cookie that ties it
// to the browser that started it.
//
// Consume methods return the entry for a key and remove it so that it cannot
// be returned again, atomically: when several callers consume the same key
// concurrently, at most one of them receives the entry. A missing or already
// consumed key is a miss and returns (nil, nil). A non-nil error means the
// store itself failed and is reported to the client as a server error.
//
// Entries must come back as they were stored, including CreatedAt, which
// ZDAS sets before calling a Create method. ZDAS checks CreatedAt against the
// configured session timeout and code expiry after every consume, so a Store
// needs no expiry logic of its own beyond eventually deleting abandoned
// entries. All three entry types survive a JSON round trip, with one caveat:
// numbers in AuthCode.Claims come back as float64, so integers beyond 2^53
// lose precision. Provisioners should send large numeric claims as strings.
//
// The in-memory default caps each kind at 10,000 entries. ZDAS imposes no
// cap on a Store, and every /authorize request creates an entry, so bound
// /authorize with Config.RateLimit or in front of ZDAS.
//
// AuthCode.Used is an in-memory detail and not part of this contract.
type Store interface {
	CreateSession(ctx context.Context, key string, s *AuthSession) error
	ConsumeSession(ctx context.Context, key string) (*AuthSession, error)
	CreateCode(ctx context.Context, key string, c *AuthCode) error
	ConsumeCode(ctx context.Context, key string) (*AuthCode, error)
	CreatePendingProvision(ctx context.Context, key string, p *PendingProvision) error
	ConsumePendingProvision(ctx context.Context, key string) (*PendingProvision, error)
}

// Entry kinds, folded into store keys so that an ID of one kind can never
// select an entry of another.
const (
	kindSession   = "session"
	kindCode      = "code"
	kindProvision = "provision"
)

// maxClockSkew is how far in the future a consumed entry's CreatedAt may be
// before ZDAS treats it as a store fault. Replicas stamp and check entries
// with their own clocks, so small skew is expected.
const maxClockSkew = time.Minute

// sessionStoreAdapter exposes a SessionStore as a Store. The in-memory store
// cannot fail on consume, so every consume error is nil.
type sessionStoreAdapter struct {
	s *SessionStore
}

func (a sessionStoreAdapter) CreateSession(_ context.Context, key string, sess *AuthSession) error {
	return a.s.putSession(key, sess)
}

func (a sessionStoreAdapter) ConsumeSession(_ context.Context, key string) (*AuthSession, error) {
	return a.s.GetSession(key), nil
}

func (a sessionStoreAdapter) CreateCode(_ context.Context, key string, ac *AuthCode) error {
	return a.s.putCode(key, ac)
}

func (a sessionStoreAdapter) ConsumeCode(_ context.Context, key string) (*AuthCode, error) {
	return a.s.ConsumeCode(key), nil
}

func (a sessionStoreAdapter) CreatePendingProvision(_ context.Context, key string, pp *PendingProvision) error {
	return a.s.putPendingProvision(key, pp)
}

func (a sessionStoreAdapter) ConsumePendingProvision(_ context.Context, key string) (*PendingProvision, error) {
	return a.s.ConsumePendingProvision(key), nil
}

// hashStoreKey derives the key an entry with the given kind and ID is stored
// under for issuer. The NUL separators keep distinct inputs from colliding.
func hashStoreKey(kind, issuer, id string) string {
	sum := sha256.Sum256([]byte(kind + "\x00" + issuer + "\x00" + id))
	return hex.EncodeToString(sum[:])
}

// validID reports whether id has the form randomID produces: 32 lowercase
// hex characters. Anything else cannot name an entry, so it is rejected
// before reaching the store.
func validID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
