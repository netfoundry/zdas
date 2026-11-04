package zdas

import (
	"container/list"
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

const (
	// maxStoreEntries caps each kind of entry in the in-memory store, to
	// bound memory under a flood of /authorize requests. 10,000 concurrent
	// in-flight enrollments is far beyond any realistic volume.
	maxStoreEntries = 10_000
	// storeSweepInterval is how often the in-memory store drops expired
	// entries.
	storeSweepInterval = 30 * time.Second
	// evictionLogInterval is the least time between eviction warnings.
	evictionLogInterval = time.Minute
)

// memStore is the in-memory Store NewServer uses when no WithStore is given.
// It keeps each kind of entry in insertion order, which is creation order,
// so the oldest entry is always at the front. Expiry on consume is left to
// the caller, as for any Store; memStore only sweeps expired entries out.
type memStore struct {
	sessionTTL time.Duration
	codeTTL    time.Duration

	mu         sync.Mutex
	sessions   entryList[*AuthSession]
	codes      entryList[*AuthCode]
	provisions entryList[*PendingProvision]

	done     chan struct{}
	stopOnce sync.Once

	logger      *slog.Logger // warns of evictions; nil logs nothing
	lastEvicted time.Time    // when an eviction was last logged; guarded by mu
}

// newMemStore returns a memStore that sweeps out sessions and pending
// provisions older than sessionTTL and codes older than codeTTL every
// sweepEvery, until stop is called.
func newMemStore(sessionTTL, codeTTL, sweepEvery time.Duration) *memStore {
	s := &memStore{
		sessionTTL: sessionTTL,
		codeTTL:    codeTTL,
		sessions:   newEntryList[*AuthSession](),
		codes:      newEntryList[*AuthCode](),
		provisions: newEntryList[*PendingProvision](),
		done:       make(chan struct{}),
	}
	go s.sweepLoop(sweepEvery)
	return s
}

// stop ends the sweep goroutine. It may be called more than once.
func (s *memStore) stop() {
	s.stopOnce.Do(func() { close(s.done) })
}

// CreateSession stores sess. When the store is full it evicts the oldest
// session rather than refusing the new one: sessions are created before
// anyone authenticates, so refusing them would let anonymous /authorize
// requests lock every user out.
func (s *memStore) CreateSession(_ context.Context, key string, sess *AuthSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sessions.len() >= maxStoreEntries {
		s.sessions.removeOldest()
		if now := time.Now(); s.logger != nil && now.Sub(s.lastEvicted) >= evictionLogInterval {
			s.lastEvicted = now
			s.logger.Warn("session store full, dropping the oldest sign-ins; tighten rate_limit, global_per_second especially",
				"max_sessions", maxStoreEntries)
		}
	}
	s.sessions.add(key, sess, sess.CreatedAt)
	return nil
}

func (s *memStore) ConsumeSession(_ context.Context, key string) (*AuthSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, _ := s.sessions.take(key)
	return sess, nil
}

// CreateCode stores ac, or fails when the store is full. Codes are only
// created after an upstream login, so a full store means real load.
func (s *memStore) CreateCode(_ context.Context, key string, ac *AuthCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.codes.len() >= maxStoreEntries {
		return fmt.Errorf("code store full (%d entries)", maxStoreEntries)
	}
	s.codes.add(key, ac, ac.CreatedAt)
	return nil
}

func (s *memStore) ConsumeCode(_ context.Context, key string) (*AuthCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ac, _ := s.codes.take(key)
	return ac, nil
}

// CreatePendingProvision stores pp, or fails when the store is full, as
// CreateCode does.
func (s *memStore) CreatePendingProvision(_ context.Context, key string, pp *PendingProvision) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.provisions.len() >= maxStoreEntries {
		return fmt.Errorf("provision store full (%d entries)", maxStoreEntries)
	}
	s.provisions.add(key, pp, pp.CreatedAt)
	return nil
}

func (s *memStore) ConsumePendingProvision(_ context.Context, key string) (*PendingProvision, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pp, _ := s.provisions.take(key)
	return pp, nil
}

func (s *memStore) sweepLoop(every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-s.done:
			return
		case now := <-ticker.C:
			s.sweep(now)
		}
	}
}

// sweep removes the entries that have expired at now.
func (s *memStore) sweep(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions.removeOlderThan(now.Add(-s.sessionTTL))
	s.codes.removeOlderThan(now.Add(-s.codeTTL))
	s.provisions.removeOlderThan(now.Add(-s.sessionTTL))
}

// entryList holds one kind of entry by key, in insertion order. It is not
// safe for concurrent use.
type entryList[T any] struct {
	byKey map[string]*list.Element // of *entry[T]
	order *list.List               // oldest at the front
}

type entry[T any] struct {
	key     string
	value   T
	created time.Time
}

func newEntryList[T any]() entryList[T] {
	return entryList[T]{byKey: make(map[string]*list.Element), order: list.New()}
}

func (l *entryList[T]) len() int { return l.order.Len() }

// add stores value under key, replacing any value already there.
func (l *entryList[T]) add(key string, value T, created time.Time) {
	if e, ok := l.byKey[key]; ok {
		l.order.Remove(e)
	}
	l.byKey[key] = l.order.PushBack(&entry[T]{key: key, value: value, created: created})
}

// take removes and returns the value under key.
func (l *entryList[T]) take(key string) (T, bool) {
	e, ok := l.byKey[key]
	if !ok {
		var zero T
		return zero, false
	}
	l.remove(e)
	return e.Value.(*entry[T]).value, true
}

func (l *entryList[T]) removeOldest() {
	if e := l.order.Front(); e != nil {
		l.remove(e)
	}
}

// removeOlderThan removes entries created before cutoff, stopping at the
// first that is not. Entries added slightly out of creation order are
// caught on a later sweep.
func (l *entryList[T]) removeOlderThan(cutoff time.Time) {
	for e := l.order.Front(); e != nil && e.Value.(*entry[T]).created.Before(cutoff); e = l.order.Front() {
		l.remove(e)
	}
}

func (l *entryList[T]) remove(e *list.Element) {
	delete(l.byKey, e.Value.(*entry[T]).key)
	l.order.Remove(e)
}
