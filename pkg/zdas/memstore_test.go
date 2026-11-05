package zdas

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// Round trips, single use and key isolation are covered by the zdastest
// conformance suite in store_conformance_test.go. These tests cover what is
// particular to memStore: its caps and its sweep.

// TestMemStoreFullEvictsOldestSession verifies that a full store makes room
// for a new session by evicting the oldest, so a flood of anonymous
// /authorize requests cannot lock out every user.
func TestMemStoreFullEvictsOldestSession(t *testing.T) {
	s := newMemStore(10*time.Minute, time.Minute, storeSweepInterval)
	t.Cleanup(s.stop)
	start := time.Now().Add(-time.Minute)
	for i := range maxStoreEntries {
		if err := s.CreateSession(t.Context(), fmt.Sprintf("s%d", i), &AuthSession{CreatedAt: start.Add(time.Duration(i) * time.Millisecond)}); err != nil {
			t.Fatal(err)
		}
	}

	if err := s.CreateSession(t.Context(), "new", &AuthSession{CreatedAt: time.Now()}); err != nil {
		t.Fatalf("CreateSession on a full store: %v", err)
	}
	if n := s.sessions.len(); n != maxStoreEntries {
		t.Errorf("store holds %d sessions, want %d", n, maxStoreEntries)
	}
	if sess, _ := s.ConsumeSession(t.Context(), "s0"); sess != nil {
		t.Error("oldest session was not evicted")
	}
	if sess, _ := s.ConsumeSession(t.Context(), "s1"); sess == nil {
		t.Error("second-oldest session was evicted")
	}
	if sess, _ := s.ConsumeSession(t.Context(), "new"); sess == nil {
		t.Error("new session not stored")
	}
}

// TestMemStoreFullRefusesCodes verifies that codes, which need an upstream
// login to create, are refused rather than evicted when the store is full.
func TestMemStoreFullRefusesCodes(t *testing.T) {
	s := newMemStore(10*time.Minute, time.Minute, storeSweepInterval)
	t.Cleanup(s.stop)
	for i := range maxStoreEntries {
		if err := s.CreateCode(t.Context(), fmt.Sprintf("c%d", i), &AuthCode{CreatedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.CreateCode(t.Context(), "new", &AuthCode{CreatedAt: time.Now()}); err == nil {
		t.Error("CreateCode on a full store succeeded")
	}
	if ac, _ := s.ConsumeCode(t.Context(), "c0"); ac == nil {
		t.Error("an existing code was evicted")
	}
}

// TestMemStoreSweep verifies that sweep removes each kind of entry once it
// is older than its TTL, and nothing younger.
func TestMemStoreSweep(t *testing.T) {
	s := newMemStore(10*time.Minute, time.Minute, storeSweepInterval)
	t.Cleanup(s.stop)
	now := time.Now()
	old, young := now.Add(-11*time.Minute), now.Add(-30*time.Second)
	ctx := t.Context()
	_ = s.CreateSession(ctx, "old", &AuthSession{CreatedAt: old})
	_ = s.CreateSession(ctx, "young", &AuthSession{CreatedAt: young})
	_ = s.CreateCode(ctx, "old", &AuthCode{CreatedAt: now.Add(-2 * time.Minute)})
	_ = s.CreateCode(ctx, "young", &AuthCode{CreatedAt: young})
	_ = s.CreatePendingProvision(ctx, "old", &PendingProvision{CreatedAt: old})
	_ = s.CreatePendingProvision(ctx, "young", &PendingProvision{CreatedAt: young})

	s.sweep(now)

	for kind, n := range map[string]int{"sessions": s.sessions.len(), "codes": s.codes.len(), "provisions": s.provisions.len()} {
		if n != 1 {
			t.Errorf("%s: %d left after sweep, want 1", kind, n)
		}
	}
	if sess, _ := s.ConsumeSession(ctx, "young"); sess == nil {
		t.Error("young session was swept")
	}
}

// TestMemStoreSweepLoop verifies that the sweep goroutine runs, and stops
// on stop, which may be called twice.
func TestMemStoreSweepLoop(t *testing.T) {
	s := newMemStore(time.Millisecond, time.Millisecond, time.Millisecond)
	_ = s.CreateSession(t.Context(), "k", &AuthSession{CreatedAt: time.Now()})
	deadline := time.Now().Add(5 * time.Second)
	for {
		s.mu.Lock()
		n := s.sessions.len()
		s.mu.Unlock()
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("expired session never swept")
		}
		time.Sleep(time.Millisecond)
	}
	s.stop()
	s.stop()
}

func TestRandomIDUniqueness(t *testing.T) {
	seen := make(map[string]struct{}, 100)
	for i := 0; i < 100; i++ {
		id, err := randomID()
		if err != nil {
			t.Fatalf("randomID: %v", err)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate id after %d iterations", i)
		}
		seen[id] = struct{}{}
	}
}

// TestMemStoreLogsEviction verifies that a full store warns when it starts
// evicting sessions, at most once a minute.
func TestMemStoreLogsEviction(t *testing.T) {
	s := newMemStore(time.Hour, time.Minute, time.Hour)
	t.Cleanup(s.stop)
	var buf bytes.Buffer
	s.logger = slog.New(slog.NewTextHandler(&buf, nil))
	for i := range maxStoreEntries + 3 {
		if err := s.CreateSession(t.Context(), fmt.Sprint(i), &AuthSession{CreatedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	if n := strings.Count(buf.String(), "session store full"); n != 1 {
		t.Errorf("eviction warnings = %d, want 1: %s", n, buf.String())
	}
}

// TestMemStoreEvictionLogCountsDrops verifies that the eviction warning
// says how many sessions were dropped since the previous one.
func TestMemStoreEvictionLogCountsDrops(t *testing.T) {
	s := newMemStore(time.Hour, time.Minute, time.Hour)
	t.Cleanup(s.stop)
	var buf bytes.Buffer
	s.logger = slog.New(slog.NewTextHandler(&buf, nil))
	s.lastEvicted = time.Now() // as if a warning just went out
	for i := range maxStoreEntries + 3 {
		if err := s.CreateSession(t.Context(), fmt.Sprint(i), &AuthSession{CreatedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	if buf.Len() != 0 {
		t.Fatalf("warned within the interval: %s", buf.String())
	}
	s.lastEvicted = time.Now().Add(-evictionLogInterval)
	if err := s.CreateSession(t.Context(), "last", &AuthSession{CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "dropped=4") {
		t.Errorf("warning = %s, want dropped=4", buf.String())
	}
	buf.Reset()
	s.lastEvicted = time.Now().Add(-evictionLogInterval)
	if err := s.CreateSession(t.Context(), "after", &AuthSession{CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "dropped=1") {
		t.Errorf("next warning = %s, want dropped=1, counted from the last one", buf.String())
	}
}
