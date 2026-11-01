// Package zdastest provides helpers for testing code that embeds zdas.
package zdastest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/smilindave26/zdas/pkg/zdas"
)

// TestStore runs a conformance suite against a zdas.Store implementation.
// newStore must return an empty store; it is called once per subtest. The
// suite checks the contract documented on zdas.Store: entries survive a
// round trip with CreatedAt intact, consume returns the entry stored under
// the key it is given and no other, consume is single use for every kind of
// entry, including under concurrency, and a missing key is (nil, nil).
func TestStore(t *testing.T, newStore func(t *testing.T) zdas.Store) {
	t.Run("SessionRoundTrip", func(t *testing.T) {
		s := newStore(t)
		want := &zdas.AuthSession{
			TunnelerRedirectURI:         "https://tunneler/cb",
			TunnelerState:               "tstate",
			TunnelerCodeChallenge:       "challenge",
			TunnelerCodeChallengeMethod: "S256",
			DeviceInfo: &zdas.DeviceInfo{
				DeviceName: "laptop",
				Hostname:   "laptop.local",
				OS:         "darwin",
				Arch:       "arm64",
				OSRelease:  "25.5.0",
				OSVersion:  "26.5",
			},
			FallbackNonce:        "0123456789abcdef",
			EnrollmentMethod:     "enrollToCert",
			ClientType:           "cli",
			ZDASCodeVerifier:     "verifier",
			UpstreamProviderName: "keycloak",
			CreatedAt:            time.Now(),
		}
		requireAllSet(t, want)
		key := newKey(t)
		if err := s.CreateSession(t.Context(), key, clone(t, want)); err != nil {
			t.Fatalf("CreateSession: %v", err)
		}
		got, err := s.ConsumeSession(t.Context(), key)
		if err != nil {
			t.Fatalf("ConsumeSession: %v", err)
		}
		if got == nil {
			t.Fatal("ConsumeSession returned a miss for a fresh session")
		}
		checkCreatedAt(t, got.CreatedAt, want.CreatedAt)
		got.CreatedAt, want.CreatedAt = time.Time{}, time.Time{}
		checkJSONEqual(t, got, want)
	})

	t.Run("CodeRoundTrip", func(t *testing.T) {
		s := newStore(t)
		want := &zdas.AuthCode{
			Claims: map[string]any{
				"sub":                  "ext-1",
				"device_identity_name": "alice-laptop",
				"groups":               []any{"a", "b"},
				"level":                float64(3),
				"nested":               map[string]any{"k": "v"},
			},
			RedirectURI:         "https://tunneler/cb",
			CodeChallenge:       "challenge",
			CodeChallengeMethod: "S256",
			IsFallback:          true,
			CreatedAt:           time.Now(),
		}
		requireAllSet(t, want)
		key := newKey(t)
		if err := s.CreateCode(t.Context(), key, clone(t, want)); err != nil {
			t.Fatalf("CreateCode: %v", err)
		}
		got, err := s.ConsumeCode(t.Context(), key)
		if err != nil {
			t.Fatalf("ConsumeCode: %v", err)
		}
		if got == nil {
			t.Fatal("ConsumeCode returned a miss for a fresh code")
		}
		checkCreatedAt(t, got.CreatedAt, want.CreatedAt)
		got.CreatedAt, want.CreatedAt = time.Time{}, time.Time{}
		checkJSONEqual(t, got, want)
	})

	t.Run("PendingProvisionRoundTrip", func(t *testing.T) {
		s := newStore(t)
		want := &zdas.PendingProvision{
			TunnelerRedirectURI:         "https://tunneler/cb",
			TunnelerState:               "tstate",
			TunnelerCodeChallenge:       "challenge",
			TunnelerCodeChallengeMethod: "S256",
			IsFallback:                  true,
			FallbackNonce:               "0123456789abcdef",
			CreatedAt:                   time.Now(),
		}
		requireAllSet(t, want)
		key := newKey(t)
		if err := s.CreatePendingProvision(t.Context(), key, clone(t, want)); err != nil {
			t.Fatalf("CreatePendingProvision: %v", err)
		}
		got, err := s.ConsumePendingProvision(t.Context(), key)
		if err != nil {
			t.Fatalf("ConsumePendingProvision: %v", err)
		}
		if got == nil {
			t.Fatal("ConsumePendingProvision returned a miss for a fresh provision")
		}
		checkCreatedAt(t, got.CreatedAt, want.CreatedAt)
		got.CreatedAt, want.CreatedAt = time.Time{}, time.Time{}
		checkJSONEqual(t, got, want)
	})

	for _, k := range kinds {
		t.Run(k.name+"ConsumeIsSingleUse", func(t *testing.T) {
			s := newStore(t)
			key := newKey(t)
			if err := k.create(t.Context(), s, key, "a"); err != nil {
				t.Fatalf("create: %v", err)
			}
			if _, found, err := k.consume(t.Context(), s, key); err != nil || !found {
				t.Fatalf("first consume = %v, %v; want entry", found, err)
			}
			if _, found, err := k.consume(t.Context(), s, key); err != nil || found {
				t.Errorf("second consume = %v, %v; want miss", found, err)
			}
		})

		t.Run(k.name+"UnknownKeyIsMiss", func(t *testing.T) {
			s := newStore(t)
			if _, found, err := k.consume(t.Context(), s, newKey(t)); err != nil || found {
				t.Errorf("consume = %v, %v; want miss", found, err)
			}
		})

		// A store that ignores the key, such as a DELETE ... RETURNING
		// without its WHERE clause, passes every single-entry test but
		// hands one user's entry to another.
		t.Run(k.name+"ConsumeReturnsEntryForKey", func(t *testing.T) {
			s := newStore(t)
			a, b := newKey(t), newKey(t)
			for key, tag := range map[string]string{a: "a", b: "b"} {
				if err := k.create(t.Context(), s, key, tag); err != nil {
					t.Fatalf("create %s: %v", tag, err)
				}
			}
			if tag, found, err := k.consume(t.Context(), s, b); err != nil || !found || tag != "b" {
				t.Errorf("consume b = %q, %v, %v; want entry b", tag, found, err)
			}
			if tag, found, err := k.consume(t.Context(), s, a); err != nil || !found || tag != "a" {
				t.Errorf("consume a = %q, %v, %v; want entry a", tag, found, err)
			}
		})

		t.Run(k.name+"UnknownKeyLeavesOtherEntries", func(t *testing.T) {
			s := newStore(t)
			key := newKey(t)
			if err := k.create(t.Context(), s, key, "a"); err != nil {
				t.Fatalf("create: %v", err)
			}
			if _, found, err := k.consume(t.Context(), s, newKey(t)); err != nil || found {
				t.Errorf("consume unknown key = %v, %v; want miss", found, err)
			}
			if tag, found, err := k.consume(t.Context(), s, key); err != nil || !found || tag != "a" {
				t.Errorf("consume = %q, %v, %v; want the entry, untouched by the miss", tag, found, err)
			}
		})

		t.Run(k.name+"ConcurrentConsumeHasOneWinner", func(t *testing.T) {
			s := newStore(t)
			key := newKey(t)
			if err := k.create(t.Context(), s, key, "a"); err != nil {
				t.Fatalf("create: %v", err)
			}
			const workers = 16
			var (
				wg   sync.WaitGroup
				mu   sync.Mutex
				wins int
			)
			start := make(chan struct{})
			for range workers {
				wg.Go(func() {
					<-start
					_, found, err := k.consume(t.Context(), s, key)
					if err != nil {
						t.Errorf("consume: %v", err)
						return
					}
					if found {
						mu.Lock()
						wins++
						mu.Unlock()
					}
				})
			}
			close(start)
			wg.Wait()
			if wins != 1 {
				t.Errorf("%d concurrent consumes returned the entry; want exactly 1", wins)
			}
		})
	}
}

// kind drives the per-kind subtests through one kind of Store entry. create
// stores an entry carrying tag, and consume returns the tag of the entry it
// got, or found false on a miss.
type kind struct {
	name    string
	create  func(ctx context.Context, s zdas.Store, key, tag string) error
	consume func(ctx context.Context, s zdas.Store, key string) (tag string, found bool, err error)
}

var kinds = []kind{
	{
		name: "Session",
		create: func(ctx context.Context, s zdas.Store, key, tag string) error {
			return s.CreateSession(ctx, key, &zdas.AuthSession{TunnelerState: tag, DeviceInfo: &zdas.DeviceInfo{}, CreatedAt: time.Now()})
		},
		consume: func(ctx context.Context, s zdas.Store, key string) (string, bool, error) {
			v, err := s.ConsumeSession(ctx, key)
			if v == nil {
				return "", false, err
			}
			return v.TunnelerState, true, err
		},
	},
	{
		name: "Code",
		create: func(ctx context.Context, s zdas.Store, key, tag string) error {
			return s.CreateCode(ctx, key, &zdas.AuthCode{RedirectURI: tag, CreatedAt: time.Now()})
		},
		consume: func(ctx context.Context, s zdas.Store, key string) (string, bool, error) {
			v, err := s.ConsumeCode(ctx, key)
			if v == nil {
				return "", false, err
			}
			return v.RedirectURI, true, err
		},
	},
	{
		name: "PendingProvision",
		create: func(ctx context.Context, s zdas.Store, key, tag string) error {
			return s.CreatePendingProvision(ctx, key, &zdas.PendingProvision{TunnelerState: tag, CreatedAt: time.Now()})
		},
		consume: func(ctx context.Context, s zdas.Store, key string) (string, bool, error) {
			v, err := s.ConsumePendingProvision(ctx, key)
			if v == nil {
				return "", false, err
			}
			return v.TunnelerState, true, err
		},
	},
}

// newKey returns a key shaped like the ones zdas passes to a Store: 64
// lowercase hex characters.
func newKey(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return hex.EncodeToString(b)
}

// clone returns a deep copy of v so a store that keeps the pointer it was
// given cannot make a broken round trip look correct.
func clone[T any](t *testing.T, v *T) *T {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out := new(T)
	if err := json.Unmarshal(b, out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return out
}

// checkCreatedAt allows for a store that truncates timestamps to its own
// precision.
// requireAllSet fails the test if any exported field of the struct v points
// to, or of a struct it points to in turn, is zero. The round-trip subtests
// call it on the value they store, so a field added to an entry type
// without a value here fails the suite instead of going unchecked.
func requireAllSet(t *testing.T, v any) {
	t.Helper()
	var walk func(path string, rv reflect.Value)
	walk = func(path string, rv reflect.Value) {
		if rv.Kind() == reflect.Pointer && !rv.IsNil() {
			rv = rv.Elem()
		}
		if rv.Kind() != reflect.Struct || rv.Type() == reflect.TypeFor[time.Time]() {
			if rv.IsZero() {
				t.Fatalf("zdastest: %s is not set in the suite's test value; set it so the round trip covers it", path)
			}
			return
		}
		for i := range rv.NumField() {
			if f := rv.Type().Field(i); f.IsExported() {
				walk(path+"."+f.Name, rv.Field(i))
			}
		}
	}
	rv := reflect.ValueOf(v)
	walk(rv.Type().Elem().Name(), rv)
}

func checkCreatedAt(t *testing.T, got, want time.Time) {
	t.Helper()
	if d := got.Sub(want); d < -time.Second || d > time.Second {
		t.Errorf("CreatedAt = %v, want %v (within 1s)", got, want)
	}
}

// checkJSONEqual compares by JSON encoding, which is the representation a
// store is required to preserve.
func checkJSONEqual(t *testing.T, got, want any) {
	t.Helper()
	g, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal got: %v", err)
	}
	w, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal want: %v", err)
	}
	if string(g) != string(w) {
		t.Errorf("round trip mismatch:\n got  %s\n want %s", g, w)
	}
}
