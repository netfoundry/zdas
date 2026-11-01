package zdas

import (
	"fmt"
	"testing"
	"time"
)

func TestSessionCreateAndGet(t *testing.T) {
	store := NewSessionStore(10*time.Minute, 60*time.Second)
	defer store.Stop()

	sess := &AuthSession{
		TunnelerRedirectURI:  "https://tunneler/callback",
		DeviceInfo:           &DeviceInfo{DeviceName: "macbook"},
		UpstreamProviderName: "keycloak",
	}
	id, err := store.CreateSession(sess)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if id == "" {
		t.Fatal("session id is empty")
	}

	got := store.GetSession(id)
	if got == nil {
		t.Fatal("GetSession returned nil")
	}
	if got.DeviceInfo == nil || got.DeviceInfo.DeviceName != "macbook" {
		t.Errorf("DeviceInfo.DeviceName = %v", got.DeviceInfo)
	}
	if got.UpstreamProviderName != "keycloak" {
		t.Errorf("UpstreamProviderName = %q", got.UpstreamProviderName)
	}
}

func TestSessionConsumedOnGet(t *testing.T) {
	store := NewSessionStore(10*time.Minute, 60*time.Second)
	defer store.Stop()

	id, _ := store.CreateSession(&AuthSession{DeviceInfo: &DeviceInfo{DeviceName: "test"}})
	if store.GetSession(id) == nil {
		t.Fatal("first get should succeed")
	}
	if store.GetSession(id) != nil {
		t.Error("second get should return nil (consumed)")
	}
}

func TestSessionExpiration(t *testing.T) {
	store := NewSessionStore(1*time.Millisecond, 60*time.Second)
	defer store.Stop()

	id, _ := store.CreateSession(&AuthSession{DeviceInfo: &DeviceInfo{DeviceName: "test"}})
	time.Sleep(5 * time.Millisecond)

	if store.GetSession(id) != nil {
		t.Error("expired session should return nil")
	}
}

func TestCodeCreateAndConsume(t *testing.T) {
	store := NewSessionStore(10*time.Minute, 60*time.Second)
	defer store.Stop()

	ac := &AuthCode{
		Claims:      map[string]interface{}{"sub": "user1"},
		RedirectURI: "https://tunneler/callback",
	}
	code, err := store.CreateCode(ac)
	if err != nil {
		t.Fatalf("CreateCode: %v", err)
	}

	got := store.ConsumeCode(code)
	if got == nil {
		t.Fatal("ConsumeCode returned nil")
	}
	if got.Claims["sub"] != "user1" {
		t.Errorf("Claims[sub] = %v", got.Claims["sub"])
	}
}

func TestCodeSingleUse(t *testing.T) {
	store := NewSessionStore(10*time.Minute, 60*time.Second)
	defer store.Stop()

	code, _ := store.CreateCode(&AuthCode{Claims: map[string]interface{}{}})
	if store.ConsumeCode(code) == nil {
		t.Fatal("first consume should succeed")
	}
	if store.ConsumeCode(code) != nil {
		t.Error("second consume should return nil (already used)")
	}
}

func TestCodeExpiration(t *testing.T) {
	store := NewSessionStore(10*time.Minute, 1*time.Millisecond)
	defer store.Stop()

	code, _ := store.CreateCode(&AuthCode{Claims: map[string]interface{}{}})
	time.Sleep(5 * time.Millisecond)

	if store.ConsumeCode(code) != nil {
		t.Error("expired code should return nil")
	}
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

// TestSessionStoreFullEvictsOldest verifies that a full store makes room for
// a new session by evicting the oldest, so a flood of anonymous /authorize
// requests cannot lock out every user.
func TestSessionStoreFullEvictsOldest(t *testing.T) {
	s := NewSessionStore(10*time.Minute, time.Minute)
	t.Cleanup(s.Stop)
	start := time.Now().Add(-time.Minute)
	for i := range maxStoreEntries {
		s.putSession(fmt.Sprintf("s%d", i), &AuthSession{CreatedAt: start.Add(time.Duration(i) * time.Millisecond)})
	}

	id, err := s.CreateSession(&AuthSession{})
	if err != nil {
		t.Fatalf("CreateSession on a full store: %v", err)
	}
	if len(s.sessions) != maxStoreEntries {
		t.Errorf("store holds %d sessions, want %d", len(s.sessions), maxStoreEntries)
	}
	if _, ok := s.sessions["s0"]; ok {
		t.Error("oldest session was not evicted")
	}
	if _, ok := s.sessions["s1"]; !ok {
		t.Error("second-oldest session was evicted")
	}
	if s.GetSession(id) == nil {
		t.Error("new session not stored")
	}
}

func TestSessionStoreStopTwice(t *testing.T) {
	s := NewSessionStore(time.Minute, time.Minute)
	s.Stop()
	s.Stop()
}
