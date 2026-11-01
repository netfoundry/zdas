package zdas

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// testLimiter returns a limiter for cfg with a clock the test controls.
func testLimiter(t *testing.T, cfg RateLimitConfig) (*ipRateLimiter, *time.Time) {
	t.Helper()
	rl := newIPRateLimiter(cfg, slog.Default())
	if rl == nil {
		t.Fatal("limiter disabled")
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	rl.now = func() time.Time { return now }
	return rl, &now
}

// fromAddr returns a request whose peer is remote, with xff as its
// X-Forwarded-For headers.
func fromAddr(remote string, xff ...string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/authorize", nil)
	r.RemoteAddr = remote
	for _, v := range xff {
		r.Header.Add("X-Forwarded-For", v)
	}
	return r
}

func TestRateLimiterAllowsWithinLimit(t *testing.T) {
	rl, _ := testLimiter(t, RateLimitConfig{AuthorizePerSecond: 10, AuthorizeBurst: 10})
	for i := 0; i < 10; i++ {
		if !rl.allow(fromAddr("1.2.3.4:1")) {
			t.Fatalf("request %d should be allowed within burst", i)
		}
	}
}

func TestRateLimiterBlocksOverBurst(t *testing.T) {
	rl, now := testLimiter(t, RateLimitConfig{AuthorizePerSecond: 1, AuthorizeBurst: 2})
	rl.allow(fromAddr("1.2.3.4:1")) // 1 of 2
	rl.allow(fromAddr("1.2.3.4:2")) // 2 of 2, from another port
	if rl.allow(fromAddr("1.2.3.4:3")) {
		t.Error("third request should be blocked (burst=2)")
	}
	*now = now.Add(time.Second)
	if !rl.allow(fromAddr("1.2.3.4:1")) {
		t.Error("request after refill should be allowed")
	}
}

func TestRateLimiterPerClient(t *testing.T) {
	rl, _ := testLimiter(t, RateLimitConfig{AuthorizePerSecond: 1, AuthorizeBurst: 1})
	if !rl.allow(fromAddr("1.1.1.1:1")) {
		t.Error("first IP should be allowed")
	}
	if !rl.allow(fromAddr("2.2.2.2:1")) {
		t.Error("second IP should be allowed (separate bucket)")
	}
	if rl.allow(fromAddr("1.1.1.1:1")) {
		t.Error("first IP should be blocked (burst exhausted)")
	}
	if !rl.allow(fromAddr("[2001:db8:0:1::1]:1")) {
		t.Error("IPv6 client should be allowed")
	}
	if rl.allow(fromAddr("[2001:db8:0:1:ffff::2]:1")) {
		t.Error("another address in the same IPv6 /64 should share its bucket")
	}
	if !rl.allow(fromAddr("[2001:db8:0:2::1]:1")) {
		t.Error("an address in another /64 should have its own bucket")
	}
}

// TestRateLimiterIgnoresUntrustedXFF checks that a client cannot get a new
// bucket per request by sending its own X-Forwarded-For.
func TestRateLimiterIgnoresUntrustedXFF(t *testing.T) {
	rl, _ := testLimiter(t, RateLimitConfig{AuthorizePerSecond: 1, AuthorizeBurst: 1})
	allowed := 0
	for i := 0; i < 50; i++ {
		if rl.allow(fromAddr("192.0.2.1:1", fmt.Sprintf("10.0.%d.%d", i/256, i%256))) {
			allowed++
		}
	}
	if allowed != 1 {
		t.Errorf("allowed %d of 50 requests with rotating X-Forwarded-For, want 1", allowed)
	}
	if n := rl.lru.Len(); n != 1 {
		t.Errorf("limiter holds %d buckets, want 1", n)
	}
}

func TestRateLimiterClientAddr(t *testing.T) {
	rl, _ := testLimiter(t, RateLimitConfig{
		AuthorizePerSecond: 1,
		TrustedProxies:     []string{"10.0.0.0/8", "2001:db8::1"},
	})
	cases := []struct {
		name   string
		remote string
		xff    []string
		want   string
	}{
		{"untrusted peer", "192.0.2.1:1", nil, "192.0.2.1"},
		{"untrusted peer ignores xff", "192.0.2.1:1", []string{"198.51.100.7"}, "192.0.2.1"},
		{"no port", "192.0.2.1", nil, "192.0.2.1"},
		{"ipv4-mapped peer", "[::ffff:192.0.2.1]:1", nil, "192.0.2.1"},
		{"not an address", "@", nil, "invalid IP"},
		{"trusted proxy", "10.0.0.1:1", []string{"198.51.100.7"}, "198.51.100.7"},
		{"trusted ipv6 proxy", "[2001:db8::1]:1", []string{"198.51.100.7"}, "198.51.100.7"},
		{"client-written entries ignored", "10.0.0.1:1", []string{"203.0.113.9, 198.51.100.7"}, "198.51.100.7"},
		{"trusted hops skipped", "10.0.0.1:1", []string{"198.51.100.7, 10.0.0.2"}, "198.51.100.7"},
		{"several headers", "10.0.0.1:1", []string{"203.0.113.9", "198.51.100.7"}, "198.51.100.7"},
		{"trusted proxy without xff", "10.0.0.1:1", nil, "10.0.0.1"},
		{"garbage from trusted hop", "10.0.0.1:1", []string{"198.51.100.7, bogus"}, "10.0.0.1"},
		{"all hops trusted", "10.0.0.1:1", []string{"10.0.0.3, 10.0.0.2"}, "10.0.0.3"},
		{"hop with port", "10.0.0.1:1", []string{"198.51.100.7:4567"}, "198.51.100.7"},
		{"bracketed ipv6 hop with port", "10.0.0.1:1", []string{"[2001:db8::7]:443"}, "2001:db8::7"},
		{"bracketed ipv6 hop", "10.0.0.1:1", []string{"[2001:db8::7]"}, "2001:db8::7"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := rl.clientAddr(fromAddr(tc.remote, tc.xff...)).String(); got != tc.want {
				t.Errorf("clientAddr = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestRateLimiterRemovesIdleClients(t *testing.T) {
	rl, now := testLimiter(t, RateLimitConfig{AuthorizePerSecond: 1, AuthorizeBurst: 1})
	rl.allow(fromAddr("192.0.2.1:1"))
	*now = now.Add(rateLimitIdle + time.Second)
	rl.allow(fromAddr("192.0.2.2:1"))
	if _, ok := rl.buckets[clientKey(netip.MustParseAddr("192.0.2.1"))]; ok {
		t.Error("idle client was not removed")
	}
	if n := rl.lru.Len(); n != 1 {
		t.Errorf("limiter holds %d buckets, want 1", n)
	}
}

// TestRateLimiterEvictsAtCap verifies that a full limiter makes room for a
// new client by evicting the least recently used bucket, so that filling it
// with addresses does not lock out everyone else.
func TestRateLimiterEvictsAtCap(t *testing.T) {
	rl, _ := testLimiter(t, RateLimitConfig{AuthorizePerSecond: 1, AuthorizeBurst: 1})
	for i := range maxRateLimitBuckets {
		rl.allow(fromAddr(netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}), 1).String()))
	}
	if n := rl.lru.Len(); n != maxRateLimitBuckets {
		t.Fatalf("limiter holds %d buckets, want %d", n, maxRateLimitBuckets)
	}

	// The first client comes back, so the second is now the least
	// recently used.
	rl.allow(fromAddr("10.0.0.0:1"))
	if !rl.allow(fromAddr("192.0.2.2:1")) {
		t.Error("new client refused with the limiter full")
	}
	if n := rl.lru.Len(); n != maxRateLimitBuckets {
		t.Errorf("limiter holds %d buckets, want %d", n, maxRateLimitBuckets)
	}
	if _, ok := rl.buckets[clientKey(netip.MustParseAddr("10.0.0.1"))]; ok {
		t.Error("least recently used bucket was not evicted")
	}
	if _, ok := rl.buckets[clientKey(netip.MustParseAddr("10.0.0.0"))]; !ok {
		t.Error("recently used bucket was evicted")
	}
}

// TestRateLimiterSiteLimit verifies that cycling through the /64s of one
// IPv6 /48 runs into the /48's limit rather than getting a fresh bucket
// each time.
func TestRateLimiterSiteLimit(t *testing.T) {
	rl, _ := testLimiter(t, RateLimitConfig{AuthorizePerSecond: 1, AuthorizeBurst: 1})
	allowed := 0
	for i := range 2 * siteRateMultiplier {
		if rl.allow(fromAddr(fmt.Sprintf("[2001:db8:1:%x::1]:1", i))) {
			allowed++
		}
	}
	if allowed != siteRateMultiplier {
		t.Errorf("allowed %d requests from distinct /64s of one /48, want %d", allowed, siteRateMultiplier)
	}
	if !rl.allow(fromAddr("[2001:db8:2::1]:1")) {
		t.Error("a client in another /48 was refused")
	}
}

// TestRateLimiterLogsUntrustedXFFOnce verifies that X-Forwarded-For from an
// unlisted peer is reported, once, since behind an unlisted proxy every
// client shares one bucket.
func TestRateLimiterLogsUntrustedXFFOnce(t *testing.T) {
	var buf bytes.Buffer
	rl := newIPRateLimiter(RateLimitConfig{AuthorizePerSecond: 1}, slog.New(slog.NewTextHandler(&buf, nil)))
	rl.allow(fromAddr("192.0.2.1:1"))
	if buf.Len() != 0 {
		t.Fatalf("logged without X-Forwarded-For: %s", buf.String())
	}
	rl.allow(fromAddr("192.0.2.1:1", "198.51.100.7"))
	rl.allow(fromAddr("192.0.2.1:1", "198.51.100.8"))
	if n := strings.Count(buf.String(), "trusted_proxies"); n != 1 {
		t.Errorf("logged %d times, want once: %s", n, buf.String())
	}
}

func TestParseTrustedProxy(t *testing.T) {
	cases := []struct {
		raw     string
		want    string
		wantErr bool
	}{
		{"10.0.0.1", "10.0.0.1/32", false},
		{"10.1.2.3/8", "10.0.0.0/8", false},
		{"::ffff:10.0.0.1", "10.0.0.1/32", false},
		{"2001:db8::/32", "2001:db8::/32", false},
		{"::ffff:10.0.0.0/104", "", true},
		{"10.0.0.1/33", "", true},
		{"proxy.example.com", "", true},
		{"", "", true},
	}
	for _, tc := range cases {
		got, err := parseTrustedProxy(tc.raw)
		if (err != nil) != tc.wantErr {
			t.Errorf("parseTrustedProxy(%q) err = %v, wantErr %v", tc.raw, err, tc.wantErr)
			continue
		}
		if err == nil && got.String() != tc.want {
			t.Errorf("parseTrustedProxy(%q) = %s, want %s", tc.raw, got, tc.want)
		}
	}
}

func TestRateLimiterDisabledByDefault(t *testing.T) {
	// Config with zero rate limit - handler should not rate limit.
	h, _ := setupHandlers(t)
	mux := h.mux()
	_, challenge := generateTestPKCE(t)

	for i := 0; i < 50; i++ {
		reqURL := "/authorize?redirect_uri=http://localhost:20314/auth/callback&response_type=code&state=s1" +
			"&code_challenge=" + challenge + "&code_challenge_method=S256&device_name=laptop"
		req := httptest.NewRequest(http.MethodGet, reqURL, nil)
		req.RemoteAddr = "1.2.3.4:12345"
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code == http.StatusTooManyRequests {
			t.Fatalf("request %d got 429, but rate limiting should be disabled", i)
		}
	}
}

func TestRateLimiterEnabled(t *testing.T) {
	ks, _ := GenerateKeySet()
	reg := NewProviderRegistry()
	_ = reg.Register(&stubProvider{name: "test-idp", issuer: "https://test-idp"})
	store := newMemStore(10*time.Minute, 60*time.Second, storeSweepInterval)
	t.Cleanup(store.stop)

	cfg := Config{
		ExternalURL: "https://zdas.example.com",
		Claims:      defaultClaimsConfig(),
		Token:       TokenConfig{Issuer: "https://zdas.example.com", Audience: "ziti-enroll", Expiry: 5 * time.Minute},
		RateLimit:   RateLimitConfig{AuthorizePerSecond: 1, AuthorizeBurst: 2},
	}
	h := newTestEndpoints(cfg, ks, reg, store, nil)
	mux := h.mux()

	_, challenge := generateTestPKCE(t)
	reqURL := "/authorize?redirect_uri=http://localhost:20314/auth/callback&response_type=code&state=s1" +
		"&code_challenge=" + challenge + "&code_challenge_method=S256&device_name=laptop"

	// First two requests should succeed (burst=2).
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, reqURL, nil)
		req.RemoteAddr = "1.2.3.4:12345"
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code == http.StatusTooManyRequests {
			t.Fatalf("request %d should be allowed (within burst)", i)
		}
	}

	// Third request should be rate limited.
	req := httptest.NewRequest(http.MethodGet, reqURL, nil)
	req.RemoteAddr = "1.2.3.4:12345"
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("third request: status = %d, want 429", w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Error("429 response missing Retry-After header")
	}

	// Different IP should still be allowed.
	req = httptest.NewRequest(http.MethodGet, reqURL, nil)
	req.RemoteAddr = "5.6.7.8:12345"
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code == http.StatusTooManyRequests {
		t.Error("different IP should not be rate limited")
	}
}

func TestTrustedProxiesValidation(t *testing.T) {
	cfg := &Config{
		ExternalURL: "https://das.example.com",
		Controller:  ControllerConfig{APIURL: "https://c"},
		RateLimit:   RateLimitConfig{AuthorizePerSecond: 1, TrustedProxies: []string{"10.0.0.0/8", "proxy.internal"}},
	}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "trusted_proxies[1]") {
		t.Errorf("Validate = %v, want an error for trusted_proxies[1]", err)
	}

	// A config that skipped Validate still gets a limiter, trusting only the
	// valid entries.
	rl := newIPRateLimiter(cfg.RateLimit, slog.Default())
	if len(rl.trusted) != 1 || rl.trusted[0].String() != "10.0.0.0/8" {
		t.Errorf("trusted = %v, want [10.0.0.0/8]", rl.trusted)
	}
}
