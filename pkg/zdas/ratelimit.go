package zdas

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const (
	// rateLimitIdle is how long a client's bucket outlives its last request.
	rateLimitIdle = 5 * time.Minute
	// rateLimitSweep is how often allow removes idle buckets.
	rateLimitSweep = time.Minute
	// maxRateLimitClients caps the number of buckets. Clients are keyed by
	// addresses they cannot choose, so reaching the cap takes that many real
	// addresses; until idle buckets expire, new clients are refused.
	maxRateLimitClients = 100_000
)

// ipRateLimiter tracks per-client token buckets for rate limiting the
// /authorize endpoint. A client is an IPv4 address or an IPv6 /64, since one
// IPv6 host usually controls a whole /64.
type ipRateLimiter struct {
	rate    rate.Limit
	burst   int
	trusted []netip.Prefix // proxies whose X-Forwarded-For entries are believed
	now     func() time.Time

	mu        sync.Mutex
	clients   map[netip.Prefix]*rateLimitEntry
	lastSweep time.Time
}

type rateLimitEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// newIPRateLimiter returns a limiter for cfg, or nil when rate limiting is
// disabled. Invalid trusted proxy entries are logged and skipped; Validate
// rejects them for configs that go through it.
func newIPRateLimiter(cfg RateLimitConfig, logger *slog.Logger) *ipRateLimiter {
	if cfg.AuthorizePerSecond <= 0 {
		return nil
	}
	burst := cfg.AuthorizeBurst
	if burst <= 0 {
		burst = max(int(cfg.AuthorizePerSecond)*2, 1)
	}
	var trusted []netip.Prefix
	for _, raw := range cfg.TrustedProxies {
		p, err := parseTrustedProxy(raw)
		if err != nil {
			logger.Error("ignoring invalid rate_limit.trusted_proxies entry", "entry", raw, "error", err)
			continue
		}
		trusted = append(trusted, p)
	}
	return &ipRateLimiter{
		rate:    rate.Limit(cfg.AuthorizePerSecond),
		burst:   burst,
		trusted: trusted,
		now:     time.Now,
		clients: make(map[netip.Prefix]*rateLimitEntry),
	}
}

// parseTrustedProxy parses a trusted proxy entry: an IP address or a CIDR
// prefix.
func parseTrustedProxy(raw string) (netip.Prefix, error) {
	if strings.Contains(raw, "/") {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return netip.Prefix{}, err
		}
		if p.Addr().Is4In6() {
			return netip.Prefix{}, fmt.Errorf("%q: use the IPv4 form", raw)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// allow reports whether the client r comes from is within its rate limit.
func (rl *ipRateLimiter) allow(r *http.Request) bool {
	key := clientKey(rl.clientAddr(r))
	now := rl.now()

	rl.mu.Lock()
	defer rl.mu.Unlock()
	if now.Sub(rl.lastSweep) >= rateLimitSweep {
		rl.removeIdle(now)
	}
	entry, ok := rl.clients[key]
	if !ok {
		if len(rl.clients) >= maxRateLimitClients {
			return false
		}
		entry = &rateLimitEntry{limiter: rate.NewLimiter(rl.rate, rl.burst)}
		rl.clients[key] = entry
	}
	entry.lastSeen = now
	return entry.limiter.AllowN(now, 1)
}

// removeIdle drops buckets unused for rateLimitIdle. rl.mu must be held.
func (rl *ipRateLimiter) removeIdle(now time.Time) {
	for key, entry := range rl.clients {
		if now.Sub(entry.lastSeen) > rateLimitIdle {
			delete(rl.clients, key)
		}
	}
	rl.lastSweep = now
}

// clientAddr returns the address r is counted against: the peer address,
// or, when the peer is a trusted proxy, the rightmost X-Forwarded-For entry
// that is not one. Entries left of that one were written by the client and
// are ignored. It returns the zero Addr when RemoteAddr is not an address,
// so such requests share one bucket.
func (rl *ipRateLimiter) clientAddr(r *http.Request) netip.Addr {
	addr, ok := parseRemoteAddr(r.RemoteAddr)
	if !ok || !rl.isTrusted(addr) {
		return addr
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		hop, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			// A trusted proxy wrote something unparsable, or none wrote
			// anything; count the request against the proxy.
			return addr
		}
		addr = hop.Unmap()
		if !rl.isTrusted(addr) {
			return addr
		}
	}
	return addr
}

func (rl *ipRateLimiter) isTrusted(a netip.Addr) bool {
	for _, p := range rl.trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// parseRemoteAddr parses an http.Request RemoteAddr, with or without a port.
func parseRemoteAddr(remote string) (netip.Addr, bool) {
	if ap, err := netip.ParseAddrPort(remote); err == nil {
		return ap.Addr().Unmap(), true
	}
	a, err := netip.ParseAddr(remote)
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

// clientKey returns the bucket key for a: the address itself for IPv4, its
// /64 for IPv6, and the zero Prefix for the zero Addr.
func clientKey(a netip.Addr) netip.Prefix {
	if a.Is4() {
		return netip.PrefixFrom(a, 32)
	}
	p, _ := a.Prefix(64)
	return p
}
