package zdas

import (
	"container/list"
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
	// rateLimitIdle is how long a bucket outlives its last request.
	rateLimitIdle = 5 * time.Minute
	// maxRateLimitBuckets caps the number of buckets. At the cap the least
	// recently used bucket is evicted, so a flood of new addresses cannot
	// lock out other clients; the per-site buckets keep those addresses
	// from getting around the limit.
	maxRateLimitBuckets = 100_000
	// siteRateMultiplier is how many clients' worth of requests one IPv6
	// /48 may make in total. A /48 holds 65,536 /64s, and someone with one
	// could otherwise cycle through them for a fresh bucket each time.
	siteRateMultiplier = 16
)

// ipRateLimiter tracks token buckets for rate limiting the /authorize
// endpoint. A client is an IPv4 address or an IPv6 /64, since one IPv6 host
// usually controls a whole /64. An IPv6 client is also counted against its
// /48, with siteRateMultiplier times the client limit.
type ipRateLimiter struct {
	rate    rate.Limit
	burst   int
	trusted []netip.Prefix // proxies whose X-Forwarded-For entries are believed
	now     func() time.Time
	logger  *slog.Logger

	// untrustedXFF logs, once, X-Forwarded-For from a peer that is not a
	// trusted proxy: behind an unlisted proxy every client shares one
	// bucket, which is easy to miss.
	untrustedXFF sync.Once

	mu      sync.Mutex
	buckets map[netip.Prefix]*list.Element // of *rateLimitBucket
	lru     *list.List                     // most recently used at the front
}

type rateLimitBucket struct {
	key      netip.Prefix
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
		logger:  logger,
		buckets: make(map[netip.Prefix]*list.Element),
		lru:     list.New(),
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

// allow reports whether the client r comes from is within its rate limit,
// and for IPv6, whether its /48 is within the site limit.
func (rl *ipRateLimiter) allow(r *http.Request) bool {
	addr := rl.clientAddr(r)
	now := rl.now()

	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.removeIdle(now)
	if site, ok := siteKey(addr); ok {
		if !rl.bucket(site, now, siteRateMultiplier).AllowN(now, 1) {
			return false
		}
	}
	return rl.bucket(clientKey(addr), now, 1).AllowN(now, 1)
}

// bucket returns the limiter for key, creating it with multiplier times the
// configured rate and burst, and marks it most recently used. At the cap it
// evicts the least recently used bucket to make room. rl.mu must be held.
func (rl *ipRateLimiter) bucket(key netip.Prefix, now time.Time, multiplier int) *rate.Limiter {
	if e, ok := rl.buckets[key]; ok {
		b := e.Value.(*rateLimitBucket)
		b.lastSeen = now
		rl.lru.MoveToFront(e)
		return b.limiter
	}
	if rl.lru.Len() >= maxRateLimitBuckets {
		oldest := rl.lru.Back()
		delete(rl.buckets, oldest.Value.(*rateLimitBucket).key)
		rl.lru.Remove(oldest)
	}
	b := &rateLimitBucket{
		key:      key,
		limiter:  rate.NewLimiter(rl.rate*rate.Limit(multiplier), rl.burst*multiplier),
		lastSeen: now,
	}
	rl.buckets[key] = rl.lru.PushFront(b)
	return b.limiter
}

// removeIdle drops buckets unused for rateLimitIdle, oldest first. rl.mu
// must be held.
func (rl *ipRateLimiter) removeIdle(now time.Time) {
	for e := rl.lru.Back(); e != nil; e = rl.lru.Back() {
		b := e.Value.(*rateLimitBucket)
		if now.Sub(b.lastSeen) <= rateLimitIdle {
			return
		}
		delete(rl.buckets, b.key)
		rl.lru.Remove(e)
	}
}

// clientAddr returns the address r is counted against: the peer address,
// or, when the peer is a trusted proxy, the rightmost X-Forwarded-For entry
// that is not one. Entries left of that one were written by the client and
// are ignored. It returns the zero Addr when RemoteAddr is not an address,
// so such requests share one bucket.
func (rl *ipRateLimiter) clientAddr(r *http.Request) netip.Addr {
	addr, ok := parseHostAddr(r.RemoteAddr)
	if !ok {
		return netip.Addr{}
	}
	xff := r.Header.Values("X-Forwarded-For")
	if !rl.isTrusted(addr) {
		if len(xff) > 0 {
			rl.untrustedXFF.Do(func() {
				rl.logger.Warn("ignoring X-Forwarded-For from a peer that is not a trusted proxy; "+
					"if ZDAS is behind a proxy, list it in rate_limit.trusted_proxies, or every client shares its bucket",
					"peer", addr)
			})
		}
		return addr
	}
	hops := strings.Split(strings.Join(xff, ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		hop, ok := parseHostAddr(strings.TrimSpace(hops[i]))
		if !ok {
			// A trusted proxy wrote something unparsable, or none wrote
			// anything; count the request against the proxy.
			return addr
		}
		addr = hop
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

// parseHostAddr parses an address as RemoteAddr or an X-Forwarded-For entry
// gives it: bare ("192.0.2.1", "2001:db8::1"), with a port ("192.0.2.1:80",
// "[2001:db8::1]:80"), or bracketed without one ("[2001:db8::1]").
func parseHostAddr(s string) (netip.Addr, bool) {
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Unmap(), true
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap(), true
	}
	if inner, ok := strings.CutPrefix(s, "["); ok {
		if inner, ok := strings.CutSuffix(inner, "]"); ok {
			if a, err := netip.ParseAddr(inner); err == nil {
				return a.Unmap(), true
			}
		}
	}
	return netip.Addr{}, false
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

// siteKey returns the /48 an IPv6 address belongs to, and false for any
// other address.
func siteKey(a netip.Addr) (netip.Prefix, bool) {
	if !a.Is6() {
		return netip.Prefix{}, false
	}
	p, err := a.Prefix(48)
	return p, err == nil
}
