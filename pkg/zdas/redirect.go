package zdas

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strings"
)

// parseHTTPURL parses raw as an absolute http(s) URL with a host. It
// doesn't ask for a canonical form: IdPs differ on whether an issuer ends in
// a slash, and an issuer must match byte for byte, so Validate checks
// configured URLs with it and leaves them as they are. parseRedirectURI
// builds on it.
//
// Its errors don't quote raw, which may hold a password; the caller names
// the setting.
func parseHTTPURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	switch {
	case !strings.Contains(raw, "://"):
		// Without it, "host:1280" parses with "host" as the scheme, and
		// "10.0.0.1:1280" doesn't parse.
		return nil, errors.New("missing http:// or https://")
	case err != nil:
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err // *url.Error quotes raw
		}
		return nil, err
	case u.Scheme != "http" && u.Scheme != "https":
		return nil, fmt.Errorf("scheme must be http or https, not %q", u.Scheme)
	case u.Hostname() == "":
		return nil, errors.New("host is required")
	}
	return u, nil
}

// parseRedirectURI parses raw as an absolute http(s) URL with a host and no
// userinfo. It applies to request redirect_uri values and to
// AllowedRedirectURIs entries alike.
func parseRedirectURI(raw string) (*url.URL, error) {
	u, err := parseHTTPURL(raw)
	if err != nil {
		return nil, err
	}
	if u.User != nil {
		return nil, errors.New("userinfo is not allowed")
	}
	return u, nil
}

// parseAllowList parses AllowedRedirectURIs. It returns nil for an empty
// list, which keeps the loopback default, and otherwise a non-nil slice of
// the entries that parse, so that a list whose entries are all invalid
// allows nothing rather than falling back to the default. Invalid entries
// are logged; Config.Validate rejects them for configs that go through it.
func parseAllowList(raw []string, logger *slog.Logger) []*url.URL {
	if len(raw) == 0 {
		return nil
	}
	entries := make([]*url.URL, 0, len(raw))
	for i, r := range raw {
		u, err := parseRedirectURI(r)
		if err != nil {
			// By index, since the entry may hold a password.
			logger.Error("ignoring invalid allowed_redirect_uris entry", "index", i, "error", err)
			continue
		}
		entries = append(entries, u)
	}
	return entries
}

// redirectAllowed reports whether a code may be sent to u, which must come
// from parseRedirectURI, under allowList from parseAllowList. With a nil
// list, only loopback callbacks are accepted (RFC 8252 section 7.3), which
// is all a tunneler sends.
func redirectAllowed(u *url.URL, allowList []*url.URL) bool {
	if allowList == nil {
		return isLoopbackHost(u.Hostname())
	}
	for _, entry := range allowList {
		if redirectMatches(u, entry) {
			return true
		}
	}
	return false
}

// redirectMatches compares u with entry. For a host other than loopback,
// scheme, host, port and path must match exactly, and the query too when
// entry has one (RFC 9700 section 2.1). A loopback entry matches any port
// when it has none, since loopback callbacks listen on an ephemeral one
// (RFC 8252 section 7.3), and any path when it has none.
func redirectMatches(u, entry *url.URL) bool {
	if u.Scheme != entry.Scheme || !strings.EqualFold(u.Hostname(), entry.Hostname()) {
		return false
	}
	if !isLoopbackHost(entry.Hostname()) {
		return effectivePort(u) == effectivePort(entry) && u.Path == entry.Path &&
			(entry.RawQuery == "" || u.RawQuery == entry.RawQuery)
	}
	if entry.Port() != "" && effectivePort(u) != effectivePort(entry) {
		return false
	}
	return entry.Path == "" || entry.Path == "/" || u.Path == entry.Path
}

// effectivePort returns u's port, or the default port for its scheme.
func effectivePort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}

// isLoopbackHost reports whether host is "localhost" or a loopback IP
// literal. Shorthand and non-canonical forms ("127.1", "localhost.", hex)
// are rejected rather than resolved.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// withQuery returns rawURL with v added to its query string, after any query
// it already has and before any fragment.
func withQuery(rawURL string, v url.Values) string {
	base, fragment, hasFragment := strings.Cut(rawURL, "#")
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	out := base + sep + v.Encode()
	if hasFragment {
		out += "#" + fragment
	}
	return out
}
