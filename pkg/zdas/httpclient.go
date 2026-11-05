package zdas

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// outboundTimeout bounds each request ZDAS makes to the controller or an
// upstream identity provider.
const outboundTimeout = 15 * time.Second

// httpClient is the shared HTTP client for requests to upstream identity
// providers (OIDC discovery and keys, token exchanges, GitHub API calls,
// etc.), with a timeout and a cap on response size.
var httpClient = &http.Client{
	Timeout:   outboundTimeout,
	Transport: limitedBodyTransport{base: http.DefaultTransport},
}

// limitedBodyTransport truncates response bodies at maxResponseBytes, for
// readers such as go-oidc's that read a whole body without a cap of their
// own.
type limitedBodyTransport struct {
	base http.RoundTripper
}

func (t limitedBodyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	resp.Body = limitedBody{Reader: io.LimitReader(resp.Body, maxResponseBytes), Closer: resp.Body}
	return resp, nil
}

type limitedBody struct {
	io.Reader
	io.Closer
}

// PublicHTTPClient returns a client for WithUpstreamHTTPClient, for an
// embedder whose upstream issuers are chosen by someone it does not fully
// trust, such as a tenant admin. It connects only to public addresses:
// loopback, private, link-local, shared (100.64.0.0/10) and other
// non-public ranges are refused. The check is on the address actually
// dialed, so a host name that resolves to one is refused too. It follows no
// redirects and ignores proxy settings from the environment, since a proxy
// would connect on its behalf. It has ZDAS's own timeout and response size
// cap. An issuer on a private network needs a client of your own instead.
func PublicHTTPClient() *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second, Control: refuseNonPublic}
	t := baseTransport()
	t.Proxy = nil
	t.DialContext = dialer.DialContext
	return &http.Client{
		Timeout:       outboundTimeout,
		Transport:     limitedBodyTransport{base: t},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// nonPublicPrefixes are ranges isPublicAddr refuses beyond those netip
// classifies: "this network", shared address space (RFC 6598), IETF
// protocol assignments, benchmarking, reserved, and the NAT64 prefix, which
// can reach any IPv4 address.
var nonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"),
}

// isPublicAddr reports whether a is a public unicast address.
func isPublicAddr(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsGlobalUnicast() || a.IsPrivate() {
		return false
	}
	for _, p := range nonPublicPrefixes {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

// refuseNonPublic is a net.Dialer Control function that fails a connection
// to an address that is not public.
func refuseNonPublic(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("refusing to connect to %s: %w", address, err)
	}
	if !isPublicAddr(ap.Addr()) {
		return fmt.Errorf("refusing to connect to non-public address %s", ap.Addr())
	}
	return nil
}

// tlsClient returns a client with outboundTimeout whose transport is
// baseTransport's, keeping its proxy settings, dial and handshake timeouts
// and HTTP/2, with tlsCfg in place of its TLS config.
func tlsClient(tlsCfg *tls.Config) *http.Client {
	t := baseTransport()
	t.TLSClientConfig = tlsCfg
	return &http.Client{Timeout: outboundTimeout, Transport: t}
}

// boundedClient returns a copy of c with ZDAS's response size cap on its
// transport, and with outboundTimeout when c has no timeout, so that a
// client ZDAS did not build gets the limits its own client has.
func boundedClient(c *http.Client) *http.Client {
	bc := *c
	base := c.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	bc.Transport = limitedBodyTransport{base: base}
	if bc.Timeout == 0 {
		bc.Timeout = outboundTimeout
	}
	return &bc
}

// baseTransport returns a copy of http.DefaultTransport to configure. An
// embedder may have replaced that with another RoundTripper, such as one
// that adds tracing; ZDAS needs an *http.Transport to set its own dialer and
// TLS config, so it then starts from the settings Go's default transport
// has, without the replacement.
func baseTransport() *http.Transport {
	if t, ok := http.DefaultTransport.(*http.Transport); ok {
		return t.Clone()
	}
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
}

// maxResponseBytes is the cap on outbound response body reads. Prevents a
// compromised upstream or MITM from exhausting memory. 2 MB is generous for
// any JSON API response ZDAS consumes.
const maxResponseBytes = 2 << 20

// readResponseBody reads a response body with a size cap to prevent memory
// exhaustion from oversized upstream responses.
func readResponseBody(resp *http.Response) ([]byte, error) {
	return io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
}

// TokenError reports a token endpoint that answered with a status other than
// 200. Body is the endpoint's reply, which an embedder may not want to show
// to whoever chose the endpoint; StatusCode alone is safe to show.
type TokenError struct {
	StatusCode int
	Body       []byte
}

func (e *TokenError) Error() string {
	return fmt.Sprintf("token endpoint returned %d: %s", e.StatusCode, truncateBody(e.Body))
}

// maxErrorBody is how much of an unexpected response body an error message
// quotes, so that a large reply does not end up whole in the logs.
const maxErrorBody = 512

// truncateBody returns body for an error message, cut to maxErrorBody bytes.
func truncateBody(body []byte) string {
	if len(body) <= maxErrorBody {
		return string(body)
	}
	return string(body[:maxErrorBody]) + "...(truncated)"
}

// oidcTokenExchange performs an OAuth2 token exchange POST with client and
// returns the parsed JSON response body.
func oidcTokenExchange(ctx context.Context, client *http.Client, tokenURL string, params url.Values) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(params.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := readResponseBody(resp)
	if err != nil {
		return nil, fmt.Errorf("read token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &TokenError{StatusCode: resp.StatusCode, Body: body}
	}

	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parse token response: %w", err)
	}
	return result, nil
}
