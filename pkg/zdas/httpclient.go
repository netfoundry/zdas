package zdas

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// httpClient is the shared HTTP client for requests to upstream identity
// providers (OIDC discovery and keys, token exchanges, GitHub API calls,
// etc.), with a timeout and a cap on response size.
var httpClient = &http.Client{
	Timeout:   15 * time.Second,
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
	return fmt.Sprintf("token endpoint returned %d: %s", e.StatusCode, e.Body)
}

// oidcTokenExchange performs an OAuth2 token exchange POST with client and
// returns the parsed JSON response body. It is a package-level function
// variable so tests can replace the transport without starting real HTTP
// servers.
var oidcTokenExchange = defaultOIDCTokenExchange

func defaultOIDCTokenExchange(ctx context.Context, client *http.Client, tokenURL string, params url.Values) (map[string]interface{}, error) {
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

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parse token response: %w", err)
	}
	return result, nil
}
