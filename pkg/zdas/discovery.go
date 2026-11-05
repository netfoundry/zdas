package zdas

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// providerSetupTimeout bounds building one OIDC provider, which fetches
	// the issuer's discovery document.
	providerSetupTimeout = 30 * time.Second
	// signerPageSize is the page size requested from the controller, the
	// largest it allows on public list endpoints.
	signerPageSize = 500
	// maxSignerPages bounds the pages fetched per poll, so that a
	// controller reporting a wrong total cannot keep a poll going forever.
	maxSignerPages = 20
	// maxParallelProviderBuilds bounds how many issuers a poll contacts at
	// once.
	maxParallelProviderBuilds = 16
)

// signerDiscovery polls the Ziti controller's public ext-jwt-signers endpoint and
// builds OIDCProvider instances from signers that have enrollment enabled
// (enrollToCertEnabled or enrollToTokenEnabled).
// It merges them into the ProviderRegistry alongside any configured providers.
type signerDiscovery struct {
	cfg             ControllerConfig
	registry        *ProviderRegistry
	configuredNames map[string]struct{}
	client          *http.Client // reaches the controller
	upstreamClient  *http.Client // reaches discovered issuers; nil uses the defaults
	setupTimeout    time.Duration
	pageSize        int
	logger          *slog.Logger

	pollMu sync.Mutex               // serializes polls
	built  map[string]builtProvider // by name, from the last poll; guarded by pollMu

	// selfToToken is whether ZDAS's own signer allows enroll-to-token, as
	// of the last poll.
	selfToToken atomic.Bool

	mu                sync.Mutex
	cancel            context.CancelFunc
	stopped           chan struct{}
	networkJWTsBody   []byte // cached response from GET /network-jwts
	extJWTSignersBody []byte // cached response from GET /edge/client/v1/external-jwt-signers
}

// newSignerDiscovery creates a signerDiscovery poller that reaches the
// controller with client and discovered issuers with upstream, or with
// ZDAS's own client when upstream is nil. configuredNames is the set of
// provider names that come from the ZDAS config (GitHub, etc.) and must not
// collide with discovered signers.
func newSignerDiscovery(cfg ControllerConfig, client, upstream *http.Client, registry *ProviderRegistry, configuredNames map[string]struct{}, logger *slog.Logger) *signerDiscovery {
	return &signerDiscovery{
		cfg:             cfg,
		registry:        registry,
		configuredNames: configuredNames,
		client:          client,
		upstreamClient:  upstream,
		setupTimeout:    providerSetupTimeout,
		pageSize:        signerPageSize,
		logger:          logger,
	}
}

// start begins periodic polling at the configured PollInterval. It runs the
// first poll synchronously and returns an error if it fails. Subsequent poll
// failures are logged but non-fatal.
func (d *signerDiscovery) start(ctx context.Context) error {
	if err := d.poll(ctx); err != nil {
		return fmt.Errorf("initial discovery poll: %w", err)
	}
	if d.cfg.PollInterval <= 0 {
		return nil
	}

	pollCtx, cancel := context.WithCancel(ctx)
	stopped := make(chan struct{})
	d.mu.Lock()
	d.cancel, d.stopped = cancel, stopped
	d.mu.Unlock()

	go d.loop(pollCtx, stopped)
	return nil
}

// stop cancels the background poll loop and waits for it to exit.
func (d *signerDiscovery) stop() {
	d.mu.Lock()
	cancel := d.cancel
	stopped := d.stopped
	d.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if stopped != nil {
		<-stopped
	}
}

// loop polls every PollInterval until ctx is done, then closes stopped.
func (d *signerDiscovery) loop(ctx context.Context, stopped chan<- struct{}) {
	defer close(stopped)
	ticker := time.NewTicker(d.cfg.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := d.poll(ctx); err != nil {
				d.logger.Warn("discovery poll failed, keeping previous providers", "error", err)
			}
		}
	}
}

// signerPage is one page of the controller's response to
// GET /edge/client/v1/external-jwt-signers. Entries are kept as sent so that
// a merged list re-serves every field.
type signerPage struct {
	Data []json.RawMessage `json:"data"`
	Meta struct {
		Pagination signerPagination `json:"pagination"`
	} `json:"meta"`
}

type signerPagination struct {
	Limit      int `json:"limit"`
	Offset     int `json:"offset"`
	TotalCount int `json:"totalCount"`
}

// signerEntry is the part of a signer ZDAS uses. The client API does not
// send the signer's issuer. Tunnelers treat externalAuthUrl as the IdP's
// OIDC issuer and read its discovery document from there, so ZDAS does too.
type signerEntry struct {
	Name                 string   `json:"name"`
	ClientID             string   `json:"clientId"`
	ExternalAuthURL      string   `json:"externalAuthUrl"`
	Scopes               []string `json:"scopes"`
	Audience             string   `json:"audience"`
	EnrollToCertEnabled  bool     `json:"enrollToCertEnabled"`
	EnrollToTokenEnabled bool     `json:"enrollToTokenEnabled"`
}

// equal reports whether s and o have the same settings.
func (s signerEntry) equal(o signerEntry) bool {
	return s.Name == o.Name && s.ClientID == o.ClientID && s.ExternalAuthURL == o.ExternalAuthURL &&
		slices.Equal(s.Scopes, o.Scopes) && s.Audience == o.Audience &&
		s.EnrollToCertEnabled == o.EnrollToCertEnabled && s.EnrollToTokenEnabled == o.EnrollToTokenEnabled
}

// cachedNetworkJWTs returns the cached response from the controller's
// /network-jwts endpoint, or nil if not yet fetched.
func (d *signerDiscovery) cachedNetworkJWTs() []byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.networkJWTsBody
}

// cachedExtJWTSigners returns the cached response from the controller's
// /edge/client/v1/external-jwt-signers endpoint, or nil if not yet fetched.
func (d *signerDiscovery) cachedExtJWTSigners() []byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.extJWTSignersBody
}

func (d *signerDiscovery) poll(ctx context.Context) error {
	d.pollMu.Lock()
	defer d.pollMu.Unlock()

	rawSigners, signers, err := d.fetchSigners(ctx)
	if err != nil {
		return err
	}
	selfToToken := false
	for _, s := range signers {
		if d.isSelf(s) && s.EnrollToTokenEnabled {
			selfToToken = true
		}
	}
	d.selfToToken.Store(selfToToken)

	// Fetch network JWTs alongside signers. Failure is non-fatal - keep
	// the stale cache and log a warning.
	if body, err := d.fetchNetworkJWTs(ctx); err != nil {
		d.logger.Warn("failed to fetch network JWTs, keeping stale cache", "error", err)
	} else {
		d.mu.Lock()
		d.networkJWTsBody = body
		d.mu.Unlock()
	}

	d.mu.Lock()
	d.extJWTSignersBody = rawSigners
	d.mu.Unlock()

	// Build providers in parallel, so that one slow issuer delays the poll
	// by at most setupTimeout rather than holding up every other signer.
	usable := d.usableSigners(signers)
	built := make([]*OIDCProvider, len(usable))
	sem := make(chan struct{}, maxParallelProviderBuilds)
	var wg sync.WaitGroup
	for i, s := range usable {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			built[i] = d.buildProvider(ctx, s)
		}()
	}
	wg.Wait()

	providers := make([]UpstreamProvider, 0, len(built))
	d.built = make(map[string]builtProvider, len(built))
	for i, p := range built {
		if p != nil {
			providers = append(providers, p)
			d.built[p.Name()] = builtProvider{signer: usable[i], provider: p}
		}
	}
	if err := d.registry.SetOIDCProviders(providers, d.configuredNames); err != nil {
		return fmt.Errorf("update provider registry: %w", err)
	}
	return nil
}

// selfAllowsTokenEnrollment reports whether, as of the last poll, ZDAS's own
// signer on the controller allows enroll-to-token.
func (d *signerDiscovery) selfAllowsTokenEnrollment() bool {
	return d.selfToToken.Load()
}

// usableSigners returns the signers to build providers for: those with
// enrollment enabled, other than ZDAS itself, that have an externalAuthUrl,
// and whose name, ignoring case, is not already taken by a configured
// provider or an earlier signer. A signer whose name is taken is skipped rather than
// failing the poll, so that one misnamed signer cannot stop discovery.
func (d *signerDiscovery) usableSigners(signers []signerEntry) []signerEntry {
	taken := make(map[string]bool, len(d.configuredNames)+len(signers))
	for name := range d.configuredNames {
		taken[strings.ToLower(name)] = true
	}
	var usable []signerEntry
	for _, s := range signers {
		switch {
		case !s.EnrollToCertEnabled && !s.EnrollToTokenEnabled:
			continue
		case d.isSelf(s):
			d.logger.Debug("excluding self from discovered signers", "name", s.Name, "external_auth_url", s.ExternalAuthURL)
			continue
		case s.ExternalAuthURL == "":
			d.logger.Debug("skipping signer with no externalAuthUrl", "name", s.Name)
			continue
		case taken[strings.ToLower(s.Name)]:
			d.logger.Warn("skipping signer whose name is already taken by another provider", "name", s.Name, "external_auth_url", s.ExternalAuthURL)
			continue
		}
		taken[strings.ToLower(s.Name)] = true
		usable = append(usable, s)
	}
	return usable
}

// isSelf reports whether s is ZDAS's own signer: its externalAuthUrl is
// SelfIssuer or, as older setup instructions had it, a path under it.
func (d *signerDiscovery) isSelf(s signerEntry) bool {
	self := strings.TrimSuffix(d.cfg.SelfIssuer, "/")
	if self == "" {
		return false
	}
	return s.ExternalAuthURL == self || strings.HasPrefix(s.ExternalAuthURL, self+"/")
}

// builtProvider is a provider discovery built and the signer it was built
// from.
type builtProvider struct {
	signer   signerEntry
	provider *OIDCProvider
}

// buildProvider builds the provider for s, allowing setupTimeout for its
// discovery document. If that fails and the last poll built a provider from
// identical signer settings, it returns that one, so that an issuer that is
// briefly unreachable does not break sign-ins already under way. It returns
// nil if there is neither.
func (d *signerDiscovery) buildProvider(ctx context.Context, s signerEntry) *OIDCProvider {
	setupCtx, cancel := context.WithTimeout(ctx, d.setupTimeout)
	defer cancel()
	p, err := NewOIDCProvider(setupCtx, OIDCProviderConfig{
		Name:       s.Name,
		Issuer:     s.ExternalAuthURL,
		ClientID:   s.ClientID,
		Scopes:     signerScopes(s.Scopes),
		Audience:   s.Audience,
		HTTPClient: d.upstreamClient,
		Logger:     d.logger,
	})
	if err == nil {
		d.logger.Info("discovered oidc provider", "name", s.Name, "issuer", s.ExternalAuthURL)
		if _, seen := d.built[s.Name]; !seen {
			// A discovered provider has no policy of its own, so say so
			// once, the first time it appears.
			d.logger.Warn("discovered provider admits every user its issuer signs in; to restrict who may enroll, configure a provider with this name and a policy",
				"name", s.Name, "issuer", s.ExternalAuthURL)
		}
		return p
	}
	if prev, ok := d.built[s.Name]; ok && prev.signer.equal(s) {
		d.logger.Warn("failed to refresh oidc provider from signer, keeping previous", "name", s.Name, "error", err)
		return prev.provider
	}
	d.logger.Warn("failed to create oidc provider from signer, skipping", "name", s.Name, "error", err)
	return nil
}

// signerScopes returns the scopes to request for a signer: ZDAS's defaults,
// which give it the claims it names identities from, followed by the
// signer's own, which the IdP may need, e.g. for group claims.
func signerScopes(extra []string) []string {
	scopes := slices.Clone(defaultOIDCScopes)
	for _, e := range extra {
		for _, sc := range strings.Fields(e) {
			if !slices.Contains(scopes, sc) {
				scopes = append(scopes, sc)
			}
		}
	}
	return scopes
}

// fetchSigners fetches every page of the controller's signer list. It
// returns the body to re-serve, which is the controller's own response when
// the list fits on one page, and the parsed entries.
func (d *signerDiscovery) fetchSigners(ctx context.Context) (rawBody []byte, entries []signerEntry, err error) {
	var all []json.RawMessage
	for page := 1; ; page++ {
		body, err := d.fetchSignerPage(ctx, len(all))
		if err != nil {
			return nil, nil, err
		}
		var resp signerPage
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, nil, fmt.Errorf("parse signers response: %w", err)
		}
		if page == 1 {
			rawBody = body
		}
		all = append(all, resp.Data...)
		// Stop at the last page. A controller that ignores limit sends more
		// than a page at once, and one that sends no total doesn't page.
		total := resp.Meta.Pagination.TotalCount
		if len(resp.Data) == 0 || len(resp.Data) > d.pageSize || len(all) >= total {
			break
		}
		if page == maxSignerPages {
			d.logger.Warn("signer list longer than the page limit, ignoring the rest",
				"pages", maxSignerPages, "fetched", len(all), "total", total)
			break
		}
		rawBody = nil // more than one page: re-serve the merged list
	}

	entries = make([]signerEntry, len(all))
	for i, raw := range all {
		if err := json.Unmarshal(raw, &entries[i]); err != nil {
			return nil, nil, fmt.Errorf("parse signer %d: %w", i, err)
		}
	}
	if rawBody == nil {
		var merged signerPage
		merged.Data = all
		merged.Meta.Pagination = signerPagination{Limit: len(all), TotalCount: len(all)}
		if rawBody, err = json.Marshal(merged); err != nil {
			return nil, nil, fmt.Errorf("merge signer pages: %w", err)
		}
	}
	return rawBody, entries, nil
}

func (d *signerDiscovery) fetchSignerPage(ctx context.Context, offset int) ([]byte, error) {
	q := url.Values{"limit": {strconv.Itoa(d.pageSize)}, "offset": {strconv.Itoa(offset)}}
	reqURL := d.cfg.APIURL + "/edge/client/v1/external-jwt-signers?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build signers request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch signers: %w", err)
	}
	defer resp.Body.Close()
	body, err := readResponseBody(resp)
	if err != nil {
		return nil, fmt.Errorf("read signers response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("signers endpoint returned %d: %s", resp.StatusCode, truncateBody(body))
	}
	return body, nil
}

// The Edge API paths, which ZDAS appends to the controller's root URL.
const (
	clientAPIPath     = "/edge/client/v1"
	managementAPIPath = "/edge/management/v1"
)

// controllerRoot returns the controller's root URL from rawURL, which may be
// the root or an Edge API URL, as ztAPI in an identity file is. A path in
// front of the API path, such as a reverse proxy's prefix, is kept.
func controllerRoot(rawURL string) string {
	u := strings.TrimSuffix(rawURL, "/")
	for _, p := range []string{clientAPIPath, managementAPIPath} {
		if root, ok := strings.CutSuffix(u, p); ok {
			return root
		}
	}
	return u
}

// controllerClient builds an HTTP client for controller communication.
//   - identity set (from cfg.IdentityFile): CA from the identity, no client cert
//   - ca bundle set: CA from PEM file + system roots
//   - neither set: system CA pool only (works for publicly-trusted controllers)
//
// No client certificate is presented; this is for the public Edge Client API.
func controllerClient(cfg ControllerConfig, id *parsedIdentity) (*http.Client, error) {
	if id != nil {
		return discoveryClientFromIdentity(id), nil
	}
	if cfg.CABundle != "" {
		return clientFromCABundle(cfg.CABundle)
	}
	return &http.Client{Timeout: outboundTimeout}, nil
}

// clientFromCABundle builds an HTTP client that trusts both the system CA pool
// and the certificates in the given PEM file.
func clientFromCABundle(path string) (*http.Client, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read ca bundle: %w", err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no valid certificates in ca bundle %s", path)
	}
	return tlsClient(&tls.Config{RootCAs: pool}), nil
}

func (d *signerDiscovery) fetchNetworkJWTs(ctx context.Context) ([]byte, error) {
	reqURL := d.cfg.APIURL + "/network-jwts"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build network-jwts request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch network-jwts: %w", err)
	}
	defer resp.Body.Close()
	body, err := readResponseBody(resp)
	if err != nil {
		return nil, fmt.Errorf("read network-jwts response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("network-jwts endpoint returned %d: %s", resp.StatusCode, truncateBody(body))
	}
	return body, nil
}
