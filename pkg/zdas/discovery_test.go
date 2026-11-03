package zdas

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// signerResponse is the controller's signer list as a mock controller sends
// it.
type signerResponse struct {
	Data []signerEntry `json:"data"`
}

// mockControllerAndIDPs sets up:
//   - a mock Ziti controller that returns the given signer entries
//   - for each signer entry, a mock OIDC discovery server (if the
//     externalAuthUrl is left as "", it is set to the mock server's URL, its
//     issuer)
//
// Returns the controller server and a list of OIDC mock servers.
func mockControllerAndIDPs(t *testing.T, signers []signerEntry) (*httptest.Server, []*httptest.Server) {
	t.Helper()

	// Start mock OIDC servers for any signers that need one.
	var idpServers []*httptest.Server
	for i := range signers {
		if !signers[i].EnrollToCertEnabled {
			continue
		}
		idpServer, _ := mockOIDCServer(t, map[string]any{"sub": "testuser"})
		idpServers = append(idpServers, idpServer)
		if signers[i].ExternalAuthURL == "" {
			signers[i].ExternalAuthURL = idpServer.URL
		}
	}

	ctrlMux := http.NewServeMux()
	ctrlMux.HandleFunc("/edge/client/v1/external-jwt-signers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(signerResponse{Data: signers})
	})
	ctrlMux.HandleFunc("/network-jwts", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data":[{"token":"mock-network-jwt"}]}`))
	})
	ctrlServer := httptest.NewServer(ctrlMux)
	t.Cleanup(ctrlServer.Close)
	return ctrlServer, idpServers
}

func TestDiscoveryPoll(t *testing.T) {
	signers := []signerEntry{
		{Name: "keycloak", ClientID: "kc-client", EnrollToCertEnabled: true},
	}
	ctrl, _ := mockControllerAndIDPs(t, signers)

	reg := NewProviderRegistry()
	d := newSignerDiscovery(ControllerConfig{
		APIURL:     ctrl.URL,
		SelfIssuer: "https://zdas.example.com",
	}, http.DefaultClient, nil, reg, nil, slog.Default())

	if err := d.poll(context.Background()); err != nil {
		t.Fatalf("poll: %v", err)
	}

	if reg.Len() != 1 {
		t.Fatalf("expected 1 provider, got %d: %v", reg.Len(), reg.Names())
	}
	p, err := reg.Resolve("keycloak")
	if err != nil {
		t.Fatalf("Resolve keycloak: %v", err)
	}
	if p.Name() != "keycloak" {
		t.Errorf("name = %q", p.Name())
	}
}

func TestDiscoveryExcludesSelf(t *testing.T) {
	// One signer is ZDAS itself (matching self_issuer), one is a real IdP.
	selfIssuer := "https://zdas.example.com"
	signers := []signerEntry{
		{Name: "zdas-signer", ExternalAuthURL: selfIssuer, ClientID: "c", EnrollToCertEnabled: true},
		{Name: "keycloak", ClientID: "kc-client", EnrollToCertEnabled: true},
	}
	ctrl, _ := mockControllerAndIDPs(t, signers)

	reg := NewProviderRegistry()
	d := newSignerDiscovery(ControllerConfig{
		APIURL:     ctrl.URL,
		SelfIssuer: selfIssuer,
	}, http.DefaultClient, nil, reg, nil, slog.Default())
	if err := d.poll(context.Background()); err != nil {
		t.Fatalf("poll: %v", err)
	}

	if reg.Len() != 1 {
		t.Fatalf("expected 1 provider (self excluded), got %d: %v", reg.Len(), reg.Names())
	}
	if _, err := reg.Resolve("zdas-signer"); err == nil {
		t.Error("zdas-signer should have been excluded")
	}
}

func TestDiscoveryFiltersNonEnrollToCert(t *testing.T) {
	signers := []signerEntry{
		{Name: "auth-only", ClientID: "c", ExternalAuthURL: "https://auth-only", EnrollToCertEnabled: false},
		{Name: "enroll", ClientID: "c", EnrollToCertEnabled: true},
	}
	ctrl, _ := mockControllerAndIDPs(t, signers)

	reg := NewProviderRegistry()
	d := newSignerDiscovery(ControllerConfig{APIURL: ctrl.URL}, http.DefaultClient, nil, reg, nil, slog.Default())
	if err := d.poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if reg.Len() != 1 {
		t.Fatalf("expected 1 provider, got %d", reg.Len())
	}
}

// TestDiscoveryNameCollisionSkipsSigner verifies that a signer whose name is
// taken, ignoring case, by a configured provider or an earlier signer is
// skipped without failing the poll, so later polls still pick up removals.
func TestDiscoveryNameCollisionSkipsSigner(t *testing.T) {
	signers := []signerEntry{
		{Name: "GitHub", ClientID: "c", EnrollToCertEnabled: true},
		{Name: "kc", ClientID: "c", EnrollToCertEnabled: true},
		{Name: "KC", ClientID: "c2", EnrollToCertEnabled: true},
	}
	ctrl, _ := mockControllerAndIDPs(t, signers)

	reg := NewProviderRegistry()
	configured := map[string]struct{}{"github": {}}
	gh := &stubProvider{name: "github", issuer: "https://github.com"}
	_ = reg.Register(gh)

	d := newSignerDiscovery(ControllerConfig{APIURL: ctrl.URL}, http.DefaultClient, nil, reg, configured, slog.Default())
	if err := d.poll(context.Background()); err != nil {
		t.Fatalf("poll: %v", err)
	}
	names := reg.Names()
	slices.Sort(names)
	if !slices.Equal(names, []string{"github", "kc"}) {
		t.Fatalf("providers = %v, want [github kc]", names)
	}
	if p, _ := reg.Resolve("github"); p != gh {
		t.Error("configured provider was replaced")
	}

	// The signer is removed on the controller; the colliding signer must not
	// keep the poll from applying that.
	signers2 := []signerEntry{{Name: "GitHub", ClientID: "c", EnrollToCertEnabled: true}}
	ctrl2, _ := mockControllerAndIDPs(t, signers2)
	d.cfg.APIURL = ctrl2.URL
	if err := d.poll(context.Background()); err != nil {
		t.Fatalf("second poll: %v", err)
	}
	if _, err := reg.Resolve("kc"); err == nil {
		t.Error("signer removed on the controller is still registered")
	}
}

func TestDiscoveryIsSelf(t *testing.T) {
	cases := []struct {
		self string
		s    signerEntry
		want bool
	}{
		{"https://zdas.example.com", signerEntry{ExternalAuthURL: "https://zdas.example.com"}, true},
		{"https://zdas.example.com", signerEntry{ExternalAuthURL: "https://zdas.example.com/"}, true},
		{"https://zdas.example.com/", signerEntry{ExternalAuthURL: "https://zdas.example.com"}, true},
		{"https://zdas.example.com", signerEntry{ExternalAuthURL: "https://zdas.example.com/authorize"}, true},
		{"https://zdas.example.com/", signerEntry{ExternalAuthURL: "https://zdas.example.com/authorize"}, true},
		{"https://zdas.example.com", signerEntry{ExternalAuthURL: "https://zdas.example.com.evil"}, false},
		{"https://zdas.example.com", signerEntry{ExternalAuthURL: "https://zdas.example.com.evil/authorize"}, false},
		{"https://zdas.example.com", signerEntry{ExternalAuthURL: "https://idp.example.com"}, false},
		{"", signerEntry{ExternalAuthURL: "https://idp.example.com"}, false},
	}
	for _, tc := range cases {
		d := &signerDiscovery{cfg: ControllerConfig{SelfIssuer: tc.self}}
		if got := d.isSelf(tc.s); got != tc.want {
			t.Errorf("isSelf(%+v) with SelfIssuer %q = %v, want %v", tc.s, tc.self, got, tc.want)
		}
	}
}

// TestDiscoveryUnresponsiveIssuer verifies that issuers that never answer
// delay a poll by about the setup timeout, not by that once per issuer, and
// do not keep other signers' providers from being registered.
func TestDiscoveryUnresponsiveIssuer(t *testing.T) {
	release := make(chan struct{})
	hung := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	t.Cleanup(hung.Close)
	t.Cleanup(func() { close(release) })

	signers := []signerEntry{
		{Name: "hung-1", ExternalAuthURL: hung.URL + "/a", ClientID: "c", EnrollToCertEnabled: true},
		{Name: "hung-2", ExternalAuthURL: hung.URL + "/b", ClientID: "c", EnrollToCertEnabled: true},
		{Name: "hung-3", ExternalAuthURL: hung.URL + "/c", ClientID: "c", EnrollToCertEnabled: true},
		{Name: "kc", ClientID: "c", EnrollToCertEnabled: true},
	}
	ctrl, _ := mockControllerAndIDPs(t, signers)

	reg := NewProviderRegistry()
	d := newSignerDiscovery(ControllerConfig{APIURL: ctrl.URL}, http.DefaultClient, nil, reg, nil, slog.Default())
	d.setupTimeout = 500 * time.Millisecond

	start := time.Now()
	if err := d.poll(context.Background()); err != nil {
		t.Fatalf("poll: %v", err)
	}
	// Built one after another, three hung issuers would take 1.5s.
	if elapsed := time.Since(start); elapsed > 1200*time.Millisecond {
		t.Errorf("poll took %v with three unresponsive issuers", elapsed)
	}
	if names := reg.Names(); !slices.Equal(names, []string{"kc"}) {
		t.Errorf("providers = %v, want [kc]", names)
	}
}

// TestDiscoveryKeepsProviderWhenRefreshFails verifies that a signer whose
// issuer is briefly unreachable keeps the provider the last poll built, but
// only while the signer's settings are unchanged.
func TestDiscoveryKeepsProviderWhenRefreshFails(t *testing.T) {
	signers := []signerEntry{{Name: "kc", ClientID: "c", EnrollToCertEnabled: true}}
	ctrl, idps := mockControllerAndIDPs(t, signers)

	reg := NewProviderRegistry()
	d := newSignerDiscovery(ControllerConfig{APIURL: ctrl.URL}, http.DefaultClient, nil, reg, nil, slog.Default())
	if err := d.poll(context.Background()); err != nil {
		t.Fatalf("poll: %v", err)
	}
	first, err := reg.Resolve("kc")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	idps[0].Close()
	if err := d.poll(context.Background()); err != nil {
		t.Fatalf("poll with issuer down: %v", err)
	}
	if p, err := reg.Resolve("kc"); err != nil || p != first {
		t.Errorf("provider after failed refresh = %v, %v; want the previous one", p, err)
	}

	signers[0].ClientID = "changed"
	if err := d.poll(context.Background()); err != nil {
		t.Fatalf("poll with changed signer: %v", err)
	}
	if _, err := reg.Resolve("kc"); err == nil {
		t.Error("provider kept although the signer's settings changed")
	}
}

// TestDiscoveryPaginates verifies that discovery follows the controller's
// pagination, registers signers from every page, and re-serves the merged
// list with each entry as the controller sent it.
func TestDiscoveryPaginates(t *testing.T) {
	var entries []string
	for i := range 3 {
		idp, _ := mockOIDCServer(t, map[string]any{"sub": "u"})
		entries = append(entries, fmt.Sprintf(
			`{"id":"id%d","name":"kc%d","externalAuthUrl":%q,"clientId":"c","enrollToCertEnabled":true}`, i, i, idp.URL))
	}
	var offsets []string
	ctrlMux := http.NewServeMux()
	ctrlMux.HandleFunc("/edge/client/v1/external-jwt-signers", func(w http.ResponseWriter, r *http.Request) {
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		offsets = append(offsets, r.URL.Query().Get("offset"))
		end := min(offset+limit, len(entries))
		fmt.Fprintf(w, `{"data":[%s],"meta":{"pagination":{"limit":%d,"offset":%d,"totalCount":%d}}}`,
			strings.Join(entries[offset:end], ","), limit, offset, len(entries))
	})
	ctrl := httptest.NewServer(ctrlMux)
	t.Cleanup(ctrl.Close)

	reg := NewProviderRegistry()
	d := newSignerDiscovery(ControllerConfig{APIURL: ctrl.URL}, http.DefaultClient, nil, reg, nil, slog.Default())
	d.pageSize = 2
	if err := d.poll(context.Background()); err != nil {
		t.Fatalf("poll: %v", err)
	}

	if !slices.Equal(offsets, []string{"0", "2"}) {
		t.Errorf("requested offsets %v, want [0 2]", offsets)
	}
	names := reg.Names()
	slices.Sort(names)
	if !slices.Equal(names, []string{"kc0", "kc1", "kc2"}) {
		t.Errorf("providers = %v, want [kc0 kc1 kc2]", names)
	}
	var served struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
		Meta struct {
			Pagination signerPagination `json:"pagination"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(d.cachedExtJWTSigners(), &served); err != nil {
		t.Fatalf("parse served signers: %v", err)
	}
	if len(served.Data) != 3 || served.Data[2].ID != "id2" {
		t.Errorf("served signers = %+v, want all three with their ids", served.Data)
	}
	if served.Meta.Pagination.TotalCount != 3 {
		t.Errorf("served totalCount = %d, want 3", served.Meta.Pagination.TotalCount)
	}
}

func TestDiscoveryCachesNetworkJWTs(t *testing.T) {
	signers := []signerEntry{
		{Name: "kc", ClientID: "c", EnrollToCertEnabled: true},
	}
	ctrl, _ := mockControllerAndIDPs(t, signers)

	reg := NewProviderRegistry()
	d := newSignerDiscovery(ControllerConfig{APIURL: ctrl.URL}, http.DefaultClient, nil, reg, nil, slog.Default())
	if d.cachedNetworkJWTs() != nil {
		t.Error("expected nil before first poll")
	}
	if err := d.poll(t.Context()); err != nil {
		t.Fatal(err)
	}
	body := d.cachedNetworkJWTs()
	if body == nil {
		t.Fatal("expected cached network JWTs after poll")
	}
	if !strings.Contains(string(body), "mock-network-jwt") {
		t.Errorf("unexpected cached body: %s", body)
	}
}

func TestDiscoveryCachesExtJWTSigners(t *testing.T) {
	signers := []signerEntry{
		{Name: "kc", ClientID: "c", EnrollToCertEnabled: true},
	}
	ctrl, _ := mockControllerAndIDPs(t, signers)

	reg := NewProviderRegistry()
	d := newSignerDiscovery(ControllerConfig{APIURL: ctrl.URL}, http.DefaultClient, nil, reg, nil, slog.Default())
	if d.cachedExtJWTSigners() != nil {
		t.Error("expected nil before first poll")
	}
	if err := d.poll(t.Context()); err != nil {
		t.Fatal(err)
	}
	body := d.cachedExtJWTSigners()
	if body == nil {
		t.Fatal("expected cached ext-jwt-signers after poll")
	}
	// Verify the cached body round-trips to the same signers the mock served.
	var got signerResponse
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal cached body: %v", err)
	}
	if len(got.Data) == 0 {
		t.Fatal("expected at least one signer in cached body")
	}
	if got.Data[0].Name != "kc" {
		t.Errorf("signer name = %q, want kc", got.Data[0].Name)
	}
}

func TestDiscoveryControllerUnreachable(t *testing.T) {
	reg := NewProviderRegistry()
	d := newSignerDiscovery(ControllerConfig{APIURL: "http://127.0.0.1:1"}, http.DefaultClient, nil, reg, nil, slog.Default())
	err := d.poll(context.Background())
	if err == nil {
		t.Error("expected error for unreachable controller")
	}
}

func TestDiscoveryRefreshReplacesOIDCProviders(t *testing.T) {
	// First poll discovers "kc-old".
	signers1 := []signerEntry{
		{Name: "kc-old", ClientID: "c", EnrollToCertEnabled: true},
	}
	ctrl1, _ := mockControllerAndIDPs(t, signers1)

	reg := NewProviderRegistry()
	d := newSignerDiscovery(ControllerConfig{APIURL: ctrl1.URL}, http.DefaultClient, nil, reg, nil, slog.Default())
	if err := d.poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if reg.Len() != 1 {
		t.Fatalf("after first poll: %d providers", reg.Len())
	}

	// Second poll discovers "kc-new" instead. Simulate by re-creating with new ctrl.
	signers2 := []signerEntry{
		{Name: "kc-new", ClientID: "c", EnrollToCertEnabled: true},
	}
	ctrl2, _ := mockControllerAndIDPs(t, signers2)
	d.cfg.APIURL = ctrl2.URL

	if err := d.poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if reg.Len() != 1 {
		t.Fatalf("after second poll: expected 1, got %d: %v", reg.Len(), reg.Names())
	}
	if _, err := reg.Resolve("kc-new"); err != nil {
		t.Error("kc-new should exist after refresh")
	}
	if _, err := reg.Resolve("kc-old"); err == nil {
		t.Error("kc-old should have been replaced")
	}
}

// TestClientFromCABundle verifies that a client built from a CA bundle
// trusts a server whose certificate that bundle issued.
func TestClientFromCABundle(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(srv.Close)
	path := filepath.Join(t.TempDir(), "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	client, err := clientFromCABundle(path)
	if err != nil {
		t.Fatalf("clientFromCABundle: %v", err)
	}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET with the bundle's client: %v", err)
	}
	resp.Body.Close()

	if _, err := http.Get(srv.URL); err == nil {
		t.Error("default client trusted the test server; the test proves nothing")
	}
	if err := os.WriteFile(path, []byte("not pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := clientFromCABundle(path); err == nil {
		t.Error("clientFromCABundle accepted a file with no certificates")
	}
}

// pagedController returns a controller whose signer list is n entries
// without enrollment enabled, paged by limit and offset when honorLimit is
// set and sent whole otherwise. It records each request's offset.
func pagedController(t *testing.T, n int, honorLimit bool) (*httptest.Server, *[]string) {
	t.Helper()
	var offsets []string
	mux := http.NewServeMux()
	mux.HandleFunc("/edge/client/v1/external-jwt-signers", func(w http.ResponseWriter, r *http.Request) {
		offsets = append(offsets, r.URL.Query().Get("offset"))
		offset, end := 0, n
		if honorLimit {
			limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
			offset, _ = strconv.Atoi(r.URL.Query().Get("offset"))
			end = min(offset+limit, n)
		}
		var entries []string
		for i := offset; i < end; i++ {
			entries = append(entries, fmt.Sprintf(`{"name":"s%d"}`, i))
		}
		fmt.Fprintf(w, `{"data":[%s],"meta":{"pagination":{"totalCount":%d}}}`, strings.Join(entries, ","), n)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &offsets
}

// TestDiscoveryPageLimit verifies that a poll stops after maxSignerPages
// even when the controller reports more.
func TestDiscoveryPageLimit(t *testing.T) {
	ctrl, offsets := pagedController(t, 1000, true)
	d := newSignerDiscovery(ControllerConfig{APIURL: ctrl.URL}, http.DefaultClient, nil, NewProviderRegistry(), nil, slog.Default())
	d.pageSize = 2
	if err := d.poll(t.Context()); err != nil {
		t.Fatalf("poll: %v", err)
	}
	if len(*offsets) != maxSignerPages {
		t.Errorf("fetched %d pages, want %d", len(*offsets), maxSignerPages)
	}
}

// TestDiscoveryControllerIgnoresLimit verifies that a controller that sends
// more than a page at once is read once, not asked again at an offset.
func TestDiscoveryControllerIgnoresLimit(t *testing.T) {
	ctrl, offsets := pagedController(t, 5, false)
	d := newSignerDiscovery(ControllerConfig{APIURL: ctrl.URL}, http.DefaultClient, nil, NewProviderRegistry(), nil, slog.Default())
	d.pageSize = 2
	if err := d.poll(t.Context()); err != nil {
		t.Fatalf("poll: %v", err)
	}
	if len(*offsets) != 1 {
		t.Errorf("fetched %d pages, want 1", len(*offsets))
	}
	var served signerPage
	if err := json.Unmarshal(d.cachedExtJWTSigners(), &served); err != nil || len(served.Data) != 5 {
		t.Errorf("served %d signers, %v; want all 5", len(served.Data), err)
	}
}

// TestDiscoveryLoop verifies that start keeps polling every PollInterval
// and that stop ends the loop.
func TestDiscoveryLoop(t *testing.T) {
	var mu sync.Mutex
	polls := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/edge/client/v1/external-jwt-signers", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		polls++
		mu.Unlock()
		fmt.Fprint(w, `{"data":[]}`)
	})
	ctrl := httptest.NewServer(mux)
	t.Cleanup(ctrl.Close)
	count := func() int { mu.Lock(); defer mu.Unlock(); return polls }

	d := newSignerDiscovery(ControllerConfig{APIURL: ctrl.URL, PollInterval: time.Millisecond}, http.DefaultClient, nil, NewProviderRegistry(), nil, slog.Default())
	if err := d.start(t.Context()); err != nil {
		t.Fatalf("start: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for count() < 3 {
		if time.Now().After(deadline) {
			t.Fatalf("only %d polls", count())
		}
		time.Sleep(time.Millisecond)
	}
	d.stop()
	after := count()
	time.Sleep(20 * time.Millisecond)
	if n := count(); n != after {
		t.Errorf("%d polls after stop", n-after)
	}
	d.stop()
}

// clientAPISigner is a signer as the controller's client API sends it
// (ClientExternalJWTSignerDetail): there is no issuer, and externalAuthUrl
// is the IdP's issuer.
const clientAPISigner = `{
	"_links": {"self": {"href": "./external-jwt-signers/s1"}},
	"createdAt": "2026-10-01T12:00:00.000Z",
	"id": "s1",
	"tags": {},
	"updatedAt": "2026-10-01T12:00:00.000Z",
	"audience": %s,
	"clientId": "kc-client",
	"enrollToCertEnabled": true,
	"enrollToTokenEnabled": false,
	"externalAuthUrl": %q,
	"name": %q,
	"scopes": %s,
	"targetToken": "ID"
}`

// TestDiscoveryClientAPIShape verifies that a signer in the client API's
// shape becomes a provider whose issuer is its externalAuthUrl, that sends
// the browser to the authorization endpoint from the issuer's discovery
// document, and that requests the signer's scopes and audience.
func TestDiscoveryClientAPIShape(t *testing.T) {
	withExtras, _ := mockOIDCServer(t, map[string]any{"sub": "u"})
	plain, _ := mockOIDCServer(t, map[string]any{"sub": "u"})
	ctrlMux := http.NewServeMux()
	ctrlMux.HandleFunc("/edge/client/v1/external-jwt-signers", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"data":[`+clientAPISigner+`,`+clientAPISigner+`],"meta":{"pagination":{"limit":500,"offset":0,"totalCount":2}}}`,
			`"api://ziti"`, withExtras.URL, "with-extras", `["openid","offline_access","groups"]`,
			`null`, plain.URL, "plain", `null`)
	})
	ctrl := httptest.NewServer(ctrlMux)
	t.Cleanup(ctrl.Close)

	reg := NewProviderRegistry()
	d := newSignerDiscovery(ControllerConfig{APIURL: ctrl.URL}, http.DefaultClient, nil, reg, nil, slog.Default())
	if err := d.poll(t.Context()); err != nil {
		t.Fatalf("poll: %v", err)
	}

	cases := []struct {
		name, issuer, scope, audience string
	}{
		{"with-extras", withExtras.URL, "openid profile email offline_access groups", "api://ziti"},
		{"plain", plain.URL, "openid profile email", ""},
	}
	for _, tc := range cases {
		p, err := reg.Resolve(tc.name)
		if err != nil {
			t.Fatalf("Resolve %s: %v (providers %v)", tc.name, err, reg.Names())
		}
		if p.Issuer() != tc.issuer {
			t.Errorf("%s: Issuer() = %q, want %q", tc.name, p.Issuer(), tc.issuer)
		}
		u, err := url.Parse(p.AuthorizeURL("st", "https://zdas.test/callback"))
		if err != nil {
			t.Fatalf("%s: parse authorize URL: %v", tc.name, err)
		}
		if got := u.Scheme + "://" + u.Host + u.Path; got != tc.issuer+"/authorize" {
			t.Errorf("%s: authorize endpoint = %q, want %q", tc.name, got, tc.issuer+"/authorize")
		}
		q := u.Query()
		if q.Get("scope") != tc.scope {
			t.Errorf("%s: scope = %q, want %q", tc.name, q.Get("scope"), tc.scope)
		}
		if q.Get("audience") != tc.audience || tc.audience == "" && q.Has("audience") {
			t.Errorf("%s: audience = %q, want %q", tc.name, q["audience"], tc.audience)
		}
	}
}

func TestSignerScopes(t *testing.T) {
	cases := []struct {
		extra []string
		want  []string
	}{
		{nil, []string{"openid", "profile", "email"}},
		{[]string{"openid", "email"}, []string{"openid", "profile", "email"}},
		{[]string{"groups", "offline_access", "groups"}, []string{"openid", "profile", "email", "groups", "offline_access"}},
		{[]string{" groups  api://x/read ", ""}, []string{"openid", "profile", "email", "groups", "api://x/read"}},
	}
	for _, tc := range cases {
		if got := signerScopes(tc.extra); !slices.Equal(got, tc.want) {
			t.Errorf("signerScopes(%q) = %q, want %q", tc.extra, got, tc.want)
		}
	}
	if !slices.Equal(defaultOIDCScopes, []string{"openid", "profile", "email"}) {
		t.Errorf("defaultOIDCScopes changed to %q", defaultOIDCScopes)
	}
}

// TestSignerEntryEqual verifies that a change to any setting makes a signer
// unequal, so that discovery does not keep a provider built from old
// settings.
func TestSignerEntryEqual(t *testing.T) {
	base := signerEntry{
		Name: "kc", ClientID: "c", ExternalAuthURL: "https://idp", Scopes: []string{"groups"},
		Audience: "a", EnrollToCertEnabled: true,
	}
	changes := map[string]func(*signerEntry){
		"name":     func(s *signerEntry) { s.Name = "other" },
		"clientId": func(s *signerEntry) { s.ClientID = "other" },
		"url":      func(s *signerEntry) { s.ExternalAuthURL = "https://other" },
		"scopes":   func(s *signerEntry) { s.Scopes = []string{"groups", "more"} },
		"audience": func(s *signerEntry) { s.Audience = "other" },
		"cert":     func(s *signerEntry) { s.EnrollToCertEnabled = false },
		"token":    func(s *signerEntry) { s.EnrollToTokenEnabled = true },
	}
	same := base
	same.Scopes = slices.Clone(base.Scopes)
	if !base.equal(same) {
		t.Error("identical signers are not equal")
	}
	for name, change := range changes {
		s := base
		s.Scopes = slices.Clone(base.Scopes)
		change(&s)
		if base.equal(s) {
			t.Errorf("signers differing in %s are equal", name)
		}
	}
}

func TestControllerRoot(t *testing.T) {
	cases := map[string]string{
		"https://ctrl:1280":                          "https://ctrl:1280",
		"https://ctrl:1280/":                         "https://ctrl:1280",
		"https://ctrl:1280/edge/client/v1":           "https://ctrl:1280",
		"https://ctrl:1280/edge/client/v1/":          "https://ctrl:1280",
		"https://ctrl:1280/edge/management/v1":       "https://ctrl:1280",
		"https://ctrl/ziti/edge/client/v1":           "https://ctrl/ziti",
		"https://ctrl/ziti":                          "https://ctrl/ziti",
		"https://ctrl/edge/client/v1/edge/client/v1": "https://ctrl/edge/client/v1",
	}
	for in, want := range cases {
		if got := controllerRoot(in); got != want {
			t.Errorf("controllerRoot(%q) = %q, want %q", in, got, want)
		}
	}
}
