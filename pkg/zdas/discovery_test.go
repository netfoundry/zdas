package zdas

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
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
//   - for each signer entry, a mock OIDC discovery server (if the issuer is
//     left as "", it gets filled in automatically from the mock server URL)
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
		idpServer, _ := mockOIDCServer(t, map[string]interface{}{"sub": "testuser"})
		idpServers = append(idpServers, idpServer)
		if signers[i].Issuer == "" {
			signers[i].Issuer = idpServer.URL
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

func TestDiscoveryRunOnce(t *testing.T) {
	signers := []signerEntry{
		{Name: "keycloak", ClientID: "kc-client", EnrollToCertEnabled: true},
	}
	ctrl, _ := mockControllerAndIDPs(t, signers)

	reg := NewProviderRegistry()
	d, err := NewDiscovery(ControllerConfig{
		APIURL:     ctrl.URL,
		SelfIssuer: "https://zdas.example.com",
	}, reg, nil, slog.Default())
	if err != nil {
		t.Fatalf("NewDiscovery: %v", err)
	}

	if err := d.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
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
		{Name: "zdas-signer", Issuer: selfIssuer, ClientID: "c", EnrollToCertEnabled: true},
		{Name: "keycloak", ClientID: "kc-client", EnrollToCertEnabled: true},
	}
	ctrl, _ := mockControllerAndIDPs(t, signers)

	reg := NewProviderRegistry()
	d, err := NewDiscovery(ControllerConfig{
		APIURL:     ctrl.URL,
		SelfIssuer: selfIssuer,
	}, reg, nil, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	if err := d.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
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
		{Name: "auth-only", ClientID: "c", Issuer: "https://auth-only", EnrollToCertEnabled: false},
		{Name: "enroll", ClientID: "c", EnrollToCertEnabled: true},
	}
	ctrl, _ := mockControllerAndIDPs(t, signers)

	reg := NewProviderRegistry()
	d, err := NewDiscovery(ControllerConfig{APIURL: ctrl.URL}, reg, nil, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	if err := d.RunOnce(context.Background()); err != nil {
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

	d, err := NewDiscovery(ControllerConfig{APIURL: ctrl.URL}, reg, configured, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	if err := d.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
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
	if err := d.RunOnce(context.Background()); err != nil {
		t.Fatalf("second RunOnce: %v", err)
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
		{"https://zdas.example.com", signerEntry{Issuer: "https://zdas.example.com"}, true},
		{"https://zdas.example.com", signerEntry{ExternalAuthURL: "https://zdas.example.com/authorize"}, true},
		{"https://zdas.example.com/", signerEntry{ExternalAuthURL: "https://zdas.example.com/authorize"}, true},
		{"https://zdas.example.com", signerEntry{ExternalAuthURL: "https://zdas.example.com"}, true},
		{"https://zdas.example.com", signerEntry{ExternalAuthURL: "https://zdas.example.com.evil/authorize"}, false},
		{"https://zdas.example.com", signerEntry{Issuer: "https://idp.example.com"}, false},
		{"", signerEntry{Issuer: "https://idp.example.com", ExternalAuthURL: "https://idp.example.com/auth"}, false},
	}
	for _, tc := range cases {
		d := &Discovery{cfg: ControllerConfig{SelfIssuer: tc.self}}
		if got := d.isSelf(tc.s); got != tc.want {
			t.Errorf("isSelf(%+v) with SelfIssuer %q = %v, want %v", tc.s, tc.self, got, tc.want)
		}
	}
}

// TestDiscoveryUnresponsiveIssuer verifies that an issuer that never answers
// delays a poll by at most the setup timeout and does not keep other
// signers' providers from being registered.
func TestDiscoveryUnresponsiveIssuer(t *testing.T) {
	release := make(chan struct{})
	hung := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	t.Cleanup(hung.Close)
	t.Cleanup(func() { close(release) })

	signers := []signerEntry{
		{Name: "hung", Issuer: hung.URL, ClientID: "c", EnrollToCertEnabled: true},
		{Name: "kc", ClientID: "c", EnrollToCertEnabled: true},
	}
	ctrl, _ := mockControllerAndIDPs(t, signers)

	reg := NewProviderRegistry()
	d, err := NewDiscovery(ControllerConfig{APIURL: ctrl.URL}, reg, nil, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	d.setupTimeout = 200 * time.Millisecond

	start := time.Now()
	if err := d.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("poll took %v with one unresponsive issuer", elapsed)
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
	d, err := NewDiscovery(ControllerConfig{APIURL: ctrl.URL}, reg, nil, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	if err := d.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	first, err := reg.Resolve("kc")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	idps[0].Close()
	if err := d.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce with issuer down: %v", err)
	}
	if p, err := reg.Resolve("kc"); err != nil || p != first {
		t.Errorf("provider after failed refresh = %v, %v; want the previous one", p, err)
	}

	signers[0].ClientID = "changed"
	if err := d.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce with changed signer: %v", err)
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
		idp, _ := mockOIDCServer(t, map[string]interface{}{"sub": "u"})
		entries = append(entries, fmt.Sprintf(
			`{"id":"id%d","name":"kc%d","issuer":%q,"clientId":"c","enrollToCertEnabled":true}`, i, i, idp.URL))
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
	d, err := NewDiscovery(ControllerConfig{APIURL: ctrl.URL}, reg, nil, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	d.pageSize = 2
	if err := d.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
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
	if err := json.Unmarshal(d.ExtJWTSignersBody(), &served); err != nil {
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
	d, err := NewDiscovery(ControllerConfig{APIURL: ctrl.URL}, reg, nil, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	if d.NetworkJWTsBody() != nil {
		t.Error("expected nil before first poll")
	}
	if err := d.RunOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	body := d.NetworkJWTsBody()
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
	d, err := NewDiscovery(ControllerConfig{APIURL: ctrl.URL}, reg, nil, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	if d.ExtJWTSignersBody() != nil {
		t.Error("expected nil before first poll")
	}
	if err := d.RunOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	body := d.ExtJWTSignersBody()
	if body == nil {
		t.Fatal("expected cached ext-jwt-signers after poll")
	}
	// Verify the cached body round-trips to the same signers the mock served.
	var got signerResponse
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal cached body: %v", err)
	}
	if len(got.Data) == 0 {
		t.Error("expected at least one signer in cached body")
	}
	if got.Data[0].Name != "kc" {
		t.Errorf("signer name = %q, want kc", got.Data[0].Name)
	}
}

func TestDiscoveryControllerUnreachable(t *testing.T) {
	reg := NewProviderRegistry()
	d, err := NewDiscovery(ControllerConfig{APIURL: "http://127.0.0.1:1"}, reg, nil, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	err = d.RunOnce(context.Background())
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
	d, err := NewDiscovery(ControllerConfig{APIURL: ctrl1.URL}, reg, nil, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	if err := d.RunOnce(context.Background()); err != nil {
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

	if err := d.RunOnce(context.Background()); err != nil {
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
