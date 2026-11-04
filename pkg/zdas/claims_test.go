package zdas

import (
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

func defaultClaimsConfig() ClaimsConfig {
	return ClaimsConfig{
		UsernameClaim:     "preferred_username",
		NameTemplate:      "{username}-{device_name}",
		IdentityNameClaim: "device_identity_name",
		ExternalIDClaim:   "device_external_id",
	}
}

func TestComposeClaimsBasic(t *testing.T) {
	identity := &UpstreamIdentity{
		Subject:  "u42",
		Username: "jsmith",
		Issuer:   "https://keycloak.example.com",
		Raw:      map[string]any{"preferred_username": "jsmith", "sub": "u42"},
	}
	info := &DeviceInfo{DeviceName: "macbook-pro", Hostname: "macbook-pro", OS: "darwin", Arch: "arm64"}
	claims := ComposeClaims(defaultClaimsConfig(), FallbackConfig{}, identity, info, "")

	if got := claims["device_identity_name"]; got != "jsmith-macbook-pro" {
		t.Errorf("device_identity_name = %q", got)
	}
	if got, ok := claims["device_external_id"].(string); !ok || len(got) != 64 {
		t.Errorf("device_external_id = %q (expected 64-char hex)", got)
	}
	if got := claims["upstream_sub"]; got != "u42" {
		t.Errorf("upstream_sub = %v", got)
	}
	if got := claims["upstream_iss"]; got != "https://keycloak.example.com" {
		t.Errorf("upstream_iss = %v", got)
	}
	if got := claims["device_name"]; got != "macbook-pro" {
		t.Errorf("device_name = %v", got)
	}
}

func TestComposeClaimsUsernameFallback(t *testing.T) {
	identity := &UpstreamIdentity{
		Subject:  "sub1",
		Username: "fallback-user",
		Issuer:   "https://idp",
		Raw:      map[string]any{},
	}
	claims := ComposeClaims(defaultClaimsConfig(), FallbackConfig{}, identity, &DeviceInfo{DeviceName: "laptop"}, "")
	if got := claims["device_identity_name"]; got != "fallback-user-laptop" {
		t.Errorf("identity name with fallback = %q", got)
	}
}

func TestComposeClaimsSubjectFallback(t *testing.T) {
	identity := &UpstreamIdentity{
		Subject: "anon-sub",
		Issuer:  "https://idp",
		Raw:     map[string]any{},
	}
	claims := ComposeClaims(defaultClaimsConfig(), FallbackConfig{}, identity, &DeviceInfo{DeviceName: "phone"}, "")
	if got := claims["device_identity_name"]; got != "anon-sub-phone" {
		t.Errorf("identity name with subject fallback = %q", got)
	}
}

func TestComposeClaimsFallback(t *testing.T) {
	identity := &UpstreamIdentity{
		Subject:  "u42",
		Username: "jsmith",
		Issuer:   "https://keycloak",
		Raw:      map[string]any{"preferred_username": "jsmith"},
	}
	fbCfg := FallbackConfig{
		Enabled:          true,
		TempNameTemplate: "{username}-pending-{nonce_short}",
	}
	claims := ComposeClaims(defaultClaimsConfig(), fbCfg, identity, nil, "a3f9b2")

	if got := claims["device_identity_name"]; got != "jsmith-pending-a3f9b2" {
		t.Errorf("fallback identity name = %q", got)
	}
	if got, ok := claims["device_external_id"].(string); !ok || len(got) != 64 {
		t.Errorf("fallback external_id = %q", got)
	}
	if got := claims["device_name"]; got != "" {
		t.Errorf("fallback device_name should be empty, got %q", got)
	}
}

func TestComposeClaimsFallbackWithPartialDeviceInfo(t *testing.T) {
	identity := &UpstreamIdentity{
		Subject:  "u42",
		Username: "jsmith",
		Issuer:   "https://keycloak",
		Raw:      map[string]any{"preferred_username": "jsmith"},
	}
	fbCfg := FallbackConfig{
		Enabled:          true,
		TempNameTemplate: "{username}-pending-{nonce_short}",
	}
	// Partial DeviceInfo: no device_name, but OS is known (e.g. iOS tunneler).
	info := &DeviceInfo{OS: "iOS", Arch: "arm64"}
	claims := ComposeClaims(defaultClaimsConfig(), fbCfg, identity, info, "a3f9b2")

	// Nonce triggers fallback path even when DeviceInfo is non-nil.
	if got := claims["device_identity_name"]; got != "jsmith-pending-a3f9b2" {
		t.Errorf("fallback identity name = %q, want jsmith-pending-a3f9b2", got)
	}
	if got := claims["device_name"]; got != "" {
		t.Errorf("fallback device_name should be empty, got %q", got)
	}
}

func TestComposeClaimsFallbackUniqueExternalIDs(t *testing.T) {
	identity := &UpstreamIdentity{Subject: "u1", Issuer: "https://idp"}
	fbCfg := FallbackConfig{TempNameTemplate: "{username}-pending-{nonce_short}"}

	c1 := ComposeClaims(defaultClaimsConfig(), fbCfg, identity, nil, "aaaaaa")
	c2 := ComposeClaims(defaultClaimsConfig(), fbCfg, identity, nil, "bbbbbb")

	if c1["device_external_id"] == c2["device_external_id"] {
		t.Error("different nonces should produce different external IDs")
	}
}

func TestExpandFallbackTemplate(t *testing.T) {
	got := expandFallbackTemplate("{username}-pending-{nonce_short}", "alice", "abc123")
	if got != "alice-pending-abc123" {
		t.Errorf("expandFallbackTemplate = %q", got)
	}
}

func TestExternalIDDiffersByDevice(t *testing.T) {
	id1 := computeExternalID("iss", "sub", "device-a")
	id2 := computeExternalID("iss", "sub", "device-b")
	if id1 == id2 {
		t.Error("same user on different devices should produce different external IDs")
	}
}

func TestExternalIDDiffersByIssuer(t *testing.T) {
	id1 := computeExternalID("https://keycloak", "12345", "laptop")
	id2 := computeExternalID("https://github.com", "12345", "laptop")
	if id1 == id2 {
		t.Error("same sub from different issuers should produce different external IDs")
	}
}

func TestExpandTemplate(t *testing.T) {
	cases := []struct {
		tmpl, user string
		info       *DeviceInfo
		want       string
	}{
		{"{username}-{device_name}", "alice", &DeviceInfo{DeviceName: "macbook"}, "alice-macbook"},
		{"{device_name}@{username}", "bob", &DeviceInfo{DeviceName: "phone"}, "phone@bob"},
		{"prefix-{username}-{device_name}-suffix", "u", &DeviceInfo{DeviceName: "d"}, "prefix-u-d-suffix"},
		{"{username}-{hostname}", "alice", &DeviceInfo{Hostname: "macbook-pro.local"}, "alice-macbook-pro.local"},
		{"{username}-{device_name}-{os}-{arch}", "bob", &DeviceInfo{DeviceName: "laptop", OS: "darwin", Arch: "arm64"}, "bob-laptop-darwin-arm64"},
	}
	for _, tc := range cases {
		got := expandTemplate(tc.tmpl, tc.user, tc.info)
		if got != tc.want {
			t.Errorf("expandTemplate(%q, %q, %+v) = %q, want %q", tc.tmpl, tc.user, tc.info, got, tc.want)
		}
	}
}

func TestMintTokenRoundtrip(t *testing.T) {
	ks, err := GenerateKeySet()
	if err != nil {
		t.Fatalf("GenerateKeySet: %v", err)
	}
	identity := &UpstreamIdentity{
		Subject:  "u1",
		Username: "alice",
		Issuer:   "https://idp",
		Raw:      map[string]any{"preferred_username": "alice"},
	}
	cfg := defaultClaimsConfig()
	claims := ComposeClaims(cfg, FallbackConfig{}, identity, &DeviceInfo{DeviceName: "laptop"}, "")

	tokenCfg := TokenConfig{
		Issuer:   "https://zdas.example.com",
		Audience: "ziti-enrolltocert",
		Expiry:   300_000_000_000, // 5 min in nanoseconds
	}
	signed, err := MintToken(tokenCfg, claims, ks)
	if err != nil {
		t.Fatalf("MintToken: %v", err)
	}

	jwksBytes, _ := JWKS(ks)
	pubSet, _ := jwk.Parse(jwksBytes)
	tok, err := jwt.Parse([]byte(signed), jwt.WithKeySet(pubSet, jws.WithInferAlgorithmFromKey(true)))
	if err != nil {
		t.Fatalf("parse+verify: %v", err)
	}

	if stringClaim(tok, "iss") != "https://zdas.example.com" {
		t.Errorf("issuer = %q", stringClaim(tok, "iss"))
	}
	idName := claim(tok, "device_identity_name")
	if idName != "alice-laptop" {
		t.Errorf("device_identity_name = %v", idName)
	}
	extID := claim(tok, "device_external_id")
	if extID == nil || extID == "" {
		t.Error("device_external_id missing from token")
	}
	if stringClaim(tok, "sub") != extID {
		t.Errorf("sub = %q, device_external_id = %q, want equal", stringClaim(tok, "sub"), extID)
	}
}

// TestClaimsSurviveJSONRoundTrip verifies that AuthCode.Claims can be held in
// an external Store: claims decoded from JSON, where numbers become float64
// and arrays []interface{}, must mint the same token claims as the originals.
func TestClaimsSurviveJSONRoundTrip(t *testing.T) {
	ks, err := GenerateKeySet()
	if err != nil {
		t.Fatalf("GenerateKeySet: %v", err)
	}
	identity := &UpstreamIdentity{
		Subject:  "u1",
		Username: "alice",
		Issuer:   "https://idp",
		Raw:      map[string]any{"preferred_username": "alice"},
	}
	fbCfg := FallbackConfig{Enabled: true}
	tokenCfg := TokenConfig{Issuer: "https://zdas.test", Audience: "ziti", Expiry: time.Minute}

	for name, claims := range map[string]map[string]any{
		"composed":         ComposeClaims(defaultClaimsConfig(), fbCfg, identity, &DeviceInfo{DeviceName: "laptop", OS: "darwin"}, ""),
		"composedFallback": ComposeClaims(defaultClaimsConfig(), fbCfg, identity, &DeviceInfo{}, "0123456789abcdef"),
		"provisioner": {
			"sub":       "ext-1",
			"jti":       "j1",
			"nbf":       time.Now().Unix(),
			"count":     42,
			"ratio":     0.5,
			"groups":    []string{"a", "b"},
			"enabled":   true,
			"structure": map[string]any{"k": []int{1, 2}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			data, err := json.Marshal(claims)
			if err != nil {
				t.Fatalf("marshal claims: %v", err)
			}
			var decoded map[string]any
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("unmarshal claims: %v", err)
			}
			want := mintedClaims(t, tokenCfg, claims, ks)
			got := mintedClaims(t, tokenCfg, decoded, ks)
			if got != want {
				t.Errorf("claims changed by JSON round trip:\n got  %s\n want %s", got, want)
			}
		})
	}
}

// mintedClaims mints a token from claims and returns its payload as JSON,
// without iat and exp, which differ between calls.
func mintedClaims(t *testing.T, cfg TokenConfig, claims map[string]any, ks *KeySet) string {
	t.Helper()
	signed, err := MintToken(cfg, claims, ks)
	if err != nil {
		t.Fatalf("MintToken: %v", err)
	}
	payload, err := jws.ParseString(signed)
	if err != nil {
		t.Fatalf("parse jws: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(payload.Payload(), &m); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	delete(m, "iat")
	delete(m, "exp")
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return string(out)
}

// TestMintTokenRejectsMistypedClaim verifies that a registered claim with a
// value of the wrong type fails the mint instead of vanishing from the token.
func TestMintTokenRejectsMistypedClaim(t *testing.T) {
	ks, err := GenerateKeySet()
	if err != nil {
		t.Fatal(err)
	}
	cfg := TokenConfig{Issuer: "https://zdas.test", Audience: "ziti-enroll", Expiry: time.Minute}
	if _, err := MintToken(cfg, map[string]any{"sub": 123}, ks); err == nil {
		t.Error("MintToken accepted a numeric sub")
	}
}

// TestExpandTemplateSinglePass verifies that a value containing a
// placeholder is inserted as is, not expanded again.
func TestExpandTemplateSinglePass(t *testing.T) {
	got := expandTemplate("{username}-{device_name}", "{hostname}", &DeviceInfo{DeviceName: "laptop", Hostname: "secret-host"})
	if got != "{hostname}-laptop" {
		t.Errorf("expandTemplate = %q, want %q", got, "{hostname}-laptop")
	}
	if got := expandFallbackTemplate("{username}-{nonce_short}", "{nonce_short}", "abc"); got != "{nonce_short}-abc" {
		t.Errorf("expandFallbackTemplate = %q, want %q", got, "{nonce_short}-abc")
	}
}

// claim returns the value of the named claim in tok, or nil if it has none.
func claim(tok jwt.Token, name string) any {
	var v any
	if err := tok.Get(name, &v); err != nil {
		return nil
	}
	return v
}

// stringClaim returns the named claim in tok as a string, or "" if it has
// none or it is not a string.
func stringClaim(tok jwt.Token, name string) string {
	s, _ := claim(tok, name).(string)
	return s
}

// TestComposeClaimsExternalIDWins verifies that even with a claim name that
// collides with another claim, which Validate rejects, the external ID is
// not replaced by a value the user controls.
func TestComposeClaimsExternalIDWins(t *testing.T) {
	identity := &UpstreamIdentity{Subject: "u1", Username: "victim", Issuer: "https://idp"}
	info := &DeviceInfo{DeviceName: "laptop"}
	for _, name := range []string{"device_name", "preferred_username"} {
		cfg := defaultClaimsConfig()
		cfg.ExternalIDClaim = name
		claims := ComposeClaims(cfg, FallbackConfig{}, identity, info, "")
		if want := computeExternalID("https://idp", "u1", "laptop"); claims[name] != want {
			t.Errorf("external_id_claim %q: claim = %v, want the external ID", name, claims[name])
		}
	}
}

func TestTokenConfigAudience(t *testing.T) {
	cfg := TokenConfig{Audience: "ziti-enroll", ProvisionerAudiences: []string{"net-a", "net-b"}}
	cases := []struct {
		claims  map[string]any
		want    string
		wantErr bool
	}{
		{map[string]any{"sub": "x"}, "ziti-enroll", false},
		{map[string]any{"aud": "net-b"}, "net-b", false},
		{map[string]any{"aud": "ziti-enroll"}, "ziti-enroll", false},
		{map[string]any{"aud": "net-c"}, "", true},
		{map[string]any{"aud": []string{"net-a"}}, "", true},
		{map[string]any{"aud": ""}, "", true},
	}
	for _, tc := range cases {
		got, err := cfg.audience(tc.claims)
		if got != tc.want || (err != nil) != tc.wantErr {
			t.Errorf("audience(%v) = %q, %v; want %q, err %v", tc.claims, got, err, tc.want, tc.wantErr)
		}
	}
}

// TestMintTokenProvisionerAudience verifies that a token takes an allowed
// aud from its claims, and that any other aud is refused rather than signed.
func TestMintTokenProvisionerAudience(t *testing.T) {
	ks, _ := GenerateKeySet()
	cfg := TokenConfig{Issuer: "https://zdas.test", Audience: "ziti-enroll", Expiry: time.Minute, ProvisionerAudiences: []string{"net-b"}}
	signed, err := MintToken(cfg, map[string]any{"sub": "x", "aud": "net-b"}, ks)
	if err != nil {
		t.Fatalf("MintToken: %v", err)
	}
	tok, err := jwt.ParseInsecure([]byte(signed))
	if err != nil {
		t.Fatal(err)
	}
	if aud, _ := tok.Audience(); !slices.Equal(aud, []string{"net-b"}) {
		t.Errorf("aud = %v, want [net-b]", aud)
	}
	if _, err := MintToken(cfg, map[string]any{"sub": "x", "aud": "net-c"}, ks); err == nil {
		t.Error("MintToken signed a token for an audience not configured")
	}
}
