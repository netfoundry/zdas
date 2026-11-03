package zdas

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const minimalYAML = `
external_url: "https://das.example.com"
controller:
  api_url: "https://controller.example.com:1280"
`

func writeTempConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	return path
}

func TestLoadConfigDefaults(t *testing.T) {
	path := writeTempConfig(t, minimalYAML)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if cfg.Listen != ":18443" {
		t.Errorf("Listen default = %q, want :18443", cfg.Listen)
	}
	if cfg.TLS.Mode != TLSModeNone {
		t.Errorf("TLS.Mode default = %q, want none", cfg.TLS.Mode)
	}
	if cfg.Controller.PollInterval != 5*time.Minute {
		t.Errorf("Controller.PollInterval default = %v, want 5m", cfg.Controller.PollInterval)
	}
	if cfg.Controller.SelfIssuer != cfg.ExternalURL {
		t.Errorf("Controller.SelfIssuer should default to ExternalURL, got %q", cfg.Controller.SelfIssuer)
	}
	if cfg.Claims.UsernameClaim != "preferred_username" {
		t.Errorf("Claims.UsernameClaim default = %q", cfg.Claims.UsernameClaim)
	}
	if cfg.Claims.NameTemplate != "{username}-{device_name}" {
		t.Errorf("Claims.NameTemplate default = %q", cfg.Claims.NameTemplate)
	}
	if cfg.Claims.IdentityNameClaim != "device_identity_name" {
		t.Errorf("Claims.IdentityNameClaim default = %q", cfg.Claims.IdentityNameClaim)
	}
	if cfg.Claims.ExternalIDClaim != "device_external_id" {
		t.Errorf("Claims.ExternalIDClaim default = %q", cfg.Claims.ExternalIDClaim)
	}
	if cfg.Token.Issuer != cfg.ExternalURL {
		t.Errorf("Token.Issuer should default to ExternalURL, got %q", cfg.Token.Issuer)
	}
	if cfg.Token.Audience != "ziti-enroll" {
		t.Errorf("Token.Audience default = %q", cfg.Token.Audience)
	}
	if cfg.Token.Expiry != 5*time.Minute {
		t.Errorf("Token.Expiry default = %v", cfg.Token.Expiry)
	}
	if cfg.Session.Timeout != 10*time.Minute {
		t.Errorf("Session.Timeout default = %v", cfg.Session.Timeout)
	}
	if cfg.Session.CodeExpiry != 60*time.Second {
		t.Errorf("Session.CodeExpiry default = %v", cfg.Session.CodeExpiry)
	}
	if cfg.Fallback.Enabled {
		t.Error("Fallback.Enabled should default to false")
	}
	if cfg.Fallback.PollInterval != 10*time.Second {
		t.Errorf("Fallback.PollInterval default = %v, want 10s", cfg.Fallback.PollInterval)
	}
	if cfg.Fallback.TempNameTemplate != "{username}-pending-{nonce_short}" {
		t.Errorf("Fallback.TempNameTemplate default = %q", cfg.Fallback.TempNameTemplate)
	}
	if cfg.Fallback.Timeout != 1*time.Hour {
		t.Errorf("Fallback.Timeout default = %v, want 1h", cfg.Fallback.Timeout)
	}
}

func TestLoadConfigEnvOverrides(t *testing.T) {
	path := writeTempConfig(t, minimalYAML)
	t.Setenv("ZDAS_LISTEN", ":9999")
	t.Setenv("ZDAS_CONTROLLER_POLL_INTERVAL", "30s")
	t.Setenv("ZDAS_TOKEN_AUDIENCE", "custom-audience")

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Listen != ":9999" {
		t.Errorf("Listen env override = %q", cfg.Listen)
	}
	if cfg.Controller.PollInterval != 30*time.Second {
		t.Errorf("PollInterval env override = %v", cfg.Controller.PollInterval)
	}
	if cfg.Token.Audience != "custom-audience" {
		t.Errorf("Token.Audience env override = %q", cfg.Token.Audience)
	}
}

func TestLoadConfigProviderSecretEnvOverride(t *testing.T) {
	yaml := minimalYAML + `
providers:
  - type: github
    name: gh-prod
    client_id: "placeholder"
    client_secret: "placeholder"
`
	path := writeTempConfig(t, yaml)
	t.Setenv("ZDAS_PROVIDER_GH_PROD_CLIENT_SECRET", "real-secret")

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(cfg.Providers) != 1 {
		t.Fatalf("providers: %d", len(cfg.Providers))
	}
	if cfg.Providers[0].ClientSecret != "real-secret" {
		t.Errorf("ClientSecret env override = %q", cfg.Providers[0].ClientSecret)
	}
	if cfg.Providers[0].UsernameField != "login" {
		t.Errorf("github UsernameField default = %q", cfg.Providers[0].UsernameField)
	}
	if cfg.Providers[0].UserIDField != "id" {
		t.Errorf("github UserIDField default = %q", cfg.Providers[0].UserIDField)
	}
}

func TestValidateRequiresExternalURL(t *testing.T) {
	cfg := &Config{Controller: ControllerConfig{APIURL: "https://c"}}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "external_url") {
		t.Errorf("expected external_url error, got %v", err)
	}
}

func TestValidateRequiresControllerAPIURL(t *testing.T) {
	cfg := &Config{ExternalURL: "https://das.example.com"}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "controller.api_url") {
		t.Errorf("expected controller.api_url error, got %v", err)
	}
}

func TestValidateTLSStaticRequiresFiles(t *testing.T) {
	cfg := &Config{
		ExternalURL: "https://das.example.com",
		TLS:         TLSConfig{Mode: TLSModeStatic},
		Controller:  ControllerConfig{APIURL: "https://c"},
	}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "cert_file") {
		t.Errorf("expected static TLS file error, got %v", err)
	}
}

func TestValidateTLSACMERequiresDomains(t *testing.T) {
	cfg := &Config{
		ExternalURL: "https://das.example.com",
		TLS:         TLSConfig{Mode: TLSModeACME, ACME: ACMEConfig{CacheDir: "/tmp"}},
		Controller:  ControllerConfig{APIURL: "https://c"},
	}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "domain") {
		t.Errorf("expected acme domains error, got %v", err)
	}
}

func TestValidateRejectsDuplicateProviderNames(t *testing.T) {
	cfg := &Config{
		ExternalURL: "https://das.example.com",
		Controller:  ControllerConfig{APIURL: "https://c"},
		Providers: []ProviderConfig{
			{Type: "github", Name: "dup", ClientID: "a", ClientSecret: "b"},
			{Type: "github", Name: "dup", ClientID: "c", ClientSecret: "d"},
		},
	}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("expected duplicate provider name error, got %v", err)
	}
}

func TestValidateGithubRequiresSecret(t *testing.T) {
	cfg := &Config{
		ExternalURL: "https://das.example.com",
		Controller:  ControllerConfig{APIURL: "https://c"},
		Providers: []ProviderConfig{
			{Type: "github", Name: "gh", ClientID: "abc"},
		},
	}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "client_secret") {
		t.Errorf("expected github client_secret error, got %v", err)
	}
}

func TestValidateOIDCRequiresIssuerAndClientID(t *testing.T) {
	cases := []struct {
		name string
		p    ProviderConfig
	}{
		{"missing both", ProviderConfig{Type: "oidc", Name: "kc"}},
		{"missing issuer", ProviderConfig{Type: "oidc", Name: "kc", ClientID: "c"}},
		{"missing client_id", ProviderConfig{Type: "oidc", Name: "kc", OIDCIssuerURL: "https://kc"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{
				ExternalURL: "https://das.example.com",
				Controller:  ControllerConfig{APIURL: "https://c"},
				Providers:   []ProviderConfig{tc.p},
			}
			cfg.ApplyDefaults()
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "oidc_issuer_url") {
				t.Errorf("expected oidc_issuer_url error, got %v", err)
			}
		})
	}
}

func TestValidateOIDCAccepts(t *testing.T) {
	cfg := &Config{
		ExternalURL: "https://das.example.com",
		Controller:  ControllerConfig{APIURL: "https://c"},
		Providers: []ProviderConfig{
			{Type: "oidc", Name: "kc", ClientID: "c", OIDCIssuerURL: "https://kc.example.com"},
		},
	}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		t.Errorf("valid oidc config rejected: %v", err)
	}
}

func TestValidateRequireUserInfoNeedsFetch(t *testing.T) {
	cfg := &Config{
		ExternalURL: "https://das.example.com",
		Controller:  ControllerConfig{APIURL: "https://c"},
		Providers: []ProviderConfig{
			{Type: "oidc", Name: "kc", ClientID: "c", OIDCIssuerURL: "https://kc.example.com", RequireUserInfo: true},
		},
	}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "fetch_userinfo") {
		t.Errorf("expected require_userinfo error, got %v", err)
	}
}

func TestLoadConfigOIDCUserInfoFields(t *testing.T) {
	path := writeTempConfig(t, minimalYAML+`
providers:
  - type: oidc
    name: okta
    client_id: c
    oidc_issuer_url: https://okta.example.com
    fetch_userinfo: true
    require_userinfo: true
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	p := cfg.Providers[0]
	if !p.FetchUserInfo || !p.RequireUserInfo {
		t.Errorf("FetchUserInfo = %v, RequireUserInfo = %v, want both true", p.FetchUserInfo, p.RequireUserInfo)
	}
}

func TestValidateNameTemplateMustContainPlaceholders(t *testing.T) {
	cfg := &Config{
		ExternalURL: "https://das.example.com",
		Controller:  ControllerConfig{APIURL: "https://c"},
		Claims:      ClaimsConfig{NameTemplate: "{username}-only"},
	}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "device_name") {
		t.Errorf("expected name_template placeholder error, got %v", err)
	}
}

func TestValidateFallbackWithoutIdentityFile(t *testing.T) {
	cfg := &Config{
		ExternalURL: "https://das.example.com",
		Controller:  ControllerConfig{APIURL: "https://c"},
		Fallback:    FallbackConfig{Enabled: true},
	}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		t.Errorf("fallback without identity_file should be valid, got %v", err)
	}
}

func TestValidateFallbackTempTemplateMustContainUsername(t *testing.T) {
	cfg := &Config{
		ExternalURL: "https://das.example.com",
		Controller:  ControllerConfig{APIURL: "https://c", IdentityFile: "/tmp/id.json"},
		Fallback:    FallbackConfig{Enabled: true, TempNameTemplate: "no-username-{nonce_short}"},
	}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "temp_name_template") {
		t.Errorf("expected temp_name_template error, got %v", err)
	}
}

func TestValidateIDPSelectorURL(t *testing.T) {
	cases := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"empty ok", "", false},
		{"https ok", "https://app.example.com/pick-idp", false},
		{"http ok", "http://app.example.com/pick-idp", false},
		{"absolute path ok", "/enroll/pick-idp", false},
		{"with query ok", "https://app.example.com/pick-idp?source=zdas", false},
		{"bare word rejected", "not-a-url", true},
		{"ftp rejected", "ftp://nope", true},
		{"relative path rejected", "enroll/pick", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{
				ExternalURL:    "https://das.example.com",
				Controller:     ControllerConfig{APIURL: "https://c"},
				IDPSelectorURL: tc.url,
			}
			cfg.ApplyDefaults()
			err := cfg.Validate()
			if tc.wantErr && err == nil {
				t.Errorf("expected error for %q, got nil", tc.url)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error for %q: %v", tc.url, err)
			}
		})
	}
}

func TestIDPSelectorURLEnvOverride(t *testing.T) {
	path := writeTempConfig(t, minimalYAML)
	t.Setenv("ZDAS_IDP_SELECTOR_URL", "https://app.example.com/pick-idp")

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.IDPSelectorURL != "https://app.example.com/pick-idp" {
		t.Errorf("IDPSelectorURL env override = %q", cfg.IDPSelectorURL)
	}
}

func TestFallbackEnvOverride(t *testing.T) {
	path := writeTempConfig(t, minimalYAML)
	t.Setenv("ZDAS_FALLBACK_ENABLED", "true")
	t.Setenv("ZDAS_FALLBACK_POLL_INTERVAL", "30s")
	t.Setenv("ZDAS_CONTROLLER_IDENTITY_FILE", "/tmp/id.json")

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if !cfg.Fallback.Enabled {
		t.Error("Fallback.Enabled env override failed")
	}
	if cfg.Fallback.PollInterval != 30*time.Second {
		t.Errorf("Fallback.PollInterval env override = %v", cfg.Fallback.PollInterval)
	}
	if cfg.Controller.IdentityFile != "/tmp/id.json" {
		t.Errorf("Controller.IdentityFile env override = %q", cfg.Controller.IdentityFile)
	}
}

func TestEnvProviderKey(t *testing.T) {
	cases := map[string]string{
		"github":        "GITHUB",
		"gh-prod":       "GH_PROD",
		"Keycloak v2":   "KEYCLOAK_V2",
		"foo.bar":       "FOO_BAR",
		"already_upper": "ALREADY_UPPER",
	}
	for in, want := range cases {
		if got := envProviderKey(in); got != want {
			t.Errorf("envProviderKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSetBool(t *testing.T) {
	cases := []struct {
		val     string
		want    bool
		wantErr bool
	}{
		{"true", true, false},
		{"TRUE", true, false},
		{"1", true, false},
		{"yes", true, false},
		{"Yes", true, false},
		{"false", false, false},
		{"0", false, false},
		{"no", false, false},
		{"on", false, true},
		{"", false, true},
	}
	for _, tc := range cases {
		t.Setenv("ZDAS_TEST_BOOL", tc.val)
		got := !tc.want // so a no-op shows up
		err := setBool(&got, "ZDAS_TEST_BOOL")
		if (err != nil) != tc.wantErr {
			t.Errorf("setBool(%q) err = %v, wantErr %v", tc.val, err, tc.wantErr)
			continue
		}
		if err == nil && got != tc.want {
			t.Errorf("setBool(%q) = %v, want %v", tc.val, got, tc.want)
		}
	}
}

// TestNewServerRequiresDefaults verifies that a config that skipped
// ApplyDefaults is refused rather than minting tokens that are already
// expired.
func TestNewServerRequiresDefaults(t *testing.T) {
	cfg := Config{
		ExternalURL: "https://zdas.test",
		Controller:  ControllerConfig{APIURL: "https://ctrl"},
		Token:       TokenConfig{Issuer: "https://zdas.test", Audience: "ziti-enroll"},
	}
	if _, err := NewServer(cfg, slog.Default()); err == nil || !strings.Contains(err.Error(), "token.expiry") {
		t.Errorf("NewServer = %v, want a token.expiry error", err)
	}

	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate after ApplyDefaults: %v", err)
	}
	cfg.Session.Timeout = -time.Second
	if err := cfg.Validate(); err == nil {
		t.Error("Validate accepted a negative session timeout")
	}
}

// TestLoadConfigRejectsUnknownKeys verifies that a misspelled setting fails
// loading instead of leaving the control it names at its default.
func TestLoadConfigRejectsUnknownKeys(t *testing.T) {
	for name, body := range map[string]string{
		"misspelled allowed_orgs": minimalYAML + `
providers:
  - name: github
    type: github
    client_id: id
    client_secret: secret
    allowed_org: [netfoundry]
`,
		"misspelled rate_limit": minimalYAML + `
ratelimit:
  authorize_per_second: 1
`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadConfig(writeTempConfig(t, body)); err == nil {
				t.Error("LoadConfig accepted an unknown key")
			}
		})
	}
	if _, err := LoadConfig(writeTempConfig(t, "")); err == nil || strings.Contains(err.Error(), "parse config file") {
		t.Errorf("an empty file should fail validation, not parsing: %v", err)
	}
}

func TestClaimsCheckNames(t *testing.T) {
	cases := []struct {
		name, identity, external string
		wantErr                  bool
	}{
		{"defaults", "device_identity_name", "device_external_id", false},
		{"external ID in sub", "device_identity_name", "sub", false},
		{"same name", "x", "x", true},
		{"external ID in device_name", "device_identity_name", "device_name", true},
		{"external ID in preferred_username", "device_identity_name", "preferred_username", true},
		{"external ID in exp", "device_identity_name", "exp", true},
		{"identity name in sub", "sub", "device_external_id", true},
		{"identity name in upstream_iss", "upstream_iss", "device_external_id", true},
	}
	for _, tc := range cases {
		err := ClaimsConfig{IdentityNameClaim: tc.identity, ExternalIDClaim: tc.external}.checkNames()
		if (err != nil) != tc.wantErr {
			t.Errorf("%s: checkNames = %v, wantErr %v", tc.name, err, tc.wantErr)
		}
	}

	// Loading a config runs the check.
	body := minimalYAML + `
claims:
  external_id_claim: device_name
`
	if _, err := LoadConfig(writeTempConfig(t, body)); err == nil || !strings.Contains(err.Error(), "external_id_claim") {
		t.Errorf("LoadConfig = %v, want an external_id_claim error", err)
	}
}
