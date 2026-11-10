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
    allow_any_user: true
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
			{Type: "github", Name: "dup", ClientID: "a", ClientSecret: "b", AllowAnyUser: true},
			{Type: "github", Name: "dup", ClientID: "c", ClientSecret: "d", AllowAnyUser: true},
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
			{Type: "oidc", Name: "kc", ClientID: "c", OIDCIssuerURL: "https://kc.example.com", AllowedEmailDomains: []string{"example.com"}},
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
    required_claims:
      groups: [ziti-users]
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
		{"no host rejected", "https:///pick-idp", true},
		{"malformed rejected", "https://app.example.com/%zz", true},
		{"upper-case scheme rejected", "HTTPS://app.example.com/pick-idp", true},
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

// TestValidateURLs checks that Validate refuses only a URL no request can
// use, and leaves the URLs it accepts as they are, trailing slashes
// included. An upper-case scheme is refused in external_url, which must
// match byte for byte, and passes in the others.
func TestValidateURLs(t *testing.T) {
	cases := []struct {
		name    string
		field   func(*Config) *string
		url     string
		wantErr string // "" when the URL is accepted
	}{
		{"external_url with trailing slash", externalURLField, "https://das.example.com/", ""},
		{"external_url under a prefix", externalURLField, "https://example.com/zdas", ""},
		{"external_url with a port", externalURLField, "http://127.0.0.1:18443", ""},
		{"external_url with no host", externalURLField, "https:///zdas", "external_url: host is required"},
		{"external_url with only a port", externalURLField, "https://:18443", "external_url: host is required"},
		{"external_url that doesn't parse", externalURLField, "https://das example.com", "external_url: invalid character"},
		{"external_url with a bad escape", externalURLField, "https://das.example.com/100%/zdas", "external_url: invalid URL escape"},
		{"external_url with an upper-case scheme", externalURLField, "HTTPS://das.example.com", "external_url must be an http(s) URL"},

		{"api_url root", apiURLField, "https://controller.example.com:1280", ""},
		{"api_url with trailing slash", apiURLField, "https://controller.example.com:1280/", ""},
		{"api_url as an Edge API URL", apiURLField, "https://controller.example.com:1280/edge/client/v1", ""},
		{"api_url with an IPv6 host", apiURLField, "https://[::1]:1280", ""},
		{"api_url with an upper-case scheme", apiURLField, "HTTPS://controller.example.com", ""},
		{"api_url with userinfo", apiURLField, "https://user:pw@controller.example.com", ""},
		{"api_url with no scheme", apiURLField, "controller.example.com:1280", "controller.api_url: missing http:// or https://"},
		{"api_url host:port only", apiURLField, "localhost:1280", "controller.api_url: missing http:// or https://"},
		{"api_url IP:port only", apiURLField, "10.0.0.1:1280", "controller.api_url: missing http:// or https://"},
		{"api_url with no host", apiURLField, "https://", "controller.api_url: host is required"},
		{"api_url with only a port", apiURLField, "http://:1280", "controller.api_url: host is required"},
		{"api_url with a bad port", apiURLField, "http://a:b:c", "controller.api_url: invalid port"},
		{"api_url not http", apiURLField, "tls://controller.example.com:1280", `controller.api_url: scheme must be http or https, not "tls"`},

		{"issuer with trailing slash", issuerURLField, "https://tenant.auth0.com/", ""},
		{"issuer without trailing slash", issuerURLField, "https://example.okta.com", ""},
		{"issuer with a path", issuerURLField, "https://kc.example.com/realms/zdas", ""},
		// Discovery then fails, since the IdP's issuer doesn't match it.
		{"issuer with an upper-case scheme", issuerURLField, "HTTPS://kc.example.com", ""},
		{"issuer with no scheme", issuerURLField, "kc.example.com", "providers[0] (kc): oidc_issuer_url: missing http:// or https://"},
		{"issuer with no host", issuerURLField, "https:///realms/zdas", "providers[0] (kc): oidc_issuer_url: host is required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{
				ExternalURL: "https://das.example.com",
				Controller:  ControllerConfig{APIURL: "https://c"},
				Providers: []ProviderConfig{
					{Type: "oidc", Name: "kc", ClientID: "c", OIDCIssuerURL: "https://kc.example.com", AllowAnyUser: true},
				},
			}
			*tc.field(cfg) = tc.url
			cfg.ApplyDefaults()
			err := cfg.Validate()
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("Validate(%q) = %v, want nil", tc.url, err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("Validate(%q) = %v, want an error containing %q", tc.url, err, tc.wantErr)
			}
			if got := *tc.field(cfg); got != tc.url {
				t.Errorf("the configured URL %q was changed to %q", tc.url, got)
			}
		})
	}
}

func externalURLField(c *Config) *string { return &c.ExternalURL }
func apiURLField(c *Config) *string      { return &c.Controller.APIURL }
func issuerURLField(c *Config) *string   { return &c.Providers[0].OIDCIssuerURL }

func TestValidateIssuerURLByProvider(t *testing.T) {
	cfg := &Config{
		ExternalURL: "https://das.example.com",
		Controller:  ControllerConfig{APIURL: "https://c"},
		Providers: []ProviderConfig{
			// A github provider has no issuer, so a stray one is ignored.
			{Type: "github", Name: "gh", ClientID: "c", ClientSecret: "s", OIDCIssuerURL: "junk", AllowAnyUser: true},
			{Type: "oidc", Name: "kc", ClientID: "c", OIDCIssuerURL: "kc.example.com", AllowAnyUser: true},
		},
	}
	cfg.ApplyDefaults()
	want := "providers[1] (kc): oidc_issuer_url: missing http:// or https://"
	if err := cfg.Validate(); err == nil || err.Error() != want {
		t.Errorf("Validate = %v, want %q", err, want)
	}
}

// TestValidateURLErrorHidesPassword checks that a URL Validate refuses
// isn't quoted in the error, since it may hold a password.
func TestValidateURLErrorHidesPassword(t *testing.T) {
	cases := map[string]func(*Config){
		"api_url that doesn't parse": func(c *Config) {
			c.Controller.APIURL = "https://user:s3cret@controller.example.com:bad"
		},
		"allowed_redirect_uris entry with userinfo": func(c *Config) {
			c.AllowedRedirectURIs = []string{"https://user:s3cret@app.example.com/cb"}
		},
	}
	for name, set := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := &Config{
				ExternalURL: "https://das.example.com",
				Controller:  ControllerConfig{APIURL: "https://c"},
			}
			set(cfg)
			cfg.ApplyDefaults()
			err := cfg.Validate()
			if err == nil {
				t.Fatal("Validate = nil, want an error")
			}
			if strings.Contains(err.Error(), "s3cret") {
				t.Errorf("Validate = %v, which quotes the password", err)
			}
		})
	}
}

func TestLoadConfigAPIURLEnvValidated(t *testing.T) {
	path := writeTempConfig(t, minimalYAML)
	t.Setenv("ZDAS_CONTROLLER_API_URL", "localhost:1280")

	_, err := LoadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "controller.api_url: missing http:// or https://") {
		t.Errorf("LoadConfig = %v, want the api_url error", err)
	}
}

func TestValidateIDPSelectorAlways(t *testing.T) {
	for _, tc := range []struct {
		url     string
		wantErr bool
	}{
		{"", true},
		{"/enroll/pick-idp", false},
	} {
		cfg := &Config{
			ExternalURL:       "https://das.example.com",
			Controller:        ControllerConfig{APIURL: "https://c"},
			IDPSelectorURL:    tc.url,
			IDPSelectorAlways: true,
		}
		cfg.ApplyDefaults()
		err := cfg.Validate()
		if (err != nil) != tc.wantErr || (err != nil && !strings.Contains(err.Error(), "idp_selector_always")) {
			t.Errorf("idp_selector_always with idp_selector_url %q: Validate = %v, want an idp_selector_always error %v", tc.url, err, tc.wantErr)
		}
	}
}

// TestIDPSelectorAlwaysLoad verifies idp_selector_always from YAML and from
// the environment, through LoadConfig.
func TestIDPSelectorAlwaysLoad(t *testing.T) {
	if _, err := LoadConfig(writeTempConfig(t, minimalYAML+"idp_selector_always: true\n")); err == nil || !strings.Contains(err.Error(), "idp_selector_always") {
		t.Errorf("idp_selector_always without idp_selector_url: LoadConfig = %v, want an error", err)
	}

	path := writeTempConfig(t, minimalYAML+"idp_selector_url: /pick\nidp_selector_always: true\n")
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if !cfg.IDPSelectorAlways {
		t.Error("idp_selector_always: true not loaded")
	}

	t.Setenv("ZDAS_IDP_SELECTOR_ALWAYS", "false")
	if cfg, err = LoadConfig(path); err != nil || cfg.IDPSelectorAlways {
		t.Errorf("env false over YAML true: %v, %v; want false", cfg.IDPSelectorAlways, err)
	}
	t.Setenv("ZDAS_IDP_SELECTOR_ALWAYS", "maybe")
	if _, err := LoadConfig(path); err == nil {
		t.Error("ZDAS_IDP_SELECTOR_ALWAYS=maybe accepted")
	}
}

func TestIDPSelectorURLEnvOverride(t *testing.T) {
	path := writeTempConfig(t, minimalYAML)
	t.Setenv("ZDAS_IDP_SELECTOR_URL", "https://app.example.com/pick-idp")
	t.Setenv("ZDAS_IDP_SELECTOR_ALWAYS", "true")

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.IDPSelectorURL != "https://app.example.com/pick-idp" {
		t.Errorf("IDPSelectorURL env override = %q", cfg.IDPSelectorURL)
	}
	if !cfg.IDPSelectorAlways {
		t.Error("IDPSelectorAlways env override not applied")
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
		{"identity name in nonce", "nonce", "device_external_id", true},
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

// TestValidateProviderPolicy verifies that a configured provider needs a
// policy or allow_any_user, not both, and only the policies its type has.
func TestValidateProviderPolicy(t *testing.T) {
	gh := ProviderConfig{Type: ProviderTypeGitHub, Name: "gh", ClientID: "c", ClientSecret: "s"}
	oidc := ProviderConfig{Type: ProviderTypeOIDC, Name: "kc", ClientID: "c", OIDCIssuerURL: "https://kc"}
	with := func(p ProviderConfig, f func(*ProviderConfig)) ProviderConfig { f(&p); return p }
	cases := []struct {
		name    string
		p       ProviderConfig
		wantErr string
	}{
		{"github open", gh, "allow_any_user: true"},
		{"github orgs", with(gh, func(p *ProviderConfig) { p.AllowedOrgs = []string{"acme"} }), ""},
		{"github any user", with(gh, func(p *ProviderConfig) { p.AllowAnyUser = true }), ""},
		{"github both", with(gh, func(p *ProviderConfig) { p.AllowedOrgs = []string{"acme"}; p.AllowAnyUser = true }), "conflicts"},
		{"github with oidc policy", with(gh, func(p *ProviderConfig) { p.AllowedEmailDomains = []string{"acme.com"} }), "are for oidc"},
		{"oidc open", oidc, "allow_any_user: true"},
		{"oidc domains", with(oidc, func(p *ProviderConfig) { p.AllowedEmailDomains = []string{"acme.com"} }), ""},
		{"oidc claims", with(oidc, func(p *ProviderConfig) { p.RequiredClaims = map[string][]string{"groups": {"z"}} }), ""},
		{"oidc any user", with(oidc, func(p *ProviderConfig) { p.AllowAnyUser = true }), ""},
		{"oidc with orgs", with(oidc, func(p *ProviderConfig) { p.AllowedOrgs = []string{"acme"} }), "is for github"},
		{"oidc claim without values", with(oidc, func(p *ProviderConfig) { p.RequiredClaims = map[string][]string{"groups": nil} }), "lists no values"},
		{"dot name", with(gh, func(p *ProviderConfig) { p.Name = "."; p.AllowAnyUser = true }), "callback path segment"},
		{"name with a space", with(oidc, func(p *ProviderConfig) { p.Name = "Keycloak Prod"; p.AllowAnyUser = true }), ""},
		{"name at the length limit", with(oidc, func(p *ProviderConfig) { p.Name = strings.Repeat("k", maxProviderNameLength); p.AllowAnyUser = true }), ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{ExternalURL: "https://das.example.com", Controller: ControllerConfig{APIURL: "https://c"}, Providers: []ProviderConfig{tc.p}}
			cfg.ApplyDefaults()
			err := cfg.Validate()
			if tc.wantErr == "" && err != nil {
				t.Errorf("Validate: %v", err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Errorf("Validate = %v, want an error containing %q", err, tc.wantErr)
			}
		})
	}
}
