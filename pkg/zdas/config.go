package zdas

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// defaultFallbackPollInterval is how often the reconciler polls when
// fallback.poll_interval is unset.
const defaultFallbackPollInterval = 10 * time.Second

// TLS modes.
const (
	TLSModeNone   = "none"
	TLSModeStatic = "static"
	TLSModeACME   = "acme"
)

// Provider types.
const (
	ProviderTypeGitHub = "github"
	ProviderTypeOIDC   = "oidc"
)

// Config is the top-level ZDAS configuration.
type Config struct {
	Listen      string           `yaml:"listen"`
	ExternalURL string           `yaml:"external_url"`
	TLS         TLSConfig        `yaml:"tls"`
	Controller  ControllerConfig `yaml:"controller"`
	Fallback    FallbackConfig   `yaml:"fallback"`
	Providers   []ProviderConfig `yaml:"providers"`
	Claims      ClaimsConfig     `yaml:"claims"`
	Token       TokenConfig      `yaml:"token"`
	Session     SessionConfig    `yaml:"session"`

	// IDPSelectorURL, when set, replaces ZDAS's built-in HTML IdP picker.
	// When ZDAS would otherwise render its own picker (multiple providers
	// registered, no idp query param on /authorize), it 302-redirects to
	// this URL with the original /authorize query string preserved plus
	// an additional `providers` parameter containing a comma-separated
	// list of available IdP names.
	//
	// The embedding application is expected to render a branded picker
	// page and direct the user back to <ExternalURL>/authorize with the
	// original query string and an `idp=<name>` parameter selecting one
	// of the listed providers. The redirect target must be on a host the
	// embedding application controls; ZDAS does not validate or sanitize
	// the URL beyond requiring it to be set at startup. Operators must
	// not allow user input to influence this field.
	IDPSelectorURL string `yaml:"idp_selector_url"`

	// AllowedRedirectURIs restricts which redirect_uri values the /authorize
	// endpoint will accept. When empty (the default), only loopback
	// callbacks are accepted: http or https to "localhost" or a loopback IP
	// literal, on any port. Tunnelers always use one, so most deployments
	// should leave this unset.
	//
	// When set, it replaces the loopback default. A redirect_uri matches an
	// entry when the parsed scheme, host and port are equal, and the path
	// too if the entry has one. An entry for a loopback host with no port,
	// such as "http://localhost", matches any port. Entries are URLs, not
	// string prefixes, and a redirect_uri with userinfo never matches.
	AllowedRedirectURIs []string        `yaml:"allowed_redirect_uris"`
	RateLimit           RateLimitConfig `yaml:"rate_limit"`
}

// RateLimitConfig controls per-client rate limiting on the /authorize
// endpoint. When AuthorizePerSecond is zero (the default), rate limiting is
// disabled.
//
// A client is the peer address of the connection: an IPv4 address, or an
// IPv6 /64. Behind a reverse proxy, list the proxy in TrustedProxies so that
// requests are counted against the address the proxy reports in
// X-Forwarded-For; otherwise every request counts against the proxy.
// X-Forwarded-For is ignored from peers that are not listed, since any
// client can send it.
type RateLimitConfig struct {
	AuthorizePerSecond float64  `yaml:"authorize_per_second"` // sustained rate per client; 0 = disabled
	AuthorizeBurst     int      `yaml:"authorize_burst"`      // peak burst per client
	TrustedProxies     []string `yaml:"trusted_proxies"`      // IP addresses or CIDR prefixes
}

// TLSConfig selects and configures the TLS serving mode.
type TLSConfig struct {
	Mode     string     `yaml:"mode"`
	CertFile string     `yaml:"cert_file"`
	KeyFile  string     `yaml:"key_file"`
	ACME     ACMEConfig `yaml:"acme"`
}

// ACMEConfig configures autocert / Let's Encrypt.
type ACMEConfig struct {
	Domains  []string `yaml:"domains"`
	CacheDir string   `yaml:"cache_dir"`
}

// ControllerConfig describes how ZDAS reaches the Ziti controller to discover
// upstream ext-jwt-signers and (optionally) manage identities via the
// management API.
type ControllerConfig struct {
	APIURL       string        `yaml:"api_url"`
	IdentityFile string        `yaml:"identity_file"` // Ziti identity JSON (cert, key, CA)
	CABundle     string        `yaml:"ca_bundle"`     // PEM CA bundle for controller TLS (when no identity file)
	PollInterval time.Duration `yaml:"poll_interval"`
	SelfIssuer   string        `yaml:"self_issuer"`
}

// FallbackConfig controls the fallback enrollment path for unmodified tunnelers
// that don't send device_name.
type FallbackConfig struct {
	Enabled          bool          `yaml:"enabled"`
	PollInterval     time.Duration `yaml:"poll_interval"`
	TempNameTemplate string        `yaml:"temp_name_template"`
	Timeout          time.Duration `yaml:"timeout"` // how long to track a fallback identity before giving up
}

// ProviderConfig is the config for an upstream provider configured directly in
// ZDAS (as opposed to discovered from the controller). Supports both OIDC and
// non-OIDC types; field applicability depends on Type.
type ProviderConfig struct {
	Type         string `yaml:"type"` // "github" | "oidc"
	Name         string `yaml:"name"`
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"` // required for github; optional for oidc (set when the IdP requires a confidential client, e.g. Google Web application)

	// OIDC-specific fields.
	OIDCIssuerURL string   `yaml:"oidc_issuer_url"` // base URL for OIDC discovery
	Scopes        []string `yaml:"scopes"`          // optional, defaults to openid+profile+email
	// FetchUserInfo merges the issuer's userinfo response into the upstream
	// identity's raw claims; see OIDCProviderConfig.FetchUserInfo. Default off.
	FetchUserInfo bool `yaml:"fetch_userinfo"`
	// RequireUserInfo makes a failed userinfo fetch fail the login. Requires
	// FetchUserInfo.
	RequireUserInfo bool `yaml:"require_userinfo"`

	// GitHub-specific fields.
	UsernameField string   `yaml:"username_field"`
	UserIDField   string   `yaml:"user_id_field"`
	AllowedOrgs   []string `yaml:"allowed_orgs"`
}

// ClaimsConfig controls how the ZDAS JWT claims are composed.
type ClaimsConfig struct {
	UsernameClaim     string `yaml:"username_claim"`
	NameTemplate      string `yaml:"name_template"`
	IdentityNameClaim string `yaml:"identity_name_claim"`
	ExternalIDClaim   string `yaml:"external_id_claim"`
}

// TokenConfig controls the ZDAS-issued token.
type TokenConfig struct {
	Issuer   string        `yaml:"issuer"`
	Audience string        `yaml:"audience"`
	Expiry   time.Duration `yaml:"expiry"`
}

// SessionConfig controls in-flight auth session and code lifetimes.
type SessionConfig struct {
	Timeout    time.Duration `yaml:"timeout"`
	CodeExpiry time.Duration `yaml:"code_expiry"`
}

// LoadConfig reads a YAML config file (if path is non-empty), applies environment
// variable overrides, fills in defaults, and validates the result.
func LoadConfig(path string) (*Config, error) {
	cfg := &Config{}
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read config file: %w", err)
		}
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parse config file: %w", err)
		}
	}
	if err := cfg.applyEnv(); err != nil {
		return nil, fmt.Errorf("apply env overrides: %w", err)
	}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// ApplyDefaults fills in any unset fields with sensible defaults. LoadConfig
// calls it after YAML parsing and env overrides, so that values neither
// source set are replaced. Embedding applications that construct Config
// directly must call it before passing the config to NewServer or
// NewHandler.
func (c *Config) ApplyDefaults() {
	if c.Listen == "" {
		c.Listen = ":18443"
	}
	if c.TLS.Mode == "" {
		c.TLS.Mode = TLSModeNone
	}
	if c.Controller.PollInterval == 0 {
		c.Controller.PollInterval = 5 * time.Minute
	}
	if c.Controller.SelfIssuer == "" {
		c.Controller.SelfIssuer = c.ExternalURL
	}
	if c.Claims.UsernameClaim == "" {
		c.Claims.UsernameClaim = preferredUsernameClaim
	}
	if c.Claims.NameTemplate == "" {
		c.Claims.NameTemplate = "{username}-{device_name}"
	}
	if c.Claims.IdentityNameClaim == "" {
		c.Claims.IdentityNameClaim = "device_identity_name"
	}
	if c.Claims.ExternalIDClaim == "" {
		c.Claims.ExternalIDClaim = "device_external_id"
	}
	if c.Token.Issuer == "" {
		c.Token.Issuer = c.ExternalURL
	}
	if c.Token.Audience == "" {
		c.Token.Audience = "ziti-enroll"
	}
	if c.Token.Expiry == 0 {
		c.Token.Expiry = 5 * time.Minute
	}
	if c.Session.Timeout == 0 {
		c.Session.Timeout = 10 * time.Minute
	}
	if c.Session.CodeExpiry == 0 {
		c.Session.CodeExpiry = 60 * time.Second
	}
	if c.Fallback.PollInterval == 0 {
		c.Fallback.PollInterval = defaultFallbackPollInterval
	}
	if c.Fallback.TempNameTemplate == "" {
		c.Fallback.TempNameTemplate = "{username}-pending-{nonce_short}"
	}
	if c.Fallback.Timeout == 0 {
		c.Fallback.Timeout = 1 * time.Hour
	}
	for i := range c.Providers {
		p := &c.Providers[i]
		if p.Type == ProviderTypeGitHub {
			if p.UsernameField == "" {
				p.UsernameField = "login"
			}
			if p.UserIDField == "" {
				p.UserIDField = "id"
			}
		}
	}
}

// Validate returns an error if the configuration is incomplete or inconsistent.
func (c *Config) Validate() error {
	if err := c.checkRequired(); err != nil {
		return err
	}
	if !strings.HasPrefix(c.ExternalURL, "http://") && !strings.HasPrefix(c.ExternalURL, "https://") {
		return errors.New("external_url must be an http(s) URL")
	}
	switch c.TLS.Mode {
	case TLSModeNone:
	case TLSModeStatic:
		if c.TLS.CertFile == "" || c.TLS.KeyFile == "" {
			return errors.New("tls.mode=static requires cert_file and key_file")
		}
	case TLSModeACME:
		if len(c.TLS.ACME.Domains) == 0 {
			return errors.New("tls.mode=acme requires at least one domain")
		}
		if c.TLS.ACME.CacheDir == "" {
			return errors.New("tls.mode=acme requires cache_dir")
		}
	default:
		return fmt.Errorf("tls.mode: unknown value %q (expected none|static|acme)", c.TLS.Mode)
	}
	if c.Controller.APIURL == "" {
		return errors.New("controller.api_url is required")
	}
	names := make(map[string]struct{}, len(c.Providers))
	for i, p := range c.Providers {
		if p.Name == "" {
			return fmt.Errorf("providers[%d]: name is required", i)
		}
		if _, dup := names[p.Name]; dup {
			return fmt.Errorf("providers[%d]: duplicate name %q", i, p.Name)
		}
		names[p.Name] = struct{}{}
		switch p.Type {
		case ProviderTypeGitHub:
			if p.ClientID == "" || p.ClientSecret == "" {
				return fmt.Errorf("providers[%d] (%s): client_id and client_secret are required for github", i, p.Name)
			}
		case ProviderTypeOIDC:
			if p.ClientID == "" || p.OIDCIssuerURL == "" {
				return fmt.Errorf("providers[%d] (%s): client_id and oidc_issuer_url are required for oidc", i, p.Name)
			}
			if p.RequireUserInfo && !p.FetchUserInfo {
				return fmt.Errorf("providers[%d] (%s): require_userinfo needs fetch_userinfo", i, p.Name)
			}
		case "":
			return fmt.Errorf("providers[%d] (%s): type is required", i, p.Name)
		default:
			return fmt.Errorf("providers[%d] (%s): unknown type %q", i, p.Name, p.Type)
		}
	}
	if !strings.Contains(c.Claims.NameTemplate, "{username}") || !strings.Contains(c.Claims.NameTemplate, "{device_name}") {
		return errors.New("claims.name_template must contain both {username} and {device_name}")
	}
	if c.Fallback.Enabled {
		if !strings.Contains(c.Fallback.TempNameTemplate, "{username}") {
			return errors.New("fallback.temp_name_template must contain {username}")
		}
	}
	if c.IDPSelectorURL != "" {
		if !strings.HasPrefix(c.IDPSelectorURL, "http://") &&
			!strings.HasPrefix(c.IDPSelectorURL, "https://") &&
			!strings.HasPrefix(c.IDPSelectorURL, "/") {
			return errors.New("idp_selector_url must be an http(s) URL or an absolute path")
		}
	}
	for i, raw := range c.AllowedRedirectURIs {
		if _, err := parseRedirectURI(raw); err != nil {
			return fmt.Errorf("allowed_redirect_uris[%d] %q: %w", i, raw, err)
		}
	}
	for i, raw := range c.RateLimit.TrustedProxies {
		if _, err := parseTrustedProxy(raw); err != nil {
			return fmt.Errorf("rate_limit.trusted_proxies[%d]: %w", i, err)
		}
	}
	return nil
}

// checkRequired returns an error for a setting NewServer cannot work
// without. ApplyDefaults fills in all but external_url, so a config that
// fails here usually skipped it: with a zero token expiry or session timeout,
// every token and session would be expired on arrival.
func (c *Config) checkRequired() error {
	switch {
	case c.ExternalURL == "":
		return errors.New("external_url is required")
	case c.Token.Issuer == "":
		return errors.New("token.issuer is required")
	case c.Token.Audience == "":
		return errors.New("token.audience is required")
	case c.Token.Expiry <= 0:
		return errors.New("token.expiry must be positive")
	case c.Session.Timeout <= 0:
		return errors.New("session.timeout must be positive")
	case c.Session.CodeExpiry <= 0:
		return errors.New("session.code_expiry must be positive")
	}
	return nil
}

// applyEnv overlays ZDAS_* environment variables onto the config. Only scalar
// fields are supported. Provider secrets are overridable per-provider via
// ZDAS_PROVIDER_<NAME>_CLIENT_ID and ZDAS_PROVIDER_<NAME>_CLIENT_SECRET where
// <NAME> is the upper-cased provider name with non-alphanumeric characters
// replaced by underscores.
func (c *Config) applyEnv() error {
	setString(&c.Listen, "ZDAS_LISTEN")
	setString(&c.ExternalURL, "ZDAS_EXTERNAL_URL")
	setString(&c.IDPSelectorURL, "ZDAS_IDP_SELECTOR_URL")

	setString(&c.TLS.Mode, "ZDAS_TLS_MODE")
	setString(&c.TLS.CertFile, "ZDAS_TLS_CERT_FILE")
	setString(&c.TLS.KeyFile, "ZDAS_TLS_KEY_FILE")
	setString(&c.TLS.ACME.CacheDir, "ZDAS_TLS_ACME_CACHE_DIR")

	setString(&c.Controller.APIURL, "ZDAS_CONTROLLER_API_URL")
	setString(&c.Controller.IdentityFile, "ZDAS_CONTROLLER_IDENTITY_FILE")
	setString(&c.Controller.CABundle, "ZDAS_CONTROLLER_CA_BUNDLE")
	setString(&c.Controller.SelfIssuer, "ZDAS_CONTROLLER_SELF_ISSUER")
	if err := setDuration(&c.Controller.PollInterval, "ZDAS_CONTROLLER_POLL_INTERVAL"); err != nil {
		return err
	}

	if err := setBool(&c.Fallback.Enabled, "ZDAS_FALLBACK_ENABLED"); err != nil {
		return err
	}
	setString(&c.Fallback.TempNameTemplate, "ZDAS_FALLBACK_TEMP_NAME_TEMPLATE")
	if err := setDuration(&c.Fallback.PollInterval, "ZDAS_FALLBACK_POLL_INTERVAL"); err != nil {
		return err
	}
	if err := setDuration(&c.Fallback.Timeout, "ZDAS_FALLBACK_TIMEOUT"); err != nil {
		return err
	}

	setString(&c.Claims.UsernameClaim, "ZDAS_CLAIMS_USERNAME_CLAIM")
	setString(&c.Claims.NameTemplate, "ZDAS_CLAIMS_NAME_TEMPLATE")
	setString(&c.Claims.IdentityNameClaim, "ZDAS_CLAIMS_IDENTITY_NAME_CLAIM")
	setString(&c.Claims.ExternalIDClaim, "ZDAS_CLAIMS_EXTERNAL_ID_CLAIM")

	setString(&c.Token.Issuer, "ZDAS_TOKEN_ISSUER")
	setString(&c.Token.Audience, "ZDAS_TOKEN_AUDIENCE")
	if err := setDuration(&c.Token.Expiry, "ZDAS_TOKEN_EXPIRY"); err != nil {
		return err
	}

	if err := setDuration(&c.Session.Timeout, "ZDAS_SESSION_TIMEOUT"); err != nil {
		return err
	}
	if err := setDuration(&c.Session.CodeExpiry, "ZDAS_SESSION_CODE_EXPIRY"); err != nil {
		return err
	}

	for i := range c.Providers {
		p := &c.Providers[i]
		key := envProviderKey(p.Name)
		setString(&p.ClientID, "ZDAS_PROVIDER_"+key+"_CLIENT_ID")
		setString(&p.ClientSecret, "ZDAS_PROVIDER_"+key+"_CLIENT_SECRET")
	}
	return nil
}

func setString(dst *string, key string) {
	if v, ok := os.LookupEnv(key); ok {
		*dst = v
	}
}

// setBool sets dst from env var key, accepting what strconv.ParseBool does
// plus "yes" and "no".
func setBool(dst *bool, key string) error {
	v, ok := os.LookupEnv(key)
	if !ok {
		return nil
	}
	switch strings.ToLower(v) {
	case "yes":
		*dst = true
		return nil
	case "no":
		*dst = false
		return nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fmt.Errorf("%s: %w", key, err)
	}
	*dst = b
	return nil
}

func setDuration(dst *time.Duration, key string) error {
	v, ok := os.LookupEnv(key)
	if !ok {
		return nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fmt.Errorf("%s: %w", key, err)
	}
	*dst = d
	return nil
}

// envProviderKey normalizes a provider name into the form used in env var names:
// upper-case, with any non-alphanumeric character replaced by underscore.
func envProviderKey(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r - 'a' + 'A')
		case (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}
