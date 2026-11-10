package zdas

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/lestrrat-go/jwx/v3/jwt"
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

	// IDPSelectorURL, when set, replaces ZDAS's built-in IdP picker. When
	// ZDAS would otherwise show its own picker (multiple providers
	// registered, no idp query param on /authorize), or with
	// IDPSelectorAlways whenever there is no idp, it 302-redirects to this
	// URL with the original /authorize query string plus two parameters:
	// `providers`, a comma-separated list of IdP names, and `consent`, an
	// opaque value.
	//
	// The picker is where the user consents to the sign-in, so it must
	// show what is being signed in to, must not be frameable, and must
	// continue only on the user's click: a form that POSTs `consent` and
	// `idp=<name>` to <ExternalURL>/authorize. ZDAS accepts the post only
	// with the cookie it set in the same browser, which a SameSite=Lax
	// cookie carries only if the picker is on the same site as ZDAS. A
	// picker that instead links back to /authorize with `idp=<name>` added
	// still works, but the user then confirms again on ZDAS's own page.
	//
	// The redirect target must be on a host the embedding application
	// controls; Validate checks only that it is an absolute path or an
	// http(s) URL with a host, and doesn't sanitize it. Operators must not
	// allow user input to influence this field.
	IDPSelectorURL string `yaml:"idp_selector_url"`

	// IDPSelectorAlways sends every sign-in that names no provider (no idp
	// query param on /authorize) to IDPSelectorURL, also when only one
	// provider is offered, so the embedding application shows every page
	// before the IdP. It needs IDPSelectorURL. The picker must still post
	// consent only on the user's click, also for one provider: that click
	// is what stops a link alone from signing someone in. A picker that
	// links back with idp still gets ZDAS's own page.
	IDPSelectorAlways bool `yaml:"idp_selector_always"`

	// LegacyCallback sends every IdP ZDAS's old shared callback,
	// <ExternalURL>/callback, instead of one per provider,
	// <ExternalURL>/callback/<provider name>. Each IdP accepts only the
	// callback URLs registered for its client, so set this until every
	// registration has the per-provider URL. Deprecated: a shared callback
	// lets one IdP get a code meant for another (RFC 9700 section 4.4),
	// and this setting will be removed.
	LegacyCallback bool `yaml:"legacy_callback"`

	// AllowedRedirectURIs restricts which redirect_uri values the /authorize
	// endpoint will accept. When empty (the default), only loopback
	// callbacks are accepted: http or https to "localhost" or a loopback IP
	// literal, on any port. Tunnelers always use one, so most deployments
	// should leave this unset.
	//
	// When set, it replaces the loopback default. Entries are URLs, not
	// string prefixes, and a redirect_uri with userinfo never matches.
	//   - An entry for a host other than loopback must give the callback's
	//     full path, and a redirect_uri matches it only exactly: the same
	//     scheme, host, port and path, and the same query if the entry has
	//     one. Validate rejects such an entry without a path.
	//   - A loopback entry, such as "http://localhost", matches any port
	//     when it has none, and any path when it has none.
	AllowedRedirectURIs []string        `yaml:"allowed_redirect_uris"`
	RateLimit           RateLimitConfig `yaml:"rate_limit"`
}

// RateLimitConfig controls rate limiting on the /authorize endpoint. The
// per-client limit applies to GET and POST alike, so a sign-in takes two
// requests from it. The global limit applies only to a valid GET, the
// request that stores a session, across all clients together. A zero rate
// turns that limit off. The zero Config has no limits; LoadConfig, which the
// zdas binary uses, starts from 2 per second with a burst of 10 per client,
// and no global limit.
//
// A client is the peer address of the connection: an IPv4 address, or an
// IPv6 /64. Behind a reverse proxy, list the proxy in TrustedProxies so that
// requests are counted against the address the proxy reports in
// X-Forwarded-For; otherwise every request counts against the proxy.
// X-Forwarded-For is ignored from peers that are not listed, since any
// client can send it. TrustedProxies also decides the client that ZDAS's
// warnings name, with or without rate limits.
type RateLimitConfig struct {
	AuthorizePerSecond float64  `yaml:"authorize_per_second"` // sustained rate per client; 0 = disabled
	AuthorizeBurst     int      `yaml:"authorize_burst"`      // peak burst per client
	TrustedProxies     []string `yaml:"trusted_proxies"`      // IP addresses or CIDR prefixes

	// GlobalPerSecond and GlobalBurst cap valid GET /authorize requests
	// from all clients together, in this process. It is off by default:
	// once a few addresses use it up, it refuses everyone, which is worse
	// than the built-in store's own answer to a flood. That store holds
	// 10,000 sessions and drops the oldest beyond that, so an attacker has
	// to create 10,000 sessions within one user's sign-in to drop it: about
	// 77 IPv4 addresses or 5 IPv6 /48s at the default per-client limit for
	// a sign-in that takes a minute. Set it to keep a shared Store small,
	// remembering each replica enforces its own, and expect it to refuse
	// real users under a flood.
	GlobalPerSecond float64 `yaml:"global_per_second"` // sustained rate, all clients; 0 = disabled
	GlobalBurst     int     `yaml:"global_burst"`      // peak burst, all clients
}

// defaultRateLimit is the rate limiting LoadConfig starts from.
var defaultRateLimit = RateLimitConfig{
	AuthorizePerSecond: 2,
	AuthorizeBurst:     10,
}

// TLSConfig selects and configures the TLS serving mode.
type TLSConfig struct {
	Mode     string     `yaml:"mode"`
	CertFile string     `yaml:"cert_file"`
	KeyFile  string     `yaml:"key_file"`
	ACME     ACMEConfig `yaml:"acme"`
}

// ACMEConfig configures autocert / Let's Encrypt. Let's Encrypt checks each
// domain on port 443, which must reach ZDAS, directly or forwarded to the
// listen address. With Listen on another port, ZDAS also listens on :443 for
// the check, and logs a warning if it can't.
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
	// AllowedEmailDomains and RequiredClaims restrict who may sign in; see
	// OIDCProviderConfig.
	AllowedEmailDomains []string            `yaml:"allowed_email_domains"`
	RequiredClaims      map[string][]string `yaml:"required_claims"`

	// GitHub-specific fields.
	UsernameField string   `yaml:"username_field"`
	UserIDField   string   `yaml:"user_id_field"`
	AllowedOrgs   []string `yaml:"allowed_orgs"`

	// AllowAnyUser acknowledges that the provider has no policy: anyone
	// who can sign in to it may enroll, which for GitHub or a public OIDC
	// IdP such as Google is anyone at all. Validate requires either a
	// policy (allowed_orgs for GitHub; allowed_email_domains or
	// required_claims for OIDC) or this.
	AllowAnyUser bool `yaml:"allow_any_user"`
}

// hasPolicy reports whether p restricts who may sign in.
func (p ProviderConfig) hasPolicy() bool {
	return len(p.AllowedOrgs) > 0 || len(p.AllowedEmailDomains) > 0 || len(p.RequiredClaims) > 0
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

	// ProvisionerAudiences are the audiences, besides Audience, that a
	// provisioner may give an enrollment's token by setting its "aud"
	// claim, in Provision's result or in CompleteProvision. An embedder
	// serving several OpenZiti networks registers ZDAS's signer on each
	// network with that network's own audience, and sets the aud of each
	// enrollment to the network it chose. Without this, one network would
	// accept a token minted for another until it expired. Any other aud
	// fails the enrollment.
	ProvisionerAudiences []string `yaml:"provisioner_audiences"`
}

// audience returns the aud for a token with claims: the claims' own aud if
// it is Audience or one of ProvisionerAudiences, or Audience if they have
// none.
func (c TokenConfig) audience(claims map[string]any) (string, error) {
	v, ok := claims[jwt.AudienceKey]
	if !ok {
		return c.Audience, nil
	}
	aud, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("claim %s must be a single string, not %T", jwt.AudienceKey, v)
	}
	if aud != c.Audience && !slices.Contains(c.ProvisionerAudiences, aud) {
		return "", fmt.Errorf("claim %s %q is not token.audience or one of token.provisioner_audiences", jwt.AudienceKey, aud)
	}
	return aud, nil
}

// SessionConfig controls in-flight auth session and code lifetimes.
type SessionConfig struct {
	Timeout    time.Duration `yaml:"timeout"`
	CodeExpiry time.Duration `yaml:"code_expiry"`
}

// LoadConfig reads a YAML config file (if path is non-empty), applies environment
// variable overrides, fills in defaults, and validates the result.
func LoadConfig(path string) (*Config, error) {
	cfg := &Config{RateLimit: defaultRateLimit}
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read config file: %w", err)
		}
		// Reject unknown keys, so that a misspelled setting such as
		// allowed_orgs fails loudly instead of leaving its control off.
		dec := yaml.NewDecoder(bytes.NewReader(data))
		dec.KnownFields(true)
		if err := dec.Decode(cfg); err != nil && !errors.Is(err, io.EOF) {
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
	// Lower-case only: external_url is the issuer of ZDAS's own tokens, which
	// is compared byte for byte, and is pasted into callback URLs.
	if !strings.HasPrefix(c.ExternalURL, "http://") && !strings.HasPrefix(c.ExternalURL, "https://") {
		return errors.New("external_url must be an http(s) URL")
	}
	if _, err := parseHTTPURL(c.ExternalURL); err != nil {
		return fmt.Errorf("external_url: %w", err)
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
	if _, err := parseHTTPURL(c.Controller.APIURL); err != nil {
		return fmt.Errorf("controller.api_url: %w", err)
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
		if err := p.check(); err != nil {
			return fmt.Errorf("providers[%d] (%s): %w", i, p.Name, err)
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
	if c.IDPSelectorAlways && c.IDPSelectorURL == "" {
		return errors.New("idp_selector_always requires idp_selector_url")
	}
	if c.IDPSelectorURL != "" && !strings.HasPrefix(c.IDPSelectorURL, "/") {
		if !strings.HasPrefix(c.IDPSelectorURL, "http://") && !strings.HasPrefix(c.IDPSelectorURL, "https://") {
			return errors.New("idp_selector_url must be an http(s) URL or an absolute path")
		}
		if _, err := parseHTTPURL(c.IDPSelectorURL); err != nil {
			return fmt.Errorf("idp_selector_url: %w", err)
		}
	}
	for i, raw := range c.AllowedRedirectURIs {
		u, err := parseRedirectURI(raw)
		if err == nil && u.Path == "" && !isLoopbackHost(u.Hostname()) {
			err = errors.New("an entry for a host other than loopback needs the callback's full path, which it must match exactly")
		}
		if err != nil {
			return fmt.Errorf("allowed_redirect_uris[%d]: %w", i, err)
		}
	}
	for i, aud := range c.Token.ProvisionerAudiences {
		if aud == "" {
			return fmt.Errorf("token.provisioner_audiences[%d] is empty", i)
		}
	}
	for i, raw := range c.RateLimit.TrustedProxies {
		if _, err := parseTrustedProxy(raw); err != nil {
			return fmt.Errorf("rate_limit.trusted_proxies[%d]: %w", i, err)
		}
	}
	return c.Claims.checkNames()
}

// maxProviderNameLength caps a configured provider's name, which goes into
// its callback path, the consent page and log lines.
const maxProviderNameLength = 255

// checkProviderName returns an error for a name that can't serve as the
// last segment of the provider's callback path: "." and "..", which a
// browser resolves away, invalid UTF-8 and control characters. Other
// characters, spaces included, are escaped in the path, so a configured
// provider can still take the name of a controller signer to override it.
func checkProviderName(name string) error {
	switch {
	case name == "":
		return errors.New("name is required")
	case name == "." || name == "..":
		return fmt.Errorf("name %q can't be a callback path segment", name)
	case len(name) > maxProviderNameLength:
		return fmt.Errorf("name is longer than %d bytes", maxProviderNameLength)
	case !utf8.ValidString(name):
		return errors.New("name is not valid UTF-8")
	case strings.ContainsFunc(name, unicode.IsControl):
		return errors.New("name has control characters")
	}
	return nil
}

// check returns an error for a provider config ZDAS cannot run, or would
// run more openly than it says: a provider with no policy and no explicit
// allow_any_user, or with a policy meant for the other type, which that type
// would ignore. Validate and NewServer both run it, so a Config built in
// code fails closed too.
func (p ProviderConfig) check() error {
	if err := checkProviderName(p.Name); err != nil {
		return err
	}
	switch p.Type {
	case ProviderTypeGitHub:
		if p.ClientID == "" || p.ClientSecret == "" {
			return errors.New("client_id and client_secret are required for github")
		}
		if len(p.AllowedEmailDomains) > 0 || len(p.RequiredClaims) > 0 {
			return errors.New("allowed_email_domains and required_claims are for oidc; use allowed_orgs for github")
		}
	case ProviderTypeOIDC:
		if p.ClientID == "" || p.OIDCIssuerURL == "" {
			return errors.New("client_id and oidc_issuer_url are required for oidc")
		}
		if _, err := parseHTTPURL(p.OIDCIssuerURL); err != nil {
			return fmt.Errorf("oidc_issuer_url: %w", err)
		}
		if p.RequireUserInfo && !p.FetchUserInfo {
			return errors.New("require_userinfo needs fetch_userinfo")
		}
		if len(p.AllowedOrgs) > 0 {
			return errors.New("allowed_orgs is for github; use allowed_email_domains or required_claims for oidc")
		}
		for claim, values := range p.RequiredClaims {
			if len(values) == 0 {
				return fmt.Errorf("required_claims.%s lists no values", claim)
			}
		}
	case "":
		return errors.New("type is required")
	default:
		return fmt.Errorf("unknown type %q", p.Type)
	}
	switch {
	case !p.hasPolicy() && !p.AllowAnyUser:
		return errors.New("anyone who can sign in to this provider could enroll; restrict it (allowed_orgs for github, allowed_email_domains or required_claims for oidc) or set allow_any_user: true")
	case p.hasPolicy() && p.AllowAnyUser:
		return errors.New("allow_any_user conflicts with the provider's restrictions")
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
	if err := setBool(&c.IDPSelectorAlways, "ZDAS_IDP_SELECTOR_ALWAYS"); err != nil {
		return err
	}

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
