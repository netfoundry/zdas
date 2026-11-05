package zdas

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDCProvider is an UpstreamProvider backed by a standard OIDC issuer. It
// can be created dynamically from ext-jwt-signers discovered on the Ziti
// controller (public client + PKCE, no secret) or configured directly with
// a client secret for IdPs that require a confidential client in the token
// exchange (e.g. Google Web application OAuth clients). PKCE is always
// applied when a verifier is threaded through the session.
type OIDCProvider struct {
	name            string
	issuer          string
	clientID        string
	clientSecret    string // optional; set for confidential-client IdPs (e.g. Google Web)
	authURL         string
	tokenURL        string
	audience        string
	sendsIss        bool // the issuer adds iss to authorization responses (RFC 9207)
	provider        *oidc.Provider
	verifier        *oidc.IDTokenVerifier
	scopes          []string
	fetchUserInfo   bool
	requireUserInfo bool
	emailDomains    []string
	requiredClaims  map[string][]string
	client          *http.Client // makes the token exchange and userinfo requests
	logger          *slog.Logger
}

// defaultOIDCScopes are the scopes requested when OIDCProviderConfig.Scopes
// is empty. Read only.
var defaultOIDCScopes = []string{"openid", "profile", "email"}

// OIDCProviderConfig holds the data needed to construct an OIDCProvider.
// Sourced either from a discovered ext-jwt-signer (secret empty) or from
// ProviderConfig for directly-configured OIDC providers.
type OIDCProviderConfig struct {
	Name         string
	Issuer       string
	ClientID     string
	ClientSecret string // optional; required by some IdPs (e.g. Google Web client) in the token exchange
	AuthURL      string
	TokenURL     string
	Scopes       []string

	// Audience, when set, is sent as the audience parameter of the
	// authorization request. Some IdPs, such as Auth0, use it to choose
	// the audience of the access token. The ID token's audience is the
	// client ID either way.
	Audience string

	// FetchUserInfo, when true, calls the issuer's userinfo endpoint with
	// the access token after the ID token is validated and merges the
	// response into UpstreamIdentity.Raw. ID token claims take precedence
	// on conflict: they are signed and audience-bound, whereas userinfo is
	// fetched with a bearer token. Useful for IdPs that omit group and
	// other authorization claims from the ID token (Okta by default, Entra
	// when the token would be too large, Auth0 custom claims).
	//
	// A failed userinfo fetch is logged and otherwise ignored unless
	// RequireUserInfo is also set. A userinfo response whose sub does not
	// match the ID token is treated as a failed fetch.
	FetchUserInfo bool

	// RequireUserInfo makes a failed userinfo fetch fail the whole
	// ExchangeAndIdentify call. It has no effect unless FetchUserInfo is
	// set.
	RequireUserInfo bool

	// AllowedEmailDomains, when set, admits only users whose verified
	// email address (see UpstreamIdentity.Email) is in one of these
	// domains, compared without regard to case. A user without a verified
	// address is refused.
	AllowedEmailDomains []string

	// RequiredClaims, when set, admits only users whose claims include, for
	// each name, one of the listed values. A claim that is a list, such as
	// groups, matches when any element does. Strings, booleans ("true",
	// "false") and numbers are compared as text. Claims come from the ID
	// token, plus userinfo when FetchUserInfo is set.
	//
	// A refused user gets an error wrapping ErrAccessDenied.
	RequiredClaims map[string][]string

	// HTTPClient, when set, makes every request to the issuer: discovery,
	// the signing keys, the token exchange and userinfo. An embedder whose
	// issuers are chosen by someone it does not fully trust uses it to
	// control where those requests may go, e.g. with a dialer that refuses
	// internal addresses. go-oidc reads discovery documents and key sets
	// whole, so the client should also bound response sizes. nil uses the
	// client in the ctx passed to NewOIDCProvider (oidc.ClientContext) if
	// there is one, for all of those requests, with ZDAS's 2 MB response
	// cap added and ZDAS's timeout if it has none, or else ZDAS's own
	// client, which has both.
	HTTPClient *http.Client

	// Logger receives userinfo fetch warnings. nil uses slog.Default().
	Logger *slog.Logger
}

// NewOIDCProvider creates an OIDCProvider from the given config. It creates an
// ID token verifier bound to the provider's OIDC discovery data.
func NewOIDCProvider(ctx context.Context, cfg OIDCProviderConfig) (*OIDCProvider, error) {
	// One client makes every request to the issuer, so that a client that
	// limits where requests go also covers the token and userinfo
	// endpoints, which the issuer's discovery document names. go-oidc keeps
	// the client it finds in ctx for later key fetches.
	client := cfg.HTTPClient
	if client == nil {
		client = httpClient
		if c, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok && c != nil {
			client = boundedClient(c)
		}
	}
	ctx = oidc.ClientContext(ctx, client)
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery for %q: %w", cfg.Issuer, err)
	}

	var meta struct {
		SendsIss bool `json:"authorization_response_iss_parameter_supported"`
	}
	if err := provider.Claims(&meta); err != nil {
		return nil, fmt.Errorf("oidc discovery for %q: %w", cfg.Issuer, err)
	}

	authURL := cfg.AuthURL
	if authURL == "" {
		authURL = provider.Endpoint().AuthURL
	}
	tokenURL := cfg.TokenURL
	if tokenURL == "" {
		tokenURL = provider.Endpoint().TokenURL
	}
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = defaultOIDCScopes
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	fetchUserInfo := cfg.FetchUserInfo
	if fetchUserInfo && provider.UserInfoEndpoint() == "" {
		if cfg.RequireUserInfo {
			return nil, fmt.Errorf("userinfo required for %q but issuer %q advertises no userinfo_endpoint", cfg.Name, cfg.Issuer)
		}
		logger.Warn("issuer advertises no userinfo_endpoint, userinfo fetch disabled", "provider", cfg.Name, "issuer", cfg.Issuer)
		fetchUserInfo = false
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: cfg.ClientID})

	return &OIDCProvider{
		name:            cfg.Name,
		issuer:          cfg.Issuer,
		clientID:        cfg.ClientID,
		clientSecret:    cfg.ClientSecret,
		authURL:         authURL,
		tokenURL:        tokenURL,
		audience:        cfg.Audience,
		sendsIss:        meta.SendsIss,
		provider:        provider,
		verifier:        verifier,
		scopes:          scopes,
		fetchUserInfo:   fetchUserInfo,
		requireUserInfo: cfg.RequireUserInfo,
		emailDomains:    cfg.AllowedEmailDomains,
		requiredClaims:  cfg.RequiredClaims,
		client:          client,
		logger:          logger,
	}, nil
}

// Name returns the provider's name.
func (p *OIDCProvider) Name() string { return p.name }

// Issuer returns the issuer URL the provider was configured with.
func (p *OIDCProvider) Issuer() string { return p.issuer }

// checkResponseIssuer returns an error if iss, the iss parameter of an
// authorization response, shows it came from another issuer (RFC 9207). iss
// must be present when the issuer says it sends it.
func (p *OIDCProvider) checkResponseIssuer(iss string) error {
	if iss == "" && !p.sendsIss {
		return nil
	}
	if iss != p.issuer {
		return fmt.Errorf("authorization response from issuer %q, want %q", iss, p.issuer)
	}
	return nil
}

// AuthorizeURL builds the upstream OIDC authorization URL, without PKCE.
func (p *OIDCProvider) AuthorizeURL(state, redirectURI string) string {
	return p.authorizeURL(state, redirectURI, "")
}

// AuthorizeURLWithPKCE is like AuthorizeURL but includes PKCE parameters.
// It returns the URL and the code verifier that must be stored in the session.
func (p *OIDCProvider) AuthorizeURLWithPKCE(state, redirectURI string) (authURL, codeVerifier string, err error) {
	verifier, challenge, err := generatePKCE()
	if err != nil {
		return "", "", err
	}
	return p.authorizeURL(state, redirectURI, challenge), verifier, nil
}

// authorizeURL builds the authorization URL, with an S256 PKCE challenge when
// challenge is not empty. It is built by hand to avoid the oauth2 package's
// automatic parameters.
func (p *OIDCProvider) authorizeURL(state, redirectURI, challenge string) string {
	v := url.Values{
		"client_id":     {p.clientID},
		"response_type": {"code"},
		"redirect_uri":  {redirectURI},
		"state":         {state},
		"scope":         {joinScopes(p.scopes)},
	}
	if p.audience != "" {
		v.Set("audience", p.audience)
	}
	if challenge != "" {
		v.Set("code_challenge", challenge)
		v.Set("code_challenge_method", "S256")
	}
	return withQuery(p.authURL, v)
}

// ExchangeAndIdentify exchanges the authorization code for tokens via the
// upstream token endpoint, validates the ID token, and returns the normalized
// identity. When the provider was configured with FetchUserInfo, userinfo
// claims are merged into Raw as described on OIDCProviderConfig.
func (p *OIDCProvider) ExchangeAndIdentify(ctx context.Context, code, redirectURI string) (*UpstreamIdentity, error) {
	return p.exchangeAndIdentify(ctx, code, redirectURI, "")
}

// ExchangeAndIdentifyWithPKCE is like ExchangeAndIdentify but includes the
// PKCE code_verifier in the token exchange.
func (p *OIDCProvider) ExchangeAndIdentifyWithPKCE(ctx context.Context, code, redirectURI, codeVerifier string) (*UpstreamIdentity, error) {
	return p.exchangeAndIdentify(ctx, code, redirectURI, codeVerifier)
}

func (p *OIDCProvider) exchangeAndIdentify(ctx context.Context, code, redirectURI, codeVerifier string) (*UpstreamIdentity, error) {
	params := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {redirectURI},
		"client_id":    {p.clientID},
	}
	if p.clientSecret != "" {
		params.Set("client_secret", p.clientSecret)
	}
	if codeVerifier != "" {
		params.Set("code_verifier", codeVerifier)
	}

	tokenResp, err := oidcTokenExchange(ctx, p.client, p.tokenURL, params)
	if err != nil {
		return nil, fmt.Errorf("token exchange with %s: %w", p.name, err)
	}

	rawIDToken, ok := tokenResp["id_token"].(string)
	if !ok || rawIDToken == "" {
		return nil, fmt.Errorf("no id_token in response from %s", p.name)
	}

	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("verify id_token from %s: %w", p.name, err)
	}

	var claims struct {
		Sub               string `json:"sub"`
		PreferredUsername string `json:"preferred_username"`
		Name              string `json:"name"`
		Email             string `json:"email"`
		EmailVerified     *bool  `json:"email_verified"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("extract claims from %s: %w", p.name, err)
	}
	if claims.Sub == "" {
		// The external ID is derived from the subject, so every user
		// without one would share a device identity.
		return nil, fmt.Errorf("id_token from %s has no sub", p.name)
	}

	var raw map[string]any
	if err := idToken.Claims(&raw); err != nil {
		return nil, fmt.Errorf("extract claims from %s: %w", p.name, err)
	}

	if p.fetchUserInfo {
		accessToken, _ := tokenResp["access_token"].(string)
		if err := p.mergeUserInfo(ctx, accessToken, claims.Sub, raw); err != nil {
			if p.requireUserInfo {
				return nil, fmt.Errorf("userinfo from %s: %w", p.name, err)
			}
			p.logger.Warn("userinfo fetch failed, continuing with id_token claims only", "provider", p.name, "error", err)
		}
	}

	username := claims.PreferredUsername
	if username == "" {
		username = claims.Name
	}
	if username == "" {
		username = claims.Sub
	}

	// Only surface the email if the upstream IdP asserts it is verified.
	// A missing email_verified claim is treated as unverified (safe default).
	email := ""
	if claims.Email != "" {
		if claims.EmailVerified != nil && *claims.EmailVerified {
			email = claims.Email
		}
	}

	if err := p.checkPolicy(email, raw); err != nil {
		return nil, err
	}

	return &UpstreamIdentity{
		Subject:  claims.Sub,
		Email:    email,
		Username: username,
		Issuer:   p.issuer,
		Raw:      raw,
	}, nil
}

// checkPolicy returns an error wrapping ErrAccessDenied unless the user with
// verified email address email and claims raw passes AllowedEmailDomains and
// RequiredClaims.
func (p *OIDCProvider) checkPolicy(email string, raw map[string]any) error {
	if len(p.emailDomains) > 0 {
		_, domain, ok := strings.Cut(email, "@")
		if !ok || !slices.ContainsFunc(p.emailDomains, func(d string) bool { return strings.EqualFold(d, domain) }) {
			return fmt.Errorf("%w: no verified email address in an allowed domain", ErrAccessDenied)
		}
	}
	for name, allowed := range p.requiredClaims {
		if !slices.ContainsFunc(claimValues(raw[name]), func(v string) bool { return slices.Contains(allowed, v) }) {
			return fmt.Errorf("%w: claim %s has none of the required values", ErrAccessDenied, name)
		}
	}
	return nil
}

// claimValues returns claim as text, one entry per element if it is a list.
// Values of other types, such as objects, give nothing.
func claimValues(claim any) []string {
	switch v := claim.(type) {
	case string:
		return []string{v}
	case bool:
		return []string{strconv.FormatBool(v)}
	case float64:
		return []string{strconv.FormatFloat(v, 'f', -1, 64)}
	case []any:
		var out []string
		for _, e := range v {
			if _, nested := e.([]any); !nested {
				out = append(out, claimValues(e)...)
			}
		}
		return out
	}
	return nil
}

// mergeUserInfo fetches the userinfo endpoint with accessToken and adds any
// claims not already present in raw. The response is rejected when its sub
// differs from the ID token's, per OIDC Core 5.3.2.
func (p *OIDCProvider) mergeUserInfo(ctx context.Context, accessToken, idTokenSub string, raw map[string]any) error {
	if accessToken == "" {
		return errors.New("no access_token in token response")
	}
	ctx = oidc.ClientContext(ctx, p.client)
	info, err := p.provider.UserInfo(ctx, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: accessToken}))
	if err != nil {
		return err
	}
	if info.Subject != idTokenSub {
		return errors.New("userinfo sub does not match id_token sub")
	}
	var extra map[string]any
	if err := info.Claims(&extra); err != nil {
		return fmt.Errorf("decode userinfo claims: %w", err)
	}
	for k, v := range extra {
		if _, exists := raw[k]; !exists {
			raw[k] = v
		}
	}
	return nil
}

// joinScopes joins scopes with space separator per OAuth2 spec.
func joinScopes(scopes []string) string {
	return strings.Join(scopes, " ")
}

// generatePKCE creates a new PKCE code verifier (32 random bytes, base64url)
// and its S256 challenge.
func generatePKCE() (verifier, challenge string, err error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("generate pkce verifier: %w", err)
	}
	verifier = base64.RawURLEncoding.EncodeToString(buf)
	return verifier, pkceChallenge(verifier), nil
}

// pkceChallenge returns the S256 code challenge for verifier.
func pkceChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
