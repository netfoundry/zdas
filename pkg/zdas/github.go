package zdas

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const (
	gitHubIssuer   = "https://github.com"
	gitHubAuthURL  = "https://github.com/login/oauth/authorize"
	gitHubTokenURL = "https://github.com/login/oauth/access_token"
	gitHubUserURL  = "https://api.github.com/user"

	// gitHubOrgsPageSize is the most organizations GitHub returns per page,
	// and maxGitHubOrgPages bounds how many pages checkOrgs reads.
	gitHubOrgsPageSize = 100
	maxGitHubOrgPages  = 10
)

// GitHubProvider is an UpstreamProvider for GitHub's OAuth 2.0 flow. GitHub
// issues opaque access tokens (not JWTs), so it cannot be registered as a Ziti
// ext-jwt-signer and must be configured directly in ZDAS.
type GitHubProvider struct {
	name          string
	clientID      string
	clientSecret  string
	usernameField string
	userIDField   string
	allowedOrgs   []string
	client        *http.Client

	// Overridable for tests.
	authBaseURL  string
	tokenBaseURL string
	userURL      string // the /user API; /orgs and /emails live under it
}

// NewGitHubProvider creates a GitHubProvider from the given config.
func NewGitHubProvider(cfg ProviderConfig) *GitHubProvider {
	return &GitHubProvider{
		name:          cfg.Name,
		clientID:      cfg.ClientID,
		clientSecret:  cfg.ClientSecret,
		usernameField: cfg.UsernameField,
		userIDField:   cfg.UserIDField,
		allowedOrgs:   cfg.AllowedOrgs,
		client:        httpClient,
		authBaseURL:   gitHubAuthURL,
		tokenBaseURL:  gitHubTokenURL,
		userURL:       gitHubUserURL,
	}
}

// Name returns the provider's name.
func (p *GitHubProvider) Name() string { return p.name }

// Issuer returns "https://github.com".
func (p *GitHubProvider) Issuer() string { return gitHubIssuer }

// AuthorizeURL builds GitHub's OAuth authorization URL.
func (p *GitHubProvider) AuthorizeURL(state, redirectURI string) string {
	return withQuery(p.authBaseURL, url.Values{
		"client_id":    {p.clientID},
		"redirect_uri": {redirectURI},
		"state":        {state},
		"scope":        {"read:user user:email read:org"},
	})
}

// ExchangeAndIdentify exchanges the code for an access token and reads the
// user from GitHub's API. With AllowedOrgs set, a user in none of them gets
// an error wrapping ErrAccessDenied.
func (p *GitHubProvider) ExchangeAndIdentify(ctx context.Context, code, redirectURI string) (*UpstreamIdentity, error) {
	accessToken, err := p.exchangeCode(ctx, code, redirectURI)
	if err != nil {
		return nil, err
	}
	user, err := p.fetchUser(ctx, accessToken)
	if err != nil {
		return nil, err
	}
	if len(p.allowedOrgs) > 0 {
		if err := p.checkOrgs(ctx, accessToken); err != nil {
			return nil, err
		}
	}

	subject := extractField(user, p.userIDField)
	if subject == "" {
		// Every user would otherwise share one external ID per device name.
		return nil, fmt.Errorf("github user has no %q field to use as subject", p.userIDField)
	}
	username := extractField(user, p.usernameField)

	// Always fetch /user/emails and use the primary verified address. The
	// /user endpoint's "email" field may be an unverified public email, so
	// we don't trust it even when present.
	email := p.fetchPrimaryEmail(ctx, accessToken)

	return &UpstreamIdentity{
		Subject:  subject,
		Email:    email,
		Username: username,
		Issuer:   gitHubIssuer,
		Raw:      user,
	}, nil
}

func (p *GitHubProvider) exchangeCode(ctx context.Context, code, redirectURI string) (string, error) {
	params := url.Values{
		"client_id":     {p.clientID},
		"client_secret": {p.clientSecret},
		"code":          {code},
		"redirect_uri":  {redirectURI},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.tokenBaseURL, strings.NewReader(params.Encode()))
	if err != nil {
		return "", fmt.Errorf("build github token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("github token request: %w", err)
	}
	defer resp.Body.Close()
	body, err := readResponseBody(resp)
	if err != nil {
		return "", fmt.Errorf("read github token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github token endpoint returned %d: %s", resp.StatusCode, truncateBody(body))
	}

	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("parse github token response: %w", err)
	}
	if errMsg, ok := result["error"].(string); ok {
		desc, _ := result["error_description"].(string)
		return "", fmt.Errorf("github token error: %s: %s", errMsg, desc)
	}
	token, ok := result["access_token"].(string)
	if !ok || token == "" {
		return "", errors.New("no access_token in github response")
	}
	return token, nil
}

func (p *GitHubProvider) fetchUser(ctx context.Context, accessToken string) (map[string]any, error) {
	var user map[string]any
	if err := p.getJSON(ctx, p.userURL, accessToken, &user); err != nil {
		return nil, fmt.Errorf("github user api: %w", err)
	}
	return user, nil
}

// checkOrgs returns nil if the user belongs to one of AllowedOrgs, reading
// up to maxGitHubOrgPages pages of the user's organizations.
func (p *GitHubProvider) checkOrgs(ctx context.Context, accessToken string) error {
	allowed := make(map[string]struct{}, len(p.allowedOrgs))
	for _, o := range p.allowedOrgs {
		allowed[o] = struct{}{}
	}
	for page := 1; page <= maxGitHubOrgPages; page++ {
		orgsURL := withQuery(strings.TrimSuffix(p.userURL, "/")+"/orgs", url.Values{
			"per_page": {strconv.Itoa(gitHubOrgsPageSize)},
			"page":     {strconv.Itoa(page)},
		})
		var orgs []struct {
			Login string `json:"login"`
		}
		if err := p.getJSON(ctx, orgsURL, accessToken, &orgs); err != nil {
			return fmt.Errorf("github orgs api: %w", err)
		}
		for _, org := range orgs {
			if _, ok := allowed[org.Login]; ok {
				return nil
			}
		}
		if len(orgs) < gitHubOrgsPageSize {
			break
		}
	}
	return fmt.Errorf("%w: user is not in an allowed GitHub organization", ErrAccessDenied)
}

// fetchPrimaryEmail fetches the user's primary verified email from the GitHub
// /user/emails endpoint. Returns empty string on any failure (best-effort).
func (p *GitHubProvider) fetchPrimaryEmail(ctx context.Context, accessToken string) string {
	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := p.getJSON(ctx, strings.TrimSuffix(p.userURL, "/")+"/emails", accessToken, &emails); err != nil {
		return ""
	}
	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email
		}
	}
	return ""
}

// getJSON GETs apiURL from GitHub's API with accessToken and decodes the
// JSON response into out.
func (p *GitHubProvider) getJSON(ctx context.Context, apiURL, accessToken string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := readResponseBody(resp)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("returned %d: %s", resp.StatusCode, truncateBody(body))
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("parse response: %w", err)
	}
	return nil
}

// extractField extracts a string value from a JSON-decoded map. Numeric values
// (like GitHub's user ID) are converted to string. A missing field, null,
// or any other type gives "", so that a field that is null for some users
// cannot give them all one shared value.
func extractField(data map[string]any, field string) string {
	switch val := data[field].(type) {
	case string:
		return val
	case float64:
		return strconv.FormatInt(int64(val), 10)
	case json.Number:
		return val.String()
	default:
		return ""
	}
}
