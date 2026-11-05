package zdas

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

var (
	// ErrNoProviders is returned by Resolve when no upstream providers are registered.
	ErrNoProviders = errors.New("no upstream providers available")
	// ErrMultipleProviders is returned by Resolve when multiple providers are
	// registered and no hint was given.
	ErrMultipleProviders = errors.New("multiple idps available, selection required")
	// ErrAccessDenied is wrapped by the error ExchangeAndIdentify returns
	// when the upstream login succeeded but the user may not enroll, such
	// as a GitHub user outside the allowed organizations. ZDAS reports it
	// to the tunneler as access_denied rather than server_error.
	ErrAccessDenied = errors.New("access denied")
)

// UpstreamProvider abstracts the differences between OIDC and non-OIDC upstreams.
// ZDAS calls AuthorizeURL to get a redirect, then ExchangeAndIdentify on
// callback.
type UpstreamProvider interface {
	// Name returns the human-readable provider name, used for display on the
	// IdP selector page and for resolution by the idp query parameter.
	Name() string

	// Issuer returns a stable identifier for this provider (OIDC issuer URL,
	// or "https://github.com" for GitHub, etc.).
	Issuer() string

	// AuthorizeURL builds the URL to redirect the user's browser to.
	// state is ZDAS's session-encoded state. redirectURI is ZDAS's callback URL.
	AuthorizeURL(state, redirectURI string) string

	// ExchangeAndIdentify exchanges the callback code for user identity.
	// For OIDC: exchanges code for tokens, validates ID token, extracts claims.
	// For GitHub: exchanges code for access token, calls /user API, maps fields.
	ExchangeAndIdentify(ctx context.Context, code, redirectURI string) (*UpstreamIdentity, error)
}

// UpstreamIdentity is the normalized user identity from any upstream provider.
type UpstreamIdentity struct {
	Subject string // unique user ID (OIDC sub, GitHub numeric ID, etc.)
	// Email is only populated when the upstream IdP asserts the address is
	// verified. For OIDC, this means email_verified=true was present in the
	// ID token. For GitHub, this means the address appeared on /user/emails
	// with primary=true and verified=true. Embedders using email for user
	// lookup can trust that an empty Email means no verified address was
	// available; they should never trust an unverified address from Raw.
	Email    string
	Username string         // human-readable username (preferred_username, GitHub login, etc.)
	Issuer   string         // where this identity came from
	Raw      map[string]any // all upstream claims/fields for debugging or future use
}

// ProviderRegistry is a concurrency-safe directory of available upstream
// providers, keyed by name. Both OIDC providers (discovered from the Ziti
// controller) and directly-configured providers (GitHub, etc.) are merged
// into the same registry.
type ProviderRegistry struct {
	mu        sync.RWMutex
	providers map[string]UpstreamProvider
}

// NewProviderRegistry returns an empty registry.
func NewProviderRegistry() *ProviderRegistry {
	return &ProviderRegistry{providers: make(map[string]UpstreamProvider)}
}

// Register adds a provider to the registry. Returns an error if a provider
// with the same name already exists.
func (r *ProviderRegistry) Register(p UpstreamProvider) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	name := p.Name()
	if _, exists := r.providers[name]; exists {
		return fmt.Errorf("provider name collision: %q", name)
	}
	r.providers[name] = p
	return nil
}

// Resolve looks up a provider by name, or else by issuer when exactly one
// provider has that issuer. If hint is empty and exactly one provider is
// registered, it returns that provider. Otherwise an empty hint with multiple
// providers returns ErrMultipleProviders. With no providers registered it
// returns ErrNoProviders, whatever the hint.
func (r *ProviderRegistry) Resolve(hint string) (UpstreamProvider, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if len(r.providers) == 0 {
		return nil, ErrNoProviders
	}
	if hint == "" {
		if len(r.providers) == 1 {
			for _, p := range r.providers {
				return p, nil
			}
		}
		return nil, ErrMultipleProviders
	}

	// Match by name first.
	if p, ok := r.providers[hint]; ok {
		return p, nil
	}
	// Fallback: match by issuer, which must name exactly one provider.
	var match UpstreamProvider
	for _, p := range r.providers {
		if p.Issuer() != hint {
			continue
		}
		if match != nil {
			return nil, fmt.Errorf("idp %q is ambiguous: more than one provider has that issuer", hint)
		}
		match = p
	}
	if match == nil {
		return nil, fmt.Errorf("unknown idp: %q", hint)
	}
	return match, nil
}

// SetOIDCProviders atomically replaces all OIDC providers (those whose names
// don't appear in the keep set). This is used by the discovery poller when the
// controller's signer list changes.
func (r *ProviderRegistry) SetOIDCProviders(oidc []UpstreamProvider, configuredNames map[string]struct{}) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Validate first - check for name collisions before mutating.
	for _, p := range oidc {
		if _, exists := configuredNames[p.Name()]; exists {
			return fmt.Errorf("discovered oidc provider %q collides with configured provider", p.Name())
		}
	}
	// Remove old OIDC entries (anything not in configuredNames).
	for name := range r.providers {
		if _, configured := configuredNames[name]; !configured {
			delete(r.providers, name)
		}
	}
	// Add new OIDC entries.
	for _, p := range oidc {
		r.providers[p.Name()] = p
	}
	return nil
}

// Names returns the names of all registered providers.
func (r *ProviderRegistry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.providers))
	for n := range r.providers {
		names = append(names, n)
	}
	return names
}

// Len returns the number of registered providers.
func (r *ProviderRegistry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.providers)
}
