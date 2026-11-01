package zdas

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// stubProvider is a minimal UpstreamProvider for registry tests.
type stubProvider struct {
	name   string
	issuer string
}

func (s *stubProvider) Name() string   { return s.name }
func (s *stubProvider) Issuer() string { return s.issuer }
func (s *stubProvider) AuthorizeURL(state, redirectURI string) string {
	return "https://stub/" + s.name
}
func (s *stubProvider) ExchangeAndIdentify(context.Context, string, string) (*UpstreamIdentity, error) {
	return &UpstreamIdentity{Subject: "stub-sub"}, nil
}

func TestRegistryRegisterAndResolveByName(t *testing.T) {
	r := NewProviderRegistry()
	p := &stubProvider{name: "keycloak", issuer: "https://kc.example.com"}
	if err := r.Register(p); err != nil {
		t.Fatalf("Register: %v", err)
	}

	got, err := r.Resolve("keycloak")
	if err != nil {
		t.Fatalf("Resolve by name: %v", err)
	}
	if got.Name() != "keycloak" {
		t.Errorf("resolved name = %q", got.Name())
	}
}

func TestRegistryResolveByIssuer(t *testing.T) {
	r := NewProviderRegistry()
	p := &stubProvider{name: "kc", issuer: "https://kc.example.com/realms/test"}
	if err := r.Register(p); err != nil {
		t.Fatal(err)
	}

	got, err := r.Resolve("https://kc.example.com/realms/test")
	if err != nil {
		t.Fatalf("Resolve by issuer: %v", err)
	}
	if got.Name() != "kc" {
		t.Errorf("resolved name = %q", got.Name())
	}
}

func TestRegistryResolveSingleProvider(t *testing.T) {
	r := NewProviderRegistry()
	p := &stubProvider{name: "only-one", issuer: "https://only"}
	if err := r.Register(p); err != nil {
		t.Fatal(err)
	}

	got, err := r.Resolve("")
	if err != nil {
		t.Fatalf("Resolve with empty hint (single): %v", err)
	}
	if got.Name() != "only-one" {
		t.Errorf("resolved name = %q", got.Name())
	}
}

func TestRegistryResolveEmptyHintMultiple(t *testing.T) {
	r := NewProviderRegistry()
	_ = r.Register(&stubProvider{name: "a", issuer: "https://a"})
	_ = r.Register(&stubProvider{name: "b", issuer: "https://b"})

	_, err := r.Resolve("")
	if !errors.Is(err, ErrMultipleProviders) {
		t.Errorf("expected ErrMultipleProviders, got %v", err)
	}
}

func TestRegistryResolveUnknown(t *testing.T) {
	r := NewProviderRegistry()
	_, err := r.Resolve("nope")
	if err == nil || !strings.Contains(err.Error(), "unknown idp") {
		t.Errorf("expected unknown idp error, got %v", err)
	}
}

func TestRegistryRejectsDuplicate(t *testing.T) {
	r := NewProviderRegistry()
	_ = r.Register(&stubProvider{name: "dup", issuer: "https://1"})
	err := r.Register(&stubProvider{name: "dup", issuer: "https://2"})
	if err == nil || !strings.Contains(err.Error(), "collision") {
		t.Errorf("expected collision error, got %v", err)
	}
}

func TestRegistrySetOIDCProviders(t *testing.T) {
	r := NewProviderRegistry()
	configured := &stubProvider{name: "github", issuer: "https://github.com"}
	_ = r.Register(configured)
	configuredNames := map[string]struct{}{"github": {}}

	oidc1 := &stubProvider{name: "kc-old", issuer: "https://old.kc"}
	_ = r.Register(oidc1) // pretend this was a previous discovery

	// Replace OIDC providers.
	oidcNew := []UpstreamProvider{
		&stubProvider{name: "kc-new", issuer: "https://new.kc"},
	}
	if err := r.SetOIDCProviders(oidcNew, configuredNames); err != nil {
		t.Fatalf("SetOIDCProviders: %v", err)
	}

	// kc-old should be gone, kc-new and github should be present.
	if r.Len() != 2 {
		t.Fatalf("expected 2 providers, got %d: %v", r.Len(), r.Names())
	}
	if _, err := r.Resolve("kc-new"); err != nil {
		t.Errorf("expected kc-new: %v", err)
	}
	if _, err := r.Resolve("github"); err != nil {
		t.Errorf("expected github: %v", err)
	}
	if _, err := r.Resolve("kc-old"); err == nil {
		t.Error("kc-old should have been removed")
	}
}

func TestRegistrySetOIDCProvidersCollision(t *testing.T) {
	r := NewProviderRegistry()
	_ = r.Register(&stubProvider{name: "github", issuer: "https://github.com"})
	configuredNames := map[string]struct{}{"github": {}}

	oidc := []UpstreamProvider{
		&stubProvider{name: "github", issuer: "https://different"},
	}
	err := r.SetOIDCProviders(oidc, configuredNames)
	if err == nil || !strings.Contains(err.Error(), "collides") {
		t.Errorf("expected collision error, got %v", err)
	}
}

// TestRegistryResolveAmbiguousIssuer verifies that an issuer shared by two
// providers resolves to neither, rather than to whichever map order gives.
func TestRegistryResolveAmbiguousIssuer(t *testing.T) {
	reg := NewProviderRegistry()
	_ = reg.Register(&stubProvider{name: "gh-a", issuer: "https://github.com"})
	_ = reg.Register(&stubProvider{name: "gh-b", issuer: "https://github.com"})
	if p, err := reg.Resolve("https://github.com"); err == nil {
		t.Errorf("Resolve = %s, want an ambiguity error", p.Name())
	}
	if p, err := reg.Resolve("gh-b"); err != nil || p.Name() != "gh-b" {
		t.Errorf("Resolve by name = %v, %v; want gh-b", p, err)
	}
}
