package zdas

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// DeviceInfo holds device metadata collected from the tunneler's query
// parameters on /authorize.
type DeviceInfo struct {
	DeviceName string // primary identifier (from device_name param)
	Hostname   string // from hostname param
	OS         string // from os param
	Arch       string // from arch param
	OSRelease  string // from os_release param
	OSVersion  string // from os_version param
}

// preferredUsernameClaim is the claim ZDAS puts the user's name in, and the
// default claim it reads the name from upstream.
const preferredUsernameClaim = "preferred_username"

// ComposeClaims builds the full set of JWT claims for a ZDAS token. When nonce
// is empty, it uses the primary path (device_name from tunneler). When nonce is
// non-empty, it uses the fallback path (temporary name with a nonce-based
// external ID) regardless of whether info is populated.
func ComposeClaims(cfg ClaimsConfig, fbCfg FallbackConfig, identity *UpstreamIdentity, info *DeviceInfo, nonce string) map[string]any {
	username := resolveUsername(cfg.UsernameClaim, identity)

	var identityName, externalID, deviceName string
	if nonce == "" {
		// Primary path: device_name present.
		identityName = expandTemplate(cfg.NameTemplate, username, info)
		externalID = computeExternalID(identity.Issuer, identity.Subject, info.DeviceName)
		deviceName = info.DeviceName
	} else {
		// Fallback path: no device_name, use nonce for temp name and external ID.
		identityName = expandFallbackTemplate(fbCfg.TempNameTemplate, username, nonce)
		externalID = computeExternalID(identity.Issuer, identity.Subject, nonce)
		deviceName = ""
	}

	claims := map[string]any{
		"sub":                  externalID, // per spec: sub = device_external_id
		"upstream_sub":         identity.Subject,
		"upstream_iss":         identity.Issuer,
		preferredUsernameClaim: username,
		"device_name":          deviceName,
	}
	// The configured names go last, and the external ID after the name, so
	// that a name that collides with another claim can never let a value
	// the user controls replace the external ID. ClaimsConfig.checkNames
	// rejects such names.
	claims[cfg.IdentityNameClaim] = identityName
	claims[cfg.ExternalIDClaim] = externalID
	return claims
}

// reservedClaims are the claims ComposeClaims and MintToken set themselves.
var reservedClaims = []string{
	jwt.SubjectKey, "upstream_sub", "upstream_iss", preferredUsernameClaim, "device_name",
	jwt.IssuerKey, jwt.AudienceKey, jwt.ExpirationKey, jwt.IssuedAtKey, jwt.NotBeforeKey, jwt.JwtIDKey,
}

// checkNames returns an error if the identity name or external ID claim
// would overwrite another claim ZDAS sets. external_id_claim may be "sub",
// which carries the external ID anyway.
func (c ClaimsConfig) checkNames() error {
	if c.IdentityNameClaim == c.ExternalIDClaim {
		return errors.New("claims.identity_name_claim and claims.external_id_claim must differ")
	}
	for _, r := range reservedClaims {
		if c.IdentityNameClaim == r {
			return fmt.Errorf("claims.identity_name_claim %q is a claim ZDAS sets itself", r)
		}
		if c.ExternalIDClaim == r && r != jwt.SubjectKey {
			return fmt.Errorf("claims.external_id_claim %q is a claim ZDAS sets itself", r)
		}
	}
	return nil
}

// expandFallbackTemplate replaces {username} and {nonce_short} in the fallback
// name template, in one pass so that a value containing a placeholder is not
// expanded again.
func expandFallbackTemplate(tmpl, username, nonce string) string {
	return strings.NewReplacer("{username}", username, "{nonce_short}", nonce).Replace(tmpl)
}

// MintToken signs a ZDAS JWT with the given claims, token config, and key set.
// It fails if a claim has a value its registered type does not allow, such as
// a non-string sub, rather than leaving the claim out.
func MintToken(cfg TokenConfig, claims map[string]any, ks *KeySet) (string, error) {
	now := time.Now()
	tok := jwt.New()

	// Set custom claims first, then override with standard claims so that
	// neither the provisioner hook nor CompleteProvision can tamper with
	// iss, aud, iat, or exp.
	if err := setClaims(tok, claims); err != nil {
		return "", err
	}
	if err := setClaims(tok, map[string]any{
		jwt.IssuerKey:     cfg.Issuer,
		jwt.AudienceKey:   cfg.Audience,
		jwt.IssuedAtKey:   now,
		jwt.ExpirationKey: now.Add(cfg.Expiry),
	}); err != nil {
		return "", err
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), ks.privateJWK))
	if err != nil {
		return "", fmt.Errorf("sign jwt: %w", err)
	}
	return string(signed), nil
}

// setClaims sets each claim on tok, failing on a value its registered
// claim does not allow, such as a non-string sub.
func setClaims(tok jwt.Token, claims map[string]any) error {
	for k, v := range claims {
		if err := tok.Set(k, v); err != nil {
			return fmt.Errorf("set claim %q: %w", k, err)
		}
	}
	return nil
}

// checkClaims reports whether MintToken can sign claims. ZDAS checks a
// provisioner's claims when it creates the code, so that a bad claim fails
// the flow with an error the tunneler sees rather than at /token.
func checkClaims(claims map[string]any) error {
	return setClaims(jwt.New(), claims)
}

// resolveUsername picks the best username from the upstream identity. It checks
// the configured claim name first, then falls back through a chain.
func resolveUsername(claim string, identity *UpstreamIdentity) string {
	// Try the configured claim from the raw map.
	if claim != "" && identity.Raw != nil {
		if v, ok := identity.Raw[claim].(string); ok && v != "" {
			return v
		}
	}
	// Fallback chain: Username (already resolved by provider) -> Subject.
	if identity.Username != "" {
		return identity.Username
	}
	return identity.Subject
}

// expandTemplate replaces placeholders in the name template with values from
// the username and device info, in one pass so that a value containing a
// placeholder is not expanded again.
func expandTemplate(tmpl, username string, info *DeviceInfo) string {
	return strings.NewReplacer(
		"{username}", username,
		"{device_name}", info.DeviceName,
		"{hostname}", info.Hostname,
		"{os}", info.OS,
		"{arch}", info.Arch,
	).Replace(tmpl)
}

// computeExternalID returns the hex-encoded SHA-256 of issuer:subject:device,
// unique across providers, users, and devices.
//
// The fields are joined by ':' without escaping, so the input is only
// unambiguous because /authorize rejects a device name containing ':'.
// Subjects and issuers can still contain ':', so two providers whose
// issuers differ only by a port, such as https://idp and https://idp:8443,
// could in principle collide for a subject that starts with the port.
// Changing the encoding would change every existing device's external ID.
func computeExternalID(issuer, subject, deviceName string) string {
	raw := issuer + ":" + subject + ":" + deviceName
	h := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", h)
}
