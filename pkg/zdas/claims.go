package zdas

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
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

// ComposeClaims builds the full set of JWT claims for a ZDAS token. When nonce
// is empty, it uses the primary path (device_name from tunneler). When nonce is
// non-empty, it uses the fallback path (temporary name with a nonce-based
// external ID) regardless of whether info is populated.
func ComposeClaims(cfg ClaimsConfig, fbCfg FallbackConfig, identity *UpstreamIdentity, info *DeviceInfo, nonce string) map[string]interface{} {
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

	claims := map[string]interface{}{
		cfg.IdentityNameClaim: identityName,
		cfg.ExternalIDClaim:   externalID,
		"sub":                 externalID, // per spec: sub = device_external_id
		"upstream_sub":        identity.Subject,
		"upstream_iss":        identity.Issuer,
		"preferred_username":  username,
		"device_name":         deviceName,
	}
	return claims
}

// expandFallbackTemplate replaces {username} and {nonce_short} in the fallback
// name template.
func expandFallbackTemplate(tmpl, username, nonce string) string {
	s := strings.ReplaceAll(tmpl, "{username}", username)
	s = strings.ReplaceAll(s, "{nonce_short}", nonce)
	return s
}

// MintToken signs a ZDAS JWT with the given claims, token config, and key set.
func MintToken(cfg TokenConfig, claims map[string]interface{}, ks *KeySet) (string, error) {
	now := time.Now()
	tok := jwt.New()

	// Set custom claims first, then override with standard claims so that
	// neither the provisioner hook nor CompleteProvision can tamper with
	// iss, aud, iat, or exp.
	for k, v := range claims {
		_ = tok.Set(k, v)
	}
	_ = tok.Set(jwt.IssuerKey, cfg.Issuer)
	_ = tok.Set(jwt.AudienceKey, cfg.Audience)
	_ = tok.Set(jwt.IssuedAtKey, now)
	_ = tok.Set(jwt.ExpirationKey, now.Add(cfg.Expiry))

	privJWK, err := jwk.FromRaw(ks.Private())
	if err != nil {
		return "", fmt.Errorf("wrap signing key: %w", err)
	}
	_ = privJWK.Set(jwk.KeyIDKey, ks.KID())
	_ = privJWK.Set(jwk.AlgorithmKey, jwa.ES256)

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256, privJWK))
	if err != nil {
		return "", fmt.Errorf("sign jwt: %w", err)
	}
	return string(signed), nil
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
// the username and device info.
func expandTemplate(tmpl, username string, info *DeviceInfo) string {
	s := strings.ReplaceAll(tmpl, "{username}", username)
	s = strings.ReplaceAll(s, "{device_name}", info.DeviceName)
	s = strings.ReplaceAll(s, "{hostname}", info.Hostname)
	s = strings.ReplaceAll(s, "{os}", info.OS)
	s = strings.ReplaceAll(s, "{arch}", info.Arch)
	return s
}

// computeExternalID returns the hex-encoded SHA-256 of issuer:subject:device,
// ensuring uniqueness across providers, users, and devices.
func computeExternalID(issuer, subject, deviceName string) string {
	raw := issuer + ":" + subject + ":" + deviceName
	h := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", h)
}
