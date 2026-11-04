package zdas

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// AuthSession holds state for an in-flight authorization flow between the
// /authorize call and the /callback.
type AuthSession struct {
	TunnelerRedirectURI         string
	TunnelerState               string
	TunnelerNonce               string // the nonce /authorize got, for the token's nonce claim; often empty
	TunnelerCodeChallenge       string
	TunnelerCodeChallengeMethod string
	DeviceInfo                  *DeviceInfo // always populated; DeviceName may be empty on fallback path
	FallbackNonce               string      // populated only on fallback path
	EnrollmentMethod            string      // from tunneler's enrollment_method param (e.g. "enrollToCert", "enrollToToken")
	ClientType                  string      // from the client_type param; empty for unmodified tunnelers
	ZDASCodeVerifier            string      // ZDAS's own PKCE verifier for upstream (empty for non-PKCE providers)
	UpstreamProviderName        string
	CallbackURL                 string // the redirect_uri sent upstream; empty before consent, and in sessions from before it was kept
	CreatedAt                   time.Time
}

// AuthCode holds composed claims alongside the metadata needed to validate the
// tunneler's code exchange request.
type AuthCode struct {
	Claims              map[string]any
	RedirectURI         string
	CodeChallenge       string
	CodeChallengeMethod string
	IsFallback          bool // true if enrolled via fallback path
	CreatedAt           time.Time
}

// PendingProvision holds state for an interactive provisioning detour.
// Created when a provisioner returns a RedirectURL, consumed by
// CompleteProvision.
type PendingProvision struct {
	TunnelerRedirectURI         string
	TunnelerState               string
	TunnelerNonce               string
	TunnelerCodeChallenge       string
	TunnelerCodeChallengeMethod string
	IsFallback                  bool
	FallbackNonce               string // set on the fallback path, for the reconciler
	CreatedAt                   time.Time
}

func randomID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate random id: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// generateShortNonce returns a 16-character hex nonce for fallback enrollments.
// 8 bytes of entropy pushes the birthday-collision bound to ~4 billion, which
// is safe for any realistic volume of concurrent fallback enrollments.
func generateShortNonce() (string, error) {
	b := make([]byte, 8) // 8 bytes = 16 hex chars
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	return hex.EncodeToString(b), nil
}
