package zdas

import (
	"context"
)

// EnrollmentProvisioner is an optional hook for embedding applications. When
// set, ZDAS calls Provision after upstream authentication succeeds instead of
// using its built-in claim composition. The provisioner handles user lookup,
// network assignment, and device creation in the embedding application's data
// model.
type EnrollmentProvisioner interface {
	// Provision is called after upstream auth succeeds. Return
	// ProvisionResult with Claims set to proceed immediately (mint the JWT).
	// Return ProvisionResult with RedirectURL set to redirect the browser
	// to an application-hosted page (e.g., network picker) for interactive
	// selection before completing the flow.
	//
	// To reject the request with a structured error that ZDAS will surface
	// to the tunneler, return a *ProvisionError. Plain errors are treated
	// as server failures and surfaced as OIDC server_error.
	Provision(ctx context.Context, req ProvisionRequest) (*ProvisionResult, error)
}

// ProvisionError is a structured error that an EnrollmentProvisioner can
// return to control the OIDC error code and description surfaced to the
// tunneler. Code must be one of the ZDAS-supported OIDC error codes:
// "access_denied", "invalid_request", or "server_error". Anything else is
// rejected and replaced with "server_error". Description is rendered to the
// user via the OIDC error_description query parameter; it should be short,
// human-readable, and actionable. ZDAS truncates very long descriptions and
// strips control characters before sending.
type ProvisionError struct {
	Code        string
	Description string
}

func (e *ProvisionError) Error() string {
	if e.Description != "" {
		return e.Description
	}
	return e.Code
}

// isValidProvisionErrorCode reports whether code is one of the OIDC error
// codes ZDAS will pass through to the tunneler. Anything else is treated as
// a misbehaving provisioner and falls back to "server_error".
func isValidProvisionErrorCode(code string) bool {
	switch code {
	case "access_denied", "invalid_request", "server_error":
		return true
	}
	return false
}

// ProvisionRequest contains everything the provisioner needs to make decisions
// about user and device provisioning.
type ProvisionRequest struct {
	// From upstream IdP (after successful authentication).
	Email    string // user's email address
	Name     string // display name
	Subject  string // stable user ID (OIDC sub, GitHub numeric ID)
	Provider string // provider name ("google", "github", etc.)
	// Raw holds the upstream identity's claims as the provider returned
	// them: for OIDC the ID token's, plus userinfo when fetched, and for
	// GitHub the /user fields. Use it for policies ZDAS doesn't apply
	// itself, such as group membership. Of the email fields, only Email
	// above is known to be verified.
	Raw map[string]any

	// From tunneler query params on /authorize. DeviceName and other fields
	// will be empty for unmodified tunnelers (fallback path).
	DeviceName       string
	Hostname         string
	OS               string
	Arch             string
	OSRelease        string
	OSVersion        string
	EnrollmentMethod string // e.g. "enrollToCert", "enrollToToken"; empty if tunneler didn't send it

	// ClientType is the free-form client_type query parameter from
	// /authorize (e.g. "tunneler", "host", "service"). It lets an embedder
	// that provisions non-device identities through the same flow tell
	// them apart from a user's device. Unmodified tunnelers do not send it,
	// so it is empty for them. ZDAS does not interpret the value.
	ClientType string

	// True when the tunneler didn't send device info (fallback path).
	IsFallback    bool
	FallbackNonce string

	// PendingID is the ID ZDAS stores the enrollment under if Provision
	// returns a RedirectURL. ZDAS also adds it to that URL as pending_id,
	// but the user's browser can change a URL. A provisioner that redirects
	// should record PendingID with its own state for this enrollment, tied
	// to the user it authenticated, and pass the recorded value to
	// Handler.CompleteProvision. That way a pending ID from someone else's
	// enrollment cannot be paired with this user's claims.
	PendingID string
}

// ProvisionResult tells ZDAS how to proceed after provisioning.
type ProvisionResult struct {
	// Claims to include in the ZDAS JWT. When non-empty, ZDAS mints the
	// token immediately. The map should include at minimum the identity
	// name claim and external ID claim from ClaimsConfig, and a registered
	// claim such as sub must have the type the JWT spec gives it.
	Claims map[string]any

	// RedirectURL, when non-empty and Claims is empty, redirects the browser
	// to an application-hosted page for interactive selection. ZDAS adds a
	// pending_id query parameter, and the application's handler for the
	// page finishes the flow by passing it to Handler.CompleteProvision.
	// A result with neither fails the enrollment with server_error.
	RedirectURL string
}
