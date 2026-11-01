package zdas

import (
	"context"
	"errors"
	"net/http"
	"slices"
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
}

// ProvisionResult tells ZDAS how to proceed after provisioning.
type ProvisionResult struct {
	// Claims to include in the ZDAS JWT. When non-nil, ZDAS mints the token
	// immediately. The map should include at minimum the identity name claim
	// and external ID claim from ClaimsConfig.
	Claims map[string]interface{}

	// RedirectURL, when non-empty and Claims is nil, redirects the browser
	// to an application-hosted page for interactive selection. ZDAS adds a
	// pending_id query parameter, and the application's handler for the
	// page finishes the flow by passing it to Handler.CompleteProvision.
	RedirectURL string
}

// Option configures optional behavior on NewServer / NewHandler.
type Option func(*serverOptions)

type serverOptions struct {
	provisioner EnrollmentProvisioner
	keys        *KeySet      // nil generates a key at startup
	verifyKeys  []*KeySet    // published in the JWKS alongside keys
	store       Store        // nil uses an in-memory SessionStore
	upstream    *http.Client // nil uses each provider's default clients
	err         error        // misuse of an option, reported by NewServer
}

// WithProvisioner sets an EnrollmentProvisioner hook. When set, ZDAS calls
// it after upstream authentication instead of using built-in claim composition.
func WithProvisioner(p EnrollmentProvisioner) Option {
	return func(o *serverOptions) { o.provisioner = p }
}

// WithKeySet makes ZDAS sign tokens with active instead of a key generated at
// startup, and publish active plus every verifyOnly key at
// /.well-known/jwks.json. Replicas behind a load balancer must share the same
// keys, because the Ziti controller may fetch the JWKS from a replica other
// than the one that signed the token. A verifyOnly key with the same kid as
// active or an earlier verifyOnly key is published once.
//
// To rotate from K1 to K2 across replicas without rejecting any token:
//
//  1. Roll out WithKeySet(K1, K2) to every replica. K2 is published but
//     not yet used. Wait until the Ziti controller's cached copy of the
//     JWKS includes K2.
//  2. Roll out WithKeySet(K2, K1). K2 signs, and K1 still verifies tokens
//     already in flight.
//  3. Once the token expiry has passed since step 2 finished, roll out
//     WithKeySet(K2).
//
// Skipping step 1, or its wait, lets a replica sign with K2 while another
// replica or the controller's cache knows only K1. NewServer fails if any
// key is nil.
func WithKeySet(active *KeySet, verifyOnly ...*KeySet) Option {
	return func(o *serverOptions) {
		if active == nil || slices.Contains(verifyOnly, nil) {
			o.err = errors.Join(o.err, errors.New("WithKeySet: nil key set"))
			return
		}
		o.keys = active
		o.verifyKeys = verifyOnly
	}
}

// WithUpstreamHTTPClient makes every request ZDAS sends to an upstream
// identity provider go through c: OIDC discovery, signing keys, token
// exchanges and userinfo, for configured providers and those discovered from
// the controller's signers, and GitHub's OAuth and API calls. Requests to the
// Ziti controller do not use it. An embedder whose issuers are chosen by
// someone it does not fully trust uses it to control where those requests
// may go, e.g. with a dialer that refuses internal addresses. NewServer
// fails if c is nil.
func WithUpstreamHTTPClient(c *http.Client) Option {
	return func(o *serverOptions) {
		if c == nil {
			o.err = errors.Join(o.err, errors.New("WithUpstreamHTTPClient: nil client"))
			return
		}
		o.upstream = c
	}
}

// WithStore makes ZDAS keep in-flight enrollment state in s instead of in
// memory, so that a flow started on one replica can finish on another. See
// Store for the contract. ZDAS does not stop or close s; its lifetime belongs
// to the caller. Entries are bound to Config.Token.Issuer, so replicas
// sharing s must share the issuer, and a Store shared by differently
// configured instances cannot leak entries between them. Replicas compare
// entry timestamps written by each other, so their clocks must agree to
// within a minute.
//
// Two pieces of per-process state are not in the Store: fallback
// enrollments tracked for reconciliation, which are lost if the replica
// that handled the callback restarts before the tunneler connects, and the
// /authorize rate limit, which each replica enforces on its own.
// NewServer fails if s is nil.
func WithStore(s Store) Option {
	return func(o *serverOptions) {
		if s == nil {
			o.err = errors.Join(o.err, errors.New("WithStore: nil store"))
			return
		}
		o.store = s
	}
}
