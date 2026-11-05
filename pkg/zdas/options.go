package zdas

import (
	"errors"
	"net/http"
	"slices"
)

// Option configures optional behavior on NewServer / NewHandler.
type Option func(*serverOptions)

type serverOptions struct {
	provisioner EnrollmentProvisioner
	keys        *KeySet      // nil generates a key at startup
	verifyKeys  []*KeySet    // published in the JWKS alongside keys
	store       Store        // nil uses the in-memory memStore
	upstream    *http.Client // nil uses each provider's default clients
	err         error        // misuse of an option, reported by NewServer
}

// WithProvisioner sets an EnrollmentProvisioner hook. When set, ZDAS calls
// it after upstream authentication instead of using built-in claim
// composition. NewServer fails if p is nil.
func WithProvisioner(p EnrollmentProvisioner) Option {
	return func(o *serverOptions) {
		if p == nil {
			o.err = errors.Join(o.err, errors.New("WithProvisioner: nil provisioner"))
			return
		}
		o.provisioner = p
	}
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
// may go, e.g. with a dialer that refuses internal addresses; c should also
// bound response sizes, since go-oidc reads discovery documents and key sets
// whole. NewServer fails if c is nil.
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
// sharing s must share the issuer, and instances with different issuers
// cannot see each other's entries in it. Instances that share s and an
// issuer but differ otherwise, such as in audience or provisioner, can
// consume each other's codes and sessions: give each its own issuer or its
// own Store. Replicas compare
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
