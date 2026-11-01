// Package zdas implements the Ziti Device Authentication Service: an
// OIDC-compliant authorization server that sits between OpenZiti tunnelers
// and an upstream IdP, injecting device-specific claims into JWTs so that
// each device a user enrolls from gets a unique Ziti identity.
//
// # Embedding
//
// Two levels of the package are supported for embedding in other Go
// applications. Both are covered by the compatibility promise below.
//
// The full service: [NewHandler] (or [NewServer]) with a [Config] mounts
// the /authorize, /callback, /token, and discovery endpoints on the
// embedder's mux. [WithProvisioner] and [EnrollmentProvisioner] let the
// embedder own user lookup and identity creation, and
// [Handler.CompleteProvision] finishes an enrollment the provisioner sent
// to one of the embedder's pages. [WithKeySet] and [WithStore] let several
// replicas behind a load balancer share signing keys and in-flight
// enrollment state, with the per-replica exceptions listed on WithStore;
// package zdastest provides a conformance suite for [Store]
// implementations, and [JWKS] publishes the keys from somewhere other than
// ZDAS's own endpoint. [WithUpstreamHTTPClient] sends every request to
// upstream identity providers through the embedder's client, for an
// embedder whose issuers are chosen by someone it does not fully trust.
//
// The provider layer alone: [NewOIDCProvider], [NewGitHubProvider],
// [UpstreamProvider], [UpstreamIdentity], and [ProviderRegistry] can be
// used without any of the device-enrollment handlers by an application
// that only needs to federate login to an upstream IdP. The embedder
// builds the redirect with AuthorizeURL (or AuthorizeURLWithPKCE for
// OIDC), and on callback turns the code into an [UpstreamIdentity] with
// ExchangeAndIdentify (or ExchangeAndIdentifyWithPKCE). Nothing in that
// path depends on a session store, a Ziti controller, or ZDAS
// configuration.
//
// # Compatibility
//
// Exported identifiers in this package are treated as a public API. Until
// v1, a minor release may still remove or change one, and its release notes
// say which and what replaces it. Otherwise struct fields are only added,
// never removed or retyped; new fields are optional and default to the
// previous behavior. Interface methods are only added when every
// implementation in this package gains them at the same time, and
// embedders that implement [UpstreamProvider] or [Store] themselves should
// expect to add new methods on upgrade. Query parameters that tunnelers
// send to /authorize are only added, and unmodified tunnelers keep working
// without them.
package zdas
