# ZDAS - OpenZiti Device Authentication Service

ZDAS is a lightweight Go service that solves a specific problem with [OpenZiti](https://openziti.io) device enrollment: standard OIDC providers issue tokens about *users*, not *devices*. If the same user enrolls from three devices, the tokens are identical and the second and third enrollments fail because the external ID collides.

ZDAS sits between the tunneler and your upstream identity provider, delegates user authentication to the IdP, collects device info from the tunneler, and mints its own JWT that combines both. Each device gets a unique OpenZiti identity. Works with both `enroll-to-cert` and `enroll-to-token` enrollment types.

## How it works

```
Tunneler          ZDAS              Upstream IdP       OpenZiti Controller
   |                |                    |                   |
   |-- /authorize ->|                    |                   |
   |   (device info)|                    |                   |
   |                |-- /authorize ----->|                   |
   |                |   (PKCE, user auth)|                   |
   |                |<-- callback -------|                   |
   |                |                    |                   |
   |                | compose claims:    |                   |
   |                |  username + device |                   |
   |                | sign with own key  |                   |
   |                |                    |                   |
   |<-- ZDAS JWT ---|                    |                   |
   |                                                         |
   |-- enroll (Bearer ZDAS JWT) ---------------------------->|
   |                                    validates via JWKS ->|
   |                                    creates identity     |
```

ZDAS discovers upstream IdPs automatically by polling the controller's public `external-jwt-signers` endpoint - no parallel IdP configuration needed. Non-OIDC providers like GitHub (which issues opaque tokens, not JWTs) can be configured directly.

When multiple identity providers are available, ZDAS presents a selection page in the browser so the user can choose where to authenticate.

## Features

- **Single binary, no database.** Ephemeral EC P-256 keys generated at startup, served via JWKS. In-memory session store with automatic cleanup.
- **Controller-driven IdP discovery.** ZDAS polls the OpenZiti controller for ext-jwt-signers with enrollment enabled (cert or token), so adding a new IdP to the controller automatically makes it available through ZDAS.
- **Non-OIDC provider support.** GitHub (and other OAuth-only providers) can be configured directly. Both discovered and configured providers are unified behind a common `UpstreamProvider` interface.
- **Fallback for unmodified tunnelers.** Deploy ZDAS before updating any tunnelers. Unmodified tunnelers enroll with a temporary name, and ZDAS renames the identity via the management API after the tunneler connects and reports `envInfo`. Set `fallback.enabled: false` once all tunnelers are updated.
- **Three TLS modes.** `acme` (automatic Let's Encrypt), `static` (bring your own cert), or `none` (behind a reverse proxy).
- **Embeddable.** `pkg/zdas` is an importable Go package. Mount the handler on your own mux or run it standalone.

## Requirements

- **OpenZiti controller v2.0+** - ZDAS relies on `enroll-to-cert` and `enroll-to-token`, which were added in v2.0. Against older controllers, discovery finds no eligible signers and auto-enrollment is not available.

## Quick start

```bash
# Build
go build -o zdas ./cmd/zdas/

# Configure (see config.example.yaml for all options)
cp config.example.yaml config.yaml
# Edit config.yaml: set external_url, controller.api_url

# Register ZDAS as an ext-jwt-signer on the controller.
# Include --enroll-to-cert, --enroll-to-token, or both.
ziti edge create ext-jwt-signer zdas-signer \
  "https://das.example.com" \
  --jwks-endpoint "https://das.example.com/.well-known/jwks.json" \
  --external-auth-url "https://das.example.com/authorize" \
  --audience "ziti-enroll" \
  --client-id "ziti-enroll" \
  --enroll-to-cert \
  --enroll-to-token \
  --enroll-name-claims-selector "device_identity_name" \
  --claims-property "device_external_id" \
  --use-external-id

# Run
./zdas -config config.yaml
```

## Configuration

ZDAS is configured via YAML, environment variables, or both (env vars override YAML). See [`config.example.yaml`](config.example.yaml) for the full reference.

Key settings:

| Setting | Description | Default |
|---------|-------------|---------|
| `external_url` | Public URL where tunnelers and the controller reach ZDAS | (required) |
| `controller.api_url` | OpenZiti controller Edge Client API URL | (required) |
| `controller.identity_file` | OpenZiti admin identity JSON (cert, key, CA) for management API | (optional, required for fallback) |
| `fallback.enabled` | Allow enrollment without device info from unmodified tunnelers | `false` |
| `claims.name_template` | Template for identity names. Placeholders: `{username}`, `{device_name}`, `{hostname}`, `{os}`, `{arch}` | `{username}-{device_name}` |
| `token.expiry` | How long enrollment tokens are valid | `5m` |
| `tls.mode` | `none`, `static`, or `acme` | `none` |
| `allowed_redirect_uris` | URLs `/authorize` may redirect back to, matched on scheme, host and port | loopback only |

Environment variable overrides follow the pattern `ZDAS_SECTION_FIELD`, e.g. `ZDAS_CONTROLLER_API_URL`, `ZDAS_FALLBACK_ENABLED`, `ZDAS_PROVIDER_GITHUB_CLIENT_SECRET`.

## Tunneler integration

Updated tunnelers send device info as query parameters on the authorize URL:

- `device_name` - primary device identifier (hostname, machine-id, or user-chosen name)
- `hostname`, `os`, `arch`, `os_release`, `os_version` - optional, for richer identity names
- `client_type` - optional free-form hint (`tunneler`, `host`, `service`) passed through to an embedding application's provisioner

The IdP sign-in must finish in the browser the tunneler opened. ZDAS ties each enrollment to that browser with a cookie, so a sign-in completed anywhere else, such as another browser or a phone following an emailed magic link, is rejected at `/callback` with `400 session not found or expired`. The user has to start again from the tunneler. A callback from the wrong browser leaves the enrollment in place, so it can't be used to cancel someone else's.

Unmodified tunnelers work without changes when `fallback.enabled` is true. They enroll with a temporary name (e.g., `jsmith-pending-a3f9b2`) that ZDAS reconciles to the real hostname after the tunneler connects.

## Embedding

Mount the full service on your own mux:

```go
import "github.com/smilindave26/zdas/pkg/zdas"

handler, err := zdas.NewHandler(cfg, logger)
mux.Handle("/device-auth/", http.StripPrefix("/device-auth", handler))
// ... on shutdown:
handler.Stop()
```

Set `external_url` to the public URL including the mount prefix (`https://example.com/device-auth` above). ZDAS scopes the cookie that binds an enrollment to the browser that started it to that path.

To run several replicas behind a load balancer, give every replica the same signing key and a shared store for in-flight enrollments:

```go
ks, err := zdas.NewKeySet(privateKey) // the same EC P-256 key on every replica
handler, err := zdas.NewHandler(cfg, logger,
	zdas.WithKeySet(ks),
	zdas.WithStore(myStore), // your zdas.Store, e.g. backed by a database
)
```

`WithKeySet` documents how to rotate keys across replicas, and `zdastest.TestStore` is a conformance suite for your `Store` implementation.

A provisioner (`zdas.WithProvisioner`) can send the browser to a page of yours, such as a network picker, by returning `ProvisionResult.RedirectURL`. ZDAS passes the enrollment's pending ID to your provisioner as `ProvisionRequest.PendingID`; record it with your own state for the user you authenticated. Your handler for the page finishes the flow with `handler.CompleteProvision(w, r, pendingID, claims, err)`, passing the pending ID you recorded. Take both the pending ID and the claims from your own server-side state, never from the request: the user enrolling can change the URL. ZDAS also adds the ID to the redirect as `pending_id`, for compatibility.

If someone you do not fully trust chooses the upstream issuers, such as a tenant admin in a multi-tenant service, pass `zdas.WithUpstreamHTTPClient(client)` so that discovery, signing keys, token exchanges and userinfo all go through a client you control, for example one whose dialer refuses internal addresses. `OIDCProviderConfig.HTTPClient` does the same for a provider used on its own. A refused token exchange is a `*zdas.TokenError`, whose `StatusCode` can be shown without the reply.

Or use the provider layer on its own to federate login to an upstream IdP without the enrollment handlers:

```go
p, err := zdas.NewOIDCProvider(ctx, zdas.OIDCProviderConfig{
	Name:          "okta",
	Issuer:        "https://example.okta.com",
	ClientID:      clientID,
	ClientSecret:  clientSecret,
	FetchUserInfo: true, // merge userinfo claims (e.g. groups) into identity.Raw
})
authURL, verifier, err := p.AuthorizeURLWithPKCE(state, callbackURL)
// ... redirect the browser, then on callback:
identity, err := p.ExchangeAndIdentifyWithPKCE(ctx, code, callbackURL, verifier)
```

See the package documentation for the compatibility promise covering both uses.

## Project layout

```
cmd/zdas/          standalone binary
pkg/zdas/
  config.go        configuration and validation
  keys.go          EC P-256 signing keys and JWKS
  provider.go      UpstreamProvider interface and registry
  oidc.go          OIDC provider (from discovered signers)
  github.go        GitHub OAuth provider
  discovery.go     controller-driven IdP discovery
  claims.go        claim composition and JWT minting
  handlers.go      HTTP endpoints (/authorize, /callback, /token, OIDC discovery, JWKS)
  redirect.go      redirect_uri validation (loopback by default)
  binding.go       cookie binding /callback to the browser that started /authorize
  store.go         Store interface for in-flight enrollment state
  session.go       the entries a Store holds
  memstore.go      in-memory Store (the default)
  zdastest/        conformance suite for Store implementations
  provisioner.go   EnrollmentProvisioner hook for embedders
  options.go       NewServer / NewHandler options
  ratelimit.go     per-client rate limiting on /authorize
  httpclient.go    outbound HTTP clients and response limits
  identity.go      OpenZiti identity file parsing and management API auth
  reconciler.go    fallback identity reconciliation
  server.go        server assembly and TLS modes
  acme.go          Let's Encrypt autocert
```

## License

Apache 2.0. See [LICENSE](LICENSE).
