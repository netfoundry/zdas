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

Before sending the browser to an IdP, ZDAS shows a page where the user continues: a button for each available identity provider, or one when there is only one. This click is the user's consent. Without it, a link someone else built could sign in a user whose IdP session is still live, with no prompt at all. The page shows the device as the device describes itself. It also warns, before its buttons, against continuing from a link someone sent, and against sending anyone the address the browser returns to. An embedding application can show its own picker instead (`idp_selector_url`), with several providers, or for every sign-in that names none with `idp_selector_always`; see `Config.IDPSelectorURL` for what that page must do.

See [docs/security.md](docs/security.md) for the security model: what ZDAS enforces, what a deployment must do, and the reasoning behind its design decisions.

## Features

- **Single binary, no database.** Ephemeral EC P-256 keys generated at startup, served via JWKS. In-memory session store with automatic cleanup.
- **Controller-driven IdP discovery.** ZDAS polls the OpenZiti controller for ext-jwt-signers with enrollment enabled (cert or token), so adding a new IdP to the controller automatically makes it available through ZDAS. As for tunnelers, a signer's external auth URL must be the IdP's OIDC issuer: ZDAS reads the issuer's discovery document for the authorization endpoint, and requests the signer's scopes and audience.
- **Non-OIDC provider support.** GitHub (and other OAuth-only providers) can be configured directly. Both discovered and configured providers are unified behind a common `UpstreamProvider` interface. A configured provider must say who may enroll: `allowed_orgs` for GitHub, and `allowed_email_domains` and/or `required_claims` for OIDC. For a provider anyone can sign in to, it must instead set `allow_any_user: true` explicitly. `NewServer` and `NewHandler` check this too, so a `Config` built in code without `Validate` is held to the same rule. An embedder's provisioner gets the raw upstream claims (`ProvisionRequest.Raw`) for its own rules.
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
  --external-auth-url "https://das.example.com" \
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
| `controller.api_url` | OpenZiti controller URL, e.g. `https://ctrl.example.com:1280`. A client or management API URL also works. | (required) |
| `controller.identity_file` | OpenZiti identity JSON (cert, key, CA) for the management API. It needs only the `identity.read` and `identity.update` permissions (`ziti edge create identity <name> --permissions identity.read,identity.update`); ZDAS warns if it is a full admin. `identity.update` still lets it change any non-admin identity's name, role attributes, external ID and auth policy, so whoever holds the file can take over any non-admin identity. Guard it as you would an identity admin's. | (optional, required for fallback) |
| `fallback.enabled` | Allow enrollment without device info from unmodified tunnelers | `false` |
| `rate_limit` | Limits on `/authorize`, per client, and optionally for everyone together. Behind a reverse proxy, also set `rate_limit.trusted_proxies`, or the per-client limit applies to everyone at once, and every client is logged as the proxy. | 2/s (burst 10) per client; no global limit |
| `claims.name_template` | Template for identity names. Placeholders: `{username}`, `{device_name}`, `{hostname}`, `{os}`, `{arch}` | `{username}-{device_name}` |
| `token.expiry` | How long enrollment tokens are valid | `5m` |
| `tls.mode` | `none`, `static`, or `acme`. With `acme`, Let's Encrypt checks each domain on port 443, which must reach ZDAS, directly or forwarded to the `listen` address. | `none` |
| `allowed_redirect_uris` | URLs `/authorize` may redirect back to. Entries for hosts other than loopback need the full callback path and match exactly. | loopback only |

Environment variable overrides follow the pattern `ZDAS_SECTION_FIELD`, e.g. `ZDAS_CONTROLLER_API_URL`, `ZDAS_FALLBACK_ENABLED`, `ZDAS_PROVIDER_GITHUB_CLIENT_SECRET`.

## Tunneler integration

Updated tunnelers send device info as query parameters on the authorize URL:

- `device_name` - primary device identifier (hostname, machine-id, or user-chosen name). Since v0.11.0 it may not contain `:` or be longer than 255 bytes, so that the external ID stays unambiguous; such names are refused with `invalid_request`.
- `hostname`, `os`, `arch`, `os_release`, `os_version` - optional, for richer identity names
- `client_type` - optional free-form hint (`tunneler`, `host`, `service`) passed through to an embedding application's provisioner

Each IdP sends the browser back to ZDAS at `<external_url>/callback/<provider name>`, so register that URL as a redirect URI with each IdP's client. For a discovered signer, that's the signer's client, and the provider name is the signer's name. On a GitHub OAuth app, turn off wildcard matching for the callback URL. With it on, GitHub sends a code to any subdomain or sub-path of the URL, and it is on for apps that had a single callback URL before August 3, 2026. A response that arrives at another provider's callback is refused. That stops an IdP mix-up, where one IdP gets a code meant for another (RFC 9700 section 4.4). ZDAS also checks the response's `iss` (RFC 9207) when the IdP sends one. Until every registration has been updated, `legacy_callback: true` keeps sending the old shared `<external_url>/callback`. That setting is deprecated and will be removed.

The IdP sign-in must finish in the browser the tunneler opened. ZDAS ties each enrollment to that browser with a cookie. A sign-in completed anywhere else, such as another browser or a phone following an emailed magic link, is refused at `/callback` and cancelled, so the user has to start again from the tunneler and finish in the browser it opens. The page the other browser shows warns against sending its address to anyone. See `docs/security.md` for what the binding does and doesn't stop.

Unmodified tunnelers work without changes when `fallback.enabled` is true. They enroll with a temporary name (e.g., `jsmith-pending-a3f9b2`) that ZDAS reconciles to the real hostname after the tunneler connects.

Fallback works with enroll-to-cert only. Each fallback login gets a new external ID, so an identity enrolled by token couldn't sign in again once its first token expired. While fallback is on, register ZDAS's signer with `--enroll-to-cert` and not `--enroll-to-token`. If ZDAS's signer allows enroll-to-token, ZDAS refuses fallback logins and logs an error. It checks the signer every `controller.poll_interval`.

## Embedding

Mount the full service on your own mux:

```go
import "github.com/netfoundry/zdas/pkg/zdas"

handler, err := zdas.NewHandler(cfg, logger)
mux.Handle("/device-auth/", http.StripPrefix("/device-auth", handler))
// ... on shutdown:
handler.Stop()
```

Set `external_url` to the public URL including the mount prefix (`https://example.com/device-auth` above). ZDAS scopes the cookie that binds an enrollment to the browser that started it to that path. Under a mount prefix, that cookie's name can't start with `__Host-`, which keeps a sibling subdomain from setting it; see `docs/security.md`.

Route `/callback` and everything below it, for every method, to the handler, as the mount above does. ZDAS warns the user, and cancels the sign-in, at any response under `/callback` it never asked for. A narrower route, such as only `GET /callback/{provider}`, leaves those to your own mux.

To run several replicas behind a load balancer, give every replica the same signing key and a shared store for in-flight enrollments:

```go
ks, err := zdas.NewKeySet(privateKey) // the same EC P-256 key on every replica
handler, err := zdas.NewHandler(cfg, logger,
	zdas.WithKeySet(ks),
	zdas.WithStore(myStore), // your zdas.Store, e.g. backed by a database
)
```

`WithKeySet` documents how to rotate keys across replicas, and `zdastest.TestStore` is a conformance suite for your `Store` implementation.

To make ZDAS's own pages match your application, pass `zdas.WithPageBranding(f)`. ZDAS calls `f` with each request it answers with a page, so you can brand each tenant its own way. The `PageBranding` it returns sets the title and heading, the intro line, a label for each provider's button, a logo with an optional dark-mode version, and the button colors. The pages are the consent page and the errors a browser sees from `/authorize`, `/callback` and `CompleteProvision`; an error comes as a page only to a request that accepts `text/html`, and as plain text otherwise. A rate-limit refusal is always plain text. The consent page's warning, and its place before the buttons, stay as they are. `f` runs for anyone's requests, many at once: keep it quick, choose the tenant from `r.Host` rather than the query, and don't log `r`; see `WithPageBranding`.

A provisioner (`zdas.WithProvisioner`) can send the browser to a page of yours, such as a network picker, by returning `ProvisionResult.RedirectURL`. ZDAS passes the enrollment's pending ID to your provisioner as `ProvisionRequest.PendingID`; record it with your own state for the user you authenticated. Your handler for the page finishes the flow with `handler.CompleteProvision(w, r, pendingID, claims, err)`, passing the pending ID you recorded. Take both the pending ID and the claims from your own server-side state, never from the request: the user enrolling can change the URL. ZDAS also adds the ID to the redirect as `pending_id`, for compatibility.

An embedder that serves several OpenZiti networks registers ZDAS's signer on each with its own audience, lists them in `Token.ProvisionerAudiences`, and sets the `aud` claim of each enrollment, in `ProvisionResult.Claims` or `CompleteProvision`, to the network it chose. Otherwise a token minted for one network is accepted by the others until it expires. An `aud` that isn't configured fails the enrollment.

If someone you do not fully trust chooses the upstream issuers, such as a tenant admin in a multi-tenant service, pass `zdas.WithUpstreamHTTPClient(client)` so that discovery, signing keys, token exchanges and userinfo all go through a client you control. `zdas.PublicHTTPClient()` is one that connects only to public addresses and follows no redirects. `OIDCProviderConfig.HTTPClient` does the same for a provider used on its own. A refused token exchange is a `*zdas.TokenError`, whose `StatusCode` can be shown without the reply.

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
  pages.go         consent and error pages, and their branding
  redirect.go      redirect_uri validation (loopback by default)
  binding.go       cookie binding /callback to the browser that started /authorize
  store.go         Store interface for in-flight enrollment state
  session.go       the entries a Store holds
  memstore.go      in-memory Store (the default)
  zdastest/        conformance suite for Store implementations
  provisioner.go   EnrollmentProvisioner hook for embedders
  options.go       NewServer / NewHandler options
  ratelimit.go     rate limiting on /authorize
  httpclient.go    outbound HTTP clients and response limits
  identity.go      OpenZiti identity file parsing and management API auth
  reconciler.go    fallback identity reconciliation
  server.go        server assembly and TLS modes
  acme.go          Let's Encrypt autocert
```

## License

Apache 2.0. See [LICENSE](LICENSE).
