# Security model

This document covers:
- what ZDAS protects
- what it relies on the people who deploy it to do
- the design decisions behind behavior that can look like a gap

To report a vulnerability, see [SECURITY.md](../SECURITY.md).

## What ZDAS is for

ZDAS sits between OpenZiti tunnelers and upstream identity providers (IdPs). A user signs in to an IdP in the browser. ZDAS then mints a short-lived token whose external ID combines:
- the upstream issuer
- the user's subject at that issuer
- the device name the tunneler reports

The OpenZiti controller trusts ZDAS as an external JWT signer, and enrolls or authenticates the identity with that external ID.

ZDAS holds no long-lived user state. Its signing key is ephemeral unless an embedder supplies one, and its built-in store keeps sign-ins in progress in memory.

## Who is trusted

| Party | Trusted to |
|-------|------------|
| The operator, through config | choose the configured IdPs, the policies on them, the controller, and the redirect URIs ZDAS accepts |
| The controller admin | choose the external JWT signers that ZDAS discovers. A discovered signer is used as the admin configured it, with no further restriction. |
| An upstream IdP | say who the user is, within the policy configured for that IdP |
| The user | sign in as themselves. ZDAS does not trust the device details a tunneler sends to be anything but labels. |
| The embedding application, if any | run its provisioner and pages on the server side, and choose the claims and audience for each enrollment |

Anyone on the internet can reach `/authorize`, `/callback` and `/token`.

## What ZDAS enforces

**The sign-in flow**
- **PKCE (S256)** is required from the tunneler, and ZDAS uses its own PKCE toward OIDC IdPs. A `code_challenge` must be a canonical S256 value.
- **Redirect URIs** are loopback-only by default (RFC 8252). An allow-list entry for a host other than loopback must match exactly.
- **Consent:** nothing goes to an IdP until the user clicks on a ZDAS page that can't be framed. A link alone therefore can't sign in someone whose IdP session is still live.
- **Browser binding:** the sign-in is bound to the browser that started it by a SameSite=Lax cookie. The consent post and the IdP's callback are accepted only from that browser.
- **One callback per provider:** a response at another provider's callback is refused, and so is a response whose `iss` names another issuer. This stops one IdP getting a code meant for another (RFC 9700 section 4.4, RFC 9207).

**Tokens**
- ZDAS sets `iss`, `iat` and `exp` itself. `aud` is the configured audience, or one from `token.provisioner_audiences` that a provisioner chose.
- The external ID is written last, so a configured claim name can't replace it.
- Codes are single use, short-lived, and bound to the tunneler's PKCE verifier and redirect URI.

**Who may enroll**
- A configured provider must have a policy (`allowed_orgs`, `allowed_email_domains`, `required_claims`) or say `allow_any_user: true` explicitly.
- Only a verified email address counts toward `allowed_email_domains`.

**Resource limits**
- Request parameters, form bodies and headers have size limits.
- The `zdas` binary rate-limits `/authorize` per client and in total.
- The built-in store holds a bounded number of sign-ins. When full, it drops the oldest sign-in still in progress, rather than refusing new ones, and logs a warning.

**The controller**
- The fallback reconciler needs only the `identity.read` and `identity.update` permissions, and ZDAS warns if it is given a full admin.
- Fallback logins are refused while ZDAS's own signer allows enroll-to-token, for the reason under [Fallback identities](#fallback-identities) below.

## What a deployment must do

**Operators**
- **Restrict configured providers.** For GitHub, Google and other public IdPs, `allow_any_user: true` means anyone at all can enroll.
- **Register redirect URIs:** register `<external_url>/callback/<provider name>` with each IdP's client.
- **Behind a reverse proxy,** set `rate_limit.trusted_proxies`, and serve ZDAS over HTTPS.
- **The reconciler identity:** give it only `identity.read` and `identity.update`, and protect its identity file. `identity.update` can still rename any identity and change its role attributes, which decide service access through existing policies.
- **Fallback:** with fallback on, let ZDAS's signer allow enroll-to-cert only.
- **Prefer enroll-to-cert.** After enrollment, the device signs in with its own certificate rather than with a ZDAS token.

**Embedders**
- **Provisioning:** finish interactive provisioning with `Handler.CompleteProvision`, taking the pending ID and the claims from your own server-side state, never from the request.
- **A picker of your own (`IDPSelectorURL`):** it is where the user consents. It must be on the same site as ZDAS, must not be frameable, and must POST `consent` and `idp` back on the user's click.
- **More than one network:** if you serve several OpenZiti networks, register ZDAS's signer on each with its own audience. List those audiences in `token.provisioner_audiences`, and set each enrollment's `aud` to the network you chose.
- **Issuers you don't control:** if someone you don't fully trust chooses upstream issuers, pass `WithUpstreamHTTPClient`. `PublicHTTPClient` connects only to public addresses.
- **Your own `http.Server`:** set `MaxHeaderBytes`, and rate-limit `/authorize` (`RateLimitConfig`), since a `Config` built in code has no limits.

## Design decisions

### The device name is a label

The device half of an identity is the name the tunneler reports. ZDAS can't check it.

Anyone who can sign in to the IdP as the user can claim any of that user's device names, and so authenticate as those devices' identities with a ZDAS token. Doing that takes the user's own sign-in, so it doesn't let anyone act as a different user.

Binding a token to a device would need the device to prove it holds a key, which tunnelers don't do today. With enroll-to-cert, a device signs in afterwards with its own certificate, which is the binding that matters.

### No per-user device limit

ZDAS keeps no durable record of a user's devices: its store holds only sign-ins in progress. An embedder that needs a limit enforces it in its provisioner, which sees each enrollment and can keep a count.

### Pending provisions

When a provisioner sends the browser to a page of its own, ZDAS gives it a pending ID to record. The embedder finishes the enrollment by passing that ID and the claims, both from its own server-side state, to `Handler.CompleteProvision`. ZDAS has no public route for finishing it. A pending ID taken from someone else's browser is therefore useless on its own.

### External ID encoding

The external ID is a SHA-256 hash of the issuer, the subject and the device name, separated by `:`. Device names may not contain `:`.

In theory, an issuer and subject that themselves contain `:` could produce the same input as a different pair. Producing it would take an IdP administrator choosing such values deliberately. Changing the encoding would change every existing external ID, so every enrolled identity would need re-enrolling.

### Device name limits

Since v0.11.0, a `device_name` containing `:`, or longer than 255 bytes, is refused with `invalid_request`. This keeps the external ID encoding unambiguous. A tunneler that sent such names before v0.11.0 must send a different name.

### Fallback identities

Unmodified tunnelers send no device name. Each such sign-in therefore gets a new external ID and a temporary identity name, which the reconciler renames once the tunneler reports its hostname.

Because the external ID changes every time, a fallback identity can't sign in with a ZDAS token again. That is why fallback is for enroll-to-cert only.

### The binary's default upstream client

The `zdas` binary connects wherever its IdPs are, including private addresses, because its issuers come only from its own config and the controller's signers, and both are trusted. An embedder whose issuers come from less trusted parties uses `PublicHTTPClient` or a client of its own.

### OIDC scope

ZDAS is an authorization server for OpenZiti tunnelers, not a general OIDC provider.
- **Accepted:** the authorization code flow with PKCE. A `response_type` other than `code` is refused.
- **`nonce`:** a `nonce` sent to `/authorize` is copied into the token.
- **One token:** the `id_token` is the same token as the `access_token`.
- **Not implemented:** `client_id` registration, `prompt`, `max_age`, and refresh tokens.

### Store eviction

When the built-in store is full, it drops the oldest sign-in still in progress instead of refusing new ones. Sign-ins start before anyone authenticates, so refusing them would let anonymous requests lock everyone out. The global rate limit keeps a flood from reaching that point.
