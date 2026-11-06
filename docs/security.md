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
| The controller admin | choose the external JWT signers that ZDAS discovers. A discovered signer is used as the admin configured it, with no further restriction; see [Discovered providers](#discovered-providers). |
| An upstream IdP | say who the user is, within the policy configured for that IdP |
| The user | sign in as themselves. ZDAS does not trust the device details a tunneler sends to be anything but labels. |
| The embedding application, if any | run its provisioner and pages on the server side, and choose the claims and audience for each enrollment |

Anyone on the internet can reach these routes:
- `/authorize` (GET and POST), `/callback` and `/callback/<provider>`, and `/token`
- `/.well-known/openid-configuration` and `/.well-known/jwks.json`
- `/network-jwts`, `/external-jwt-signers` and `/edge/client/v1/external-jwt-signers`, copies of the controller's own public data; see [Mirrored controller data](#mirrored-controller-data)

## What ZDAS enforces

**The sign-in flow**
- **PKCE (S256)** is required from the tunneler, and ZDAS uses its own PKCE toward OIDC IdPs. A `code_challenge` must be a canonical S256 value.
- **Redirect URIs** are loopback-only by default (RFC 8252). An allow-list entry for a host other than loopback must match exactly.
- **Consent:** nothing goes to an IdP until the user clicks on a ZDAS page that can't be framed. A link alone therefore can't sign in someone whose IdP session is still live.
- **Browser binding:** the sign-in is bound to the browser that started it by a SameSite=Lax cookie. The consent post and the IdP's callback are accepted only from that browser. One that names the sign-in from any other browser cancels it. See [Phishing with a sign-in link](#phishing-with-a-sign-in-link) for what that does and doesn't stop.
- **One callback per provider:** a response at another provider's callback is refused, and so is a response whose `iss` names another issuer. This stops one IdP getting a code meant for another (RFC 9700 section 4.4, RFC 9207).

**Tokens**
- ZDAS sets `iss`, `iat` and `exp` itself. `aud` is the configured audience, or one from `token.provisioner_audiences` that a provisioner chose.
- The external ID is written last, so a configured claim name can't replace it.
- Codes are single use, short-lived, and bound to the tunneler's PKCE verifier and redirect URI.

**Who may enroll**
- A configured provider must have a policy (`allowed_orgs`, `allowed_email_domains`, `required_claims`) or say `allow_any_user: true` explicitly, and a policy for the other provider type is refused. This holds for a `Config` built in code as well as one loaded from a file.
- Only a verified email address counts toward `allowed_email_domains`.

**Resource limits**
- Request parameters, form bodies and headers have size limits.
- The `zdas` binary rate-limits `/authorize` per client. A limit for all clients together is available, but off by default; see [Store eviction](#store-eviction).
- Requests the limits refuse are logged, with counts, at most once a minute.
- The built-in store holds a bounded number of sign-ins. When full, it drops the oldest sign-in still in progress, rather than refusing new ones, and logs a warning.

**The controller**
- The fallback reconciler needs only the `identity.read` and `identity.update` permissions, and ZDAS warns if it is given a full admin.
- Each discovered provider is logged with a warning the first time it appears, since it has no policy.
- Fallback logins are refused while ZDAS's own signer allows enroll-to-token, for the reason under [Fallback identities](#fallback-identities) below.

## What a deployment must do

**Operators**
- **Restrict configured providers.** For GitHub, Google and other public IdPs, `allow_any_user: true` means anyone at all can enroll.
- **Register redirect URIs:** register `<external_url>/callback/<provider name>` with each IdP's client, to be matched exactly. On a GitHub OAuth app, turn off wildcard matching for each callback URL. With it on, GitHub sends a code to any subdomain or sub-path of the URL, including hosts outside ZDAS.
- **Behind a reverse proxy,** set `rate_limit.trusted_proxies`, and serve ZDAS over HTTPS.
- **The reconciler identity:** give it only `identity.read` and `identity.update`, and guard its identity file as you would an identity admin's. `identity.update` can still change every field of any non-admin identity except its permissions. That includes its role attributes, which decide service access through existing policies, its auth policy, and its external ID, which decides who can sign in as it with a token. So whoever holds the file can take over any non-admin identity, and with it every permission that identity has, such as another operator identity's.
- **Discovered providers:** restrict one by configuring a provider with the signer's name, issuer, client ID and scopes, and a policy.
- **Fallback:** with fallback on, let ZDAS's signer allow enroll-to-cert only.
- **Prefer enroll-to-cert.** After enrollment, the device signs in with its own certificate rather than with a ZDAS token.

**Embedders**
- **Provisioning:** finish interactive provisioning with `Handler.CompleteProvision`, taking the pending ID and the claims from your own server-side state, never from the request.
- **A picker of your own (`IDPSelectorURL`):** it is where the user consents. It must be on the same site as ZDAS, must not be frameable, and must POST `consent` and `idp` back on the user's click.
- **More than one network:** if you serve several OpenZiti networks, register ZDAS's signer on each with its own audience. List those audiences in `token.provisioner_audiences`, and set each enrollment's `aud` to the network you chose. A provisioner that sets no `aud` gets `token.audience`. One signing key then signs for every network, so whoever gets it can mint tokens for all of them. Where networks must not share that risk, run a separate ZDAS, with its own key and issuer, for each.
- **Issuers you don't control:** if someone you don't fully trust chooses upstream issuers, pass `WithUpstreamHTTPClient`. `PublicHTTPClient` connects only to public addresses.
- **Routing:** send `/callback` and everything below it, for every method, to ZDAS's handler. ZDAS warns the user, and cancels the sign-in, at any response under `/callback` it never asked for, and a narrower route leaves those to your own mux.
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

### Phishing with a sign-in link

A phisher can start a sign-in themselves, with a PKCE challenge they hold, and get a victim to sign in to it. The code then goes to a loopback address on the victim's machine, where nothing listens, so the phisher still needs the victim to send back the address the browser shows. ZDAS can't tell that from a real sign-in, since a loopback redirect doesn't show who owns the port (RFC 8252).

ZDAS makes that harder, but can't prevent it: a victim who sends back that address hands over the sign-in.
- **The consent page** comes before the IdP, so a link alone doesn't sign anyone in. It warns, before its buttons, not to continue with a link someone sent and not to send the resulting address to anyone. It shows the device's own description as a short label, without hidden characters and marked as unchecked, because whoever sent the link chose it.
- **The browser binding** covers the step after the IdP. A phisher can consent in their own browser and send the victim the IdP's address instead, which skips the consent page when the IdP approves without asking. If the victim's browser then reaches `/callback` with the sign-in's ID but without its cookie, the sign-in is cancelled, and the address the victim might send back is useless.
- **The phisher can get around the binding** by editing `state` in the IdP's address before sending it. The victim's browser then names no sign-in, nothing is cancelled, and the phisher can finish with the address the victim sends back. Nothing in that address ties the IdP's code to the sign-in except `state`, so the binding can't catch it, and ZDAS doesn't cancel it.
- **The warning** covers both cases: every `/callback` that names no sign-in waiting for it, or reaches one from another browser, tells the user not to send the page's address to anyone, whatever the address holds. An edited IdP address can return the code in the query, in a URL fragment the server never sees, in a JWT, or as a form post, so the warning doesn't depend on finding it. A response at a path below a provider's callback, or sent with a method other than GET or HEAD, gets the same warning and cancels the sign-in its `state` names.
- **The log** has a warning for each sign-in cancelled from another browser or at a callback ZDAS never asked for. It names the client, the provider, how long ago the sign-in started, the binding cookie the request carried (`missing`, `wrong`, or `right` at a callback ZDAS never asked for) and the User-Agent. That helps tell a phish from a blocked cookie or a link scanner. Callbacks that finish no sign-in are counted, with the last one's client, in at most one line a minute.
  - Behind a proxy listed in `rate_limit.trusted_proxies`, the client is the address the proxy forwarded, so it is only as good as the proxy's handling of `X-Forwarded-For`.
  - In the phishing case, the client logged is the victim's address. Treat the log as holding personal data.
- **Sibling hosts:** a host under the same parent domain as ZDAS can set cookies that ZDAS's host receives, including one that stands in for a binding cookie. When `external_url` is an `https://` URL with no path, or just `/`, the binding cookie's name starts with `__Host-`, which browsers accept only from ZDAS's own host. Under a mount prefix it can't, so run ZDAS on a host whose sibling subdomains you control. Over plain HTTP it can't either, and anyone on the network path can set the cookie.

The binding also means a sign-in can't be moved between browsers on purpose. A user who opens an emailed sign-in link in another app, or whose app hands off to a different browser, must start again and finish in the browser the app opens. And anyone who learns a sign-in's ID while it is in progress, from the IdP's address or the picker's, can cancel it with one request, though not take it over.

The real fix is enroll-to-cert, which ends the flow with a certificate that only the device holds.

### Discovered providers

ZDAS uses each external JWT signer the controller lists that allows enrollment as an upstream provider, with no policy of its own, since the controller admin chose the signer and its IdP. So a discovered provider admits every user its issuer signs in, and ZDAS logs a warning the first time each one appears.

To restrict one, configure a provider with the signer's name, issuer and client ID, plus a policy. ZDAS then uses it in place of the discovered one, and keeps the same callback URL. A discovered provider requests `openid`, `profile` and `email` plus the signer's own scopes, while a configured provider's `scopes` replace those defaults, so list them all, including any a policy on `groups` needs. The signer's audience isn't carried over.

### Mirrored controller data

ZDAS serves copies of two of the controller's public responses: the network JWTs at `/network-jwts`, and the external JWT signers at `/external-jwt-signers` and `/edge/client/v1/external-jwt-signers`. A tunneler pointed at ZDAS's URL can then find the network and its signers there.

- **The data is public:** the controller serves both to anyone, so on a public controller ZDAS exposes nothing new. On a controller that is not reachable from the internet, ZDAS is what makes them public.
- **ZDAS becomes a source of trust:** a tunneler that enrolls from ZDAS's URL trusts the controller and CA the network JWT names. ZDAS fetches it over TLS checked against the system roots together with the identity file's CA or `ca_bundle`, or against the system roots alone, or over plain HTTP if `controller.api_url` uses it, and passes it on as received. Serve ZDAS over HTTPS, and use an `https://` controller URL, wherever tunnelers bootstrap from it.

### Store eviction

When the built-in store is full, it drops the oldest sign-in still in progress instead of refusing new ones. Sign-ins start before anyone authenticates, so refusing them would let anonymous requests lock everyone out. To drop a user's sign-in, an attacker has to create 10,000 sessions within the minute or so that user takes, either before or after the consent click. With the default per-client limit, that takes about 77 IPv4 addresses or 5 IPv6 /48s, and the same flood drops every sign-in in progress, not just one. The per-client limit raises the cost of that; it doesn't rule it out. Each sign-in lasts at most the session timeout in all, from `/authorize` to `/callback`, so time on the consent page comes out of the time left for the IdP.

A limit on `/authorize` for all clients together (`global_per_second`) is off by default for the same reason. Once a few addresses use it up, it refuses everyone. It is there for a shared Store that has to stay small, and then only valid requests spend it. Each replica enforces its own, so a Store shared by N replicas sees up to N times the rate.
