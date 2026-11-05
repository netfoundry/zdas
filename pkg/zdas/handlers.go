package zdas

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/time/rate"
)

// endpoints serves the ZDAS HTTP endpoints and holds their dependencies.
type endpoints struct {
	cfg         Config
	keys        *KeySet   // active signing key
	jwksKeys    []*KeySet // keys served at /.well-known/jwks.json: keys first, unique by kid
	registry    *ProviderRegistry
	store       Store
	discovery   *signerDiscovery      // for cached network JWTs; may be nil in tests
	reconciler  *fallbackReconciler   // nil when fallback is disabled
	provisioner EnrollmentProvisioner // nil uses built-in ComposeClaims
	rateLimiter *ipRateLimiter        // nil when rate limiting is disabled
	globalLimit *rate.Limiter         // GET /authorize for all clients; nil when disabled
	rejections  *rejectionLog         // counts and logs what the limits refuse
	misses      callbackMissLog       // counts and logs callbacks that finish no sign-in
	redirects   []*url.URL            // parsed cfg.AllowedRedirectURIs; nil keeps the loopback default
	logger      *slog.Logger

	// Scope of the browser binding cookie, from cfg.ExternalURL.
	cookiePath   string
	cookieSecure bool
}

// newEndpoints returns endpoints that sign with keys, publish keys plus
// verifyKeys in the JWKS, and expire store entries by cfg.Session.
func newEndpoints(cfg Config, keys *KeySet, verifyKeys []*KeySet, registry *ProviderRegistry, store Store, discovery *signerDiscovery, reconciler *fallbackReconciler, provisioner EnrollmentProvisioner, logger *slog.Logger) *endpoints {
	var jwksKeys []*KeySet
	if keys != nil {
		jwksKeys = uniqueKeySets(keys, verifyKeys)
	}
	h := &endpoints{
		cfg:         cfg,
		keys:        keys,
		jwksKeys:    jwksKeys,
		registry:    registry,
		store:       store,
		discovery:   discovery,
		reconciler:  reconciler,
		provisioner: provisioner,
		logger:      logger,
	}
	h.cookiePath, h.cookieSecure = bindingCookieScope(cfg.ExternalURL)
	h.rateLimiter = newIPRateLimiter(cfg.RateLimit, logger)
	h.rejections = newRejectionLog(logger)
	h.misses.log.Interval = callbackMissLogInterval
	if rl := cfg.RateLimit; rl.GlobalPerSecond > 0 {
		h.globalLimit = rate.NewLimiter(rate.Limit(rl.GlobalPerSecond), defaultBurst(rl.GlobalPerSecond, rl.GlobalBurst))
	}
	h.redirects = parseAllowList(cfg.AllowedRedirectURIs, logger)
	return h
}

// mux returns an http.ServeMux wired to all ZDAS endpoints.
func (h *endpoints) mux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", h.handleDiscovery)
	mux.HandleFunc("GET /.well-known/jwks.json", h.handleJWKS)
	mux.HandleFunc("GET /network-jwts", h.handleNetworkJWTs)
	mux.HandleFunc("GET /edge/client/v1/external-jwt-signers", h.handleExtJWTSigners)
	mux.HandleFunc("GET /external-jwt-signers", h.handleExtJWTSigners)
	mux.HandleFunc("GET /authorize", h.handleAuthorize)
	mux.HandleFunc("POST /authorize", h.handleConsent)
	mux.HandleFunc("GET /callback", h.handleCallback)
	mux.HandleFunc("GET /callback/{provider}", h.handleCallback)
	mux.HandleFunc("/callback", h.handleStrayCallback)
	mux.HandleFunc("/callback/", h.handleStrayCallback)
	mux.HandleFunc("POST /token", h.handleToken)
	return mux
}

func (h *endpoints) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	ext := h.cfg.ExternalURL
	doc := map[string]any{
		"issuer":                                h.cfg.Token.Issuer,
		"authorization_endpoint":                ext + "/authorize",
		"token_endpoint":                        ext + "/token",
		"jwks_uri":                              ext + "/.well-known/jwks.json",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"ES256"},
		"grant_types_supported":                 []string{"authorization_code"},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(doc)
}

func (h *endpoints) handleNetworkJWTs(w http.ResponseWriter, r *http.Request) {
	if h.discovery == nil {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	body := h.discovery.cachedNetworkJWTs()
	if body == nil {
		http.Error(w, "network JWTs not yet available", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}

func (h *endpoints) handleExtJWTSigners(w http.ResponseWriter, r *http.Request) {
	if h.discovery == nil {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	body := h.discovery.cachedExtJWTSigners()
	if body == nil {
		http.Error(w, "external JWT signers not yet available", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}

func (h *endpoints) handleJWKS(w http.ResponseWriter, r *http.Request) {
	data, err := publicJWKS(h.jwksKeys)
	if err != nil {
		h.logger.Error("marshal jwks", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

// Limits on the /authorize parameters a session keeps. Sessions are created
// before anyone authenticates, so unbounded values would let anonymous
// requests fill memory. Tunnelers send far less than these.
const (
	maxRedirectURILength = 2048
	maxStateLength       = 512
	maxNonceLength       = 512
	// s256ChallengeLength is the length of an S256 code_challenge: a
	// SHA-256 digest in unpadded base64url (RFC 7636 section 4.2).
	s256ChallengeLength = 43
)

func (h *endpoints) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if h.rateLimiter != nil && !h.rateLimiter.allow(r) {
		h.rejections.add(rejectClient)
		tooManyRequests(w)
		return
	}

	q := r.URL.Query()
	redirectURI := q.Get("redirect_uri")
	state := q.Get("state")
	nonce := q.Get("nonce")
	deviceName := q.Get("device_name")
	hostname := q.Get("hostname")
	osName := q.Get("os")
	arch := q.Get("arch")
	osRelease := q.Get("os_release")
	osVersion := q.Get("os_version")
	idpHint := q.Get("idp") // set by the IdP selector page, not by tunnelers
	enrollmentMethod := q.Get("enrollment_method")
	clientType := q.Get("client_type") // optional hint for embedders; not sent by unmodified tunnelers
	codeChallenge := q.Get("code_challenge")
	codeChallengeMethod := q.Get("code_challenge_method")

	// Validate redirect_uri early - before we trust it for error redirects.
	// state is echoed in those redirects, so it is checked here too.
	if redirectURI == "" {
		http.Error(w, "redirect_uri is required", http.StatusBadRequest)
		return
	}
	if len(redirectURI) > maxRedirectURILength {
		http.Error(w, "redirect_uri is too long", http.StatusBadRequest)
		return
	}
	if len(state) > maxStateLength {
		http.Error(w, "state is too long", http.StatusBadRequest)
		return
	}
	if len(nonce) > maxNonceLength {
		http.Error(w, "nonce is too long", http.StatusBadRequest)
		return
	}
	parsedRedirect, err := parseRedirectURI(redirectURI)
	if err != nil {
		http.Error(w, "redirect_uri must be a valid http(s) URL", http.StatusBadRequest)
		return
	}
	if !redirectAllowed(parsedRedirect, h.redirects) {
		http.Error(w, "redirect_uri is not allowed", http.StatusBadRequest)
		return
	}

	// Validate remaining required parameters. Tunnelers always send
	// response_type=code, the only flow ZDAS has; one that sends nothing is
	// let through, as before.
	if rt := q.Get("response_type"); rt != "" && rt != "code" {
		oidcErrorRedirect(w, r, redirectURI, state, "unsupported_response_type", "only response_type=code is supported")
		return
	}
	if codeChallenge == "" || codeChallengeMethod == "" {
		oidcErrorRedirect(w, r, redirectURI, state, "invalid_request", "PKCE code_challenge and code_challenge_method are required")
		return
	}
	if codeChallengeMethod != "S256" {
		oidcErrorRedirect(w, r, redirectURI, state, "invalid_request", "only S256 code_challenge_method is supported")
		return
	}
	if !validS256Challenge(codeChallenge) {
		oidcErrorRedirect(w, r, redirectURI, state, "invalid_request", "code_challenge must be a base64url SHA-256 digest")
		return
	}
	var fallbackNonce string
	if deviceName == "" {
		if !h.cfg.Fallback.Enabled {
			oidcErrorRedirect(w, r, redirectURI, state, "invalid_request", "device_name parameter required")
			return
		}
		// Every fallback login gets a new external ID, so a token-enrolled
		// fallback identity could not sign in again once its first token
		// expired. Unmodified tunnelers don't say how they enroll, so
		// fallback is refused whenever ZDAS's signer allows enroll-to-token.
		if h.discovery != nil && h.discovery.selfAllowsTokenEnrollment() {
			h.logger.Error("refusing fallback login: ZDAS's signer on the controller allows enroll-to-token, which fallback identities cannot use; enable only enroll-to-cert on it while fallback is on")
			oidcErrorRedirect(w, r, redirectURI, state, "invalid_request", "device_name parameter required: fallback enrollment supports enroll-to-cert only")
			return
		}
		// Fallback path: generate a nonce for this enrollment.
		nonce, err := generateShortNonce()
		if err != nil {
			h.logger.Error("generate fallback nonce", "error", err)
			oidcErrorRedirect(w, r, redirectURI, state, "server_error", "internal error")
			return
		}
		fallbackNonce = nonce
	} else if len(deviceName) > 255 {
		oidcErrorRedirect(w, r, redirectURI, state, "invalid_request", "device_name too long (max 255 characters)")
		return
	} else if displayText(deviceName, maxDisplayedDeviceRunes) == "" {
		// The consent page would show the hostname instead, while the
		// identity is named after this.
		oidcErrorRedirect(w, r, redirectURI, state, "invalid_request", "device_name must contain visible characters")
		return
	} else if strings.Contains(deviceName, ":") {
		// The external ID hashes issuer, subject and device name joined by
		// ':', so a ':' here could make one user's device collide with
		// another's. See computeExternalID.
		oidcErrorRedirect(w, r, redirectURI, state, "invalid_request", "device_name must not contain ':'")
		return
	}
	// Always populate DeviceInfo with whatever the tunneler sent. On the
	// fallback path DeviceName will be empty, but os/hostname/arch may
	// still be present and useful to the consumer (e.g. provisioner).
	deviceInfo := &DeviceInfo{
		DeviceName: strings.Clone(deviceName),
		Hostname:   truncateParam(hostname, 255),
		OS:         truncateParam(osName, 64),
		Arch:       truncateParam(arch, 64),
		OSRelease:  truncateParam(osRelease, 128),
		OSVersion:  truncateParam(osVersion, 128),
	}

	// Work out which providers to offer, but go no further: the user
	// continues from a ZDAS page (handleConsent), so that a link alone
	// cannot sign in someone whose IdP session is still live.
	var choices []string
	switch provider, err := h.registry.Resolve(idpHint); {
	case err == nil:
		choices = []string{provider.Name()}
	case errors.Is(err, ErrMultipleProviders):
		choices = h.registry.Names()
		sort.Strings(choices)
	case errors.Is(err, ErrNoProviders):
		h.logger.Error("no upstream providers configured")
		oidcErrorRedirect(w, r, redirectURI, state, "server_error", "no upstream providers available")
		return
	default:
		oidcErrorRedirect(w, r, redirectURI, state, "invalid_request", "unknown idp")
		return
	}

	// Copy what the session keeps: values parsed from the query can share
	// its memory, and the session would keep the whole request line alive.
	// UpstreamProviderName stays empty until the user chooses.
	sess := &AuthSession{
		TunnelerRedirectURI:         strings.Clone(redirectURI),
		TunnelerState:               strings.Clone(state),
		TunnelerNonce:               strings.Clone(nonce),
		TunnelerCodeChallenge:       strings.Clone(codeChallenge),
		TunnelerCodeChallengeMethod: strings.Clone(codeChallengeMethod),
		DeviceInfo:                  deviceInfo,
		FallbackNonce:               fallbackNonce,
		EnrollmentMethod:            truncateParam(enrollmentMethod, 64),
		ClientType:                  truncateParam(clientType, 64),
	}
	// The global limit is spent only here, by a request that stores a
	// session, so that invalid requests cannot use it up.
	if h.globalLimit != nil && !h.globalLimit.Allow() {
		h.rejections.add(rejectGlobal)
		tooManyRequests(w)
		return
	}
	consentID, err := h.startSession(w, r, sess)
	if err != nil {
		h.logger.Error("create session", "error", err)
		oidcErrorRedirect(w, r, redirectURI, state, "server_error", "internal error")
		return
	}
	if len(choices) > 1 && h.cfg.IDPSelectorURL != "" {
		h.redirectToIDPSelector(w, r, choices, consentID)
		return
	}
	h.renderConsent(w, deviceInfo, parsedRedirect, choices, consentID)
}

// callbackURL returns the redirect_uri ZDAS sends provider: its own
// callback path, or the shared one with LegacyCallback.
func (h *endpoints) callbackURL(provider string) string {
	if h.cfg.LegacyCallback {
		return h.cfg.ExternalURL + "/callback"
	}
	return h.cfg.ExternalURL + "/callback/" + url.PathEscape(provider)
}

// maxConsentRequestBytes caps the form posted from the consent page, which
// holds a session ID and a provider name.
const maxConsentRequestBytes = 4 << 10

// consentMissing is the response to a consent form without a matching
// session.
const consentMissing = "sign-in request not found or expired; start again from the app"

// handleConsent takes the form posted from the page /authorize shows, and
// sends the browser to the chosen provider. The session /authorize stored
// is bound to its browser by a SameSite=Lax cookie, which a cross-site
// form post does not carry, so the post must come from that browser.
func (h *endpoints) handleConsent(w http.ResponseWriter, r *http.Request) {
	if h.rateLimiter != nil && !h.rateLimiter.allow(r) {
		h.rejections.add(rejectClient)
		tooManyRequests(w)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxConsentRequestBytes)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "malformed form body", http.StatusBadRequest)
		return
	}
	// Resolve the provider before consuming the session, so that a post
	// naming none or an unknown one leaves the session for another try.
	provider, err := h.registry.Resolve(r.PostFormValue("idp"))
	switch {
	case errors.Is(err, ErrNoProviders):
		h.logger.Error("no upstream providers configured")
		http.Error(w, "no sign-in providers are available; try again later", http.StatusServiceUnavailable)
		return
	case err != nil:
		http.Error(w, "unknown or missing sign-in provider; go back and choose one", http.StatusBadRequest)
		return
	}
	sess, otherBrowser, err := h.consumeBoundSession(w, r, r.PostFormValue("consent"))
	if err != nil {
		h.logger.Error("consume session", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if otherBrowser {
		h.logger.Warn("consent posted from a browser that did not start the sign-in; cancelled it")
		http.Error(w, sessionWarning, http.StatusBadRequest)
		return
	}
	// A session that already has a provider is waiting for /callback, not
	// for consent.
	if sess == nil || sess.UpstreamProviderName != "" {
		http.Error(w, consentMissing, http.StatusBadRequest)
		return
	}
	sess.UpstreamProviderName = provider.Name()
	sess.CallbackURL = h.callbackURL(provider.Name())

	// For OIDC, use our own PKCE pair toward the upstream, keeping the
	// verifier in the session for /callback. Other providers (GitHub) get
	// none.
	oidcProv, usePKCE := provider.(*OIDCProvider)
	var challenge string
	if usePKCE {
		if sess.ZDASCodeVerifier, challenge, err = generatePKCE(); err != nil {
			h.logger.Error("generate pkce", "error", err)
			oidcErrorRedirect(w, r, sess.TunnelerRedirectURI, sess.TunnelerState, "server_error", "internal error")
			return
		}
	}
	sessionState, err := h.startSession(w, r, sess)
	if err != nil {
		h.logger.Error("create session", "error", err)
		oidcErrorRedirect(w, r, sess.TunnelerRedirectURI, sess.TunnelerState, "server_error", "internal error")
		return
	}
	var upstreamURL string
	if usePKCE {
		upstreamURL = oidcProv.authorizeURL(sessionState, sess.CallbackURL, challenge)
	} else {
		upstreamURL = provider.AuthorizeURL(sessionState, sess.CallbackURL)
	}

	if sess.FallbackNonce != "" {
		h.logger.Info("redirecting to upstream (fallback)", "provider", provider.Name(), "nonce", sess.FallbackNonce)
	} else {
		h.logger.Info("redirecting to upstream", "provider", provider.Name(), "device", sess.DeviceInfo.DeviceName)
	}
	http.Redirect(w, r, upstreamURL, http.StatusSeeOther)
}

// sessionWarning is the response to a consent post or /callback that
// finishes no sign-in: from a browser that did not start it, which cancels
// it, or a /callback that names no session waiting for one. A phisher who
// starts a sign-in in their own browser and sends the victim the IdP's
// address needs the victim to send back the address this lands on, so the
// text warns against exactly that, first. It also follows a reload after a
// sign-in that worked, so it ends with what to do then.
const sessionWarning = "This sign-in can't be finished here. " +
	"If someone sent you a sign-in link, or asks you to send them this page's address, don't: it would let them enroll a device as you. " +
	"If you were signing in yourself, it has expired, was cancelled, or was started in a different browser: start again from the app and finish in the browser it opens. " +
	"If you had already finished, you can close this page."

func (h *endpoints) handleCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	code := q.Get("code")
	sessionState := q.Get("state")

	// The session holds the tunneler's redirect_uri, which every outcome
	// below needs, including an upstream error.
	sess, otherBrowser, err := h.consumeBoundSession(w, r, sessionState)
	if err != nil {
		h.logger.Error("consume session", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if otherBrowser {
		h.logger.Warn("callback from a browser that did not start the sign-in; cancelled it")
		http.Error(w, sessionWarning, http.StatusBadRequest)
		return
	}
	// A session without a provider is still waiting for consent.
	if sess == nil || sess.UpstreamProviderName == "" {
		// A phisher who started the sign-in can edit the IdP's address so
		// that the victim's browser names no session here and cancels
		// nothing, then finish it with the address the victim sends back.
		// The edit can also move the code out of the query (into a
		// fragment, a JWT or a form post), so every miss warns, whatever the
		// query holds.
		h.misses.add(h.logger, r, code != "")
		http.Error(w, sessionWarning, http.StatusBadRequest)
		return
	}

	if errParam := q.Get("error"); errParam != "" {
		desc := q.Get("error_description")
		h.logger.Warn("upstream returned error", "error", errParam, "description", desc)
		oidcErrorRedirect(w, r, sess.TunnelerRedirectURI, sess.TunnelerState, upstreamErrorCode(errParam), sanitizeErrorDescription(desc))
		return
	}
	if code == "" {
		h.logger.Warn("upstream callback without a code", "provider", sess.UpstreamProviderName)
		oidcErrorRedirect(w, r, sess.TunnelerRedirectURI, sess.TunnelerState, "server_error", "upstream returned no authorization code")
		return
	}

	provider, err := h.registry.Resolve(sess.UpstreamProviderName)
	if err != nil {
		h.logger.Error("resolve provider from session", "provider", sess.UpstreamProviderName, "error", err)
		oidcErrorRedirect(w, r, sess.TunnelerRedirectURI, sess.TunnelerState, "server_error", "provider no longer available")
		return
	}

	// A response that reached the wrong callback, or that names another
	// issuer, came from an IdP other than the one this sign-in went to: a
	// mix-up attack (RFC 9700 section 4.4). Its code must not be sent to
	// this provider's token endpoint.
	callbackURL := sess.CallbackURL
	if callbackURL == "" {
		callbackURL = h.cfg.ExternalURL + "/callback"
	}
	reached := h.cfg.ExternalURL + "/callback"
	if p := r.PathValue("provider"); p != "" {
		reached += "/" + url.PathEscape(p)
	}
	if reached != callbackURL {
		h.logger.Warn("upstream response at another provider's callback", "provider", provider.Name(), "callback", reached)
		oidcErrorRedirect(w, r, sess.TunnelerRedirectURI, sess.TunnelerState, "invalid_request", "sign-in response came back for another identity provider")
		return
	}
	if oidcProv, ok := provider.(*OIDCProvider); ok {
		if err := oidcProv.checkResponseIssuer(q.Get("iss")); err != nil {
			h.logger.Warn("upstream response from another issuer", "provider", provider.Name(), "error", err)
			oidcErrorRedirect(w, r, sess.TunnelerRedirectURI, sess.TunnelerState, "invalid_request", "sign-in response came back for another identity provider")
			return
		}
	}

	var identity *UpstreamIdentity
	if oidcProv, ok := provider.(*OIDCProvider); ok && sess.ZDASCodeVerifier != "" {
		identity, err = oidcProv.ExchangeAndIdentifyWithPKCE(r.Context(), code, callbackURL, sess.ZDASCodeVerifier)
	} else {
		identity, err = provider.ExchangeAndIdentify(r.Context(), code, callbackURL)
	}
	if errors.Is(err, ErrAccessDenied) {
		h.logger.Info("upstream identity not permitted", "provider", provider.Name(), "error", err)
		oidcErrorRedirect(w, r, sess.TunnelerRedirectURI, sess.TunnelerState, "access_denied", "your account is not permitted to enroll")
		return
	}
	if err != nil {
		h.logger.Error("exchange and identify", "provider", provider.Name(), "error", err)
		oidcErrorRedirect(w, r, sess.TunnelerRedirectURI, sess.TunnelerState, "server_error", "upstream authentication failed")
		return
	}

	var claims map[string]any
	if h.provisioner != nil {
		// Choose the pending ID up front so the provisioner can record it;
		// the entry is stored only if Provision redirects.
		pendingID, err := randomID()
		if err != nil {
			h.logger.Error("generate pending id", "error", err)
			oidcErrorRedirect(w, r, sess.TunnelerRedirectURI, sess.TunnelerState, "server_error", "internal error")
			return
		}
		req := ProvisionRequest{
			Email:            identity.Email,
			Name:             identity.Username,
			Subject:          identity.Subject,
			Provider:         sess.UpstreamProviderName,
			Raw:              identity.Raw,
			EnrollmentMethod: sess.EnrollmentMethod,
			ClientType:       sess.ClientType,
			IsFallback:       sess.FallbackNonce != "",
			FallbackNonce:    sess.FallbackNonce,
			DeviceName:       sess.DeviceInfo.DeviceName,
			Hostname:         sess.DeviceInfo.Hostname,
			OS:               sess.DeviceInfo.OS,
			Arch:             sess.DeviceInfo.Arch,
			OSRelease:        sess.DeviceInfo.OSRelease,
			OSVersion:        sess.DeviceInfo.OSVersion,
			PendingID:        pendingID,
		}
		result, err := h.provisioner.Provision(r.Context(), req)
		if err == nil && (result == nil || (len(result.Claims) == 0 && result.RedirectURL == "")) {
			err = errors.New("provisioner returned neither claims nor a redirect URL")
		}
		if err != nil {
			h.handleProvisionerError(w, r, err, sess.TunnelerRedirectURI, sess.TunnelerState, "provider", sess.UpstreamProviderName)
			return
		}
		if len(result.Claims) == 0 {
			// Interactive provisioning - stash session state and redirect.
			err := h.createPendingProvision(r.Context(), pendingID, &PendingProvision{
				TunnelerRedirectURI:         sess.TunnelerRedirectURI,
				TunnelerState:               sess.TunnelerState,
				TunnelerNonce:               sess.TunnelerNonce,
				TunnelerCodeChallenge:       sess.TunnelerCodeChallenge,
				TunnelerCodeChallengeMethod: sess.TunnelerCodeChallengeMethod,
				IsFallback:                  sess.FallbackNonce != "",
				FallbackNonce:               sess.FallbackNonce,
			})
			if err != nil {
				h.logger.Error("create pending provision", "error", err)
				oidcErrorRedirect(w, r, sess.TunnelerRedirectURI, sess.TunnelerState, "server_error", "internal error")
				return
			}
			http.Redirect(w, r, withQuery(result.RedirectURL, url.Values{"pending_id": {pendingID}}), http.StatusFound)
			return
		}
		claims = result.Claims
	} else {
		claims = ComposeClaims(h.cfg.Claims, h.cfg.Fallback, identity, sess.DeviceInfo, sess.FallbackNonce)
	}

	claims = ownClaims(claims, sess.TunnelerNonce)
	if err := checkClaims(h.cfg.Token, claims); err != nil {
		h.handleProvisionerError(w, r, fmt.Errorf("provisioner returned claims that cannot be signed: %w", err),
			sess.TunnelerRedirectURI, sess.TunnelerState, "provider", sess.UpstreamProviderName)
		return
	}

	ac := &AuthCode{
		Claims:              claims,
		RedirectURI:         sess.TunnelerRedirectURI,
		CodeChallenge:       sess.TunnelerCodeChallenge,
		CodeChallengeMethod: sess.TunnelerCodeChallengeMethod,
		IsFallback:          sess.FallbackNonce != "",
	}
	zdasCode, err := h.createCode(r.Context(), ac)
	if err != nil {
		h.logger.Error("create auth code", "error", err)
		oidcErrorRedirect(w, r, sess.TunnelerRedirectURI, sess.TunnelerState, "server_error", "internal error")
		return
	}
	h.trackFallback(claims, sess.FallbackNonce)

	redir := withQuery(sess.TunnelerRedirectURI, url.Values{
		"code":  {zdasCode},
		"state": {sess.TunnelerState},
	})
	deviceLog := sess.DeviceInfo.DeviceName
	if deviceLog == "" {
		deviceLog = "fallback"
	}
	h.logger.Info("callback complete, redirecting to tunneler", "provider", provider.Name(), "device", deviceLog)
	http.Redirect(w, r, redir, http.StatusFound)
}

// maxCallbackFormBytes caps the body a stray POST to /callback is read for
// its state. A form_post response can carry an ID token next to it.
const maxCallbackFormBytes = 64 << 10

// handleStrayCallback answers what reaches /callback other than a GET of a
// provider's callback: another method, such as an IdP's form_post response,
// or a path below a callback, which GitHub accepts as a redirect_uri. ZDAS
// never asks for either, so it comes from an IdP address someone edited.
// The session its state names is consumed, cancelling a phisher's sign-in
// as handleCallback does for another browser, and the browser is warned.
func (h *endpoints) handleStrayCallback(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxCallbackFormBytes)
	sess, otherBrowser, err := h.consumeBoundSession(w, r, r.FormValue("state"))
	if err != nil {
		h.logger.Error("consume session", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if sess != nil || otherBrowser {
		h.logger.Warn("sign-in response at a callback ZDAS never asked for; cancelled it", "method", r.Method, "path", r.URL.Path)
	}
	h.misses.add(h.logger, r, r.FormValue("code") != "")
	http.Error(w, sessionWarning, http.StatusBadRequest)
}

// callbackMissLogInterval is the least time between log lines about
// callbacks that finish no sign-in.
const callbackMissLogInterval = time.Minute

// callbackMissLog counts the /callback requests that finish no sign-in, and
// logs how many at most once per callbackMissLogInterval. One that carries a
// code can be a phisher's edited IdP address, so operators can see them
// without a flood filling the log.
type callbackMissLog struct {
	count    atomic.Int64
	withCode atomic.Int64
	log      rate.Sometimes
}

// add counts one miss, whether it carried a code, and logs the counts since
// the last line when callbackMissLogInterval has passed. It reads nothing
// from r but its method and path, so the log never reads a request body.
func (l *callbackMissLog) add(logger *slog.Logger, r *http.Request, hadCode bool) {
	l.count.Add(1)
	if hadCode {
		l.withCode.Add(1)
	}
	l.log.Do(func() {
		logger.Warn("callbacks finished no sign-in; one with a code may be from an edited sign-in link",
			"count", l.count.Swap(0), "with_code", l.withCode.Swap(0), "last_method", r.Method, "last_path", r.URL.Path)
	})
}

// maxTokenRequestBytes caps a /token request body. A real one is a few
// hundred bytes.
const maxTokenRequestBytes = 16 << 10

func (h *endpoints) handleToken(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxTokenRequestBytes)
	if err := r.ParseForm(); err != nil {
		tokenError(w, "invalid_request", "malformed form body")
		return
	}

	grantType := r.FormValue("grant_type")
	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")
	codeVerifier := r.FormValue("code_verifier")

	if grantType != "authorization_code" {
		tokenError(w, "unsupported_grant_type", "only authorization_code is supported")
		return
	}
	if code == "" {
		tokenError(w, "invalid_request", "code is required")
		return
	}

	ac, err := h.consumeCode(r.Context(), code)
	if err != nil {
		h.logger.Error("consume code", "error", err)
		tokenError(w, "server_error", "internal error")
		return
	}
	if ac == nil {
		tokenError(w, "invalid_grant", "code is invalid, expired, or already used")
		return
	}
	if ac.RedirectURI != redirectURI {
		tokenError(w, "invalid_grant", "redirect_uri mismatch")
		return
	}
	if !verifyPKCE(ac.CodeChallenge, ac.CodeChallengeMethod, codeVerifier) {
		tokenError(w, "invalid_grant", "PKCE verification failed")
		return
	}

	signed, err := MintToken(h.cfg.Token, ac.Claims, h.keys)
	if err != nil {
		h.logger.Error("mint token", "error", err)
		tokenError(w, "server_error", "token signing failed")
		return
	}

	resp := map[string]any{
		"access_token": signed,
		"id_token":     signed,
		"token_type":   "Bearer",
		"expires_in":   int(h.cfg.Token.Expiry.Seconds()),
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(resp)
}

// upstreamErrorCode returns the error code to send the tunneler for an
// error the upstream IdP returned to /callback: the code itself when it is
// one OAuth 2.0 or OpenID Connect defines for an authorization response, and
// server_error otherwise.
func upstreamErrorCode(code string) string {
	switch code {
	case "invalid_request", "unauthorized_client", "access_denied",
		"unsupported_response_type", "invalid_scope", "server_error",
		"temporarily_unavailable", "interaction_required", "login_required",
		"account_selection_required", "consent_required":
		return code
	}
	return "server_error"
}

// sanitizeErrorDescription enforces RFC 6749 section 4.1.2.1 character class
// for OIDC error_description: printable ASCII excluding " and \, with newlines
// and other control characters replaced by spaces. Truncates to 200 chars to
// keep redirect URLs reasonable.
func sanitizeErrorDescription(s string) string {
	const maxLen = 200
	if len(s) > maxLen {
		s = s[:maxLen]
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		// Allowed: %x20-21, %x23-5B, %x5D-7E (RFC 6749 §4.1.2.1).
		switch {
		case c == 0x20 || c == 0x21,
			c >= 0x23 && c <= 0x5B,
			c >= 0x5D && c <= 0x7E:
			out = append(out, c)
		default:
			out = append(out, ' ')
		}
	}
	return string(out)
}

// truncateParam returns a copy of a tunneler-supplied query parameter, cut to
// maxLen bytes. It copies so that a stored value does not keep the request's
// query string in memory.
func truncateParam(s string, maxLen int) string {
	if len(s) > maxLen {
		s = s[:maxLen]
	}
	return strings.Clone(s)
}

// validS256Challenge reports whether challenge is an S256 code_challenge: a
// 32-byte digest in canonical unpadded base64url.
func validS256Challenge(challenge string) bool {
	if len(challenge) != s256ChallengeLength {
		return false
	}
	digest, err := base64.RawURLEncoding.Strict().DecodeString(challenge)
	return err == nil && len(digest) == sha256.Size
}

// handleProvisionerError translates an error from the EnrollmentProvisioner
// into an OIDC error redirect. A *ProvisionError with a valid OIDC code is
// passed through to the tunneler. Anything else (plain error or invalid code)
// becomes server_error with a generic description. logArgs are added to
// the log entry.
func (h *endpoints) handleProvisionerError(w http.ResponseWriter, r *http.Request, err error, redirectURI, state string, logArgs ...any) {
	logger := h.logger.With(logArgs...)
	var pe *ProvisionError
	if errors.As(err, &pe) {
		if !isValidProvisionErrorCode(pe.Code) {
			logger.Warn("provisioner returned invalid error code, falling back to server_error",
				"code", pe.Code)
			oidcErrorRedirect(w, r, redirectURI, state, "server_error", "provisioning failed")
			return
		}
		logger.Info("provisioner rejected request",
			"code", pe.Code,
			"description", pe.Description,
		)
		oidcErrorRedirect(w, r, redirectURI, state, pe.Code, sanitizeErrorDescription(pe.Description))
		return
	}
	logger.Error("provisioner failed", "error", err)
	oidcErrorRedirect(w, r, redirectURI, state, "server_error", "provisioning failed")
}

// completeProvision implements Handler.CompleteProvision.
func (h *endpoints) completeProvision(w http.ResponseWriter, r *http.Request, pendingID string, claims map[string]any, err error) {
	pp, cerr := h.consumePendingProvision(r.Context(), pendingID)
	if cerr != nil {
		h.logger.Error("consume pending provision", "error", cerr)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if pp == nil {
		http.Error(w, "pending provision not found or expired", http.StatusBadRequest)
		return
	}
	if err == nil && len(claims) == 0 {
		err = errors.New("CompleteProvision called with neither claims nor an error")
	}
	if err == nil {
		claims = ownClaims(claims, pp.TunnelerNonce)
		if cerr := checkClaims(h.cfg.Token, claims); cerr != nil {
			err = fmt.Errorf("CompleteProvision called with claims that cannot be signed: %w", cerr)
		}
	}
	if err != nil {
		h.handleProvisionerError(w, r, err, pp.TunnelerRedirectURI, pp.TunnelerState)
		return
	}

	ac := &AuthCode{
		Claims:              claims,
		RedirectURI:         pp.TunnelerRedirectURI,
		CodeChallenge:       pp.TunnelerCodeChallenge,
		CodeChallengeMethod: pp.TunnelerCodeChallengeMethod,
		IsFallback:          pp.IsFallback,
	}
	zdasCode, err := h.createCode(r.Context(), ac)
	if err != nil {
		h.logger.Error("create auth code from provision", "error", err)
		oidcErrorRedirect(w, r, pp.TunnelerRedirectURI, pp.TunnelerState, "server_error", "internal error")
		return
	}

	h.trackFallback(claims, pp.FallbackNonce)
	redir := withQuery(pp.TunnelerRedirectURI, url.Values{
		"code":  {zdasCode},
		"state": {pp.TunnelerState},
	})
	http.Redirect(w, r, redir, http.StatusFound)
}

// trackFallback queues the identity in claims for the reconciler when nonce
// marks a fallback enrollment. The reconciler renames the identity once the
// tunneler reports its hostname.
func (h *endpoints) trackFallback(claims map[string]any, nonce string) {
	if nonce == "" || h.reconciler == nil {
		return
	}
	if extID, ok := claims[h.cfg.Claims.ExternalIDClaim].(string); ok {
		username, _ := claims[preferredUsernameClaim].(string)
		h.reconciler.track(extID, username, nonce)
	}
}

// verifyPKCE validates the code_verifier against the stored code_challenge
// using the S256 method. Uses constant-time comparison to avoid timing leaks.
func verifyPKCE(challenge, method, verifier string) bool {
	if method != "S256" || verifier == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(pkceChallenge(verifier)), []byte(challenge)) == 1
}

// oidcErrorRedirect sends an OIDC-compliant error redirect.
func oidcErrorRedirect(w http.ResponseWriter, r *http.Request, redirectURI, state, errCode, errDesc string) {
	v := url.Values{
		"error":             {errCode},
		"error_description": {errDesc},
	}
	if state != "" {
		v.Set("state", state)
	}
	http.Redirect(w, r, withQuery(redirectURI, v), http.StatusFound)
}

// storeKey returns the key the entry of the given kind and ID is stored
// under. See Store for why it is a hash.
func (h *endpoints) storeKey(kind, id string) string {
	return hashStoreKey(kind, h.cfg.Token.Issuer, id)
}

// createSession stores sess under a new ID, bound to nonce (see
// bindingHash), and returns the ID. A new session is stamped with the
// current time; one carried over from consent keeps its CreatedAt, so that
// a sign-in lasts at most the session timeout in all.
func (h *endpoints) createSession(ctx context.Context, sess *AuthSession, nonce string) (string, error) {
	if nonce == "" {
		return "", errors.New("create session: no binding nonce")
	}
	id, err := randomID()
	if err != nil {
		return "", err
	}
	if sess.CreatedAt.IsZero() {
		sess.CreatedAt = time.Now()
	}
	sess.BindingHash = bindingHash(nonce)
	if err := h.store.CreateSession(ctx, h.storeKey(kindSession, id), sess); err != nil {
		return "", err
	}
	return id, nil
}

// createCode is createSession for authorization codes.
func (h *endpoints) createCode(ctx context.Context, ac *AuthCode) (string, error) {
	code, err := randomID()
	if err != nil {
		return "", err
	}
	ac.CreatedAt = time.Now()
	if err := h.store.CreateCode(ctx, h.storeKey(kindCode, code), ac); err != nil {
		return "", err
	}
	return code, nil
}

// createPendingProvision stamps pp with the current time and stores it under
// id, which the caller chose with randomID so it could pass it to the
// provisioner first.
func (h *endpoints) createPendingProvision(ctx context.Context, id string, pp *PendingProvision) error {
	pp.CreatedAt = time.Now()
	return h.store.CreatePendingProvision(ctx, h.storeKey(kindProvision, id), pp)
}

// consumeSession consumes an auth session and treats one that is no longer
// fresh as a miss, so a Store without expiry logic of its own never hands
// back an expired session. A malformed ID is a miss without a store lookup.
// It returns (nil, false, nil) on a miss. nonce is the one in the browser's
// binding cookie, or "" for none. When it is not the session's, the session
// is consumed all the same and consumeSession returns (nil, true, nil), so a
// sign-in whose session ID reaches another browser cannot be finished
// anywhere.
func (h *endpoints) consumeSession(ctx context.Context, id, nonce string) (sess *AuthSession, otherBrowser bool, err error) {
	if !validID(id) {
		return nil, false, nil
	}
	sess, err = h.store.ConsumeSession(ctx, h.storeKey(kindSession, id))
	if err != nil || sess == nil || !h.fresh(kindSession, sess.CreatedAt, h.cfg.Session.Timeout) {
		return nil, false, err
	}
	if sess.BindingHash == "" {
		// createSession binds every session, so the Store lost the hash,
		// as one that predates the field would. Without it no browser can
		// be told apart, so the session is treated as missing.
		h.logger.Warn("store returned session without BindingHash, treating as expired")
		return nil, false, nil
	}
	if subtle.ConstantTimeCompare([]byte(sess.BindingHash), []byte(bindingHash(nonce))) != 1 {
		return nil, true, nil
	}
	return sess, false, nil
}

// consumeCode is consumeSession for authorization codes, checked against the
// code expiry.
func (h *endpoints) consumeCode(ctx context.Context, code string) (*AuthCode, error) {
	if !validID(code) {
		return nil, nil
	}
	ac, err := h.store.ConsumeCode(ctx, h.storeKey(kindCode, code))
	if err != nil || ac == nil || !h.fresh(kindCode, ac.CreatedAt, h.cfg.Session.CodeExpiry) {
		return nil, err
	}
	return ac, nil
}

// consumePendingProvision is consumeSession for pending provisions, checked
// against the session timeout.
func (h *endpoints) consumePendingProvision(ctx context.Context, id string) (*PendingProvision, error) {
	if !validID(id) {
		return nil, nil
	}
	pp, err := h.store.ConsumePendingProvision(ctx, h.storeKey(kindProvision, id))
	if err != nil || pp == nil || !h.fresh(kindProvision, pp.CreatedAt, h.cfg.Session.Timeout) {
		return nil, err
	}
	return pp, nil
}

// fresh reports whether an entry created at createdAt is still within ttl.
// A zero CreatedAt, or one further in the future than clock skew explains,
// means the store did not return the entry as stored; those are logged so
// they do not pass for ordinary expiry.
func (h *endpoints) fresh(kind string, createdAt time.Time, ttl time.Duration) bool {
	age := time.Since(createdAt)
	switch {
	case createdAt.IsZero():
		h.logger.Warn("store returned entry without CreatedAt, treating as expired", "kind", kind)
		return false
	case age < -maxClockSkew:
		h.logger.Warn("store returned entry created in the future, treating as expired",
			"kind", kind, "created_at", createdAt)
		return false
	}
	return age <= ttl
}

// tokenError writes a JSON error response for the /token endpoint: 500 for
// server_error, which is ZDAS's failure, and 400 for the rest (RFC 6749
// section 5.2).
func tokenError(w http.ResponseWriter, errCode, errDesc string) {
	status := http.StatusBadRequest
	if errCode == "server_error" {
		status = http.StatusInternalServerError
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error":             errCode,
		"error_description": errDesc,
	})
}

// redirectToIDPSelector sends the browser to the embedding application's
// picker with the original query string plus providers, the names to offer,
// and consent, the session ID the picker posts back. See
// Config.IDPSelectorURL.
func (h *endpoints) redirectToIDPSelector(w http.ResponseWriter, r *http.Request, providers []string, consentID string) {
	q := r.URL.Query()
	q.Set("providers", strings.Join(providers, ","))
	q.Set("consent", consentID)

	h.logger.Info("redirecting to host app idp selector",
		"url", h.cfg.IDPSelectorURL,
		"providers", providers,
	)
	http.Redirect(w, r, withQuery(h.cfg.IDPSelectorURL, q), http.StatusFound)
}

// consentPageData is what the consent page shows. Everything about the
// device comes from the request, so the page presents it as the device's
// own description, not as something ZDAS vouches for.
type consentPageData struct {
	Device    string   // the device's name, or its hostname on the fallback path
	Details   string   // OS and architecture, as reported
	ReturnTo  string   // the host and port the browser returns to
	Providers []string // one button each
	Consent   string   // the session ID the form posts back
}

// renderConsent shows the page the user continues from: one button per
// provider in providers, posting back to /authorize. The page cannot be
// framed, so another site cannot trick the user into clicking it.
func (h *endpoints) renderConsent(w http.ResponseWriter, info *DeviceInfo, redirect *url.URL, providers []string, consentID string) {
	device := displayText(info.DeviceName, maxDisplayedDeviceRunes)
	if device == "" {
		device = displayText(info.Hostname, maxDisplayedDeviceRunes)
	}
	data := consentPageData{
		Device:    device,
		Details:   displayText(strings.TrimSpace(info.OS+" "+info.Arch), maxDisplayedDeviceRunes),
		ReturnTo:  redirect.Host,
		Providers: providers,
		Consent:   consentID,
	}
	var buf bytes.Buffer
	if err := consentPage.Execute(&buf, data); err != nil {
		h.logger.Error("render consent page", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	hdr := w.Header()
	hdr.Set("Content-Type", "text/html; charset=utf-8")
	hdr.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")
	hdr.Set("X-Frame-Options", "DENY")
	hdr.Set("X-Content-Type-Options", "nosniff")
	hdr.Set("Referrer-Policy", "no-referrer")
	hdr.Set("Cache-Control", "no-store")
	w.Write(buf.Bytes())
}

// maxDisplayedDeviceRunes caps how much of the device's own description the
// consent page shows. Whoever sent the link chose that text, so it is kept
// to a label rather than room for a message.
const maxDisplayedDeviceRunes = 64

// maxCombiningMarks is how many combining marks displayText keeps after a
// character. Real text needs one or two; more can stack up over the
// surrounding lines.
const maxCombiningMarks = 2

// displayText returns s for showing on a page: without control, format
// (bidi override) and other unprintable characters, characters that print
// as blank, invalid UTF-8, leading or trailing spaces and marks with no
// character before them, with at most maxCombiningMarks marks on any
// character, and cut to at most limit
// characters and their marks, with an ellipsis when cut. It returns "" for
// text that would show as nothing.
func displayText(s string, limit int) string {
	var b strings.Builder
	n, marks := 0, 0
	for _, r := range s {
		if r == utf8.RuneError || !unicode.IsPrint(r) || printsBlank(r) || (r == ' ' && n == 0) {
			continue
		}
		if unicode.Is(unicode.M, r) {
			// A mark with no character before it shows as nothing, or
			// stacks over ZDAS's own text.
			if n == 0 || marks == maxCombiningMarks {
				continue
			}
			marks++
			b.WriteRune(r)
			continue
		}
		marks = 0
		if n == limit {
			b.WriteString("…")
			break
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimRight(b.String(), " ")
}

// printsBlank reports whether r is a printable character that renders as
// blank space: Hangul fillers, the Braille blank and Khmer's inherent
// vowels.
func printsBlank(r rune) bool {
	switch r {
	case '\u115F', '\u1160', '\u17B4', '\u17B5', '\u2800', '\u3164', '\uFFA0':
		return true
	}
	return false
}

// consentPage is the page renderConsent shows. The form has no action, so
// it posts to the page's own URL, wherever ZDAS is mounted. The device's
// description is shown as code, apart from ZDAS's own text, and the warning
// comes before the buttons.
var consentPage = template.Must(template.New("consent").Parse(`<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in to OpenZiti</title>
<style>
  body { font-family: -apple-system, system-ui, sans-serif; max-width: 420px; margin: 80px auto; padding: 0 20px; color: #333; }
  h1 { font-size: 1.4em; font-weight: 600; margin-bottom: 16px; }
  p { line-height: 1.4; }
  .note { font-size: 0.9em; color: #666; }
  code { background: #f5f5f5; padding: 1px 4px; border-radius: 4px; }
  button { display: block; width: 100%; padding: 14px 20px; margin: 8px 0; background: #f5f5f5; border: 1px solid #ddd; border-radius: 8px; color: #333; font-size: 1em; text-align: left; cursor: pointer; }
  button:hover { background: #e8e8e8; border-color: #ccc; }
</style>
</head>
<body>
<h1>Sign in to OpenZiti</h1>
<p>An app asked to sign you in to an OpenZiti network.</p>
{{with .Device}}<p class="note">The app describes the device as <code>{{.}}</code>{{with $.Details}} (<code>{{.}}</code>){{end}}. Whoever started this sign-in supplied that description, and this site can't check it.</p>
{{end}}<p><strong>Continue only if you started this yourself, just now, on your own device.</strong> If someone sent you this link, or later asks for the address your browser shows, stop: they are trying to enroll a device as you.</p>
<form method="post">
<input type="hidden" name="consent" value="{{.Consent}}">
{{range .Providers}}<button type="submit" name="idp" value="{{.}}">Continue with {{.}}</button>
{{end}}</form>
<p class="note">After you sign in, your browser returns to the app at {{.ReturnTo}}. Don't copy that address or send it to anyone: it carries your sign-in.</p>
</body>
</html>
`))
