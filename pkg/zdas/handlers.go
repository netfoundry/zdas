package zdas

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
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
	mux.HandleFunc("GET /callback", h.handleCallback)
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
	// s256ChallengeLength is the length of an S256 code_challenge: a
	// SHA-256 digest in unpadded base64url (RFC 7636 section 4.2).
	s256ChallengeLength = 43
)

func (h *endpoints) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if h.rateLimiter != nil && !h.rateLimiter.allow(r) {
		w.Header().Set("Retry-After", "1")
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	q := r.URL.Query()
	redirectURI := q.Get("redirect_uri")
	state := q.Get("state")
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
	parsedRedirect, err := parseRedirectURI(redirectURI)
	if err != nil {
		http.Error(w, "redirect_uri must be a valid http(s) URL", http.StatusBadRequest)
		return
	}
	if !redirectAllowed(parsedRedirect, h.redirects) {
		http.Error(w, "redirect_uri is not allowed", http.StatusBadRequest)
		return
	}

	// Validate remaining required parameters.
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

	// Resolve upstream provider.
	provider, err := h.registry.Resolve(idpHint)
	if err != nil {
		switch {
		case errors.Is(err, ErrMultipleProviders):
			if h.cfg.IDPSelectorURL != "" {
				h.redirectToIDPSelector(w, r)
				return
			}
			h.renderIDPSelector(w, r)
		case errors.Is(err, ErrNoProviders):
			h.logger.Error("no upstream providers configured")
			oidcErrorRedirect(w, r, redirectURI, state, "server_error", "no upstream providers available")
		default:
			oidcErrorRedirect(w, r, redirectURI, state, "invalid_request", "unknown idp")
		}
		return
	}

	// Build session and redirect to upstream.
	callbackURL := h.cfg.ExternalURL + "/callback"

	// Copy what the session keeps: values parsed from the query can share
	// its memory, and the session would keep the whole request line alive.
	sess := &AuthSession{
		TunnelerRedirectURI:         strings.Clone(redirectURI),
		TunnelerState:               strings.Clone(state),
		TunnelerCodeChallenge:       strings.Clone(codeChallenge),
		TunnelerCodeChallengeMethod: strings.Clone(codeChallengeMethod),
		DeviceInfo:                  deviceInfo,
		FallbackNonce:               fallbackNonce,
		EnrollmentMethod:            truncateParam(enrollmentMethod, 64),
		ClientType:                  truncateParam(clientType, 64),
		UpstreamProviderName:        provider.Name(),
	}

	// For OIDC, use our own PKCE pair toward the upstream, keeping the
	// verifier in the session for /callback. Other providers (GitHub) get
	// none.
	oidcProv, usePKCE := provider.(*OIDCProvider)
	var challenge string
	if usePKCE {
		var err error
		if sess.ZDASCodeVerifier, challenge, err = generatePKCE(); err != nil {
			h.logger.Error("generate pkce", "error", err)
			oidcErrorRedirect(w, r, redirectURI, state, "server_error", "internal error")
			return
		}
	}
	sessionState, err := h.startSession(w, r, sess)
	if err != nil {
		h.logger.Error("create session", "error", err)
		oidcErrorRedirect(w, r, redirectURI, state, "server_error", "internal error")
		return
	}
	var upstreamURL string
	if usePKCE {
		upstreamURL = oidcProv.authorizeURL(sessionState, callbackURL, challenge)
	} else {
		upstreamURL = provider.AuthorizeURL(sessionState, callbackURL)
	}

	if fallbackNonce != "" {
		h.logger.Info("redirecting to upstream (fallback)", "provider", provider.Name(), "nonce", fallbackNonce)
	} else {
		h.logger.Info("redirecting to upstream", "provider", provider.Name(), "device", deviceName)
	}
	http.Redirect(w, r, upstreamURL, http.StatusFound)
}

// sessionMissing is the /callback response when no session matches. A
// browser other than the one that started the flow lands here too, since
// it lacks the binding cookie the session is stored under.
const sessionMissing = "session not found or expired; enrollment must finish in the browser that started it"

func (h *endpoints) handleCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	code := q.Get("code")
	sessionState := q.Get("state")

	// The session holds the tunneler's redirect_uri, which every outcome
	// below needs, including an upstream error.
	sess, err := h.consumeBoundSession(w, r, sessionState)
	if err != nil {
		h.logger.Error("consume session", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if sess == nil {
		http.Error(w, sessionMissing, http.StatusBadRequest)
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

	callbackURL := h.cfg.ExternalURL + "/callback"
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

	if err := checkClaims(claims); err != nil {
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
		if cerr := checkClaims(claims); cerr != nil {
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

// createSession stamps sess with the current time, stores it under a new
// ID bound to nonce (see sessionKey), and returns the ID.
func (h *endpoints) createSession(ctx context.Context, sess *AuthSession, nonce string) (string, error) {
	id, err := randomID()
	if err != nil {
		return "", err
	}
	sess.CreatedAt = time.Now()
	if err := h.store.CreateSession(ctx, h.sessionKey(id, nonce), sess); err != nil {
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
// It returns (nil, nil) on a miss. nonce is as for createSession.
func (h *endpoints) consumeSession(ctx context.Context, id, nonce string) (*AuthSession, error) {
	if !validID(id) {
		return nil, nil
	}
	sess, err := h.store.ConsumeSession(ctx, h.sessionKey(id, nonce))
	if err != nil || sess == nil || !h.fresh(kindSession, sess.CreatedAt, h.cfg.Session.Timeout) {
		return nil, err
	}
	return sess, nil
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

// redirectToIDPSelector hands picker rendering off to the embedding
// application via cfg.IDPSelectorURL. It preserves the original /authorize
// query string so the host app can echo it back to /authorize with an idp=
// parameter added, and appends a `providers` query param listing the
// available IdP names so the host app does not need to query ZDAS to know
// what to render.
func (h *endpoints) redirectToIDPSelector(w http.ResponseWriter, r *http.Request) {
	names := h.registry.Names()
	sort.Strings(names)

	// Copy the original query string verbatim and add a providers list. We
	// intentionally do NOT remove any existing params; the host app will
	// round-trip them back to /authorize unchanged so that the
	// tunneler-supplied state, PKCE, redirect_uri, device info, etc. are
	// preserved through the picker round trip.
	q := r.URL.Query()
	q.Set("providers", strings.Join(names, ","))

	redirURL := withQuery(h.cfg.IDPSelectorURL, q)

	h.logger.Info("redirecting to host app idp selector",
		"url", h.cfg.IDPSelectorURL,
		"providers", names,
	)
	http.Redirect(w, r, redirURL, http.StatusFound)
}

// renderIDPSelector shows an HTML page listing available identity providers
// when multiple are configured and no selection has been made yet. Each link
// re-enters /authorize with the original query parameters plus idp=<name>,
// so all tunneler params (redirect_uri, state, PKCE, device info) carry through.
func (h *endpoints) renderIDPSelector(w http.ResponseWriter, r *http.Request) {
	names := h.registry.Names()
	sort.Strings(names)

	// Rebuild the original query without idp so we can add it per-provider.
	baseQuery := r.URL.Query()
	baseQuery.Del("idp")

	var links strings.Builder
	for _, name := range names {
		q := make(url.Values)
		for k, v := range baseQuery {
			q[k] = v
		}
		q.Set("idp", name)
		// Relative URL: the browser resolves "?..." against the current
		// page (/authorize), keeping the path and replacing only the
		// query. This works regardless of how the embedding application
		// mounts ZDAS (e.g., at /zdas via http.StripPrefix).
		href := "?" + q.Encode()
		fmt.Fprintf(&links, `<a href="%s">%s</a>`, html.EscapeString(href), html.EscapeString(name))
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, idpSelectorHTML, links.String())
}

const idpSelectorHTML = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Select Identity Provider</title>
<style>
  body { font-family: -apple-system, system-ui, sans-serif; max-width: 400px; margin: 80px auto; padding: 0 20px; color: #333; }
  h1 { font-size: 1.4em; font-weight: 600; margin-bottom: 24px; }
  a { display: block; padding: 14px 20px; margin: 8px 0; background: #f5f5f5; border: 1px solid #ddd; border-radius: 8px; color: #333; text-decoration: none; font-size: 1em; }
  a:hover { background: #e8e8e8; border-color: #ccc; }
</style>
</head>
<body>
<h1>Select an identity provider</h1>
%s
</body>
</html>`
