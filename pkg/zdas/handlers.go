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

// Handlers groups the HTTP handler dependencies for the ZDAS endpoints.
type Handlers struct {
	cfg         Config
	keys        *KeySet   // active signing key
	jwksKeys    []*KeySet // keys served at /.well-known/jwks.json: keys first, unique by kid
	registry    *ProviderRegistry
	store       Store
	rawKeys     bool                  // store entries under their raw IDs (NewHandlers only)
	discovery   *Discovery            // for cached network JWTs; may be nil in tests
	reconciler  *Reconciler           // nil when fallback is disabled
	provisioner EnrollmentProvisioner // nil uses built-in ComposeClaims
	rateLimiter *ipRateLimiter        // nil when rate limiting is disabled
	logger      *slog.Logger

	// Scope of the browser binding cookie, from cfg.ExternalURL.
	cookiePath   string
	cookieSecure bool
}

// NewHandlers creates a Handlers with the given dependencies. discovery,
// reconciler, and provisioner may be nil.
func NewHandlers(cfg Config, keys *KeySet, registry *ProviderRegistry, store *SessionStore, discovery *Discovery, reconciler *Reconciler, provisioner EnrollmentProvisioner, logger *slog.Logger) *Handlers {
	if store != nil {
		// Expire entries by the store's own TTLs, which the caller may have
		// set differently from cfg.Session when building the store.
		cfg.Session.Timeout, cfg.Session.CodeExpiry = store.sessionTTL, store.codeTTL
	}
	h := newHandlers(cfg, keys, nil, registry, sessionStoreAdapter{store}, discovery, reconciler, provisioner, logger)
	// Callers may populate the SessionStore directly and pass the IDs it
	// returns to the endpoints, so entries stay keyed by raw ID.
	h.rawKeys = true
	return h
}

// newHandlers creates a Handlers that signs with keys, publishes keys plus
// verifyKeys, and expires store entries by cfg.Session.
func newHandlers(cfg Config, keys *KeySet, verifyKeys []*KeySet, registry *ProviderRegistry, store Store, discovery *Discovery, reconciler *Reconciler, provisioner EnrollmentProvisioner, logger *slog.Logger) *Handlers {
	var jwksKeys []*KeySet
	if keys != nil {
		jwksKeys = uniqueKeySets(keys, verifyKeys)
	}
	h := &Handlers{
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
	return h
}

// Mux returns an http.ServeMux wired to all ZDAS endpoints.
func (h *Handlers) Mux() *http.ServeMux {
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

func (h *Handlers) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	ext := h.cfg.ExternalURL
	doc := map[string]interface{}{
		"issuer":                                ext,
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

func (h *Handlers) handleNetworkJWTs(w http.ResponseWriter, r *http.Request) {
	if h.discovery == nil {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	body := h.discovery.NetworkJWTsBody()
	if body == nil {
		http.Error(w, "network JWTs not yet available", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}

func (h *Handlers) handleExtJWTSigners(w http.ResponseWriter, r *http.Request) {
	if h.discovery == nil {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	body := h.discovery.ExtJWTSignersBody()
	if body == nil {
		http.Error(w, "external JWT signers not yet available", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}

func (h *Handlers) handleJWKS(w http.ResponseWriter, r *http.Request) {
	data, err := publicJWKS(h.jwksKeys)
	if err != nil {
		h.logger.Error("marshal jwks", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func (h *Handlers) handleAuthorize(w http.ResponseWriter, r *http.Request) {
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
	if redirectURI == "" {
		http.Error(w, "redirect_uri is required", http.StatusBadRequest)
		return
	}
	parsedRedirect, err := parseRedirectURI(redirectURI)
	if err != nil {
		http.Error(w, "redirect_uri must be a valid http(s) URL", http.StatusBadRequest)
		return
	}
	if !redirectAllowed(parsedRedirect, h.cfg.AllowedRedirectURIs) {
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
	}
	// Always populate DeviceInfo with whatever the tunneler sent. On the
	// fallback path DeviceName will be empty, but os/hostname/arch may
	// still be present and useful to the consumer (e.g. provisioner).
	deviceInfo := &DeviceInfo{
		DeviceName: deviceName,
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

	sess := &AuthSession{
		TunnelerRedirectURI:         redirectURI,
		TunnelerState:               state,
		TunnelerCodeChallenge:       codeChallenge,
		TunnelerCodeChallengeMethod: codeChallengeMethod,
		DeviceInfo:                  deviceInfo,
		FallbackNonce:               fallbackNonce,
		EnrollmentMethod:            truncateParam(enrollmentMethod, 64),
		ClientType:                  truncateParam(clientType, 64),
		UpstreamProviderName:        provider.Name(),
	}

	var upstreamURL string
	if oidcProv, ok := provider.(*OIDCProvider); ok {
		// OIDC: generate our own PKCE pair for the upstream, then store the
		// verifier in the session so /callback can use it.
		verifier, challenge, err := generatePKCE()
		if err != nil {
			h.logger.Error("generate pkce", "error", err)
			oidcErrorRedirect(w, r, redirectURI, state, "server_error", "internal error")
			return
		}
		sess.ZDASCodeVerifier = verifier
		sessionState, err := h.startSession(w, r, sess)
		if err != nil {
			h.logger.Error("create session", "error", err)
			oidcErrorRedirect(w, r, redirectURI, state, "server_error", "internal error")
			return
		}
		v := url.Values{
			"client_id":             {oidcProv.clientID},
			"response_type":         {"code"},
			"redirect_uri":          {callbackURL},
			"state":                 {sessionState},
			"scope":                 {joinScopes(oidcProv.scopes)},
			"code_challenge":        {challenge},
			"code_challenge_method": {"S256"},
		}
		upstreamURL = oidcProv.authURL + "?" + v.Encode()
	} else {
		// Non-OIDC (e.g. GitHub): no upstream PKCE.
		sessionState, err := h.startSession(w, r, sess)
		if err != nil {
			h.logger.Error("create session", "error", err)
			oidcErrorRedirect(w, r, redirectURI, state, "server_error", "internal error")
			return
		}
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

func (h *Handlers) handleCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	code := q.Get("code")
	sessionState := q.Get("state")

	if errParam := q.Get("error"); errParam != "" {
		desc := q.Get("error_description")
		h.logger.Warn("upstream returned error", "error", errParam, "description", desc)
		// We need the session to know the tunneler's redirect_uri.
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
		oidcErrorRedirect(w, r, sess.TunnelerRedirectURI, sess.TunnelerState, errParam, sanitizeErrorDescription(desc))
		return
	}

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
	if err != nil {
		h.logger.Error("exchange and identify", "provider", provider.Name(), "error", err)
		oidcErrorRedirect(w, r, sess.TunnelerRedirectURI, sess.TunnelerState, "server_error", "upstream authentication failed")
		return
	}

	var claims map[string]interface{}
	if h.provisioner != nil {
		req := ProvisionRequest{
			Email:            identity.Email,
			Name:             identity.Username,
			Subject:          identity.Subject,
			Provider:         sess.UpstreamProviderName,
			EnrollmentMethod: sess.EnrollmentMethod,
			ClientType:       sess.ClientType,
			IsFallback:       sess.FallbackNonce != "",
			FallbackNonce:    sess.FallbackNonce,
		}
		req.DeviceName = sess.DeviceInfo.DeviceName
		req.Hostname = sess.DeviceInfo.Hostname
		req.OS = sess.DeviceInfo.OS
		req.Arch = sess.DeviceInfo.Arch
		req.OSRelease = sess.DeviceInfo.OSRelease
		req.OSVersion = sess.DeviceInfo.OSVersion
		result, err := h.provisioner.Provision(r.Context(), req)
		if err != nil {
			h.handleProvisionerError(w, r, err, sess.TunnelerRedirectURI, sess.TunnelerState, "provider", sess.UpstreamProviderName)
			return
		}
		if result.RedirectURL != "" && result.Claims == nil {
			// Interactive provisioning - stash session state and redirect.
			pendingID, err := h.createPendingProvision(r.Context(), &PendingProvision{
				TunnelerRedirectURI:         sess.TunnelerRedirectURI,
				TunnelerState:               sess.TunnelerState,
				TunnelerCodeChallenge:       sess.TunnelerCodeChallenge,
				TunnelerCodeChallengeMethod: sess.TunnelerCodeChallengeMethod,
				IsFallback:                  sess.FallbackNonce != "",
			})
			if err != nil {
				h.logger.Error("create pending provision", "error", err)
				oidcErrorRedirect(w, r, sess.TunnelerRedirectURI, sess.TunnelerState, "server_error", "internal error")
				return
			}
			sep := "?"
			if strings.Contains(result.RedirectURL, "?") {
				sep = "&"
			}
			http.Redirect(w, r, result.RedirectURL+sep+"pending_id="+url.QueryEscape(pendingID), http.StatusFound)
			return
		}
		claims = result.Claims
	} else {
		claims = ComposeClaims(h.cfg.Claims, h.cfg.Fallback, identity, sess.DeviceInfo, sess.FallbackNonce)
	}

	// Track fallback enrollments for reconciliation.
	if sess.FallbackNonce != "" && h.reconciler != nil {
		if extID, ok := claims[h.cfg.Claims.ExternalIDClaim].(string); ok {
			username, _ := claims["preferred_username"].(string)
			h.reconciler.Track(extID, username, sess.FallbackNonce)
		}
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

	redir := sess.TunnelerRedirectURI + "?" + url.Values{
		"code":  {zdasCode},
		"state": {sess.TunnelerState},
	}.Encode()
	deviceLog := sess.DeviceInfo.DeviceName
	if deviceLog == "" {
		deviceLog = "fallback"
	}
	h.logger.Info("callback complete, redirecting to tunneler", "provider", provider.Name(), "device", deviceLog)
	http.Redirect(w, r, redir, http.StatusFound)
}

func (h *Handlers) handleToken(w http.ResponseWriter, r *http.Request) {
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

	resp := map[string]interface{}{
		"access_token": signed,
		"id_token":     signed,
		"token_type":   "Bearer",
		"expires_in":   int(h.cfg.Token.Expiry.Seconds()),
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(resp)
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

// truncateParam caps a tunneler-supplied query parameter to maxLen bytes.
func truncateParam(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen]
	}
	return s
}

// handleProvisionerError translates an error from the EnrollmentProvisioner
// into an OIDC error redirect. A *ProvisionError with a valid OIDC code is
// passed through to the tunneler. Anything else (plain error or invalid code)
// becomes server_error with a generic description. logArgs are added to
// the log entry.
func (h *Handlers) handleProvisionerError(w http.ResponseWriter, r *http.Request, err error, redirectURI, state string, logArgs ...any) {
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

// CompleteProvision finishes an enrollment that the provisioner sent to an
// interactive page with ProvisionResult.RedirectURL. The embedding
// application calls it from its own handler for that page, with the
// pending_id ZDAS added to the redirect URL and the outcome of its
// provisioning: the claims to mint, or an error, which follows the same
// rules as an error from Provision and takes precedence over claims. It
// consumes the pending provision and redirects the browser back to the
// tunneler, or responds 400 when the pending provision is missing or
// expired.
//
// The claims must come from the application's own state, never from the
// request: the user enrolling holds the pending ID, so claims taken from
// the browser would let that user enroll as any identity.
func (h *Handlers) CompleteProvision(w http.ResponseWriter, r *http.Request, pendingID string, claims map[string]any, err error) {
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
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	redir := pp.TunnelerRedirectURI + "?" + url.Values{
		"code":  {zdasCode},
		"state": {pp.TunnelerState},
	}.Encode()
	http.Redirect(w, r, redir, http.StatusFound)
}

// verifyPKCE validates the code_verifier against the stored code_challenge
// using the S256 method. Uses constant-time comparison to avoid timing leaks.
func verifyPKCE(challenge, method, verifier string) bool {
	if method != "S256" || verifier == "" {
		return false
	}
	h := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(h[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
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
	http.Redirect(w, r, redirectURI+"?"+v.Encode(), http.StatusFound)
}

// storeKey returns the key the entry of the given kind and ID is stored
// under. See Store for why it is a hash.
func (h *Handlers) storeKey(kind, id string) string {
	if h.rawKeys {
		return id
	}
	return hashStoreKey(kind, h.cfg.Token.Issuer, id)
}

// createSession stamps sess with the current time, stores it under a new
// ID bound to nonce (see sessionKey), and returns the ID.
func (h *Handlers) createSession(ctx context.Context, sess *AuthSession, nonce string) (string, error) {
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
func (h *Handlers) createCode(ctx context.Context, ac *AuthCode) (string, error) {
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

// createPendingProvision is createSession for pending provisions.
func (h *Handlers) createPendingProvision(ctx context.Context, pp *PendingProvision) (string, error) {
	id, err := randomID()
	if err != nil {
		return "", err
	}
	pp.CreatedAt = time.Now()
	if err := h.store.CreatePendingProvision(ctx, h.storeKey(kindProvision, id), pp); err != nil {
		return "", err
	}
	return id, nil
}

// consumeSession consumes an auth session and treats one that is no longer
// fresh as a miss, so a Store without expiry logic of its own never hands
// back an expired session. A malformed ID is a miss without a store lookup.
// It returns (nil, nil) on a miss. nonce is as for createSession.
func (h *Handlers) consumeSession(ctx context.Context, id, nonce string) (*AuthSession, error) {
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
func (h *Handlers) consumeCode(ctx context.Context, code string) (*AuthCode, error) {
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
func (h *Handlers) consumePendingProvision(ctx context.Context, id string) (*PendingProvision, error) {
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
func (h *Handlers) fresh(kind string, createdAt time.Time, ttl time.Duration) bool {
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

// tokenError writes a JSON error response for the /token endpoint.
func tokenError(w http.ResponseWriter, errCode, errDesc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
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
func (h *Handlers) redirectToIDPSelector(w http.ResponseWriter, r *http.Request) {
	names := h.registry.Names()
	sort.Strings(names)

	// Copy the original query string verbatim and add a providers list. We
	// intentionally do NOT remove any existing params; the host app will
	// round-trip them back to /authorize unchanged so that the
	// tunneler-supplied state, PKCE, redirect_uri, device info, etc. are
	// preserved through the picker round trip.
	q := r.URL.Query()
	q.Set("providers", strings.Join(names, ","))

	target := h.cfg.IDPSelectorURL
	sep := "?"
	if strings.Contains(target, "?") {
		sep = "&"
	}
	redirURL := target + sep + q.Encode()

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
func (h *Handlers) renderIDPSelector(w http.ResponseWriter, r *http.Request) {
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
		links.WriteString(fmt.Sprintf(
			`<a href="%s">%s</a>`,
			html.EscapeString(href),
			html.EscapeString(name),
		))
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
