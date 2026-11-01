package zdas

import (
	"net/http"
	"net/url"
)

// bindingCookiePrefix names the cookie that ties an auth session to the
// browser that started it. The name ends with the first 8 characters of
// the session ID so concurrent enrollments in one browser don't collide.
const bindingCookiePrefix = "zdas_bind_"

func bindingCookieName(sessionID string) string {
	return bindingCookiePrefix + sessionID[:8]
}

// bindingCookieScope returns the cookie path and Secure flag for the
// deployment at externalURL. The path is the URL's path, so the cookie
// reaches /authorize and /callback under whatever prefix zdas is mounted at.
func bindingCookieScope(externalURL string) (path string, secure bool) {
	u, err := url.Parse(externalURL)
	if err != nil || u.Path == "" {
		return "/", err == nil && u.Scheme == "https"
	}
	return u.Path, u.Scheme == "https"
}

// sessionKey returns the store key for session id. A session /authorize
// creates is stored under its ID and the nonce in the browser's binding
// cookie together, so a /callback without that cookie misses and leaves the
// session for the browser that has it. With an empty nonce, as for a
// /callback without the cookie, the key is the bare ID's, under which
// /authorize stores nothing.
func (h *endpoints) sessionKey(id, nonce string) string {
	if nonce != "" {
		id += "." + nonce
	}
	return h.storeKey(kindSession, id)
}

// startSession stores sess bound to a new nonce and sets a cookie holding
// the nonce, so that only the browser that started the flow can complete or
// cancel it at /callback. It returns the session ID.
func (h *endpoints) startSession(w http.ResponseWriter, r *http.Request, sess *AuthSession) (string, error) {
	nonce, err := randomID()
	if err != nil {
		return "", err
	}
	id, err := h.createSession(r.Context(), sess, nonce)
	if err != nil {
		return "", err
	}
	h.setBindingCookie(w, id, nonce, int(h.cfg.Session.Timeout.Seconds()))
	return id, nil
}

// consumeBoundSession consumes the session named by state, looked up with
// the binding cookie r carries, and expires that cookie. It returns
// (nil, nil) on a miss, including for a browser without the right cookie.
func (h *endpoints) consumeBoundSession(w http.ResponseWriter, r *http.Request, state string) (*AuthSession, error) {
	if !validID(state) {
		return nil, nil
	}
	var nonce string
	if c, err := r.Cookie(bindingCookieName(state)); err == nil {
		h.setBindingCookie(w, state, "", -1)
		if validID(c.Value) {
			nonce = c.Value
		}
	}
	return h.consumeSession(r.Context(), state, nonce)
}

func (h *endpoints) setBindingCookie(w http.ResponseWriter, id, nonce string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     bindingCookieName(id),
		Value:    nonce,
		Path:     h.cookiePath,
		MaxAge:   maxAge,
		Secure:   h.cookieSecure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}
