package zdas

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
)

// bindingCookiePrefix names the cookie that ties an auth session to the
// browser that started it. The name ends with the first 8 characters of
// the session ID so concurrent enrollments in one browser don't collide.
const bindingCookiePrefix = "zdas_bind_"

// hostCookiePrefix is the name prefix browsers accept only on a cookie that
// is Secure, has Path=/ and names no Domain. A cookie set by a sibling host,
// which could otherwise stand in for the binding cookie, can't carry it.
const hostCookiePrefix = "__Host-"

// cookieScope is where the binding cookie is sent: the path and the Secure
// flag it is set with.
type cookieScope struct {
	path   string
	secure bool
}

// bindingCookieScope returns the cookie scope for the deployment at
// externalURL. The path is the URL's path, so the cookie reaches /authorize
// and /callback under whatever prefix zdas is mounted at.
func bindingCookieScope(externalURL string) cookieScope {
	u, err := url.Parse(externalURL)
	if err != nil || u.Path == "" {
		return cookieScope{path: "/", secure: err == nil && u.Scheme == "https"}
	}
	return cookieScope{path: u.Path, secure: u.Scheme == "https"}
}

// name returns the binding cookie's name for sessionID. It has the
// __Host- prefix wherever a browser allows it, which is a Secure cookie for
// the whole host. Under a mount prefix it can't have it, and the cookie is
// as safe as the host's siblings are trusted.
func (s cookieScope) name(sessionID string) string {
	if s.secure && s.path == "/" {
		return hostCookiePrefix + bindingCookiePrefix + sessionID[:8]
	}
	return bindingCookiePrefix + sessionID[:8]
}

// bindingHash returns what a session keeps of the nonce in its browser's
// binding cookie: its SHA-256 in hex. The store holds only the hash, so
// reading it does not give anyone the cookie.
//
// A session is stored under its bare ID, so a request that names it but
// lacks the cookie still finds it, and consumes it. That cancels a sign-in
// whose session ID reaches the wrong browser: a phisher who consents in
// their own browser and sends the victim the IdP's address as ZDAS issued
// it finds the session gone by the time the victim's /callback address gets
// back to them. One who edits the state in that address before sending it
// is not stopped here; handleCallback warns the victim instead.
func bindingHash(nonce string) string {
	sum := sha256.Sum256([]byte(nonce))
	return hex.EncodeToString(sum[:])
}

// startSession stores sess bound to a new nonce and sets a cookie holding
// the nonce, so that only the browser that started the flow can complete
// it. It returns the session ID.
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

// consumeBoundSession consumes the session named by state, checked against
// the binding cookie r carries, and expires that cookie. other reports a
// session consumed for a browser without the right cookie; see
// consumeSession.
func (h *endpoints) consumeBoundSession(w http.ResponseWriter, r *http.Request, state string) (sess *AuthSession, other *otherBrowser, err error) {
	if !validID(state) {
		return nil, nil, nil
	}
	var nonce string
	c, cookieErr := r.Cookie(h.cookie.name(state))
	if cookieErr == nil {
		h.setBindingCookie(w, state, "", -1)
		if validID(c.Value) {
			nonce = c.Value
		}
	}
	sess, other, err = h.consumeSession(r.Context(), state, nonce)
	if other != nil {
		other.cookie = cookieMissing
		if cookieErr == nil {
			other.cookie = cookieWrong
		}
	}
	return sess, other, err
}

func (h *endpoints) setBindingCookie(w http.ResponseWriter, id, nonce string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     h.cookie.name(id),
		Value:    nonce,
		Path:     h.cookie.path,
		MaxAge:   maxAge,
		Secure:   h.cookie.secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}
