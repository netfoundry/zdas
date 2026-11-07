package zdas

import (
	"errors"
	"net"
	"net/http"

	"golang.org/x/crypto/acme/autocert"
)

// listenACME serves srv over HTTPS with automatic Let's Encrypt certificates.
// If the main listen address is not on port 443, it starts a secondary
// listener on :443 for the TLS-ALPN-01 challenge.
func (s *Server) listenACME(srv *http.Server) error {
	m := &autocert.Manager{
		Cache:      autocert.DirCache(s.cfg.TLS.ACME.CacheDir),
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(s.cfg.TLS.ACME.Domains...),
	}

	srv.TLSConfig = m.TLSConfig()

	if chalSrv := challengeServer(s.cfg.Listen, m); chalSrv != nil {
		s.mu.Lock()
		if s.stopping {
			s.mu.Unlock()
			return http.ErrServerClosed
		}
		s.chalSrv = chalSrv
		s.mu.Unlock()
		go func() {
			if err := chalSrv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
				s.logger.Error("acme challenge listener failed", "error", err)
			}
		}()
	}

	return srv.ListenAndServeTLS("", "")
}

// challengeServer returns a server for :443 that answers m's TLS-ALPN-01
// challenge, or nil when listen is on port 443 and the main listener
// answers it itself.
func challengeServer(listen string, m *autocert.Manager) *http.Server {
	if onHTTPSPort(listen) {
		return nil
	}
	// The challenge is answered in the TLS handshake, so ordinary requests
	// to this listener have nothing to reach.
	srv := newHTTPServer(":443", http.NotFoundHandler())
	srv.TLSConfig = m.TLSConfig()
	return srv
}

// onHTTPSPort reports whether addr, a listen address, is on port 443, where
// the TLS-ALPN-01 challenge arrives, whatever its host and however the port
// is spelled (":443", "0.0.0.0:443", "[::]:443", ":https"). A listener there
// answers the challenge itself, and a second one on :443 would race it for
// the port. With a specific host, such as "10.0.0.5:443", the challenge is
// answered on that address only, so it must be the one the domains resolve
// to.
func onHTTPSPort(addr string) bool {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	n, err := net.LookupPort("tcp", port)
	return err == nil && n == 443
}
