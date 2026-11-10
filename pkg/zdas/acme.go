package zdas

import (
	"errors"
	"net"
	"net/http"

	"golang.org/x/crypto/acme/autocert"
)

// listenACME serves srv over HTTPS with automatic Let's Encrypt certificates.
// If the main listen address is not on port 443, it also serves a listener
// on :443 for the TLS-ALPN-01 challenge.
func (s *Server) listenACME(srv *http.Server) error {
	m := &autocert.Manager{
		Cache:      autocert.DirCache(s.cfg.TLS.ACME.CacheDir),
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(s.cfg.TLS.ACME.Domains...),
	}

	srv.TLSConfig = m.TLSConfig()

	if chalSrv := challengeServer(s.cfg.Listen, s.challengeAddr, m); chalSrv != nil {
		if err := s.serveChallenge(chalSrv); err != nil {
			return err
		}
	}

	return srv.ListenAndServeTLS("", "")
}

// serveChallenge binds chalSrv's address and serves it in the background.
// If the address can't be bound, as when ZDAS lacks permission for :443 or
// another process holds it, it logs a warning and carries on: the main
// listener answers the challenge too, so certificates are still issued when
// port 443 is forwarded to the listen address. It returns
// http.ErrServerClosed if Shutdown has been called.
func (s *Server) serveChallenge(chalSrv *http.Server) error {
	ln, err := net.Listen("tcp", chalSrv.Addr)
	if err != nil {
		s.logger.Warn("acme challenge listener not started; certificates can be issued only if port 443 is forwarded to the listen address",
			"addr", chalSrv.Addr, "listen", s.cfg.Listen, "error", err)
		return nil
	}
	s.mu.Lock()
	if s.stopping {
		s.mu.Unlock()
		ln.Close()
		return http.ErrServerClosed
	}
	s.chalSrv = chalSrv
	s.mu.Unlock()
	go func() {
		defer ln.Close() // ServeTLS doesn't close it if it fails before serving
		if err := chalSrv.ServeTLS(ln, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.logger.Error("acme challenge listener failed", "error", err)
		}
	}()
	return nil
}

// challengeServer returns a server for addr, which is :443 outside tests,
// that answers m's TLS-ALPN-01 challenge, or nil when listen is on port 443
// and the main listener answers it itself.
func challengeServer(listen, addr string, m *autocert.Manager) *http.Server {
	if onHTTPSPort(listen) {
		return nil
	}
	// The challenge is answered in the TLS handshake, so ordinary requests
	// to this listener have nothing to reach.
	srv := newHTTPServer(addr, http.NotFoundHandler())
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
