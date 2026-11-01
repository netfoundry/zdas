package zdas

import (
	"net/http"

	"golang.org/x/crypto/acme/autocert"
)

// listenACME serves srv over HTTPS with automatic Let's Encrypt certificates.
// If the main listen address is not :443, it starts a secondary listener on :443
// for the TLS-ALPN-01 challenge.
func (s *Server) listenACME(srv *http.Server) error {
	m := &autocert.Manager{
		Cache:      autocert.DirCache(s.cfg.TLS.ACME.CacheDir),
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(s.cfg.TLS.ACME.Domains...),
	}

	srv.TLSConfig = m.TLSConfig()

	if s.cfg.Listen != ":443" {
		chalSrv := newHTTPServer(":443", m.HTTPHandler(nil))
		chalSrv.TLSConfig = m.TLSConfig()
		s.mu.Lock()
		if s.stopping {
			s.mu.Unlock()
			return http.ErrServerClosed
		}
		s.chalSrv = chalSrv
		s.mu.Unlock()
		go func() {
			if err := chalSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				s.logger.Error("acme challenge listener failed", "error", err)
			}
		}()
	}

	return srv.ListenAndServeTLS("", "")
}
