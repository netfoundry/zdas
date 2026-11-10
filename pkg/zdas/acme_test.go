package zdas

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

func TestOnHTTPSPort(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{":443", true},
		{"0.0.0.0:443", true},
		{"[::]:443", true},
		{"127.0.0.1:443", true},
		{"10.0.0.5:443", true},
		{"localhost:443", true},
		{"[::1]:443", true},
		{":https", true},
		{":HTTPS", true},
		{"[::]:https", true},
		{":+443", true},
		{":0443", true},
		{":18443", false},
		{":4430", false},
		{":http", false},
		{"0.0.0.0:8443", false},
		{":65536", false},
		{":", false},
		{"host:", false},
		{"::443", false},
		{"443", false},
		{"", false},
		{":no-such-service", false},
	}
	for _, tc := range cases {
		if got := onHTTPSPort(tc.addr); got != tc.want {
			t.Errorf("onHTTPSPort(%q) = %v, want %v", tc.addr, got, tc.want)
		}
	}
}

func TestChallengeServer(t *testing.T) {
	m := &autocert.Manager{}
	for _, listen := range []string{":443", "0.0.0.0:443", "[::]:443", ":https"} {
		if srv := challengeServer(listen, ":443", m); srv != nil {
			t.Errorf("challengeServer(%q) = server on %q, want nil", listen, srv.Addr)
		}
	}
	for _, listen := range []string{":8443", "0.0.0.0:18443"} {
		srv := challengeServer(listen, "127.0.0.1:9443", m)
		if srv == nil {
			t.Fatalf("challengeServer(%q) = nil, want a server", listen)
		}
		if srv.Addr != "127.0.0.1:9443" {
			t.Errorf("challengeServer(%q).Addr = %q, want 127.0.0.1:9443", listen, srv.Addr)
		}
		if srv.TLSConfig == nil || !slices.Contains(srv.TLSConfig.NextProtos, acme.ALPNProto) {
			t.Errorf("challengeServer(%q) doesn't offer %s", listen, acme.ALPNProto)
		}
	}
}

// freeAddr returns a loopback address with a port that was free a moment ago.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// newChallengeTestServer returns a challenge server for addr whose TLS
// handshake always fails with an alert, so a client can tell it is served.
func newChallengeTestServer(addr string) *http.Server {
	srv := newHTTPServer(addr, http.NotFoundHandler())
	srv.TLSConfig = &tls.Config{GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return nil, errors.New("no certificate")
	}}
	return srv
}

// newACMETestServer returns a Server in acme mode listening on listen, which
// logs to logs and is shut down when the test ends.
func newACMETestServer(t *testing.T, listen string, logs io.Writer) *Server {
	t.Helper()
	cfg := replicaConfig(t)
	cfg.Listen = listen
	cfg.TLS = TLSConfig{Mode: TLSModeACME, ACME: ACMEConfig{Domains: []string{"zdas.test"}, CacheDir: t.TempDir()}}
	s, err := NewServer(cfg, slog.New(slog.NewTextHandler(logs, nil)))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { s.Shutdown(context.Background()) })
	return s
}

// skipIfBindRaced skips the test if serveChallenge couldn't bind a port from
// freeAddr because another process took it in the meantime.
func skipIfBindRaced(t *testing.T, logs *logBuffer) {
	t.Helper()
	if strings.Contains(logs.String(), "acme challenge listener not started") {
		t.Skip("another process took the test port")
	}
}

// checkServed fails the test unless a TLS server is serving addr within a
// few seconds. A handshake without a server name gets an alert from autocert
// and from newChallengeTestServer alike, which a listener that is bound but
// not served never sends.
func checkServed(t *testing.T, addr string) {
	t.Helper()
	var conn net.Conn
	var err error
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if conn, err = net.DialTimeout("tcp", addr, time.Second); err == nil || time.Now().After(deadline) {
			break
		}
	}
	if err != nil {
		t.Fatalf("%s isn't listening: %v", addr, err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	err = tls.Client(conn, &tls.Config{InsecureSkipVerify: true}).Handshake()
	if err == nil || !strings.Contains(err.Error(), "remote error") {
		t.Errorf("handshake with %s = %v, want a remote error", addr, err)
	}
}

// waitFree fails the test unless addr can be bound within a few seconds.
// Shutdown returns before Serve closes its listener.
func waitFree(t *testing.T, addr string) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		ln, err := net.Listen("tcp", addr)
		if err == nil {
			ln.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s is still bound: %v", addr, err)
		}
	}
}

func TestServeChallenge(t *testing.T) {
	var logs logBuffer
	s := newACMETestServer(t, freeAddr(t), &logs)
	if s.challengeAddr != ":443" {
		t.Errorf("challengeAddr = %q, want :443", s.challengeAddr)
	}
	addr := freeAddr(t)
	chalSrv := newChallengeTestServer(addr)
	if err := s.serveChallenge(chalSrv); err != nil {
		t.Fatalf("serveChallenge = %v, want nil", err)
	}
	skipIfBindRaced(t, &logs)
	if s.chalSrv != chalSrv {
		t.Error("the challenge server isn't recorded for Shutdown")
	}
	checkServed(t, addr)

	if err := s.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	waitFree(t, addr)
	if strings.Contains(logs.String(), "acme challenge") {
		t.Errorf("unexpected log: %s", logs.String())
	}
}

func TestServeChallengeBindFailure(t *testing.T) {
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()

	var logs bytes.Buffer
	s := &Server{cfg: Config{Listen: ":8443"}, logger: slog.New(slog.NewTextHandler(&logs, nil))}
	if err := s.serveChallenge(newChallengeTestServer(taken.Addr().String())); err != nil {
		t.Fatalf("serveChallenge = %v, want nil so the main listener still starts", err)
	}
	if s.chalSrv != nil {
		t.Error("a challenge server that never bound is recorded")
	}
	for _, want := range []string{"level=WARN", "acme challenge listener not started", "addr=" + taken.Addr().String(), "listen=:8443"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("log %q doesn't contain %q", logs.String(), want)
		}
	}
}

func TestServeChallengeAfterShutdown(t *testing.T) {
	var logs logBuffer
	s := newACMETestServer(t, freeAddr(t), &logs)
	if err := s.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	addr := freeAddr(t)
	err := s.serveChallenge(newChallengeTestServer(addr))
	if err == nil {
		skipIfBindRaced(t, &logs)
	}
	if !errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("serveChallenge = %v, want http.ErrServerClosed", err)
	}
	if s.chalSrv != nil {
		t.Error("a challenge server is recorded after Shutdown")
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("the address is still bound: %v", err)
	}
	ln.Close()
}

// TestListenACMEChallengePortTaken verifies that ZDAS still serves when it
// can't bind the challenge address, since port 443 may be forwarded to it.
func TestListenACMEChallengePortTaken(t *testing.T) {
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()

	var logs logBuffer
	listen := freeAddr(t)
	s := newACMETestServer(t, listen, &logs)
	s.challengeAddr = taken.Addr().String()
	done := make(chan error, 1)
	go func() { done <- s.Start(context.Background()) }()
	checkServed(t, listen)
	if !strings.Contains(logs.String(), "acme challenge listener not started") {
		t.Errorf("log %q doesn't warn that the challenge listener didn't start", logs.String())
	}

	if err := s.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Start after Shutdown = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return after Shutdown")
	}
}

// TestListenACMEListenPortTaken verifies that Start returns the main
// listener's bind error after the challenge listener started, and that
// Shutdown then frees the challenge address.
func TestListenACMEListenPortTaken(t *testing.T) {
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()

	var logs logBuffer
	s := newACMETestServer(t, taken.Addr().String(), &logs)
	chalAddr := freeAddr(t)
	s.challengeAddr = chalAddr
	err = s.Start(context.Background())
	skipIfBindRaced(t, &logs)
	if err == nil || !strings.Contains(err.Error(), taken.Addr().String()) {
		t.Errorf("Start = %v, want the error binding %s", err, taken.Addr())
	}
	s.mu.Lock()
	started := s.chalSrv != nil
	s.mu.Unlock()
	if !started {
		t.Error("the challenge listener didn't start")
	}

	if err := s.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	waitFree(t, chalAddr)
}
