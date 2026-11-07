package zdas

import (
	"slices"
	"testing"

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
		if srv := challengeServer(listen, m); srv != nil {
			t.Errorf("challengeServer(%q) = server on %q, want nil", listen, srv.Addr)
		}
	}
	for _, listen := range []string{":8443", "0.0.0.0:18443"} {
		srv := challengeServer(listen, m)
		if srv == nil {
			t.Fatalf("challengeServer(%q) = nil, want a server", listen)
		}
		if srv.Addr != ":443" {
			t.Errorf("challengeServer(%q).Addr = %q, want :443", listen, srv.Addr)
		}
		if srv.TLSConfig == nil || !slices.Contains(srv.TLSConfig.NextProtos, acme.ALPNProto) {
			t.Errorf("challengeServer(%q) doesn't offer %s", listen, acme.ALPNProto)
		}
	}
}
