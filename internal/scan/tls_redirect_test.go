package scan

import (
	"errors"
	"testing"
)

func TestIsTLSRedirectMismatch(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{errors.New(`Get "https://example.test:8080/x": http: server gave HTTP response to HTTPS client`), true},
		{errors.New("tls: first record does not look like a TLS handshake"), true},
		{errors.New("connection refused"), false},
		{errors.New("context canceled"), false},
		{nil, false},
	}
	for _, tc := range cases {
		if got := isTLSRedirectMismatch(tc.err); got != tc.want {
			t.Fatalf("isTLSRedirectMismatch(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}
