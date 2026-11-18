package scopeproxy

import (
	"errors"
	"strings"
	"testing"
)

func TestChromiumArgsRoutesThroughProxyAndRemovesBypasses(t *testing.T) {
	args, err := ChromiumArgs("http://127.0.0.1:41234")
	if err != nil {
		t.Fatalf("ChromiumArgs: %v", err)
	}
	joined := strings.Join(args, "\n")
	for _, want := range []string{
		"--proxy-server=http://127.0.0.1:41234",
		"--proxy-bypass-list=<-loopback>", // otherwise loopback targets skip the proxy
		// EXCLUDE is measured: host-resolver-rules hit address literals too.
		"--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE ::1",
		"--dns-prefetch-disable",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("args %q do not contain %q", args, want)
		}
	}
	if strings.Contains(joined, "no-sandbox") {
		t.Fatalf("ChromiumArgs must never weaken the process sandbox: %q", args)
	}
	if !strings.Contains(args[0], "127.0.0.1:41234") {
		t.Fatalf("first argument must be the proxy server, got %q", args[0])
	}
}

func TestChromiumArgsRefusesUnsafeProxyURLs(t *testing.T) {
	for _, tc := range []struct {
		url  string
		want error
	}{
		{"socks5://127.0.0.1:9050", ErrProxyURLNotHTTP},
		{"http://localhost:8080", ErrProxyURLNotLoopback},   // a name the browser would resolve
		{"http://example.com:8080", ErrProxyURLNotLoopback}, // not loopback
		{"http://10.0.0.1:8080", ErrProxyURLNotLoopback},
		{"http://127.0.0.1", ErrProxyURLNotLoopback},                // no explicit port
		{"http://user:pass@127.0.0.1:8080", ErrProxyURLNotLoopback}, // credentials
		{"http://127.0.0.1:8080/path", ErrProxyURLNotLoopback},
	} {
		if _, err := ChromiumArgs(tc.url); !errors.Is(err, tc.want) {
			t.Errorf("ChromiumArgs(%q) = %v, want %v", tc.url, err, tc.want)
		}
	}
	if got, err := ChromiumProxyServer("http://[::1]:8080"); err != nil || got != "http://[::1]:8080" {
		t.Fatalf("ChromiumProxyServer([::1]) = %q, %v", got, err)
	}
}
