package scopeproxy

// Real-Chromium check that the resolver-rule exception list is complete: with
// the full ChromiumArgs set, a proxy and an origin that both live on the IPv6
// loopback must still work. Chromium applies --host-resolver-rules to address
// literals, so without "EXCLUDE ::1" this navigation fails with
// ERR_PROXY_CONNECTION_FAILED even though nothing is out of scope. Measured, not
// assumed: the same navigation fails with only "EXCLUDE 127.0.0.1" present.

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"
)

func TestChromiumIPv6LoopbackProxyWork(t *testing.T) {
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback on this host: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<!doctype html><title>v6-origin</title>")
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	originAddr := ln.Addr().String()
	_, originPort, err := net.SplitHostPort(originAddr)
	if err != nil {
		t.Fatal(err)
	}

	log := &eventLog{}
	s := startProxy(t, Config{
		Policy:     allow(net.JoinHostPort("::1", originPort)),
		ListenAddr: "[::1]:0",
		Observer:   log.observe,
	})

	args, err := ChromiumArgs(s.ProxyURL())
	if err != nil {
		t.Fatalf("ChromiumArgs(%q): %v", s.ProxyURL(), err)
	}
	b := launchChromium(t, args)
	page := openPage(t, b, "http://[::1]:"+originPort+"/")
	if title, _ := page.Title(); title != "v6-origin" {
		t.Fatalf("page title = %q, want v6-origin: the IPv6 loopback proxy was not usable (stats=%+v)", title, s.Stats())
	}
	if _, ok := log.waitFor(func(ev Event) bool {
		port, _ := strconv.Atoi(originPort)
		return ev.Allowed && ev.Host == "::1" && ev.Port == port
	}, 5*time.Second); !ok {
		t.Fatalf("the proxy never recorded the allowed IPv6 request (stats=%+v)", s.Stats())
	}
	// The browser resolved nothing: the rule list only exempts the literals.
	// Chromium also fetches /favicon.ico, so the count is at least one.
	if st := s.Stats(); st.Forwarded < 1 {
		t.Fatalf("stats = %+v, want at least one forwarded request", st)
	}
}
