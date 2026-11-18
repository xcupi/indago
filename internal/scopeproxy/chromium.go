package scopeproxy

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// This file is the "point the browser at the proxy" half of the primitive. It
// is a pure function so the switches can be tested and reviewed without
// launching a browser, and so the eventual browser integration can adopt them
// without this package importing internal/browser.

// chromiumResolverSentinel is the host-resolver-rules target that makes every
// DNS lookup inside Chromium fail. It is how the browser is kept from resolving
// names on its own: a proxied request carries the name to the proxy, so the
// browser never needs an answer, and any lookup it would have made (preconnect,
// dns-prefetch, a leaked direct request) fails instead of reaching a resolver.
//
// The loopback EXCLUDEs are required and were measured, not assumed: Chromium
// applies host-resolver-rules to address literals too, so "MAP * ~NOTFOUND"
// alone made a navigation to http://127.0.0.1:PORT/ fail with
// ERR_NAME_NOT_RESOLVED and an IPv6-loopback proxy fail with
// ERR_PROXY_CONNECTION_FAILED. Excluding 127.0.0.1 and ::1 restores exactly the
// two literal spellings that need no DNS at all; every name is still ~NOTFOUND.
// (TestChromiumScopeProxyRefusesOutOfScopeLoopback and
// TestChromiumIPv6LoopbackProxyWork are the checks.)
const chromiumResolverRules = "MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE ::1"

// Errors returned by ChromiumArgs.
var (
	// ErrProxyURLNotHTTP is returned for a non-http proxy URL. SOCKS is not
	// implemented by this package and is not silently downgraded to HTTP.
	ErrProxyURLNotHTTP = errors.New("scopeproxy: the proxy URL must use the http scheme")
	// ErrProxyURLNotLoopback is returned when the proxy host is not a literal
	// loopback address. A name would have to be resolved by the browser, which
	// defeats the resolver hardening below.
	ErrProxyURLNotLoopback = errors.New("scopeproxy: the proxy URL must be a loopback IP literal with an explicit port")
)

// ChromiumArgs returns the Chromium switches that route every request through
// this proxy and remove the two ways a browser can escape it:
//
//   - --proxy-bypass-list=<-loopback> subtracts Chromium's implicit
//     "never proxy localhost/127.0.0.1" rules. Without it, a target on loopback
//     is reached directly and the proxy never sees the request — measured by
//     TestChromiumLoopbackBypassIsRemoved.
//   - --host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE ::1
//     makes every browser-side DNS lookup for a NAME fail while leaving address
//     literals usable, and --dns-prefetch-disable stops hint-driven resolution.
//     Measured by TestChromiumProxyCarriesNamesWithoutBrowserDNS: a page whose
//     host has no resolvable name still loads through the proxy, while the
//     out-of-scope name is never looked up at all.
//
// Callers must still keep Chromium's process sandbox on: none of these switches
// change it, and this package never asks for --no-sandbox.
func ChromiumArgs(proxyURL string) ([]string, error) {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("scopeproxy: parse proxy URL: %w", err)
	}
	if u.Scheme != "http" {
		return nil, fmt.Errorf("%w (got %q)", ErrProxyURLNotHTTP, u.Scheme)
	}
	if u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("%w: the URL must not carry credentials, a path, a query or a fragment", ErrProxyURLNotLoopback)
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProxyURLNotLoopback, err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return nil, fmt.Errorf("%w (got host %q)", ErrProxyURLNotLoopback, host)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return nil, fmt.Errorf("%w: invalid port %q", ErrProxyURLNotLoopback, port)
	}
	literal := net.JoinHostPort(ip.String(), port)
	return []string{
		"--proxy-server=http://" + literal,
		"--proxy-bypass-list=<-loopback>",
		"--host-resolver-rules=" + chromiumResolverRules,
		"--dns-prefetch-disable",
	}, nil
}

// ChromiumProxyServer returns just the --proxy-server value ChromiumArgs uses,
// for callers (Playwright's own proxy option, for example) that configure the
// server separately from the extra switches.
func ChromiumProxyServer(proxyURL string) (string, error) {
	args, err := ChromiumArgs(proxyURL)
	if err != nil {
		return "", err
	}
	return strings.TrimPrefix(args[0], "--proxy-server="), nil
}
