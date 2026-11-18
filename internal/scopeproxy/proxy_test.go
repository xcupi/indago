package scopeproxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// origin is a loopback HTTP origin that records the request-targets it served.
type origin struct {
	srv   *httptest.Server
	hits  atomic.Int64
	mu    sync.Mutex
	paths []string
	hosts []string
}

func newOrigin(t *testing.T) *origin { return newOriginWithBody(t, "") }

// newOriginWithBody serves body for every request when it is non-empty, and a
// minimal page echoing the request-target otherwise.
func newOriginWithBody(t *testing.T, body string) *origin {
	t.Helper()
	o := &origin{}
	o.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		o.hits.Add(1)
		o.mu.Lock()
		o.paths = append(o.paths, r.RequestURI)
		o.hosts = append(o.hosts, r.Host)
		o.mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		if body != "" {
			_, _ = io.WriteString(w, body)
			return
		}
		fmt.Fprintf(w, "<!doctype html><title>origin</title><p>%s</p>", r.RequestURI)
	}))
	t.Cleanup(o.srv.Close)
	return o
}

func (o *origin) hostPort(t *testing.T) string {
	t.Helper()
	u, err := url.Parse(o.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Host
}

func (o *origin) host(t *testing.T) string {
	t.Helper()
	h, _, err := net.SplitHostPort(o.hostPort(t))
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func (o *origin) port(t *testing.T) int {
	t.Helper()
	_, p, err := net.SplitHostPort(o.hostPort(t))
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if _, err := fmt.Sscanf(p, "%d", &n); err != nil {
		t.Fatal(err)
	}
	return n
}

func (o *origin) lastHost() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.hosts) == 0 {
		return ""
	}
	return o.hosts[len(o.hosts)-1]
}

func (o *origin) lastPath() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.paths) == 0 {
		return ""
	}
	return o.paths[len(o.paths)-1]
}

// connCounter is a raw TCP listener that counts accepted connections and never
// speaks HTTP. It is how "the browser did not even open a socket" is measured:
// an HTTP server would log a failed request, but this counts the socket itself.
type connCounter struct {
	ln    net.Listener
	count atomic.Int64
}

func newConnCounter(t *testing.T) *connCounter {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c := &connCounter{ln: ln}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			c.count.Add(1)
			_ = conn.Close()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return c
}

func (c *connCounter) addr() string { return c.ln.Addr().String() }

func (c *connCounter) hostPort(t *testing.T) (string, int) {
	t.Helper()
	host, port, err := net.SplitHostPort(c.addr())
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if _, err := fmt.Sscanf(port, "%d", &n); err != nil {
		t.Fatal(err)
	}
	return host, n
}

// recordingResolver is the only DNS this proxy performs, instrumented so a test
// can assert which names were looked up — and, more importantly, which were not.
type recordingResolver struct {
	mu      sync.Mutex
	calls   []string
	answers map[string][]net.IPAddr
	err     error
}

func newRecordingResolver() *recordingResolver {
	return &recordingResolver{answers: map[string][]net.IPAddr{}}
}

func (r *recordingResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	r.mu.Lock()
	r.calls = append(r.calls, host)
	r.mu.Unlock()
	if r.err != nil {
		return nil, r.err
	}
	if ips, ok := r.answers[host]; ok {
		return ips, nil
	}
	return nil, fmt.Errorf("no answer for %q", host)
}

func (r *recordingResolver) lookedUp() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...)
}

func startProxy(t *testing.T, cfg Config) *Server {
	t.Helper()
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func allow(hosts ...string) PolicyFunc {
	allowed := map[string]bool{}
	for _, h := range hosts {
		allowed[h] = true
	}
	return func(host string, port int) bool { return allowed[net.JoinHostPort(host, fmt.Sprint(port))] }
}

func proxyHTTPClient(t *testing.T, s *Server) *http.Client {
	t.Helper()
	u, err := url.Parse(s.ProxyURL())
	if err != nil {
		t.Fatal(err)
	}
	tr := &http.Transport{Proxy: http.ProxyURL(u), DisableKeepAlives: true}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 10 * time.Second}
}

// rawExchange writes one request verbatim and reads one response.
func rawExchange(t *testing.T, proxyAddr, request string) (*http.Response, string) {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: "GET"})
	if err != nil {
		t.Fatalf("read response for %q: %v", strings.SplitN(request, "\r\n", 2)[0], err)
	}
	body, _ := io.ReadAll(resp.Body)
	return resp, string(body)
}

// rawConnect sends a CONNECT request and returns the status line plus a reader
// positioned after the response headers, so a caller can read the tunnel.
func rawConnect(t *testing.T, proxyAddr, target string) (int, *bufio.Reader, net.Conn) {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read CONNECT status: %v", err)
	}
	var status int
	if _, err := fmt.Sscanf(line, "HTTP/1.1 %d", &status); err != nil {
		t.Fatalf("parse status line %q: %v", line, err)
	}
	for {
		h, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read CONNECT headers: %v", err)
		}
		if h == "\r\n" || h == "\n" {
			break
		}
	}
	return status, br, conn
}

// ---------------------------------------------------------------------------
// pure parsing
// ---------------------------------------------------------------------------

func TestParseAuthorityRejectsMalformedShapes(t *testing.T) {
	for _, tc := range []struct {
		raw         string
		defaultPort int
	}{
		{"", 0},
		{"example.com", 0},          // CONNECT requires a port
		{"example.com:", 80},        // empty port
		{":443", 0},                 // empty host
		{"example.com:0", 0},        // port 0 is not a service
		{"example.com:65536", 0},    // out of range
		{"example.com:-1", 0},       // not decimal
		{"example.com:1x", 0},       // not decimal
		{"user@example.com:443", 0}, // userinfo
		{"example.com:443/x", 0},    // path
		{"example.com:443?x", 0},    // query
		{"example.com:443#x", 0},    // fragment
		{"http://example.com:443", 0},
		{"example.com.:443", 0}, // trailing-dot spelling
		{".example.com:443", 0},
		{"exa mple.com:443", 0},
		{"example.com:443\t", 0},
		{"exa\\mple.com:443", 0}, // WHATWG/RFC separator differential
		{"[::1]443", 0},          // text after the bracket without ':'
		{"[::1", 0},              // unterminated
		{"[example.com]:443", 0}, // bracketed non-IP
		{"::1:443", 0},           // bare IPv6 is ambiguous with host:port
		{"0:0:0:0:0:0:0:1", 0},
		{"2130706433:80", 0},         // decimal IPv4 alias
		{"0x7f.0.0.1:80", 0},         // hex IPv4 alias
		{"01.2.3.4:80", 0},           // zero-padded IPv4 alias
		{"[::ffff:127.0.0.1]:80", 0}, // IPv4-mapped: Go and WHATWG differ
	} {
		if a, err := parseAuthority(tc.raw, tc.defaultPort); err == nil {
			t.Errorf("parseAuthority(%q, %d) accepted as %+v; every one of these is a shape two parsers can read differently", tc.raw, tc.defaultPort, a)
		}
	}
}

func TestParseAuthorityAcceptsBareAndCanonicalForms(t *testing.T) {
	for _, tc := range []struct {
		raw      string
		defPort  int
		wantHost string
		wantPort int
	}{
		{"example.com:8443", 0, "example.com", 8443},
		{"example.com", 80, "example.com", 80},
		{"127.0.0.1:8080", 0, "127.0.0.1", 8080},
		{"127.0.0.1", 443, "127.0.0.1", 443},
		{"[::1]:8080", 0, "::1", 8080},
		{"[::1]", 443, "::1", 443},
		{"EXAMPLE.com:80", 0, "example.com", 80},
		{"internal_host:80", 0, "internal_host", 80},
	} {
		a, err := parseAuthority(tc.raw, tc.defPort)
		if err != nil {
			t.Errorf("parseAuthority(%q, %d) refused: %v", tc.raw, tc.defPort, err)
			continue
		}
		if a.host != tc.wantHost || a.port != tc.wantPort {
			t.Errorf("parseAuthority(%q, %d) = %s:%d, want %s:%d", tc.raw, tc.defPort, a.host, a.port, tc.wantHost, tc.wantPort)
		}
	}
}

func TestSplitAbsoluteTarget(t *testing.T) {
	for _, tc := range []struct {
		raw      string
		wantAuth string
		wantRest string
		wantErr  bool
	}{
		{raw: "http://example.com:8080/a/b?q=1", wantAuth: "example.com:8080", wantRest: "/a/b?q=1"},
		{raw: "http://example.com", wantAuth: "example.com", wantRest: "/"},
		{raw: "http://example.com?x=1", wantAuth: "example.com", wantRest: "/?x=1"},
		{raw: "http://example.com/a%2Fb?q=%20", wantAuth: "example.com", wantRest: "/a%2Fb?q=%20"},
		{raw: "/origin-form", wantErr: true},
		{raw: "*", wantErr: true},
		{raw: "https://example.com/a", wantErr: true},
		{raw: "http:///path", wantErr: true},
		{raw: "http://example.com/#frag", wantErr: true},
		{raw: "http://example.com/\x00", wantErr: true},
	} {
		auth, rest, err := splitAbsoluteTarget(tc.raw)
		if tc.wantErr {
			if err == nil {
				t.Errorf("splitAbsoluteTarget(%q) = %q,%q; want an error", tc.raw, auth, rest)
			}
			continue
		}
		if err != nil || auth != tc.wantAuth || rest != tc.wantRest {
			t.Errorf("splitAbsoluteTarget(%q) = %q,%q,%v; want %q,%q", tc.raw, auth, rest, err, tc.wantAuth, tc.wantRest)
		}
	}
}

func TestSameTargetMatchesOnlyTheValidatedAuthority(t *testing.T) {
	a, err := parseAuthority("example.com:8080", 0)
	if err != nil {
		t.Fatal(err)
	}
	if !sameTarget("example.com:8080", a) || !sameTarget("EXAMPLE.com:8080", a) {
		t.Fatalf("sameTarget rejected the validated authority")
	}
	for _, addr := range []string{
		"example.com:8081",   // other port
		"other.example:8080", // other host
		"example.com",        // no port
		"example.com:http",   // non-numeric port
		"",                   // nothing
		"127.0.0.1:8080",     // an address the policy never saw
	} {
		if sameTarget(addr, a) {
			t.Errorf("sameTarget(%q) matched authority %s; a transport dial must never leave the checked destination", addr, a)
		}
	}
}

func TestAuditAuthorityIsBoundedAndStripped(t *testing.T) {
	injected := "evil\r\n2026 log: forged" + strings.Repeat("A", 1000)
	got := sanitizeForAudit(injected)
	if strings.ContainsAny(got, "\r\n") {
		t.Fatalf("sanitizeForAudit left line breaks in %q", got)
	}
	if len(got) > maxAuditedAuthorityBytes {
		t.Fatalf("sanitizeForAudit returned %d bytes, want <= %d", len(got), maxAuditedAuthorityBytes)
	}
}

// ---------------------------------------------------------------------------
// construction fails closed
// ---------------------------------------------------------------------------

func TestNewRequiresPolicy(t *testing.T) {
	if _, err := New(Config{}); !errors.Is(err, ErrNoPolicy) {
		t.Fatalf("New without a policy = %v, want ErrNoPolicy", err)
	}
}

func TestNewRefusesNonLoopbackListener(t *testing.T) {
	_, err := New(Config{Policy: PolicyFunc(func(string, int) bool { return true }), ListenAddr: "0.0.0.0:0"})
	if !errors.Is(err, ErrNonLoopbackListener) {
		t.Fatalf("New on 0.0.0.0 = %v, want ErrNonLoopbackListener", err)
	}
}

func TestNewRefusesOperatorProxyChain(t *testing.T) {
	_, err := New(Config{
		Policy:        PolicyFunc(func(string, int) bool { return true }),
		UpstreamProxy: "http://127.0.0.1:3128",
	})
	if !errors.Is(err, ErrUpstreamProxyUnsupported) {
		t.Fatalf("New with UpstreamProxy = %v, want ErrUpstreamProxyUnsupported", err)
	}
}

// ---------------------------------------------------------------------------
// absolute-form requests
// ---------------------------------------------------------------------------

func TestForwardAllowedReachesOriginWithExactTarget(t *testing.T) {
	o := newOrigin(t)
	s := startProxy(t, Config{Policy: allow(o.hostPort(t))})
	client := proxyHTTPClient(t, s)

	resp, err := client.Get(o.srv.URL + "/a%2Fb/c?q=%20x&z=1")
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d (%s), want 200", resp.StatusCode, body)
	}
	if o.hits.Load() != 1 {
		t.Fatalf("origin hits = %d, want 1", o.hits.Load())
	}
	if got, want := o.lastPath(), "/a%2Fb/c?q=%20x&z=1"; got != want {
		t.Fatalf("origin saw request-target %q, want %q (the proxy must not re-encode the path)", got, want)
	}
	if st := s.Stats(); st.Forwarded != 1 || st.Allowed != 1 || st.Denied != 0 {
		t.Fatalf("stats = %+v", st)
	}
}

func TestForwardDeniedOnWrongPortIsNeverDialled(t *testing.T) {
	in := newOrigin(t)
	out := newConnCounter(t)
	s := startProxy(t, Config{Policy: allow(in.hostPort(t))})

	// Same host, different port: the allowlist is host:port, not host.
	target := "http://" + out.addr() + "/leak"
	resp, err := proxyHTTPClient(t, s).Get(target)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if out.count.Load() != 0 {
		t.Fatalf("out-of-scope listener saw %d connections, want 0", out.count.Load())
	}
	if st := s.Stats(); st.Denied != 1 || st.Allowed != 0 || st.Forwarded != 0 {
		t.Fatalf("stats = %+v", st)
	}
}

func TestForwardDeniedHostIsNeverResolved(t *testing.T) {
	o := newOrigin(t)
	res := newRecordingResolver()
	res.answers["in-scope.test"] = []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}
	s := startProxy(t, Config{
		Policy: PolicyFunc(func(host string, port int) bool {
			// Host:port allowlist: the in-scope name on the origin's port only.
			return host == "in-scope.test" && port == o.port(t)
		}),
		Resolver: res,
	})

	// In-scope by name: the proxy resolves it once, after the policy allows it.
	resp, err := proxyHTTPClient(t, s).Get(fmt.Sprintf("http://in-scope.test:%d/ok", o.port(t)))
	if err != nil {
		t.Fatalf("GET in-scope.test: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("in-scope status = %d, want 200", resp.StatusCode)
	}
	if got := res.lookedUp(); len(got) != 1 || got[0] != "in-scope.test" {
		t.Fatalf("resolver calls = %v, want exactly [in-scope.test]", got)
	}

	// Out-of-scope by name: denied before any lookup.
	resp2, err := proxyHTTPClient(t, s).Get(fmt.Sprintf("http://denied.test:%d/leak", o.port(t)))
	if err != nil {
		t.Fatalf("GET denied.test: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("denied status = %d, want 403", resp2.StatusCode)
	}
	if got := res.lookedUp(); len(got) != 1 {
		t.Fatalf("resolver calls after the denied request = %v; a denied name must never be resolved", got)
	}
	if o.hits.Load() != 1 {
		t.Fatalf("origin hits = %d, want 1 (only the allowed request)", o.hits.Load())
	}
}

func TestForwardOriginFormAndHTTPSAbsoluteFormFailClosed(t *testing.T) {
	o := newOrigin(t)
	out := newConnCounter(t)
	s := startProxy(t, Config{Policy: allow(o.hostPort(t), out.addr())})

	for _, tc := range []struct {
		name    string
		request string
		want    int
	}{
		{
			name:    "origin-form",
			request: "GET /path HTTP/1.1\r\nHost: " + o.hostPort(t) + "\r\nConnection: close\r\n\r\n",
			want:    http.StatusBadRequest,
		},
		{
			name:    "https-absolute-form",
			request: "GET https://" + o.hostPort(t) + "/path HTTP/1.1\r\nHost: " + o.hostPort(t) + "\r\nConnection: close\r\n\r\n",
			want:    http.StatusNotImplemented,
		},
		{
			// RFC 7230 §5.4: a proxy MUST ignore the received Host header in
			// absolute-form and use the request-target's authority. net/http
			// applies that rule before the handler runs, so this asserts the
			// origin sees the CHECKED authority, not the header's claim.
			name:    "host-header-cannot-redirect-the-origin",
			request: "GET http://" + o.hostPort(t) + "/path HTTP/1.1\r\nHost: " + out.addr() + "\r\nConnection: close\r\n\r\n",
			want:    http.StatusOK,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, body := rawExchange(t, s.Addr(), tc.request)
			defer resp.Body.Close()
			if resp.StatusCode != tc.want {
				t.Fatalf("status = %d (%s), want %d", resp.StatusCode, body, tc.want)
			}
		})
	}
	if got, want := o.lastHost(), o.hostPort(t); got != want {
		t.Fatalf("origin saw Host %q, want %q (the request-target authority)", got, want)
	}
	if out.count.Load() != 0 {
		t.Fatalf("out-of-scope listener saw %d connections, want 0", out.count.Load())
	}
}

func TestForwardPolicyPanicDeniesWithoutDialling(t *testing.T) {
	o := newOrigin(t)
	s := startProxy(t, Config{Policy: PolicyFunc(func(string, int) bool { panic("policy bug") })})

	resp, err := proxyHTTPClient(t, s).Get(o.srv.URL + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if o.hits.Load() != 0 {
		t.Fatalf("origin hits = %d, want 0", o.hits.Load())
	}
	if st := s.Stats(); st.Denied != 1 {
		t.Fatalf("stats = %+v, want one denial", st)
	}
}

func TestForwardDialFailureIsRecordedAndDenied(t *testing.T) {
	// Port 1 on loopback: nothing listens, so the dial fails after the policy
	// allows it. The failure must be a denial, never a forwarded request.
	s := startProxy(t, Config{Policy: allow("127.0.0.1:1")})
	resp, err := proxyHTTPClient(t, s).Get("http://127.0.0.1:1/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	if st := s.Stats(); st.Denied != 1 || st.Forwarded != 0 {
		t.Fatalf("stats = %+v", st)
	}
}

func TestForwardResolveFailureDenies(t *testing.T) {
	res := newRecordingResolver()
	res.err = errors.New("simulated resolver outage")
	s := startProxy(t, Config{Policy: PolicyFunc(func(string, int) bool { return true }), Resolver: res})
	resp, err := proxyHTTPClient(t, s).Get("http://does-not-exist.test:80/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
}

func TestForwardPermitAddressRefusesResolvedAddress(t *testing.T) {
	o := newOrigin(t)
	res := newRecordingResolver()
	res.answers["filtered.test"] = []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}
	s := startProxy(t, Config{
		Policy:        PolicyFunc(func(string, int) bool { return true }),
		Resolver:      res,
		PermitAddress: func(net.IP) bool { return false },
	})
	resp, err := proxyHTTPClient(t, s).Get(fmt.Sprintf("http://filtered.test:%d/", o.port(t)))
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	if o.hits.Load() != 0 {
		t.Fatalf("origin hits = %d, want 0: the address was refused before dialling", o.hits.Load())
	}
}

// ---------------------------------------------------------------------------
// CONNECT
// ---------------------------------------------------------------------------

func TestConnectAllowedTunnelsToOrigin(t *testing.T) {
	o := newOrigin(t)
	s := startProxy(t, Config{Policy: allow(o.hostPort(t))})

	status, br, conn := rawConnect(t, s.Addr(), o.hostPort(t))
	if status != http.StatusOK {
		t.Fatalf("CONNECT status = %d, want 200", status)
	}
	if _, err := fmt.Fprintf(conn, "GET /through-tunnel HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", o.hostPort(t)); err != nil {
		t.Fatalf("write tunnel request: %v", err)
	}
	resp, err := http.ReadResponse(br, &http.Request{Method: "GET"})
	if err != nil {
		t.Fatalf("read tunneled response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("tunneled status = %d, want 200", resp.StatusCode)
	}
	if o.lastPath() != "/through-tunnel" {
		t.Fatalf("origin saw %q", o.lastPath())
	}
	if st := s.Stats(); st.Tunnels != 1 || st.Allowed != 1 {
		t.Fatalf("stats = %+v", st)
	}
}

func TestConnectDeniedOnPortNeverConnects(t *testing.T) {
	in := newOrigin(t)
	out := newConnCounter(t)
	res := newRecordingResolver()
	s := startProxy(t, Config{Policy: allow(in.hostPort(t)), Resolver: res})

	status, _, _ := rawConnect(t, s.Addr(), out.addr())
	if status != http.StatusForbidden {
		t.Fatalf("CONNECT status = %d, want 403", status)
	}
	if out.count.Load() != 0 {
		t.Fatalf("out-of-scope listener saw %d connections, want 0", out.count.Load())
	}
	if got := res.lookedUp(); len(got) != 0 {
		t.Fatalf("resolver calls = %v, want none", got)
	}
}

func TestConnectMalformedAuthoritiesFailClosed(t *testing.T) {
	o := newOrigin(t)
	out := newConnCounter(t)
	res := newRecordingResolver()
	// A permissive policy: even a policy that would say yes must not get a
	// malformed authority past the parser.
	s := startProxy(t, Config{
		Policy:   PolicyFunc(func(string, int) bool { return true }),
		Resolver: res,
	})

	for _, target := range []string{
		"example.com",
		"example.com:",
		":443",
		"example.com:0",
		"example.com:65536",
		"example.com:http",
		"user@example.com:443",
		"example.com:443/path",
		"example.com.:443",
		"exa mple.com:443",
		"[::1]443",
		"[::1",
		"::1:443",
		"2130706433:80",
		"http://example.com:443",
	} {
		conn, err := net.Dial("tcp", s.Addr())
		if err != nil {
			t.Fatalf("dial proxy: %v", err)
		}
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
		resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: "CONNECT"})
		if err == nil {
			if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusForbidden {
				t.Errorf("CONNECT %q -> %d, want a refusal", target, resp.StatusCode)
			}
			resp.Body.Close()
		}
		_ = conn.Close()
	}
	if out.count.Load() != 0 {
		t.Fatalf("out-of-scope listener saw %d connections, want 0", out.count.Load())
	}
	if got := res.lookedUp(); len(got) != 0 {
		t.Fatalf("resolver calls = %v, want none: nothing may be looked up for a malformed target", got)
	}
	if o.hits.Load() != 0 {
		t.Fatalf("origin hits = %d, want 0", o.hits.Load())
	}
}

// ---------------------------------------------------------------------------
// connection bound
// ---------------------------------------------------------------------------

func TestConnectionLimitRefusesInsteadOfQueueing(t *testing.T) {
	o := newOrigin(t)
	s := startProxy(t, Config{Policy: allow(o.hostPort(t)), MaxConnections: 1})

	// Hold one tunnel open: it occupies the only slot.
	status, _, _ := rawConnect(t, s.Addr(), o.hostPort(t))
	if status != http.StatusOK {
		t.Fatalf("CONNECT status = %d, want 200", status)
	}
	resp, err := proxyHTTPClient(t, s).Get(o.srv.URL + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 while the only slot is held", resp.StatusCode)
	}
	if o.hits.Load() != 0 {
		t.Fatalf("origin hits = %d, want 0", o.hits.Load())
	}
}
