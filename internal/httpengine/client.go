package httpengine

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sync/atomic"
	"syscall"
	"time"

	utls "github.com/refraction-networking/utls"
)

// DefaultUserAgent identifies Indago honestly. Per project policy the engine does
// NOT spoof browsers or implement anti-bot/WAF evasion.
const DefaultUserAgent = "Indago"

// DefaultMaxBodyBytes caps response body reads unless overridden.
const DefaultMaxBodyBytes int64 = 10 << 20 // 10 MiB

// Config configures a Client. Start from DefaultConfig and adjust.
type Config struct {
	// Timeout is the per-request overall timeout (0 = none; context still applies).
	Timeout time.Duration
	// FollowRedirects controls whether 3xx redirects are followed.
	FollowRedirects bool
	// MaxRedirects caps the redirect chain when following (<=0 → 10).
	MaxRedirects int
	// ProxyURL routes requests through an http/https/socks5 proxy ("" = direct).
	// Ignored when ProxyPool is non-empty.
	ProxyURL string
	// ProxyPool, when non-empty, routes requests through one of the listed
	// proxies, picked round-robin per request (operator-supplied
	// infrastructure; see domain.ScanConfig.ProxyPool for the full
	// rationale and boundary). Takes priority over ProxyURL.
	ProxyPool []string
	// UserAgent is sent unless a request/default header overrides it ("" = none).
	UserAgent string
	// MaxBodyBytes caps response body reads. 0 → DefaultMaxBodyBytes; negative →
	// unlimited (use with care).
	MaxBodyBytes int64
	// InsecureSkipVerify disables TLS certificate verification (default false).
	InsecureSkipVerify bool
	// DefaultHeaders are applied to every request (overridable per request).
	DefaultHeaders map[string]string
	// CookieJar, when set, is used for cross-request cookie persistence (session
	// reuse). When nil and DisableCookies is false, a fresh in-memory jar is used.
	CookieJar http.CookieJar
	// DisableCookies turns off the cookie jar entirely.
	DisableCookies bool
	// RandomizeTLSFingerprint, when true, performs the TLS handshake with a
	// randomized (but realistic) ClientHello via uTLS instead of Go's own
	// crypto/tls ClientHello — Go's default has its own distinct, easily
	// fingerprinted TLS signature (JA3), unrelated to the UserAgent header
	// Indago sends. Operator opt-in only, default false (CLI
	// -randomize-tls-fingerprint, API randomize_tls_fingerprint) — see
	// AGENTS.md §2.2. MUTUALLY EXCLUSIVE with ProxyURL/ProxyPool: Go's
	// http.Transport performs TLS internally, with its own TLSClientConfig,
	// AFTER establishing any proxy tunnel (CONNECT or SOCKS5) — it never
	// consults DialTLSContext for a proxied connection (see
	// net/http/transport.go's dialConn), so this flag would silently have
	// NO effect whenever a proxy is also configured. New rejects the
	// combination outright rather than ship a flag that quietly no-ops.
	RandomizeTLSFingerprint bool
}

// DefaultConfig returns conservative, sensible defaults.
func DefaultConfig() Config {
	return Config{
		Timeout:         30 * time.Second,
		FollowRedirects: true,
		MaxRedirects:    10,
		UserAgent:       DefaultUserAgent,
		MaxBodyBytes:    DefaultMaxBodyBytes,
	}
}

// Client is the real HTTP engine. It is safe for concurrent use by multiple
// goroutines; a shared transport (connection pool) and cookie jar are reused
// across requests, while redirect capture is per-call.
type Client struct {
	transport       *http.Transport
	jar             http.CookieJar
	timeout         time.Duration
	followRedirects bool
	maxRedirects    int
	maxBodyBytes    int64
	userAgent       string
	defaultHeaders  map[string]string
}

var _ Engine = (*Client)(nil)

// New builds a Client from cfg.
func New(cfg Config) (*Client, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()

	// Scope is enforced on the request's hostname (internal/scan/scoped.go), not
	// the resolved IP — intentionally, since an operator may legitimately scope
	// an internal/private target. But a hostname's DNS can change between that
	// check and this dial (or simply resolve somewhere the operator never
	// intended), and link-local addresses are never a legitimate scan target —
	// that range is where every major cloud provider's instance-metadata
	// service lives (169.254.169.254) and SSRF-into-metadata is a standing risk
	// for any tool that fetches operator-specified URLs. Block it at the one
	// point that sees the address actually being connected to, regardless of
	// which hostname or redirect hop produced it.
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   rejectLinkLocal,
	}
	tr.DialContext = dialer.DialContext

	if cfg.ProxyURL != "" {
		pu, err := url.Parse(cfg.ProxyURL)
		if err != nil {
			return nil, fmt.Errorf("httpengine: invalid proxy url %q: %w", cfg.ProxyURL, err)
		}
		tr.Proxy = http.ProxyURL(pu)
	}
	if len(cfg.ProxyPool) > 0 {
		pool := make([]*url.URL, 0, len(cfg.ProxyPool))
		for _, p := range cfg.ProxyPool {
			pu, err := url.Parse(p)
			if err != nil {
				return nil, fmt.Errorf("httpengine: invalid proxy pool entry %q: %w", p, err)
			}
			pool = append(pool, pu)
		}
		var next uint64
		tr.Proxy = func(*http.Request) (*url.URL, error) {
			i := atomic.AddUint64(&next, 1) - 1
			return pool[i%uint64(len(pool))], nil
		}
	}
	if cfg.RandomizeTLSFingerprint {
		if cfg.ProxyURL != "" || len(cfg.ProxyPool) > 0 {
			return nil, fmt.Errorf("httpengine: RandomizeTLSFingerprint and a proxy (ProxyURL/ProxyPool) cannot both be set: " +
				"Go's http.Transport performs TLS internally after any proxy tunnel, never through a custom TLS dialer, " +
				"so the fingerprint override would silently have no effect")
		}
		tr.DialTLSContext = randomizedTLSDialer(dialer, cfg.InsecureSkipVerify)
	}
	if tr.TLSClientConfig == nil {
		tr.TLSClientConfig = &tls.Config{}
	}
	tr.TLSClientConfig.InsecureSkipVerify = cfg.InsecureSkipVerify

	var jar http.CookieJar
	if !cfg.DisableCookies {
		if cfg.CookieJar != nil {
			jar = cfg.CookieJar
		} else {
			j, err := cookiejar.New(nil)
			if err != nil {
				return nil, fmt.Errorf("httpengine: cookie jar: %w", err)
			}
			jar = j
		}
	}

	maxRedirects := cfg.MaxRedirects
	if maxRedirects <= 0 {
		maxRedirects = 10
	}
	maxBody := cfg.MaxBodyBytes
	if maxBody == 0 {
		maxBody = DefaultMaxBodyBytes
	}

	return &Client{
		transport:       tr,
		jar:             jar,
		timeout:         cfg.Timeout,
		followRedirects: cfg.FollowRedirects,
		maxRedirects:    maxRedirects,
		maxBodyBytes:    maxBody,
		userAgent:       cfg.UserAgent,
		defaultHeaders:  cloneStringMap(cfg.DefaultHeaders),
	}, nil
}

// randomizedTLSDialer returns an http.Transport.DialTLSContext implementation
// that performs the TLS handshake with uTLS's utls.HelloRandomized —
// randomized-but-internally-consistent cipher suites/extensions within a
// realistic space, rather than Go's own crypto/tls ClientHello, which has a
// distinct, easily fingerprinted (JA3) signature of its own regardless of
// what the UserAgent header claims. dialer is reused as-is so this dial path
// goes through the SAME rejectLinkLocal SSRF guard as every other connection
// this Client makes — never bypassed for this path.
//
// KNOWN LIMITATION: the returned net.Conn is a *utls.UConn, not a stdlib
// *tls.Conn, so Go's Transport (see dialConn in net/http/transport.go) never
// populates persistConn.tlsState from it and therefore never discovers an
// ALPN-negotiated "h2" — every connection through this dialer is pinned to
// HTTP/1.1. This does not affect scan correctness (every reflection/
// candidate/verification request is already a simple, independent exchange),
// only connection-reuse efficiency; documented here rather than silently
// accepted.
func randomizedTLSDialer(dialer *net.Dialer, insecureSkipVerify bool) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		rawConn, err := dialer.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("httpengine: randomized TLS dial: %w", err)
		}
		uConn := utls.UClient(rawConn, &utls.Config{ServerName: host, InsecureSkipVerify: insecureSkipVerify}, utls.HelloRandomized)
		if err := uConn.HandshakeContext(ctx); err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("httpengine: randomized TLS handshake: %w", err)
		}
		return uConn, nil
	}
}

// rejectLinkLocal is a net.Dialer.Control hook: it runs after DNS resolution
// but before the socket connects, so it sees the actual IP about to be dialed
// (not just the hostname) — refusing it here closes the window between a
// hostname-based scope check and the real connection. See the comment in New.
func rejectLinkLocal(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil // not host:port; let the dial itself fail naturally
	}
	ip := net.ParseIP(host)
	if ip != nil && (ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()) {
		return fmt.Errorf("httpengine: refusing to connect to link-local address %s (cloud metadata/APIPA range)", ip)
	}
	return nil
}

// NewDefault returns a Client with DefaultConfig.
func NewDefault() *Client {
	c, _ := New(DefaultConfig()) // DefaultConfig never errors
	return c
}

// CookieJar returns the client's cookie jar (nil if cookies are disabled). It
// lets a caller share or inspect session cookies.
func (c *Client) CookieJar() http.CookieJar { return c.jar }

// Close releases idle connections held by the transport.
func (c *Client) Close() { c.transport.CloseIdleConnections() }

// Do executes an HTTP request and captures the response. Scope must be checked
// by the caller before calling Do.
func (c *Client) Do(ctx context.Context, req *Request) (*Response, error) {
	if req == nil {
		return nil, fmt.Errorf("%w: nil request", ErrInvalidRequest)
	}
	if c.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}
	if req.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, req.Timeout)
		defer cancel()
	}

	hr, err := c.buildRequest(ctx, req)
	if err != nil {
		return nil, err
	}

	captured := &CapturedRequest{
		Method:  hr.Method,
		URL:     hr.URL.String(),
		Headers: hr.Header.Clone(),
		Body:    req.Body,
	}

	// Per-call redirect capture keeps the Client concurrency-safe.
	var chain []string
	client := &http.Client{
		Transport: c.transport,
		Jar:       c.jar,
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			chain = append(chain, r.URL.String())
			if !c.followRedirects {
				return http.ErrUseLastResponse
			}
			if len(via) >= c.maxRedirects {
				return fmt.Errorf("%w (limit %d)", ErrTooManyRedirects, c.maxRedirects)
			}
			return nil
		},
	}

	start := time.Now()
	resp, err := client.Do(hr)
	if err != nil {
		// Context and redirect-limit errors propagate (errors.Is sees the
		// sentinels through the *url.Error wrapper).
		return nil, err
	}
	defer resp.Body.Close()

	body, truncated, err := readLimited(resp.Body, c.maxBodyBytes)
	if err != nil {
		return nil, fmt.Errorf("httpengine: read body: %w", err)
	}
	received := time.Now()

	return &Response{
		Status:        resp.StatusCode,
		StatusText:    resp.Status,
		Proto:         resp.Proto,
		Headers:       resp.Header,
		Body:          body,
		Truncated:     truncated,
		ContentLength: resp.ContentLength,
		FinalURL:      finalURL(resp, hr),
		RedirectChain: chain,
		Duration:      received.Sub(start),
		ReceivedAt:    received,
		Request:       captured,
	}, nil
}

func (c *Client) buildRequest(ctx context.Context, req *Request) (*http.Request, error) {
	method := req.Method
	if method == "" {
		method = http.MethodGet
	}

	u, err := url.Parse(req.URL)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	if !u.IsAbs() || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("%w: URL must be an absolute http(s) URL: %q", ErrInvalidRequest, req.URL)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("%w: missing host in %q", ErrInvalidRequest, req.URL)
	}

	var body io.Reader
	if len(req.Body) > 0 {
		body = bytes.NewReader(req.Body)
	}
	hr, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}

	// Default headers first, then user agent (unless provided), then per-request
	// headers (highest priority), then content type, then cookies.
	for k, v := range c.defaultHeaders {
		hr.Header.Set(k, v)
	}
	if c.userAgent != "" && hr.Header.Get("User-Agent") == "" {
		hr.Header.Set("User-Agent", c.userAgent)
	}
	for k, v := range req.Headers {
		hr.Header.Set(k, v)
	}
	if hr.Header.Get("Content-Type") == "" && req.ContentType != "" {
		hr.Header.Set("Content-Type", req.ContentType)
	}
	for _, ck := range req.Cookies {
		if ck != nil {
			hr.AddCookie(ck)
		}
	}
	return hr, nil
}

// finalURL returns the URL after redirects.
func finalURL(resp *http.Response, fallback *http.Request) string {
	if resp.Request != nil && resp.Request.URL != nil {
		return resp.Request.URL.String()
	}
	return fallback.URL.String()
}

// readLimited reads up to max bytes (max < 0 means unlimited), reporting whether
// the body was truncated at the cap.
func readLimited(r io.Reader, max int64) ([]byte, bool, error) {
	if max < 0 {
		b, err := io.ReadAll(r)
		return b, false, err
	}
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(b)) > max {
		return b[:max], true, nil
	}
	return b, false, nil
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
