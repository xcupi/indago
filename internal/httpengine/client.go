package httpengine

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"time"
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
	ProxyURL string
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

	if cfg.ProxyURL != "" {
		pu, err := url.Parse(cfg.ProxyURL)
		if err != nil {
			return nil, fmt.Errorf("httpengine: invalid proxy url %q: %w", cfg.ProxyURL, err)
		}
		tr.Proxy = http.ProxyURL(pu)
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
