package browser

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

// This file adds per-scan operator-proxy support to browser RENDERING without
// touching the shared Browser interface or the Manager's pool: a scan that
// configures domain.ScanConfig.ProxyPool gets a decorator around the one shared
// Browser, and every render that decorator performs creates its context with
// that proxy. Nothing here mutates the Manager, the pool, or another scan.
//
// It deliberately does not change RenderOptions (another in-flight change is
// already editing it); renderThroughProxy mirrors Render field for field.
// TestRenderAndRenderThroughProxyAgree is the drift guard.

// ErrProxyUnsupported is returned when a Browser wrapped by WithProxyPool
// cannot actually carry a per-context proxy (for example a test double, or a
// future non-Manager implementation). The render is REFUSED rather than
// performed directly: silently degrading to a direct connection would defeat
// the operator's proxy and the scan's egress expectations.
var ErrProxyUnsupported = errors.New("browser: this browser implementation cannot apply an operator proxy")

// WithProxyPool returns b with the given operator proxy pool applied to every
// render, round-robin. It is per scan and per call: b itself is not modified,
// the Manager's pooled browsers and every other scan's contexts are unaffected,
// and each render gets its own context (so Chromium's per-context network
// stack, not a process-wide proxy, carries the traffic).
//
// An empty pool (or one with only blank entries) returns b unchanged, so the
// overwhelmingly common direct-connection case keeps exactly its current code
// path. A nil b is returned as-is: "no browser configured" is a supported
// configuration, not a proxy failure.
func WithProxyPool(b Browser, pool []string) Browser {
	if b == nil {
		return nil
	}
	cleaned := make([]string, 0, len(pool))
	for _, p := range pool {
		if s := strings.TrimSpace(p); s != "" {
			cleaned = append(cleaned, s)
		}
	}
	if len(cleaned) == 0 {
		return b
	}
	return &proxyPoolBrowser{inner: b, pool: cleaned}
}

type proxyPoolBrowser struct {
	inner Browser
	pool  []string
	next  atomic.Uint64
}

// nextProxy round-robins through the pool, matching verifyExecutor.nextProxy
// and domXSSExecutor.nextProxy so one scan's browser traffic is spread the same
// way across the operator's proxies on every path.
func (p *proxyPoolBrowser) nextProxy() string {
	i := p.next.Add(1) - 1
	return p.pool[i%uint64(len(p.pool))]
}

// Render implements Browser. The proxy is applied to this render's context
// only, and a render whose proxy cannot be installed fails closed.
func (p *proxyPoolBrowser) Render(ctx context.Context, rawURL string, opts RenderOptions) (*RenderResult, error) {
	proxy := p.nextProxy()
	m, ok := p.inner.(*Manager)
	if !ok {
		return nil, fmt.Errorf("%w: rendering %s would otherwise go direct", ErrProxyUnsupported, redactURL(rawURL))
	}
	res, err := m.renderThroughProxy(ctx, rawURL, opts, proxy)
	if err != nil {
		return nil, redactProxyCredentials(err, proxy)
	}
	return res, nil
}

// Close is a no-op on purpose: the wrapped Browser is the process-wide shared
// Manager. Closing it from a scan's discovery teardown would kill every other
// running scan's browser work. Ownership of that Manager stays with the server
// that created it.
func (p *proxyPoolBrowser) Close() error { return nil }

// renderThroughProxy is Render with one operator proxy for this context. Keep
// the body in sync with Manager.Render (manager.go): same scope gate, same
// stored session, same User-Agent handling, same readiness/observation window,
// same state-changing policy (never allowed for a discovery render), same
// collected observations. TestRenderAndRenderThroughProxyAgree fails if they
// drift.
func (m *Manager) renderThroughProxy(ctx context.Context, url string, opts RenderOptions, proxy string) (*RenderResult, error) {
	if m == nil {
		return nil, errors.New("browser: nil manager (fail closed: no render was attempted)")
	}
	var extra map[string]string
	if strings.TrimSpace(opts.UserAgent) != "" {
		extra = map[string]string{"User-Agent": opts.UserAgent}
	}
	c, err := m.NewContext(ctx, ContextOptions{
		StorageStatePath: opts.SessionStatePath,
		AllowRequest:     opts.AllowRequest,
		ExtraHeaders:     extra,
		ProxyServer:      proxy,
		// Discovery rendering never opts into state-changing requests: the
		// browser is loading a page to observe it, not to write to the target.
		AllowStateChanging: false,
	})
	if err != nil {
		return nil, err
	}
	defer c.Close()

	page, err := c.NewPage(ctx)
	if err != nil {
		return nil, err
	}

	nav, err := page.Navigate(ctx, url, NavOptions{WaitUntil: opts.WaitUntil, Timeout: opts.Timeout, Limiter: opts.Limiter})
	if err != nil {
		return nil, err
	}

	html, err := page.Content(ctx)
	if err != nil {
		return nil, err
	}
	if opts.ObservationWindow > 0 {
		timer := time.NewTimer(opts.ObservationWindow)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
		}
	}

	res := &RenderResult{
		FinalURL:       nav.FinalURL,
		Status:         nav.Status,
		HTML:           html,
		PageErrors:     page.PageErrors(),
		DialogMessages: page.DialogMessages(),
		Network:        page.NetworkEvents(),
		Blocked:        page.BlockedRequests(),
	}
	for _, cm := range page.ConsoleMessages() {
		if cm.Type == "error" {
			res.ConsoleErrors = append(res.ConsoleErrors, cm.Text)
		} else {
			res.ConsoleLogs = append(res.ConsoleLogs, cm.Text)
		}
	}
	if opts.Screenshot {
		shot, err := page.Screenshot(ctx, ScreenshotOptions{})
		if err != nil {
			return nil, err
		}
		res.Screenshot = shot
	}
	return res, nil
}

// redactProxyCredentials removes a proxy URL's userinfo from an error message
// before it can reach a log or an evidence record. Operator proxies may carry
// credentials ("http://user:pass@proxy:8080"), and Playwright's own context
// error can echo the proxy URL; the scan's discovery error is logged, so the
// secret is stripped here rather than trusted not to be echoed.
//
// It rewrites only when the userinfo actually appears in the message and keeps
// the cause reachable (errors.Is/As still work) so callers that classify the
// error are unaffected.
func redactProxyCredentials(err error, proxy string) error {
	if err == nil {
		return nil
	}
	userinfo, ok := proxyUserinfo(proxy)
	if !ok {
		return err
	}
	secret := userinfo + "@"
	msg := err.Error()
	if !strings.Contains(msg, secret) {
		return err
	}
	return &redactedError{msg: strings.ReplaceAll(msg, secret, "***@"), cause: err}
}

type redactedError struct {
	msg   string
	cause error
}

func (e *redactedError) Error() string { return e.msg }
func (e *redactedError) Unwrap() error { return e.cause }

// proxyUserinfo extracts the raw userinfo of a proxy URL (the exact bytes an
// error message would echo), or reports that there is none.
func proxyUserinfo(proxy string) (string, bool) {
	if u, err := url.Parse(proxy); err == nil {
		if u.User == nil {
			return "", false
		}
		return u.User.String(), true
	}
	// Fall back to the raw form for a URL net/url cannot parse: only a "user@"
	// component is treated as a credential.
	i := strings.Index(proxy, "://")
	if i < 0 {
		return "", false
	}
	rest := proxy[i+3:]
	at := strings.LastIndex(rest, "@")
	if at <= 0 {
		return "", false
	}
	return rest[:at], true
}

// redactURL keeps a URL out of an error in a form that cannot leak credentials
// either (a render URL should never carry any, but the message is logged).
func redactURL(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		u.User = nil
		u.RawQuery = ""
		u.Fragment = ""
		return u.String()
	}
	return "the requested URL"
}

var _ Browser = (*proxyPoolBrowser)(nil)
