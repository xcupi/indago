package browser

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"
)

// Manager owns the browser engine lifecycle and a reusable pool of browsers, and
// hands out isolated contexts. It is safe for concurrent use and implements the
// Browser facade via Render.
type Manager struct {
	cfg Config
	log *slog.Logger
	drv driver

	mu       sync.Mutex
	browsers []browserHandle
	next     int
	contexts map[*Context]struct{}
	closed   bool

	// createMu serializes calls that create a new Playwright object (a context
	// or a page) against the underlying driver. Object creation registers new
	// event-handler state on the single shared connection/dispatch goroutine
	// Playwright uses per driver; concurrent creation calls from independent
	// goroutines (e.g. discovery's browser-network source and candidate
	// verification both use this same Manager at once) have been observed to
	// race inside that registration — not in Indago's own bookkeeping, which
	// is already guarded by mu. Operations on an already-created context/page
	// are not serialized here, only the moment of creation.
	createMu sync.Mutex
}

var _ Browser = (*Manager)(nil)

// NewManager starts the Playwright engine and launches the browser pool.
func NewManager(cfg Config, log *slog.Logger) (*Manager, error) {
	exe := cfg.ExecutablePath
	if exe == "" {
		exe = os.Getenv("INDAGO_CHROMIUM_PATH")
	}
	return newManager(cfg, log, func() (driver, error) { return newPlaywrightDriver(exe) })
}

// newManager is the injectable constructor used by tests.
func newManager(cfg Config, log *slog.Logger, factory newDriverFunc) (*Manager, error) {
	if log == nil {
		log = slog.Default()
	}
	cfg = cfg.withDefaults()

	drv, err := factory()
	if err != nil {
		return nil, fmt.Errorf("browser: start engine: %w", err)
	}

	m := &Manager{
		cfg:      cfg,
		log:      log,
		drv:      drv,
		contexts: make(map[*Context]struct{}),
	}
	for i := 0; i < cfg.PoolSize; i++ {
		b, err := drv.Launch(cfg.Headless)
		if err != nil {
			_ = m.Close() // tear down anything already launched
			return nil, fmt.Errorf("browser: launch: %w", err)
		}
		m.browsers = append(m.browsers, b)
	}
	m.log.Info("browser manager started", "pool", cfg.PoolSize, "headless", cfg.Headless)
	return m, nil
}

// pickBrowser returns the next pooled browser round-robin. Caller holds m.mu.
func (m *Manager) pickBrowserLocked() (browserHandle, error) {
	if m.closed {
		return nil, ErrClosed
	}
	if len(m.browsers) == 0 {
		return nil, ErrNoBrowser
	}
	b := m.browsers[m.next%len(m.browsers)]
	m.next++
	return b, nil
}

// NewContext creates an isolated context, optionally seeded with saved session
// material for a persistent authenticated context.
func (m *Manager) NewContext(ctx context.Context, opts ContextOptions) (*Context, error) {
	m.mu.Lock()
	b, err := m.pickBrowserLocked()
	m.mu.Unlock()
	if err != nil {
		return nil, err
	}

	ch, err := callCtxCreate(ctx, func() (contextHandle, error) {
		m.createMu.Lock()
		defer m.createMu.Unlock()
		return b.NewContext(opts.StorageStatePath, opts.AllowRequest)
	})
	if err != nil {
		return nil, fmt.Errorf("browser: new context: %w", err)
	}

	c := &Context{mgr: m, handle: ch, allow: opts.AllowRequest, pages: make(map[*Page]struct{})}

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		_ = ch.Close()
		return nil, ErrClosed
	}
	m.contexts[c] = struct{}{}
	m.mu.Unlock()
	return c, nil
}

// Stats returns a snapshot of pool resources.
func (m *Manager) Stats() PoolStats {
	m.mu.Lock()
	defer m.mu.Unlock()
	return PoolStats{Browsers: len(m.browsers), OpenContexts: len(m.contexts)}
}

// Close performs a graceful shutdown: it closes every open context, every pooled
// browser, then stops the engine. It is idempotent. The underlying calls are
// synchronous round-trips into the Playwright process with no cancellation of
// their own, so the whole sequence is bounded by cfg.ShutdownTimeout — a
// wedged driver/Chromium process would otherwise block Close (and so the
// whole program's graceful shutdown) forever.
func (m *Manager) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	contexts := make([]*Context, 0, len(m.contexts))
	for c := range m.contexts {
		contexts = append(contexts, c)
	}
	browsers := m.browsers
	m.browsers = nil
	m.contexts = make(map[*Context]struct{})
	m.mu.Unlock()

	var firstErr error
	note := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for _, c := range contexts {
			note(c.closeHandle())
		}
		for _, b := range browsers {
			note(b.Close())
		}
		note(m.drv.Stop())
	}()

	select {
	case <-done:
		m.log.Info("browser manager closed")
	case <-time.After(m.cfg.ShutdownTimeout):
		m.log.Warn("browser manager close timed out; abandoning an unresponsive driver/browser process",
			"timeout", m.cfg.ShutdownTimeout)
		firstErr = fmt.Errorf("browser: close timed out after %s", m.cfg.ShutdownTimeout)
	}
	return firstErr
}

// forget removes a context from tracking (called when a Context closes itself).
func (m *Manager) forget(c *Context) {
	m.mu.Lock()
	delete(m.contexts, c)
	m.mu.Unlock()
}

// Render implements the Browser facade: it opens a throwaway isolated context,
// loads the URL, gathers observations, and tears the context down.
func (m *Manager) Render(ctx context.Context, url string, opts RenderOptions) (*RenderResult, error) {
	c, err := m.NewContext(ctx, ContextOptions{StorageStatePath: opts.SessionStatePath, AllowRequest: opts.AllowRequest})
	if err != nil {
		return nil, err
	}
	defer c.Close()

	page, err := c.NewPage(ctx)
	if err != nil {
		return nil, err
	}

	nav, err := page.Navigate(ctx, url, NavOptions{WaitUntil: opts.WaitUntil, Timeout: opts.Timeout})
	if err != nil {
		return nil, err
	}

	html, err := page.Content(ctx)
	if err != nil {
		return nil, err
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

// InteractiveLogin launches a VISIBLE browser so the operator can authenticate
// (including MFA), waits for the success URL (or ctx/timeout), saves the session
// to StorageStatePath, and tears the browser down. The saved path can later seed
// a persistent authenticated context.
//
// This requires a display; on a headless host it will fail to launch — that is
// expected, as interactive login is an operator action.
func (m *Manager) InteractiveLogin(ctx context.Context, opts LoginOptions) (*LoginResult, error) {
	if opts.LoginURL == "" || opts.StorageStatePath == "" {
		return nil, fmt.Errorf("browser: interactive login requires LoginURL and StorageStatePath")
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}

	m.mu.Lock()
	closed := m.closed
	m.mu.Unlock()
	if closed {
		return nil, ErrClosed
	}

	// A dedicated, visible browser outside the (headless) pool.
	b, err := m.drv.Launch(false)
	if err != nil {
		return nil, fmt.Errorf("browser: launch visible: %w", err)
	}
	defer b.Close()

	ch, err := b.NewContext(opts.StorageStatePath, nil) // operator-driven login: no scope gate
	if err != nil {
		return nil, fmt.Errorf("browser: login context: %w", err)
	}
	defer ch.Close()

	ph, err := ch.NewPage()
	if err != nil {
		return nil, fmt.Errorf("browser: login page: %w", err)
	}

	if _, _, err := gotoWithCtx(ctx, ph, opts.LoginURL, WaitLoad, m.cfg.NavigationTimeout); err != nil {
		return nil, fmt.Errorf("browser: open login page: %w", err)
	}

	if opts.SuccessURLGlob != "" {
		if err := callCtxErr(ctx, func() error {
			return ph.WaitForURL(opts.SuccessURLGlob, timeout)
		}); err != nil {
			return nil, fmt.Errorf("browser: waiting for login success: %w", err)
		}
	}

	if err := ch.SaveStorageState(opts.StorageStatePath); err != nil {
		return nil, fmt.Errorf("browser: save session: %w", err)
	}
	// The saved state is the target's own auth cookies/tokens — sensitive
	// regardless of the process umask or Playwright's own default file mode,
	// so restrict it explicitly rather than trust either.
	if err := os.Chmod(opts.StorageStatePath, 0o600); err != nil {
		return nil, fmt.Errorf("browser: restrict session file permissions: %w", err)
	}
	_, finalURL, _ := ph.Goto(opts.LoginURL, WaitCommit, m.cfg.NavigationTimeout) // best-effort current URL
	return &LoginResult{StorageStatePath: opts.StorageStatePath, FinalURL: finalURL}, nil
}

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

// Context is an isolated browser context. Cookies and storage are not shared
// with other contexts.
type Context struct {
	mgr    *Manager
	handle contextHandle
	allow  func(url string) bool // scope gate (nil = allow all)

	mu     sync.Mutex
	pages  map[*Page]struct{}
	closed bool
}

// NewPage opens a new page in this context.
func (c *Context) NewPage(ctx context.Context) (*Page, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, ErrClosed
	}
	c.mu.Unlock()

	ph, err := callCtxCreate(ctx, func() (pageHandle, error) {
		c.mgr.createMu.Lock()
		defer c.mgr.createMu.Unlock()
		return c.handle.NewPage()
	})
	if err != nil {
		return nil, fmt.Errorf("browser: new page: %w", err)
	}
	p := newPage(c, ph)

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		_ = ph.Close()
		return nil, ErrClosed
	}
	c.pages[p] = struct{}{}
	c.mu.Unlock()
	return p, nil
}

// SetCookies adds cookies to the context.
func (c *Context) SetCookies(ctx context.Context, cookies []Cookie) error {
	return callCtxErr(ctx, func() error { return c.handle.AddCookies(cookies) })
}

// Cookies returns the context's cookies.
func (c *Context) Cookies(ctx context.Context) ([]Cookie, error) {
	return callCtx(ctx, func() ([]Cookie, error) { return c.handle.Cookies() })
}

// SaveStorageState persists cookies + localStorage to path for later reuse.
func (c *Context) SaveStorageState(ctx context.Context, path string) error {
	return callCtxErr(ctx, func() error { return c.handle.SaveStorageState(path) })
}

// Close closes the context and its pages and removes it from the Manager.
func (c *Context) Close() error {
	err := c.closeHandle()
	c.mgr.forget(c)
	return err
}

func (c *Context) closeHandle() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.pages = make(map[*Page]struct{})
	c.mu.Unlock()
	return c.handle.Close()
}

func (c *Context) forget(p *Page) {
	c.mu.Lock()
	delete(c.pages, p)
	c.mu.Unlock()
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

// Page is a single page within a context. It accumulates observed console
// messages, dialogs, and network events.
type Page struct {
	ctxp   *Context
	handle pageHandle

	mu       sync.Mutex
	console  []ConsoleMessage
	dialogs  []string
	pageErrs []string
	network  []NetworkEvent
	blocked  []string
	closed   bool
}

func newPage(c *Context, ph pageHandle) *Page {
	p := &Page{ctxp: c, handle: ph}
	ph.OnConsole(func(m ConsoleMessage) {
		p.mu.Lock()
		p.console = append(p.console, m)
		p.mu.Unlock()
	})
	ph.OnDialog(func(msg string) {
		p.mu.Lock()
		p.dialogs = append(p.dialogs, msg)
		p.mu.Unlock()
	})
	ph.OnPageError(func(msg string) {
		p.mu.Lock()
		p.pageErrs = append(p.pageErrs, msg)
		p.mu.Unlock()
	})
	ph.OnRequest(func(ev NetworkEvent) {
		p.mu.Lock()
		defer p.mu.Unlock()
		// Scope the observation itself, independent of the driver: a disallowed
		// request is recorded as blocked and never as a network observation, so
		// nothing out of scope can flow on to be persisted or enqueued.
		if c.allow != nil && isNetworkURL(ev.URL) && !c.allow(ev.URL) {
			p.blocked = append(p.blocked, ev.URL)
			return
		}
		p.network = append(p.network, ev)
	})
	return p
}

// Navigate loads url with the given options.
func (p *Page) Navigate(ctx context.Context, url string, opts NavOptions) (*NavResult, error) {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = p.ctxp.mgr.cfg.NavigationTimeout
	}
	wait := opts.WaitUntil
	if wait == "" {
		wait = WaitLoad
	}
	status, finalURL, err := gotoWithCtx(ctx, p.handle, url, wait, timeout)
	if err != nil {
		return nil, fmt.Errorf("browser: navigate: %w", err)
	}
	return &NavResult{Status: status, FinalURL: finalURL}, nil
}

// Content returns the current page HTML.
func (p *Page) Content(ctx context.Context) (string, error) {
	return callCtx(ctx, func() (string, error) { return p.handle.Content() })
}

// Screenshot captures a PNG screenshot.
func (p *Page) Screenshot(ctx context.Context, opts ScreenshotOptions) ([]byte, error) {
	return callCtx(ctx, func() ([]byte, error) { return p.handle.Screenshot(opts.FullPage) })
}

// LocalStorage returns the page's localStorage as a map.
func (p *Page) LocalStorage(ctx context.Context) (map[string]string, error) {
	return p.readStorage(ctx, "localStorage")
}

// SessionStorage returns the page's sessionStorage as a map.
func (p *Page) SessionStorage(ctx context.Context) (map[string]string, error) {
	return p.readStorage(ctx, "sessionStorage")
}

// SetLocalStorage sets a localStorage key.
func (p *Page) SetLocalStorage(ctx context.Context, key, value string) error {
	return p.writeStorage(ctx, "localStorage", key, value)
}

// SetSessionStorage sets a sessionStorage key.
func (p *Page) SetSessionStorage(ctx context.Context, key, value string) error {
	return p.writeStorage(ctx, "sessionStorage", key, value)
}

func (p *Page) readStorage(ctx context.Context, store string) (map[string]string, error) {
	script := fmt.Sprintf(
		`() => { const s = %s; const o = {}; for (let i=0;i<s.length;i++){const k=s.key(i); o[k]=s.getItem(k);} return JSON.stringify(o); }`,
		store)
	raw, err := callCtx(ctx, func() (any, error) { return p.handle.Evaluate(script, nil) })
	if err != nil {
		return nil, fmt.Errorf("browser: read %s: %w", store, err)
	}
	s, _ := raw.(string)
	if s == "" {
		return map[string]string{}, nil
	}
	out := map[string]string{}
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil, fmt.Errorf("browser: parse %s: %w", store, err)
	}
	return out, nil
}

func (p *Page) writeStorage(ctx context.Context, store, key, value string) error {
	script := fmt.Sprintf(`(kv) => { %s.setItem(kv.k, kv.v); }`, store)
	return callCtxErr(ctx, func() error {
		_, err := p.handle.Evaluate(script, map[string]string{"k": key, "v": value})
		return err
	})
}

// BlockedRequests returns a copy of the requests the scope gate refused.
func (p *Page) BlockedRequests() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.blocked...)
}

// isNetworkURL reports whether u is an http(s) URL (data:, blob:, about: never
// leave the browser and are not subject to the scope gate).
func isNetworkURL(u string) bool {
	return strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://")
}

// ConsoleMessages returns a copy of observed console messages.
func (p *Page) ConsoleMessages() []ConsoleMessage {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]ConsoleMessage(nil), p.console...)
}

// DialogMessages returns a copy of observed dialog messages.
func (p *Page) DialogMessages() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.dialogs...)
}

// PageErrors returns a copy of observed uncaught-exception messages.
func (p *Page) PageErrors() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.pageErrs...)
}

// NetworkEvents returns a copy of observed network requests.
func (p *Page) NetworkEvents() []NetworkEvent {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]NetworkEvent(nil), p.network...)
}

// Close closes the page.
func (p *Page) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	p.mu.Unlock()
	p.ctxp.forget(p)
	return p.handle.Close()
}

// ---------------------------------------------------------------------------
// cancellation helpers
// ---------------------------------------------------------------------------

// callCtx runs fn in a goroutine and returns early if ctx is canceled. The
// underlying driver call still carries its own timeout so it cannot run forever.
func callCtx[T any](ctx context.Context, fn func() (T, error)) (T, error) {
	var zero T
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	type result struct {
		v   T
		err error
	}
	ch := make(chan result, 1)
	go func() {
		v, err := fn()
		ch <- result{v, err}
	}()
	select {
	case <-ctx.Done():
		return zero, ctx.Err()
	case r := <-ch:
		return r.v, r.err
	}
}

func callCtxErr(ctx context.Context, fn func() error) error {
	_, err := callCtx(ctx, func() (struct{}, error) { return struct{}{}, fn() })
	return err
}

// callCtxCreate is callCtx specialized for calls that create a closeable
// browser resource (a context or a page). Plain callCtx would, on the
// ctx-wins-the-race path, simply discard whatever fn() goes on to produce —
// if fn() was in fact about to succeed, that resource was already created in
// the real browser process and nothing would ever close it, leaking it for
// the Manager's lifetime. Here, losing the race still waits for fn() in the
// background and closes anything it produced.
func callCtxCreate[T interface{ Close() error }](ctx context.Context, fn func() (T, error)) (T, error) {
	var zero T
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	type result struct {
		v   T
		err error
	}
	ch := make(chan result, 1)
	go func() {
		v, err := fn()
		ch <- result{v, err}
	}()
	select {
	case <-ctx.Done():
		go func() {
			if r := <-ch; r.err == nil {
				_ = r.v.Close()
			}
		}()
		return zero, ctx.Err()
	case r := <-ch:
		return r.v, r.err
	}
}

func gotoWithCtx(ctx context.Context, ph pageHandle, url, wait string, timeout time.Duration) (int, string, error) {
	type nav struct {
		status   int
		finalURL string
	}
	r, err := callCtx(ctx, func() (nav, error) {
		s, u, err := ph.Goto(url, wait, timeout)
		return nav{s, u}, err
	})
	return r.status, r.finalURL, err
}
