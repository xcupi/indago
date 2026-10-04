package browser

// White-box tests: they exercise the Manager against a fake driver so lifecycle,
// pooling, context isolation, cancellation, and cleanup are verified without
// launching a real browser.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// --- fake driver ---

type fakeDriver struct {
	mu        sync.Mutex
	launched  int
	stopped   bool
	browsers  []*fakeBrowser
	failAfter int           // if >0, Launch fails once this many have launched
	gotoDelay time.Duration // navigation delay, for cancellation tests
}

func fakeFactory(d *fakeDriver) newDriverFunc {
	return func() (driver, error) { return d, nil }
}

func (d *fakeDriver) Launch(headless bool) (browserHandle, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.stopped {
		return nil, errors.New("driver stopped")
	}
	if d.failAfter > 0 && d.launched >= d.failAfter {
		return nil, errors.New("launch failed")
	}
	b := &fakeBrowser{drv: d, headless: headless}
	d.launched++
	d.browsers = append(d.browsers, b)
	return b, nil
}

func (d *fakeDriver) Stop() error {
	d.mu.Lock()
	d.stopped = true
	d.mu.Unlock()
	return nil
}

func (d *fakeDriver) isStopped() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.stopped
}

func (d *fakeDriver) sawHeadful() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, b := range d.browsers {
		if !b.headless {
			return true
		}
	}
	return false
}

type fakeBrowser struct {
	drv      *fakeDriver
	headless bool
	mu       sync.Mutex
	closed   bool
	contexts []*fakeContext
}

func (b *fakeBrowser) NewContext(storageStatePath string, allow func(string) bool) (contextHandle, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil, errors.New("browser closed")
	}
	c := &fakeContext{br: b, gated: allow != nil, storagePath: storageStatePath, cookies: map[string]Cookie{}, gotoDelay: b.drv.gotoDelay}
	b.contexts = append(b.contexts, c)
	return c, nil
}

func (b *fakeBrowser) Close() error {
	b.mu.Lock()
	b.closed = true
	b.mu.Unlock()
	return nil
}

func (b *fakeBrowser) isClosed() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.closed
}

func (b *fakeBrowser) contextCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.contexts)
}

func (b *fakeBrowser) openContexts() int {
	b.mu.Lock()
	cs := append([]*fakeContext(nil), b.contexts...)
	b.mu.Unlock()
	n := 0
	for _, c := range cs {
		if !c.isClosed() {
			n++
		}
	}
	return n
}

type fakeContext struct {
	gated       bool
	br          *fakeBrowser
	storagePath string
	savedPath   string
	gotoDelay   time.Duration
	mu          sync.Mutex
	closed      bool
	cookies     map[string]Cookie
}

func (c *fakeContext) NewPage() (pageHandle, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, errors.New("context closed")
	}
	return &fakePage{ctx: c, gotoDelay: c.gotoDelay, localStorage: map[string]string{}}, nil
}

func (c *fakeContext) AddCookies(cookies []Cookie) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, ck := range cookies {
		c.cookies[ck.Name] = ck
	}
	return nil
}

func (c *fakeContext) Cookies() ([]Cookie, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Cookie, 0, len(c.cookies))
	for _, ck := range c.cookies {
		out = append(out, ck)
	}
	return out, nil
}

func (c *fakeContext) SaveStorageState(path string) error {
	c.mu.Lock()
	c.savedPath = path
	c.mu.Unlock()
	return nil
}

func (c *fakeContext) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return nil
}

func (c *fakeContext) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

type fakePage struct {
	ctx          *fakeContext
	gotoDelay    time.Duration
	mu           sync.Mutex
	closed       bool
	reqFn        func(NetworkEvent)
	conFn        func(ConsoleMessage)
	dlgFn        func(string)
	errFn        func(string)
	localStorage map[string]string
}

func (p *fakePage) Goto(url, waitUntil string, timeout time.Duration) (int, string, error) {
	if p.gotoDelay > 0 {
		time.Sleep(p.gotoDelay)
	}
	if p.reqFn != nil {
		p.reqFn(NetworkEvent{URL: url, Method: "GET", ResourceType: "document", At: time.Now()})
	}
	if p.conFn != nil {
		p.conFn(ConsoleMessage{Type: "log", Text: "hello"})
	}
	if p.dlgFn != nil {
		p.dlgFn("a dialog")
	}
	if p.errFn != nil {
		p.errFn("ReferenceError: fake is not defined")
	}
	return 200, url, nil
}

func (p *fakePage) Content() (string, error)        { return "<html>fake</html>", nil }
func (p *fakePage) Screenshot(bool) ([]byte, error) { return []byte("\x89PNG-fake"), nil }

func (p *fakePage) Evaluate(script string, arg any) (any, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if strings.Contains(script, "setItem") {
		if kv, ok := arg.(map[string]string); ok {
			p.localStorage[kv["k"]] = kv["v"]
		}
		return nil, nil
	}
	b, _ := json.Marshal(p.localStorage)
	return string(b), nil
}

func (p *fakePage) OnRequest(fn func(NetworkEvent))   { p.reqFn = fn }
func (p *fakePage) OnConsole(fn func(ConsoleMessage)) { p.conFn = fn }
func (p *fakePage) OnDialog(fn func(string))          { p.dlgFn = fn }
func (p *fakePage) OnPageError(fn func(string))       { p.errFn = fn }

func (p *fakePage) WaitForURL(glob string, timeout time.Duration) error {
	if p.gotoDelay > 0 {
		time.Sleep(p.gotoDelay)
	}
	return nil
}

func (p *fakePage) Close() error {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
	return nil
}

// --- tests ---

func newFakeManager(t *testing.T, cfg Config, d *fakeDriver) *Manager {
	t.Helper()
	m, err := newManager(cfg, quiet(), fakeFactory(d))
	if err != nil {
		t.Fatalf("newManager: %v", err)
	}
	return m
}

func TestManagerLifecycle(t *testing.T) {
	d := &fakeDriver{}
	m := newFakeManager(t, Config{PoolSize: 2}, d)

	if d.launched != 2 {
		t.Fatalf("launched = %d, want 2", d.launched)
	}
	if st := m.Stats(); st.Browsers != 2 {
		t.Fatalf("stats browsers = %d", st.Browsers)
	}

	if err := m.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if !d.isStopped() {
		t.Fatal("driver not stopped after Close")
	}
	for i, b := range d.browsers {
		if !b.isClosed() {
			t.Fatalf("browser %d not closed", i)
		}
	}
	// Idempotent.
	if err := m.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	// Use after close.
	if _, err := m.NewContext(context.Background(), ContextOptions{}); !errors.Is(err, ErrClosed) {
		t.Fatalf("expected ErrClosed, got %v", err)
	}
}

func TestLaunchFailureCleansUp(t *testing.T) {
	d := &fakeDriver{failAfter: 1} // second launch fails
	_, err := newManager(Config{PoolSize: 3}, quiet(), fakeFactory(d))
	if err == nil {
		t.Fatal("expected launch failure")
	}
	if !d.isStopped() {
		t.Fatal("engine should be stopped after failed startup")
	}
	if len(d.browsers) != 1 || !d.browsers[0].isClosed() {
		t.Fatalf("the one launched browser should be closed on cleanup")
	}
}

func TestContextIsolation(t *testing.T) {
	d := &fakeDriver{}
	m := newFakeManager(t, Config{PoolSize: 1}, d)
	defer m.Close()
	ctx := context.Background()

	cA, err := m.NewContext(ctx, ContextOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cB, err := m.NewContext(ctx, ContextOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if err := cA.SetCookies(ctx, []Cookie{{Name: "sid", Value: "secret", URL: "https://x/"}}); err != nil {
		t.Fatal(err)
	}

	aCookies, _ := cA.Cookies(ctx)
	bCookies, _ := cB.Cookies(ctx)
	if len(aCookies) != 1 || aCookies[0].Value != "secret" {
		t.Fatalf("context A should have the cookie: %v", aCookies)
	}
	if len(bCookies) != 0 {
		t.Fatalf("context B must not see A's cookie (isolation broken): %v", bCookies)
	}
}

func TestContextCancellation(t *testing.T) {
	d := &fakeDriver{gotoDelay: 500 * time.Millisecond}
	m := newFakeManager(t, Config{PoolSize: 1}, d)
	defer m.Close()

	c, err := m.NewContext(context.Background(), ContextOptions{})
	if err != nil {
		t.Fatal(err)
	}
	p, err := c.NewPage(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// Navigation that outlasts the context deadline must return promptly.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = p.Navigate(ctx, "https://slow/", NavOptions{})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected DeadlineExceeded, got %v", err)
	}
	if time.Since(start) > 300*time.Millisecond {
		t.Fatalf("cancellation was not prompt: took %s", time.Since(start))
	}

	// Pre-canceled context returns immediately.
	cctx, ccancel := context.WithCancel(context.Background())
	ccancel()
	if _, err := p.Navigate(cctx, "https://x/", NavOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected Canceled, got %v", err)
	}
}

func TestCleanupClosesContexts(t *testing.T) {
	d := &fakeDriver{}
	m := newFakeManager(t, Config{PoolSize: 1}, d)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		c, err := m.NewContext(ctx, ContextOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.NewPage(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if st := m.Stats(); st.OpenContexts != 3 {
		t.Fatalf("open contexts = %d, want 3", st.OpenContexts)
	}

	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if d.browsers[0].openContexts() != 0 {
		t.Fatalf("contexts not cleaned up: %d still open", d.browsers[0].openContexts())
	}
}

func TestContextCloseUntracks(t *testing.T) {
	d := &fakeDriver{}
	m := newFakeManager(t, Config{PoolSize: 1}, d)
	defer m.Close()
	ctx := context.Background()

	c, err := m.NewContext(ctx, ContextOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if m.Stats().OpenContexts != 1 {
		t.Fatal("expected 1 open context")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if m.Stats().OpenContexts != 0 {
		t.Fatalf("context not untracked after Close: %d", m.Stats().OpenContexts)
	}
	if !d.browsers[0].contexts[0].isClosed() {
		t.Fatal("underlying context handle not closed")
	}
}

func TestPoolRoundRobinReuse(t *testing.T) {
	d := &fakeDriver{}
	m := newFakeManager(t, Config{PoolSize: 2}, d)
	defer m.Close()
	ctx := context.Background()

	for i := 0; i < 4; i++ {
		if _, err := m.NewContext(ctx, ContextOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	// Each of the 2 pooled browsers should have received 2 contexts.
	for i, b := range d.browsers {
		if b.contextCount() != 2 {
			t.Fatalf("browser %d got %d contexts, want 2 (round-robin reuse)", i, b.contextCount())
		}
	}
}

func TestRenderGathersObservations(t *testing.T) {
	d := &fakeDriver{}
	m := newFakeManager(t, Config{PoolSize: 1}, d)
	defer m.Close()

	res, err := m.Render(context.Background(), "https://target/page", RenderOptions{Screenshot: true})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if res.Status != 200 || res.HTML != "<html>fake</html>" || res.FinalURL != "https://target/page" {
		t.Fatalf("render basics wrong: %+v", res)
	}
	if len(res.Screenshot) == 0 {
		t.Fatal("expected screenshot bytes")
	}
	if len(res.Network) != 1 || res.Network[0].Method != "GET" {
		t.Fatalf("network not observed: %v", res.Network)
	}
	if len(res.ConsoleLogs) != 1 || res.ConsoleLogs[0] != "hello" {
		t.Fatalf("console not observed: %v", res.ConsoleLogs)
	}
	if len(res.DialogMessages) != 1 || res.DialogMessages[0] != "a dialog" {
		t.Fatalf("dialog not observed: %v", res.DialogMessages)
	}
	if len(res.PageErrors) != 1 || res.PageErrors[0] != "ReferenceError: fake is not defined" {
		t.Fatalf("page error not observed: %v", res.PageErrors)
	}
	// The throwaway context must be cleaned up.
	if st := m.Stats(); st.OpenContexts != 0 {
		t.Fatalf("render left %d contexts open", st.OpenContexts)
	}
}

func TestStorageAccess(t *testing.T) {
	d := &fakeDriver{}
	m := newFakeManager(t, Config{PoolSize: 1}, d)
	defer m.Close()
	ctx := context.Background()

	c, _ := m.NewContext(ctx, ContextOptions{})
	p, _ := c.NewPage(ctx)

	if err := p.SetLocalStorage(ctx, "token", "abc"); err != nil {
		t.Fatal(err)
	}
	ls, err := p.LocalStorage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ls["token"] != "abc" {
		t.Fatalf("localStorage round-trip failed: %v", ls)
	}
}

func TestPersistentContextSeed(t *testing.T) {
	d := &fakeDriver{}
	m := newFakeManager(t, Config{PoolSize: 1}, d)
	defer m.Close()

	_, err := m.NewContext(context.Background(), ContextOptions{StorageStatePath: "/tmp/session.json"})
	if err != nil {
		t.Fatal(err)
	}
	if got := d.browsers[0].contexts[0].storagePath; got != "/tmp/session.json" {
		t.Fatalf("storage state path not propagated: %q", got)
	}
}

func TestInteractiveLogin(t *testing.T) {
	d := &fakeDriver{}
	m := newFakeManager(t, Config{PoolSize: 1, Headless: true}, d)
	defer m.Close()

	res, err := m.InteractiveLogin(context.Background(), LoginOptions{
		LoginURL:         "https://app/login",
		SuccessURLGlob:   "**/dashboard",
		StorageStatePath: "/tmp/auth.json",
		Timeout:          time.Second,
	})
	if err != nil {
		t.Fatalf("interactive login: %v", err)
	}
	if res.StorageStatePath != "/tmp/auth.json" {
		t.Fatalf("result path = %q", res.StorageStatePath)
	}
	// A visible (headful) browser must have been launched for the operator.
	if !d.sawHeadful() {
		t.Fatal("interactive login should launch a visible browser")
	}
}

func TestInteractiveLoginValidation(t *testing.T) {
	d := &fakeDriver{}
	m := newFakeManager(t, Config{PoolSize: 1}, d)
	defer m.Close()
	if _, err := m.InteractiveLogin(context.Background(), LoginOptions{}); err == nil {
		t.Fatal("expected validation error for missing LoginURL/StorageStatePath")
	}
}

func TestStubUnchanged(t *testing.T) {
	_, err := Stub{}.Render(context.Background(), "https://x/", RenderOptions{})
	if !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("stub: expected ErrNotImplemented, got %v", err)
	}
}

// An observation that fails the scope gate is recorded as blocked and never as a
// network observation, regardless of what the driver reports.
func TestScopeGateFiltersObservations(t *testing.T) {
	d := &fakeDriver{}
	m := newFakeManager(t, Config{PoolSize: 1}, d)
	defer m.Close()

	allow := func(u string) bool { return strings.HasPrefix(u, "https://in.example/") }
	res, err := m.Render(context.Background(), "https://out.example/page", RenderOptions{AllowRequest: allow})
	if err != nil {
		t.Fatal(err)
	}
	// The fake emits one request event for the navigation URL (out of scope here).
	if len(res.Network) != 0 {
		t.Fatalf("out-of-scope request leaked into observations: %v", res.Network)
	}
	if len(res.Blocked) != 1 || res.Blocked[0] != "https://out.example/page" {
		t.Fatalf("blocked = %v", res.Blocked)
	}

	res, err = m.Render(context.Background(), "https://in.example/page", RenderOptions{AllowRequest: allow})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Network) != 1 || len(res.Blocked) != 0 {
		t.Fatalf("in-scope request should be observed: net=%v blocked=%v", res.Network, res.Blocked)
	}

	// No gate: everything is observed (the caller owns scope).
	res, _ = m.Render(context.Background(), "https://out.example/page", RenderOptions{})
	if len(res.Network) != 1 {
		t.Fatalf("without a gate the observation should be kept: %v", res.Network)
	}
}

// The gate is handed to the driver so a real browser can abort the request.
func TestScopeGatePassedToDriver(t *testing.T) {
	d := &fakeDriver{}
	m := newFakeManager(t, Config{PoolSize: 1}, d)
	defer m.Close()
	if _, err := m.NewContext(context.Background(), ContextOptions{AllowRequest: func(string) bool { return false }}); err != nil {
		t.Fatal(err)
	}
	if !d.browsers[0].contexts[0].gated {
		t.Fatal("the scope gate was not passed to the driver")
	}
}
