package browser

// White-box tests: they exercise the Manager against a fake driver so lifecycle,
// pooling, context isolation, cancellation, and cleanup are verified without
// launching a real browser.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// --- fake driver ---

type fakeDriver struct {
	mu          sync.Mutex
	launched    int
	stopped     bool
	browsers    []*fakeBrowser
	failAfter   int           // if >0, Launch fails once this many have launched
	gotoDelay   time.Duration // navigation delay, for cancellation tests
	createDelay time.Duration // NewContext/NewPage delay, for cancellation-race tests
	hangStop    chan struct{} // if non-nil, Stop blocks on this channel (never closed = wedged driver)
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
	if d.hangStop != nil {
		<-d.hangStop
	}
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

func (b *fakeBrowser) NewContext(storageStatePath, proxyServer string, extraHeaders map[string]string, allow func(string) bool) (contextHandle, error) {
	if b.drv.createDelay > 0 {
		time.Sleep(b.drv.createDelay)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil, errors.New("browser closed")
	}
	c := &fakeContext{br: b, gated: allow != nil, storagePath: storageStatePath, proxyServer: proxyServer, extraHeaders: extraHeaders, cookies: map[string]Cookie{}, gotoDelay: b.drv.gotoDelay}
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
	gated        bool
	br           *fakeBrowser
	storagePath  string
	proxyServer  string
	extraHeaders map[string]string
	savedPath    string
	gotoDelay    time.Duration
	mu           sync.Mutex
	closed       bool
	cookies      map[string]Cookie
	pages        []*fakePage
}

func (c *fakeContext) NewPage() (pageHandle, error) {
	if c.br.drv.createDelay > 0 {
		time.Sleep(c.br.drv.createDelay)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, errors.New("context closed")
	}
	p := &fakePage{ctx: c, gotoDelay: c.gotoDelay, localStorage: map[string]string{}}
	c.pages = append(c.pages, p)
	return p, nil
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
	// Real Playwright writes an actual file here; match that so callers that
	// touch the file afterward (e.g. restricting its permissions) see one.
	return os.WriteFile(path, []byte(`{"cookies":[]}`), 0o644)
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
	initScripts  []string
	lastReferer  string // records the referer passed to the most recent Goto, for TestNavigateThreadsRefererToGoto
}

func (p *fakePage) Goto(url, referer, waitUntil string, timeout time.Duration) (int, string, error) {
	if p.gotoDelay > 0 {
		time.Sleep(p.gotoDelay)
	}
	p.mu.Lock()
	p.lastReferer = referer
	p.mu.Unlock()
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
		// Real playwright-go's own serializer requires map[string]any for a
		// composite argument (a map[string]string panics there — see
		// Manager.AutoLogin/writeStorage) — accept the same shape here so
		// this fake's contract matches the real driver's, not a looser one.
		if kv, ok := arg.(map[string]any); ok {
			k, _ := kv["k"].(string)
			v, _ := kv["v"].(string)
			p.localStorage[k] = v
		}
		return nil, nil
	}
	b, _ := json.Marshal(p.localStorage)
	return string(b), nil
}

func (p *fakePage) OnRequest(fn func(NetworkEvent), _ func(string) bool) error {
	p.reqFn = fn
	return nil
}
func (p *fakePage) OnConsole(fn func(ConsoleMessage))                       { p.conFn = fn }
func (p *fakePage) OnDialog(fn func(string))                                { p.dlgFn = fn }
func (p *fakePage) OnPageError(fn func(string))                             { p.errFn = fn }
func (p *fakePage) EnableRuntimeProvenance(marker, initScript string) error { return nil }
func (p *fakePage) RuntimeObservations() RuntimeObservations                { return RuntimeObservations{} }

func (p *fakePage) WaitForURL(glob string, timeout time.Duration) error {
	if p.gotoDelay > 0 {
		time.Sleep(p.gotoDelay)
	}
	return nil
}

// AddInitScript records the script (order preserved) so a test can assert
// it was installed, and — critically — installed BEFORE Navigate/Goto was
// called (see TestAddInitScriptInstalledBeforeNavigate).
func (p *fakePage) AddInitScript(script string) error {
	p.mu.Lock()
	p.initScripts = append(p.initScripts, script)
	p.mu.Unlock()
	return nil
}

func (p *fakePage) InitScripts() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.initScripts...)
}

func (p *fakePage) Close() error {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
	return nil
}

func (p *fakePage) isClosed() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closed
}

func (p *fakePage) Referer() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastReferer
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

func TestShouldCaptureJSONRequestBodyRequiresBoundedInScopeSize(t *testing.T) {
	allowInScope := func(raw string) bool { return raw == "http://in-scope.test/api" }
	for _, tc := range []struct {
		name, method, contentType, url string
		bodySize                       int
		want                           bool
	}{
		{"bounded vendor JSON", "POST", "application/vnd.api+json; charset=utf-8", "http://in-scope.test/api", 65536, true},
		{"missing size", "POST", "application/json", "http://in-scope.test/api", -1, false},
		{"oversize", "POST", "application/json", "http://in-scope.test/api", 65537, false},
		{"zero size", "POST", "application/json", "http://in-scope.test/api", 0, false},
		{"out of scope", "POST", "application/json", "https://outside.test/api", 8, false},
		{"safe method", "GET", "application/json", "http://in-scope.test/api", 8, false},
		{"options has no JSON body discovery", "OPTIONS", "application/json", "http://in-scope.test/api", 8, false},
		{"non-JSON type", "POST", "text/plain", "http://in-scope.test/api", 8, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldCaptureJSONRequestBody(tc.method, tc.contentType, tc.bodySize, tc.url, allowInScope); got != tc.want {
				t.Fatalf("shouldCaptureJSONRequestBody() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCDPNetworkEventCapturesBoundedScopedJSONBody(t *testing.T) {
	body := `{"query":"safe-marker","page":2}`
	allow := func(raw string) bool { return strings.HasPrefix(raw, "http://in-scope.test/") }
	requestEvent := func(rawURL, contentType, postData string) map[string]interface{} {
		return map[string]interface{}{
			"type": "Fetch",
			"request": map[string]interface{}{
				"url": rawURL, "method": "POST", "headers": map[string]interface{}{"Content-Type": contentType}, "postData": postData,
			},
		}
	}

	got, observedBodyBytes, ok := networkEventFromCDP(requestEvent("http://in-scope.test/api", "application/vnd.api+json", body), allow, true, 256<<10)
	if !ok || observedBodyBytes != len(body) || got.Method != "POST" || got.ResourceType != "fetch" || got.PostData != body {
		t.Fatalf("in-scope JSON event = %#v, ok=%v", got, ok)
	}
	budgeted, observedBodyBytes, ok := networkEventFromCDP(requestEvent("http://in-scope.test/api", "application/json", body), allow, true, len(body)-1)
	if !ok || observedBodyBytes != len(body) || budgeted.PostData != "" {
		t.Fatalf("body exceeded remaining aggregate budget: %#v, ok=%v", budgeted, ok)
	}
	metadataOnly, observedBodyBytes, ok := networkEventFromCDP(requestEvent("http://in-scope.test/api", "application/json", body), allow, false, 256<<10)
	if !ok || observedBodyBytes != 0 || metadataOnly.PostData != "" {
		t.Fatalf("body retained after capture budget was exhausted: %#v, ok=%v", metadataOnly, ok)
	}
	exactLimit := `"` + strings.Repeat("x", maxCapturedJSONPostDataBytes-2) + `"`
	atLimit, observedBodyBytes, ok := networkEventFromCDP(requestEvent("http://in-scope.test/api", "application/json", exactLimit), allow, true, 256<<10)
	if !ok || observedBodyBytes != maxCapturedJSONPostDataBytes || len(atLimit.PostData) != maxCapturedJSONPostDataBytes {
		t.Fatalf("request body at cap was not retained: size=%d ok=%v", len(atLimit.PostData), ok)
	}
	outOfScope, observedBodyBytes, ok := networkEventFromCDP(requestEvent("https://outside.test/api", "application/json", body), allow, true, 256<<10)
	if !ok || observedBodyBytes != 0 || outOfScope.PostData != "" {
		t.Fatalf("out-of-scope request body was captured: %#v, ok=%v", outOfScope, ok)
	}
	oversize, observedBodyBytes, ok := networkEventFromCDP(requestEvent("http://in-scope.test/api", "application/json", strings.Repeat("x", maxCapturedJSONPostDataBytes+1)), allow, true, 256<<10)
	if !ok || observedBodyBytes != maxCapturedJSONPostDataBytes+1 || oversize.PostData != "" {
		t.Fatalf("oversize request body was captured: len=%d ok=%v", len(oversize.PostData), ok)
	}
}

func TestPageNetworkJSONBodyRetentionBudgetPreservesRequestMetadata(t *testing.T) {
	fake := &fakePage{}
	page, err := newPage(&Context{}, fake)
	if err != nil {
		t.Fatal(err)
	}
	body := `"` + strings.Repeat("x", (64<<10)-2) + `"`
	for i := 0; i < 5; i++ {
		fake.reqFn(NetworkEvent{
			URL: fmt.Sprintf("http://in-scope.test/api/%d", i), Method: "POST",
			ResourceType: "fetch", ContentType: "application/json", PostData: body,
		})
	}
	events := page.NetworkEvents()
	if len(events) != 5 {
		t.Fatalf("retained %d request events, want all 5 metadata records", len(events))
	}
	for i := 0; i < 4; i++ {
		if len(events[i].PostData) != 64<<10 {
			t.Fatalf("body %d retained %d bytes, want 64 KiB", i, len(events[i].PostData))
		}
	}
	if events[4].PostData != "" || events[4].URL != "http://in-scope.test/api/4" {
		t.Fatalf("over-budget request should retain metadata but drop body: %#v", events[4])
	}

	countFake := &fakePage{}
	countPage, err := newPage(&Context{}, countFake)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxObservedJSONBodyEventsPerPage+1; i++ {
		countFake.reqFn(NetworkEvent{URL: fmt.Sprintf("http://in-scope.test/small/%d", i), Method: "POST", ContentType: "application/json", PostData: `{"q":1}`})
	}
	countEvents := countPage.NetworkEvents()
	if len(countEvents) != maxObservedJSONBodyEventsPerPage+1 || countEvents[len(countEvents)-1].PostData != "" {
		t.Fatalf("event-count budget did not preserve metadata and drop the excess body: len=%d last=%#v", len(countEvents), countEvents[len(countEvents)-1])
	}
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

// ContextOptions.ExtraHeaders must reach the underlying browser context at
// creation time — this is how a Header-location candidate's override
// (User-Agent, Referer, X-Forwarded-For, …) reaches the verifying browser
// BEFORE navigation (see verification.Input.ExtraHeaders and
// BrowserVerifier.Verify).
func TestExtraHeadersPropagateToContext(t *testing.T) {
	d := &fakeDriver{}
	m := newFakeManager(t, Config{PoolSize: 1}, d)
	defer m.Close()

	headers := map[string]string{"User-Agent": "candidate-marker"}
	_, err := m.NewContext(context.Background(), ContextOptions{ExtraHeaders: headers})
	if err != nil {
		t.Fatal(err)
	}
	got := d.browsers[0].contexts[0].extraHeaders
	if len(got) != 1 || got["User-Agent"] != "candidate-marker" {
		t.Fatalf("extra headers not propagated: %+v", got)
	}
}

// Context.SetCookies (used for a Cookie-location candidate's override — see
// verification.Input.ExtraCookies and BrowserVerifier.Verify) reaches the
// underlying browser context.
func TestSetCookiesReachesContext(t *testing.T) {
	d := &fakeDriver{}
	m := newFakeManager(t, Config{PoolSize: 1}, d)
	defer m.Close()

	c, err := m.NewContext(context.Background(), ContextOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.SetCookies(context.Background(), []Cookie{{Name: "pref", Value: "candidate-marker", URL: "http://example.com/s"}}); err != nil {
		t.Fatal(err)
	}
	cks, err := c.Cookies(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, ck := range cks {
		if ck.Name == "pref" && ck.Value == "candidate-marker" {
			found = true
		}
	}
	if !found {
		t.Fatalf("cookie override did not reach the context: %+v", cks)
	}
}

func TestInteractiveLogin(t *testing.T) {
	d := &fakeDriver{}
	m := newFakeManager(t, Config{PoolSize: 1, Headless: true}, d)
	defer m.Close()

	statePath := filepath.Join(t.TempDir(), "auth.json")
	res, err := m.InteractiveLogin(context.Background(), LoginOptions{
		LoginURL:         "https://app/login",
		SuccessURLGlob:   "**/dashboard",
		StorageStatePath: statePath,
		Timeout:          time.Second,
	})
	if err != nil {
		t.Fatalf("interactive login: %v", err)
	}
	if res.StorageStatePath != statePath {
		t.Fatalf("result path = %q", res.StorageStatePath)
	}
	// The saved state is the target's own auth cookies — must not be left
	// group/world-readable regardless of the process umask or whatever mode
	// Playwright's own writer used.
	info, err := os.Stat(statePath)
	if err != nil {
		t.Fatalf("stat saved session: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("session file mode = %o, want 0600", perm)
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

// waitForTrue polls cond until it is true or d elapses.
func waitForTrue(t *testing.T, d time.Duration, desc string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("condition %q not met within %s", desc, d)
}

// TestNewContextClosesResourceCreatedAfterCancellation covers the race where
// the caller's context is canceled (a per-call timeout, a scan cancellation)
// at almost the same moment the underlying browser actually finishes creating
// the context. NewContext correctly reports the cancellation error either
// way, but the real browser-side context that was in fact created must still
// be closed — not silently orphaned open for the rest of the Manager's life.
func TestNewContextClosesResourceCreatedAfterCancellation(t *testing.T) {
	d := &fakeDriver{createDelay: 80 * time.Millisecond}
	m := newFakeManager(t, Config{PoolSize: 1}, d)
	defer m.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := m.NewContext(ctx, ContextOptions{}); err == nil {
		t.Fatal("expected the call to report the context's cancellation")
	}

	waitForTrue(t, time.Second, "orphaned context closed", func() bool {
		d.mu.Lock()
		nbrowsers := len(d.browsers)
		var b *fakeBrowser
		if nbrowsers > 0 {
			b = d.browsers[0]
		}
		d.mu.Unlock()
		if b == nil {
			return false
		}
		b.mu.Lock()
		var fc *fakeContext
		if len(b.contexts) > 0 {
			fc = b.contexts[0]
		}
		b.mu.Unlock()
		return fc != nil && fc.isClosed()
	})
	if st := m.Stats(); st.OpenContexts != 0 {
		t.Fatalf("OpenContexts = %d, want 0 (the canceled-but-created context must not be tracked as open)", st.OpenContexts)
	}
}

// Same race, one level down: Context.NewPage against a canceled ctx.
func TestContextNewPageClosesResourceCreatedAfterCancellation(t *testing.T) {
	d := &fakeDriver{}
	m := newFakeManager(t, Config{PoolSize: 1}, d)
	defer m.Close()

	c, err := m.NewContext(context.Background(), ContextOptions{})
	if err != nil {
		t.Fatal(err)
	}
	d.createDelay = 80 * time.Millisecond // delay only the page creation below

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := c.NewPage(ctx); err == nil {
		t.Fatal("expected the call to report the context's cancellation")
	}

	waitForTrue(t, time.Second, "orphaned page closed", func() bool {
		fc := d.browsers[0].contexts[0]
		fc.mu.Lock()
		defer fc.mu.Unlock()
		return len(fc.pages) == 1 && fc.pages[0].isClosed()
	})
}

// AddInitScript must be callable before Navigate and reach the underlying
// page handle — the mechanism DOM-XSS probing (internal/scan/domxss.go)
// relies on to have its sink hooks in place before a page's own
// onload-style handler can run (a listener attached AFTER load would miss
// a handler that already fired).
func TestAddInitScriptInstalledBeforeNavigate(t *testing.T) {
	d := &fakeDriver{}
	m := newFakeManager(t, Config{PoolSize: 1}, d)
	defer m.Close()
	ctx := context.Background()

	c, err := m.NewContext(ctx, ContextOptions{})
	if err != nil {
		t.Fatal(err)
	}
	p, err := c.NewPage(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if err := p.AddInitScript(ctx, "window.__hooked = true;"); err != nil {
		t.Fatalf("AddInitScript: %v", err)
	}
	fp := d.browsers[0].contexts[0].pages[0]
	if got := fp.InitScripts(); len(got) != 1 || got[0] != "window.__hooked = true;" {
		t.Fatalf("init script not recorded before navigate: %v", got)
	}

	if _, err := p.Navigate(ctx, "https://target/page", NavOptions{}); err != nil {
		t.Fatal(err)
	}
	// Still exactly the one script: navigating does not re-install or lose it.
	if got := fp.InitScripts(); len(got) != 1 {
		t.Fatalf("init scripts after navigate = %v, want 1", got)
	}
}

// TestNavigateThreadsRefererToGoto proves NavOptions.Referer actually
// reaches the underlying pageHandle.Goto call (threaded through
// gotoWithCtx) — the new capability DOM-XSS's document.referrer source
// (internal/scan/domxss.go) needs: a navigation whose Referer HTTP header
// (and so the target page's own document.referrer) carries the probe's
// canary/payload value.
func TestNavigateThreadsRefererToGoto(t *testing.T) {
	d := &fakeDriver{}
	m := newFakeManager(t, Config{PoolSize: 1}, d)
	defer m.Close()
	ctx := context.Background()

	c, err := m.NewContext(ctx, ContextOptions{})
	if err != nil {
		t.Fatal(err)
	}
	p, err := c.NewPage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	fp := d.browsers[0].contexts[0].pages[0]

	if _, err := p.Navigate(ctx, "https://target/page", NavOptions{Referer: "https://attacker.example/evil"}); err != nil {
		t.Fatal(err)
	}
	if got := fp.Referer(); got != "https://attacker.example/evil" {
		t.Fatalf("referer = %q, want the overridden value", got)
	}

	// A Navigate call with no Referer set must not force one — leaves the
	// browser's normal referer behavior untouched.
	if _, err := p.Navigate(ctx, "https://target/other", NavOptions{}); err != nil {
		t.Fatal(err)
	}
	if got := fp.Referer(); got != "" {
		t.Fatalf("referer = %q, want empty (no override)", got)
	}
}

// TestCloseReturnsPromptlyDespiteAWedgedDriver proves Close no longer blocks
// forever when the underlying driver.Stop call never returns (ShutdownTimeout
// bounds the wait) — before the fix, Close had no timeout at all, so one
// unresponsive Playwright/Chromium process could prevent the whole program
// from ever shutting down gracefully.
func TestCloseReturnsPromptlyDespiteAWedgedDriver(t *testing.T) {
	d := &fakeDriver{hangStop: make(chan struct{})} // never closed: Stop blocks forever
	m := newFakeManager(t, Config{PoolSize: 1, ShutdownTimeout: 100 * time.Millisecond}, d)

	done := make(chan error, 1)
	go func() { done <- m.Close() }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected a timeout error from Close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not return within ShutdownTimeout + slack; it is waiting on the wedged driver forever")
	}
}
