package web_test

// Real-browser UI test: drives the actual dashboard (index.html + app.js) in a
// headless Chromium against a live server, exercising the operator workflow end
// to end — create project, add target, configure scope, create scan, start,
// pause/resume, runtime concurrency change, cancel, finding display, report
// creation, invalid input, and the session-expired state.
//
// It runs by default and SKIPS quickly when no Chromium is available, so
// `go test ./...` never fails on a machine without one (same policy as the
// other real-browser tests). Interaction is done by evaluating JavaScript in
// the page (the dashboard's own functions and DOM), never by reimplementing
// any scan logic. A blocking job handler keeps a scan in the running state so
// pause/resume/cancel are deterministic rather than racing a fast crawl.

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/evidence"
	"github.com/indago/indago/internal/httpengine"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/scan"
	"github.com/indago/indago/internal/store/memory"
	"github.com/indago/indago/internal/web"
	"github.com/indago/indago/internal/worker"
)

func findChromiumUI() string {
	if p := os.Getenv("INDAGO_CHROMIUM_PATH"); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	matches, _ := filepath.Glob(filepath.Join(home, ".cache", "ms-playwright", "chromium-*", "chrome-linux*", "chrome"))
	sort.Strings(matches)
	if len(matches) == 0 {
		return ""
	}
	return matches[len(matches)-1]
}

// uiPage holds the live server, its store, and a driven browser page.
type uiPage struct {
	t    *testing.T
	st   *memory.Store
	page *browser.Page
	url  string
}

func (u *uiPage) eval(script string) any {
	u.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	v, err := u.page.Evaluate(ctx, script)
	if err != nil {
		u.t.Fatalf("evaluate %q: %v", truncate(script, 80), err)
	}
	return v
}

func (u *uiPage) evalBool(script string) bool {
	b, _ := u.eval("!!(" + script + ")").(bool)
	return b
}

func (u *uiPage) evalStr(script string) string {
	s, _ := u.eval("String(" + script + ")").(string)
	return s
}

// setVal sets an input/select value and fires input+change so the dashboard's
// listeners (e.g. profile/auth toggles) react exactly as for a real operator.
func (u *uiPage) setVal(id, val string) {
	u.eval(fmt.Sprintf(`(function(){var e=document.getElementById(%q);e.value=%q;e.dispatchEvent(new Event('input'));e.dispatchEvent(new Event('change'));return true;})()`, id, val))
}

func (u *uiPage) click(id string) {
	if !u.evalBool(fmt.Sprintf(`(function(){var e=document.getElementById(%q);if(!e)return false;e.click();return true;})()`, id)) {
		u.t.Fatalf("click: no element #%s", id)
	}
}

// clickInScanRow clicks the button with the given label in the scans table.
func (u *uiPage) clickScanButton(label string) bool {
	return u.evalBool(fmt.Sprintf(`(function(){var bs=document.querySelectorAll('#scans button');for(var i=0;i<bs.length;i++){if(bs[i].textContent===%q){bs[i].click();return true;}}return false;})()`, label))
}

func (u *uiPage) waitUI(desc, cond string) {
	u.t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if u.evalBool(cond) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	u.t.Fatalf("UI condition never held: %s", desc)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func TestUIOperationalWorkflow(t *testing.T) {
	if testing.Short() {
		t.Skip("real-browser UI test skipped in -short mode")
	}
	exe := findChromiumUI()
	if exe == "" {
		t.Skip("no Chromium found (set INDAGO_CHROMIUM_PATH or `playwright install chromium`)")
	}
	mgr, err := browser.NewManager(browser.Config{Headless: true, ExecutablePath: exe}, nil)
	if err != nil {
		t.Skipf("browser engine unavailable: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Close() })

	// Live server with a real controller + a blocking job handler.
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	handlers := map[domain.JobType]worker.Handler{
		domain.JobTest: worker.HandlerFunc(func(ctx context.Context, _ *domain.TestJob) error {
			select {
			case <-release:
			case <-ctx.Done():
			}
			return ctx.Err()
		}),
	}
	eng, err := httpengine.New(func() httpengine.Config { c := httpengine.DefaultConfig(); c.FollowRedirects = false; return c }())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(eng.Close)
	st := memory.New()
	q := queue.NewMemory()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctrl := scan.NewController(st, q, log, "test", scan.Options{
		HTTP: eng, Handlers: handlers, IdlePoll: 10 * time.Millisecond, PollInterval: 20 * time.Millisecond,
	})
	t.Cleanup(ctrl.Shutdown)
	evStore, err := evidence.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	webSrv := web.NewServer(st, ctrl, "test", log, evStore, t.TempDir())
	srv := httptest.NewServer(webSrv.Handler())
	t.Cleanup(srv.Close)
	target := testSite(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	bctx, err := mgr.NewContext(ctx, browser.ContextOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer bctx.Close()
	page, err := bctx.NewPage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := page.Navigate(ctx, srv.URL, browser.NavOptions{}); err != nil {
		t.Fatal(err)
	}
	u := &uiPage{t: t, st: st, page: page, url: srv.URL}
	u.waitUI("app initialized", `document.getElementById('version').textContent.indexOf('v')===0`)

	// --- invalid input: empty project name shows an inline error, no project ---
	u.setVal("projName", "")
	u.click("createProject")
	u.waitUI("project name validation error", `document.getElementById('projErr').textContent.indexOf('required')>=0`)

	// --- create project (auto-selects it) ---
	u.setVal("projName", "UI Project")
	u.click("createProject")
	u.waitUI("project created + selected",
		`document.getElementById('context').textContent.indexOf('UI Project')>=0 && /UI Project/.test(document.getElementById('projects').textContent)`)

	// --- add target ---
	u.setVal("tgtName", "demo site")
	u.setVal("tgtURL", target.URL)
	u.click("addTarget")
	u.waitUI("target listed + in scan dropdown",
		fmt.Sprintf(`/demo site/.test(document.getElementById('targets').textContent) && document.querySelectorAll('#scanTarget option').length>=1 && document.getElementById('targets').textContent.indexOf(%q)>=0`, target.URL))

	// --- configure scope ---
	u.setVal("scIncludeHosts", "127.0.0.1")
	u.click("saveScope")
	u.waitUI("scope saved + shown",
		`document.getElementById('scopeErr').textContent.indexOf('saved')>=0 && /127\.0\.0\.1/.test(document.getElementById('scopeCurrent').textContent)`)

	// --- create scan (custom profile exercises the concurrency fields) ---
	u.setVal("scanName", "walkthrough")
	u.setVal("scanProfile", "custom")
	u.waitUI("custom config fields shown", `!document.getElementById('customConfig').classList.contains('hidden')`)
	u.setVal("cfgHTTP", "4")
	u.setVal("cfgDiscovery", "2")
	u.setVal("cfgBrowser", "0")
	u.setVal("cfgRate", "20")
	u.click("createScan")
	u.waitUI("scan created",
		`document.getElementById('scanErr').textContent.indexOf('created')>=0 && /walkthrough/.test(document.getElementById('scans').textContent)`)

	// --- start, then monitor ---
	if !u.clickScanButton("Start") {
		t.Fatal("no Start button in scans table")
	}
	u.waitUI("scan running", `/running/.test(document.querySelector('#scans .pill').textContent)`)
	u.clickScanButton("Monitor")
	u.waitUI("monitor visible + running",
		`!document.getElementById('monitorCard').classList.contains('hidden') && /running/.test(document.getElementById('monitorMetrics').textContent)`)

	// Resolve the scan ID from the store for API-side assertions.
	scans, _ := st.Scans().List(context.Background())
	var walk *domain.Scan
	for _, s := range scans {
		if s.Name == "walkthrough" {
			walk = s
		}
	}
	if walk == nil {
		t.Fatal("walkthrough scan not found")
	}
	scanID := string(walk.ID)

	// --- runtime concurrency change via the monitor ---
	u.setVal("rcHTTP", "9")
	u.click("applyConfig")
	u.waitUI("reconfigure applied", `document.getElementById('rcErr').textContent.indexOf('Applied')>=0`)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		cur, _ := st.Scans().Get(context.Background(), domain.ID(scanID))
		if cur.Config.HTTPConcurrency == 9 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if cur, _ := st.Scans().Get(context.Background(), domain.ID(scanID)); cur.Config.HTTPConcurrency != 9 {
		t.Fatalf("runtime HTTP concurrency = %d, want 9", cur.Config.HTTPConcurrency)
	}

	// --- pause / resume ---
	u.clickScanButton("Pause")
	u.waitUI("scan paused", `/paused/.test(document.querySelector('#scans .pill').textContent)`)
	u.clickScanButton("Resume")
	u.waitUI("scan resumed", `/running/.test(document.querySelector('#scans .pill').textContent)`)

	// --- finding display: seed one, reload the findings list via the page ---
	seedFinding(t, api{t: t, st: st, ev: evStore}, domain.ID(scanID))
	u.eval(`loadFindings()`)
	u.waitUI("finding shown", `/Reflected XSS candidate/.test(document.getElementById('findings').textContent)`)

	// --- report creation ---
	u.click("generateReport")
	u.waitUI("report row appears", `document.querySelectorAll('#reports tr').length>=1 && !/No reports yet/.test(document.getElementById('reports').textContent)`)

	// --- cancel (confirm dialog auto-accepted) ---
	u.eval(`window.confirm = function(){return true;}`)
	u.clickScanButton("Cancel")
	u.waitUI("scan canceled", `/canceled/.test(document.querySelector('#scans .pill').textContent)`)

	// --- session-expired state rendered in the UI ---
	stateFile := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(stateFile, []byte(`{"cookies":[],"origins":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	authScan, err := ctrl.CreateScan(context.Background(), scan.CreateScanParams{
		ProjectID: walk.ProjectID, TargetID: walk.TargetID, Name: "authscan",
		AuthMode: domain.AuthExisting, AuthStatePath: stateFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ctrl.Start(context.Background(), authScan.ID); err != nil {
		t.Fatal(err)
	}
	// Force the session to expire; the monitor moves the scan to awaiting_auth.
	sess, err := st.Sessions().GetByScan(context.Background(), authScan.ID)
	if err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-time.Hour)
	sess.ExpiresAt = &past
	if err := st.Sessions().Update(context.Background(), sess); err != nil {
		t.Fatal(err)
	}
	u.waitUI("awaiting_auth shown in scans table (auto-refresh)",
		`/awaiting_auth/.test(document.getElementById('scans').textContent)`)
}
