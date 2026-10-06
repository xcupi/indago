package web_test

// Real-browser UI tests for the sidebar/router application layout. They drive
// the actual dashboard (index.html + app.css + app.js + scans.js + views.js) in
// a headless Chromium against a live server:
//
//   - TestUINavigation: sidebar/route navigation updates the view in place,
//     with no full page reload.
//   - TestUIOperationalWorkflow: the operator workflow end to end — create
//     project, add target, configure scope, create scan, start, scan-detail
//     tabs, runtime concurrency change, pause/resume, finding display, report
//     creation, cancel, invalid input, and the session-expired state.
//
// They run by default and SKIP quickly when no Chromium is available. All
// interaction is by evaluating JavaScript against the dashboard's own DOM and
// functions — the test reimplements no scan logic. A blocking job handler keeps
// a scan running so lifecycle transitions are deterministic.

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

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// uiHarness is a live server + store + a driven browser page.
type uiHarness struct {
	t    *testing.T
	st   *memory.Store
	ctrl *scan.Controller
	ev   evidence.Store
	page *browser.Page
	ctx  context.Context
}

// newUIHarness builds the full stack with a blocking JobTest handler (so a
// scan stays running until the test ends) and opens the dashboard.
func newUIHarness(t *testing.T) *uiHarness {
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
	hcfg := httpengine.DefaultConfig()
	hcfg.FollowRedirects = false
	eng, err := httpengine.New(hcfg)
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
	srv := httptest.NewServer(web.NewServer(st, ctrl, "test", log, evStore, t.TempDir()).Handler())
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	bctx, err := mgr.NewContext(ctx, browser.ContextOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bctx.Close() })
	page, err := bctx.NewPage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := page.Navigate(ctx, srv.URL, browser.NavOptions{}); err != nil {
		t.Fatal(err)
	}
	u := &uiHarness{t: t, st: st, ctrl: ctrl, ev: evStore, page: page, ctx: ctx}
	u.waitUI("app initialized", `document.getElementById('version').textContent.indexOf('v')===0`)
	return u
}

func (u *uiHarness) eval(script string) any {
	u.t.Helper()
	ctx, cancel := context.WithTimeout(u.ctx, 10*time.Second)
	defer cancel()
	v, err := u.page.Evaluate(ctx, script)
	if err != nil {
		u.t.Fatalf("evaluate %q: %v", truncate(script, 90), err)
	}
	return v
}
func (u *uiHarness) evalBool(s string) bool  { b, _ := u.eval("!!(" + s + ")").(bool); return b }
func (u *uiHarness) evalStr(s string) string { v, _ := u.eval("String(" + s + ")").(string); return v }

func (u *uiHarness) setVal(id, val string) {
	u.eval(fmt.Sprintf(`(function(){var e=document.getElementById(%q);e.value=%q;e.dispatchEvent(new Event('input'));e.dispatchEvent(new Event('change'));return true;})()`, id, val))
}
func (u *uiHarness) click(id string) {
	if !u.evalBool(fmt.Sprintf(`(function(){var e=document.getElementById(%q);if(!e)return false;e.click();return true;})()`, id)) {
		u.t.Fatalf("click: no element #%s", id)
	}
}

// clickText clicks the first element matching sel whose exact text is text.
func (u *uiHarness) clickText(sel, text string) bool {
	return u.evalBool(fmt.Sprintf(`(function(){var ns=document.querySelectorAll(%q);for(var i=0;i<ns.length;i++){if(ns[i].textContent===%q){ns[i].click();return true;}}return false;})()`, sel, text))
}

// mustClickText polls for an element matching sel with the given text and
// clicks it. Polling (rather than a single attempt) absorbs the brief window
// while a view re-renders after an action, where a button may momentarily not
// be present.
func (u *uiHarness) mustClickText(sel, text string) {
	u.t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if u.clickText(sel, text) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	u.t.Fatalf("no %s with text %q appeared", sel, text)
}

// waitUI polls a boolean condition. A condition that throws (e.g. a selector
// that is still null mid-render) counts as "not yet true", not a fatal error,
// so conditions can be written without defensive null checks.
func (u *uiHarness) waitUI(desc, cond string) {
	u.t.Helper()
	ctx, cancel := context.WithTimeout(u.ctx, 10*time.Second)
	defer cancel()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		v, err := u.page.Evaluate(ctx, "!!("+cond+")")
		if err == nil {
			if b, _ := v.(bool); b {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	u.t.Fatalf("UI condition never held: %s", desc)
}

// --- navigation ---------------------------------------------------------

func TestUINavigation(t *testing.T) {
	u := newUIHarness(t)
	// A sentinel on window; a full page reload would clear it.
	u.eval(`window.__noReload = 'kept'`)

	sections := []string{"projects", "targets", "scope", "scans", "findings", "reports", "settings", "dashboard"}
	for _, s := range sections {
		u.mustClickText("#sidebar a", map[string]string{
			"dashboard": "Dashboard", "projects": "Projects", "targets": "Targets", "scope": "Scope",
			"scans": "Scans", "findings": "Findings", "reports": "Reports", "settings": "Settings",
		}[s])
		u.waitUI("nav to "+s, fmt.Sprintf(`location.hash==='#/%s' && document.querySelector('#sidebar a.active') && document.querySelector('#sidebar a.active').getAttribute('data-nav')===%q && document.getElementById('view').dataset.view===%q`, s, s, s))
		if errs := u.page.PageErrors(); len(errs) > 0 {
			t.Fatalf("JS error after navigating to %s: %v", s, errs)
		}
	}
	if u.evalStr(`window.__noReload`) != "kept" {
		t.Fatal("navigation caused a full page reload (sentinel lost)")
	}
}

// --- full workflow ------------------------------------------------------

func TestUIOperationalWorkflow(t *testing.T) {
	u := newUIHarness(t)
	target := testSite(t)

	// Projects view.
	u.mustClickText("#sidebar a", "Projects")
	u.waitUI("projects view", `document.getElementById('view').dataset.view==='projects'`)

	// Invalid input: empty project name keeps the modal open with an error.
	u.mustClickText(".page-head button", "New project")
	u.waitUI("project modal open", `!document.getElementById('modal').classList.contains('hidden')`)
	u.mustClickText("#modalBody button", "Create project")
	u.waitUI("empty-name validation", `/required/.test(document.querySelector('#modalBody .err').textContent) && !document.getElementById('modal').classList.contains('hidden')`)

	// Create a real project → selected in header, lands on Targets.
	u.setVal("p_name", "UI Project")
	u.mustClickText("#modalBody button", "Create project")
	u.waitUI("project created + selected + on targets",
		`document.getElementById('modal').classList.contains('hidden') && location.hash==='#/targets' && document.getElementById('projectSelect').selectedIndex>0`)

	// Add a target via modal.
	u.mustClickText(".page-head button", "Add target")
	u.waitUI("target modal", `!document.getElementById('modal').classList.contains('hidden')`)
	u.setVal("t_name", "demo site")
	u.setVal("t_url", target.URL)
	u.mustClickText("#modalBody button", "Add target")
	u.waitUI("target listed", fmt.Sprintf(`document.getElementById('modal').classList.contains('hidden') && document.getElementById('view').textContent.indexOf(%q)>=0`, target.URL))

	// Configure scope.
	u.mustClickText("#sidebar a", "Scope")
	u.waitUI("scope view", `document.getElementById('s_inchosts')!==null`)
	u.setVal("s_inchosts", "127.0.0.1")
	u.mustClickText(".form-actions button", "Save scope")
	u.waitUI("scope saved", `/saved/.test(document.querySelector('.ok-msg')&&document.querySelector('.ok-msg').textContent||'') && /127\.0\.0\.1/.test(document.getElementById('view').textContent)`)

	// Create a scan (custom profile exercises the concurrency fields).
	u.mustClickText("#sidebar a", "Scans")
	u.waitUI("scans view", `document.getElementById('view').dataset.view==='scans'`)
	u.mustClickText(".page-head button", "New scan")
	u.waitUI("scan modal", `document.getElementById('f_name')!==null`)
	u.setVal("f_name", "walkthrough")
	u.setVal("f_profile", "custom")
	u.waitUI("custom fields shown", `document.getElementById('f_cfgH')!==null`)
	u.setVal("f_cfgH", "4")
	u.mustClickText("#modalBody button", "Create scan")
	u.waitUI("on scan detail overview",
		`/^#\/scans\/[^/]+\/overview$/.test(location.hash) && /Overview/.test(document.querySelector('.tabs').textContent)`)

	scanID := func() string {
		scans, _ := u.st.Scans().List(context.Background())
		for _, s := range scans {
			if s.Name == "walkthrough" {
				return string(s.ID)
			}
		}
		t.Fatal("walkthrough scan not found")
		return ""
	}()

	// Start, then confirm running on the detail page.
	u.mustClickText(".page-head button", "Start")
	u.waitUI("scan running", `/running/.test(document.querySelector('.page-head').textContent)`)

	// Walk the detail tabs.
	for _, tab := range []struct{ label, marker string }{
		{"Discovery", "Injection points"},
		{"Jobs", "Test outcomes"},
		{"Evidence", "Evidence"},
		{"Reports", "Generate report"},
		{"Findings", "Findings"},
	} {
		u.mustClickText(".tabs a", tab.label)
		u.waitUI("tab "+tab.label, fmt.Sprintf(`document.getElementById('tabPanel')!==null && document.getElementById('tabPanel').textContent.indexOf(%q)>=0`, tab.marker))
	}

	// Runtime concurrency change via the Tune modal.
	u.mustClickText(".page-head button", "Tune concurrency")
	u.waitUI("tune modal", `document.getElementById('tune_h')!==null`)
	u.setVal("tune_h", "9")
	u.mustClickText("#modalBody button", "Apply")
	u.waitUI("tune modal closed", `document.getElementById('modal').classList.contains('hidden')`)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cur, _ := u.st.Scans().Get(context.Background(), domain.ID(scanID)); cur.Config.HTTPConcurrency == 9 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if cur, _ := u.st.Scans().Get(context.Background(), domain.ID(scanID)); cur.Config.HTTPConcurrency != 9 {
		t.Fatalf("runtime HTTP concurrency = %d, want 9", cur.Config.HTTPConcurrency)
	}

	// Pause / resume.
	u.mustClickText(".page-head button", "Pause")
	u.waitUI("scan paused", `/paused/.test(document.querySelector('.page-head').textContent)`)
	u.mustClickText(".page-head button", "Resume")
	u.waitUI("scan resumed", `/running/.test(document.querySelector('.page-head').textContent)`)

	// Finding display: seed one, open the Findings tab.
	seedFinding(t, api{t: t, st: u.st, ev: u.ev}, domain.ID(scanID))
	u.mustClickText(".tabs a", "Findings")
	u.waitUI("finding shown", `/Reflected XSS candidate/.test(document.getElementById('tabPanel').textContent)`)

	// Report creation on the Findings tab's generator.
	u.mustClickText("#tabPanel button", "Generate report")
	u.waitUI("report row appears", `!/No reports yet/.test(document.getElementById('reportsBody').textContent) && document.querySelectorAll('#reportsBody tr').length>=1`)

	// Cancel (confirm auto-accepted).
	u.eval(`window.confirm = function(){ return true; }`)
	u.mustClickText(".page-head button", "Cancel")
	u.waitUI("scan canceled", `/canceled/.test(document.querySelector('.page-head').textContent)`)

	// Session-expired state surfaced in the UI.
	stateFile := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(stateFile, []byte(`{"cookies":[],"origins":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	sc, err := u.ctrl.CreateScan(context.Background(), scan.CreateScanParams{
		ProjectID: mustScan(t, u.st, scanID).ProjectID, TargetID: mustScan(t, u.st, scanID).TargetID,
		Name: "authscan", AuthMode: domain.AuthExisting, AuthStatePath: stateFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := u.ctrl.Start(context.Background(), sc.ID); err != nil {
		t.Fatal(err)
	}
	sess, err := u.st.Sessions().GetByScan(context.Background(), sc.ID)
	if err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-time.Hour)
	sess.ExpiresAt = &past
	if err := u.st.Sessions().Update(context.Background(), sess); err != nil {
		t.Fatal(err)
	}
	// Wait for the backend to actually reach awaiting_auth (deterministic),
	// then drive the UI to the scan — its detail fetches status on render, so
	// the assertion does not depend on the live-refresh interval.
	deadlineA := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadlineA) {
		if cur, _ := u.st.Scans().Get(context.Background(), sc.ID); cur.State == domain.ScanAwaitingAuth {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if cur, _ := u.st.Scans().Get(context.Background(), sc.ID); cur.State != domain.ScanAwaitingAuth {
		t.Fatalf("scan did not reach awaiting_auth: %s", cur.State)
	}
	u.goHash("#/scans/" + string(sc.ID) + "/overview")
	u.waitUI("awaiting_auth shown in scan detail",
		`/awaiting_auth/.test(document.getElementById('tabPanel').textContent)`)
}

func mustScan(t *testing.T, st *memory.Store, id string) *domain.Scan {
	t.Helper()
	s, err := st.Scans().Get(context.Background(), domain.ID(id))
	if err != nil {
		t.Fatal(err)
	}
	return s
}
