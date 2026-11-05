package web_test

// Real-browser tests for the readiness / coverage UI: a scan that could not run
// the browser probes must not read as clean, the header must follow the scan's
// state, the New scan form must be short with readiness shown before Start, and
// the finding toggle must be keyboard-operable. They drive the real dashboard
// against a store seeded the way the pipeline writes it.

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/web"
)

func seedUITest(t *testing.T, u *uiHarness, scanID domain.ID, class domain.VulnClass, status domain.TestCaseStatus, outcome domain.TestOutcome, url, note string) {
	t.Helper()
	now := time.Now()
	tc := &domain.TestCase{
		ID: domain.NewID(), ScanID: scanID, JobID: domain.NewID(), VulnClass: class, Status: status, Outcome: outcome,
		Method: "GET", URL: url, Note: note, CreatedAt: now, UpdatedAt: now,
	}
	if err := u.st.TestCases().Create(context.Background(), tc); err != nil {
		t.Fatal(err)
	}
}

// The audit scenario: browser engine off, every DOM probe skipped, zero
// findings. The dashboard must say it was not fully tested, and why.
func TestUICoverageBrowserlessScanIsNotShownAsClean(t *testing.T) {
	u := newUIHarness(t)
	scanID := uiFindingsScan(t, u)
	for i := 0; i < 4; i++ {
		seedUITest(t, u, scanID, domain.VulnDOMXSS, domain.TestCaseSkipped, "", fmt.Sprintf("http://127.0.0.1:9/dom%d?q=hello", i), "dom-xss probe skipped: no browser configured for this scan")
	}
	seedUITest(t, u, scanID, domain.VulnReflectedXSS, domain.TestCaseCompleted, domain.OutcomeSuccess, "http://127.0.0.1:9/safe?q=a", "not reflected")

	u.openScanTab(scanID, "overview")
	u.waitUI("overview rendered", `document.getElementById('readiness')`)
	if !u.evalBool(`/Browser engine/.test(document.getElementById('readiness').textContent) && /OFF/.test(document.getElementById('readiness').textContent)`) {
		t.Fatalf("the overview must state the browser engine is OFF: %q", u.evalStr(`document.getElementById('readiness').textContent`))
	}
	u.waitUI("not-fully-tested banner", `document.querySelector('#coverageHost .banner[data-code="browser_disabled"]')`)
	if !u.evalBool(`/zero findings does not mean/i.test(document.getElementById('coverageHost').textContent)`) {
		t.Fatal("the banner must say that zero findings does not mean clean")
	}
	u.waitUI("gap badge in the header", `document.querySelector('.page-head .gap-badge')`)

	// Coverage tab: grouped reason + the per-test log with the URL and the note.
	u.mustClickText(".tabs a", "Coverage")
	u.waitUI("reasons table", `document.querySelectorAll('#reasonsBody tr').length===1`)
	if !u.evalBool(`/Browser engine not enabled/.test(document.getElementById('reasonsBody').textContent) && /4/.test(document.getElementById('reasonsBody').textContent)`) {
		t.Fatalf("grouped reason missing: %q", u.evalStr(`document.getElementById('reasonsBody').textContent`))
	}
	u.waitUI("test log rows", `document.querySelectorAll('#testsBody tr').length===5`)
	if !u.evalBool(`/dom0\?q=hello/.test(document.getElementById('testsBody').textContent) && /no browser configured/.test(document.getElementById('testsBody').textContent)`) {
		t.Fatal("the log must show the tested URL and the skip note")
	}

	// "Show these" narrows the log to that reason; the filter chip clears it.
	u.mustClickText("#reasonsBody button", "Show these")
	u.waitUI("filtered by reason", `document.querySelectorAll('#testsBody tr').length===4 && !/safe\?q=a/.test(document.getElementById('testsBody').textContent)`)
	u.mustClickText(".filter-bar button", "Errors / timeouts")
	u.waitUI("errors filter is empty", `/No tests match this filter/.test(document.getElementById('testsBody').textContent)`)
	if !u.evalBool(`document.querySelector('.filter-bar button[data-filter="errors"]').getAttribute('aria-pressed')==='true'`) {
		t.Fatal("the active filter must be exposed with aria-pressed")
	}
}

func TestUICoverageCleanScanDoesNotRaiseAFalseAlarm(t *testing.T) {
	u := newUIHarnessWith(t, "", web.Capabilities{BrowserEnabled: true, BrowserSandbox: true})
	scanID := uiFindingsScan(t, u)
	seedUITest(t, u, scanID, domain.VulnReflectedXSS, domain.TestCaseCompleted, domain.OutcomeSuccess, "http://127.0.0.1:9/x?q=1", "not reflected")
	u.openScanTab(scanID, "overview")
	u.waitUI("overview rendered", `document.getElementById('readiness')`)
	// Wait for the coverage response itself, not a guess at how long it takes: an
	// absence assertion made before the data lands would pass vacuously.
	u.waitUI("coverage data landed", `coverageCache.data && coverageCache.data.tests.total === 1`)
	if u.evalBool(`document.querySelector('#coverageHost .banner')`) || u.evalBool(`document.querySelector('.page-head .gap-badge')`) {
		t.Fatal("a fully-tested scan must not show a coverage warning or gap badge")
	}
}

// The header (state pill and Pause/Cancel controls) used to stay on "running"
// after the scan finished, because only the tab body was refreshed.
func TestUIScanHeaderFollowsStateChange(t *testing.T) {
	u := newUIHarness(t)
	scanID := uiFindingsScan(t, u)
	ctx := context.Background()
	sc, err := u.st.Scans().Get(ctx, scanID)
	if err != nil {
		t.Fatal(err)
	}
	sc.State = domain.ScanRunning
	if err := u.st.Scans().Update(ctx, sc); err != nil {
		t.Fatal(err)
	}
	u.openScanTab(scanID, "overview")
	u.waitUI("running header", `document.querySelector('.page-head h1 .pill.running')`)
	if !u.evalBool(`Array.from(document.querySelectorAll('.page-head button')).some(b => /Pause/.test(b.textContent))`) {
		t.Fatal("setup: a running scan must offer Pause")
	}

	sc.State = domain.ScanCompleted
	if err := u.st.Scans().Update(ctx, sc); err != nil {
		t.Fatal(err)
	}
	u.eval(`refreshNow(); true`)
	u.waitUI("header follows the completed state", `document.querySelector('.page-head h1 .pill.completed') && !document.querySelector('.page-head h1 .pill.running')`)
	if u.evalBool(`Array.from(document.querySelectorAll('.page-head button')).some(b => /Pause|Cancel/.test(b.textContent))`) {
		t.Fatal("a completed scan must not keep Pause/Cancel in the header")
	}
}

func TestUINewScanFormIsShortAndShowsReadinessBeforeStart(t *testing.T) {
	u := newUIHarness(t)
	scanID := uiFindingsScan(t, u)
	_ = scanID
	u.eval(`(async () => { await loadProjects(); setProject(ctx.projects[0].id); })(); true`)
	u.waitUI("project selected", `currentProject()`)
	u.eval(`openNewScanModal(); true`)
	u.waitUI("modal open", `document.getElementById('f_advanced')`)

	if !u.evalBool(`/Browser engine is OFF/.test(document.getElementById('readinessBanner').textContent)`) {
		t.Fatal("the modal must warn, before Start, that the browser engine is off")
	}
	if u.evalBool(`document.getElementById('f_advanced').open`) {
		t.Fatal("advanced options (proxy, TLS, performance, stop policy) must start collapsed")
	}
	// Create scan is reachable without scrolling the page and the box stays short.
	if !u.evalBool(`(function(){ var b = Array.from(document.querySelectorAll('#modal button')).find(x => x.textContent==='Create scan'); var r = b.getBoundingClientRect(); return r.bottom <= window.innerHeight; })()`) {
		t.Fatalf("Create scan is below the fold: %v", u.eval(`document.querySelector('#modal .modal-box').getBoundingClientRect().height + ' / ' + window.innerHeight`))
	}
	// Folding must not remove the options: they stay in the DOM, ready to open.
	if !u.evalBool(`document.getElementById('f_cfgD') && document.getElementById('f_proxypool')`) {
		t.Fatal("collapsed options must remain in the form")
	}
}

func TestUIFindingToggleIsKeyboardOperable(t *testing.T) {
	u := newUIHarness(t)
	scanID := uiFindingsScan(t, u)
	f := uiFinding(t, u, scanID, domain.VerdictConfirmed, uiFindingOpts{path: "/kb"}, time.Now())
	u.openScanTab(scanID, "findings")
	u.waitUI("row rendered", `document.querySelector('#findingsBody tr[data-finding-id="`+string(f.ID)+`"] button.row-toggle')`)
	sel := `#findingsBody tr[data-finding-id="` + string(f.ID) + `"] button.row-toggle`
	if !u.evalBool(`(function(){ var b = document.querySelector('` + sel + `'); b.focus(); return document.activeElement === b && b.tabIndex >= 0 && b.getAttribute('aria-expanded')==='false'; })()`) {
		t.Fatal("the finding title must be a focusable button that starts collapsed")
	}
	u.eval(`document.querySelector('` + sel + `').click(); true`)
	u.waitUI("expanded", `document.querySelector('`+sel+`').getAttribute('aria-expanded')==='true' && document.querySelector('#findingsBody tr.detail-row')`)
	u.eval(`document.querySelector('` + sel + `').click(); true`)
	u.waitUI("collapsed again", `document.querySelector('`+sel+`').getAttribute('aria-expanded')==='false' && !document.querySelector('#findingsBody tr.detail-row')`)
}

func TestUIEmptyReportPreviewNeverPrintsUndefined(t *testing.T) {
	u := newUIHarness(t)
	scanID := uiFindingsScan(t, u)
	u.openScanTab(scanID, "reports")
	u.waitUI("preview text", `/Will include/.test(document.getElementById('reportPreview').textContent)`)
	txt := u.evalStr(`document.getElementById('reportPreview').textContent`)
	if strings.Contains(txt, "undefined") || !strings.Contains(txt, "Will include 0 of 0") {
		t.Fatalf("empty preview = %q", txt)
	}
}

// Phone width: the project-level findings table and the new tests table must
// stack instead of overflowing, and nothing may scroll the page sideways.
func TestUIPhoneWidthTablesStackWithoutOverflow(t *testing.T) {
	u := newUIHarness(t)
	u.eval(layoutJS)
	scanID := uiFindingsScan(t, u)
	for i := 0; i < 3; i++ {
		uiFinding(t, u, scanID, domain.VerdictConfirmed, uiFindingOpts{path: fmt.Sprintf("/p%d", i)}, time.Now())
		seedUITest(t, u, scanID, domain.VulnDOMXSS, domain.TestCaseSkipped, "", "http://127.0.0.1:9/some/long/path/that/keeps/going?q="+strings.Repeat("a", 90), "dom-xss probe skipped: no browser configured for this scan")
	}
	// The project-level views need a selected project (kept in localStorage, shared with the iframe).
	u.eval(`(async () => { await loadProjects(); setProject(ctx.projects[0].id); })(); true`)
	u.waitUI("project selected", `currentProject()`)
	for _, route := range []string{"#/scans/" + string(scanID) + "/coverage", "#/findings"} {
		u.eval(`(function(){ var o = document.getElementById('narrow'); if (o) o.remove(); var f = document.createElement('iframe'); f.id = 'narrow';
		  f.style.cssText = 'position:fixed;left:0;top:0;width:390px;height:800px;border:0;z-index:99999;background:#000';
		  f.src = location.pathname + '` + route + `'; document.body.appendChild(f); return true; })()`)
		u.waitUI("narrow frame rendered "+route, `document.getElementById('narrow').contentDocument.querySelector('#view table tbody tr')`)
		time.Sleep(600 * time.Millisecond)
		u.eval(layoutJS)
		if v := u.violations("narrow"); len(v) > 0 {
			t.Fatalf("%s at phone width:\n  %s", route, strings.Join(v, "\n  "))
		}
		if !u.evalBool(`getComputedStyle(document.getElementById('narrow').contentDocument.querySelector('#view table thead')).display === 'none'`) {
			t.Fatalf("%s: the table must be stacked (header row hidden) at phone width", route)
		}
	}
}

// A short viewport (small laptop, landscape phone) must still reach Create scan
// without scrolling the whole form first.
func TestUINewScanActionsStayReachableOnShortViewport(t *testing.T) {
	u := newUIHarness(t)
	_ = uiFindingsScan(t, u)
	u.eval(`(async () => { await loadProjects(); setProject(ctx.projects[0].id); })(); true`)
	u.waitUI("project selected", `currentProject()`)
	u.eval(`(function(){ var f = document.createElement('iframe'); f.id = 'short';
	  f.style.cssText = 'position:fixed;left:0;top:0;width:900px;height:480px;border:0;z-index:99999;background:#000';
	  f.src = location.pathname + '#/scans'; document.body.appendChild(f); return true; })()`)
	u.waitUI("short frame rendered", `document.getElementById('short').contentWindow.openNewScanModal && document.getElementById('short').contentDocument.querySelector('#view')`)
	time.Sleep(500 * time.Millisecond)
	u.eval(`document.getElementById('short').contentWindow.openNewScanModal(); true`)
	u.waitUI("modal open in the short frame", `document.getElementById('short').contentDocument.getElementById('f_advanced')`)
	time.Sleep(300 * time.Millisecond)
	if !u.evalBool(`document.getElementById('short').contentWindow.innerHeight === 480`) {
		t.Fatal("setup: the frame is not 480px tall")
	}
	bottom := u.evalStr(`Array.from(document.getElementById('short').contentDocument.querySelectorAll('#modal button')).find(b => b.textContent === 'Create scan').getBoundingClientRect().bottom`)
	if !u.evalBool(`Array.from(document.getElementById('short').contentDocument.querySelectorAll('#modal button')).find(b => b.textContent === 'Create scan').getBoundingClientRect().bottom <= 480`) {
		t.Fatalf("Create scan is below the fold of a 480px viewport (bottom=%s)", bottom)
	}
}

// /coverage walks every test case of the scan (about 1.5s at 18k tests), and the
// Overview used to re-request it on every 2s live refresh. It must be reused for
// a short while, but a change of scan state must not show a stale verdict.
func TestUIOverviewDoesNotRefetchCoverageOnEveryRefresh(t *testing.T) {
	u := newUIHarness(t)
	scanID := uiFindingsScan(t, u)
	ctx := context.Background()
	sc, err := u.st.Scans().Get(ctx, scanID)
	if err != nil {
		t.Fatal(err)
	}
	sc.State = domain.ScanRunning
	if err := u.st.Scans().Update(ctx, sc); err != nil {
		t.Fatal(err)
	}
	u.eval(`window.__cov = 0; (function(){ var of = window.fetch; window.fetch = function(u){ if (String(u).indexOf('/coverage') >= 0) window.__cov++; return of.apply(this, arguments); }; })(); true`)
	u.openScanTab(scanID, "overview")
	u.waitUI("first coverage fetch", `window.__cov >= 1 && document.getElementById('coverageHost')`)
	time.Sleep(500 * time.Millisecond)
	before := u.evalStr(`window.__cov`)
	for i := 0; i < 4; i++ {
		u.eval(`refreshNow(); true`)
		time.Sleep(400 * time.Millisecond)
	}
	if after := u.evalStr(`window.__cov`); after != before {
		t.Fatalf("coverage was refetched on refresh: %s -> %s requests", before, after)
	}

	// The scan ends: the verdict must be recomputed immediately, not after the cache expires.
	sc.State = domain.ScanCompleted
	if err := u.st.Scans().Update(ctx, sc); err != nil {
		t.Fatal(err)
	}
	u.eval(`refreshNow(); true`)
	u.waitUI("coverage refetched after the state change", `window.__cov > `+before)
}
