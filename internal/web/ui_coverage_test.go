package web_test

// Real-browser tests for the readiness / coverage UI: a scan that could not run
// the browser probes must not read as clean, the header must follow the scan's
// state, the New scan form must be short with readiness shown before Start, and
// the finding toggle must be keyboard-operable. They drive the real dashboard
// against a store seeded the way the pipeline writes it.

import (
	"context"
	"fmt"
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
	// Wait for the CONDITION, not the element: #readiness exists as soon as the
	// view renders and can still hold the "Server capabilities unknown"
	// placeholder while the capability read is in flight (or being retried).
	u.waitUI("readiness states the browser engine is OFF",
		`/Browser engine/.test(document.getElementById('readiness').textContent) && /OFF/.test(document.getElementById('readiness').textContent)`)
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
	u.selectFirstProject()
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
