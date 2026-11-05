package web_test

// Real-browser tests for the Endpoints tab: what discovery found must be
// visible next to whether it was tested, including parameters that never ran.

import (
	"strings"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/web"
)

func explorerUIWorld(t *testing.T, caps web.Capabilities) (*uiHarness, *explorerWorld) {
	u := newUIHarnessWith(t, "", caps)
	scanID := uiFindingsScan(t, u)
	w := seedExplorerWorld(api{t: t, st: u.st}, scanID)
	return u, w
}

func TestUIEndpointsTabShowsFoundButUntestedParameters(t *testing.T) {
	u, w := explorerUIWorld(t, web.Capabilities{})
	u.openScanTab(w.scan, "endpoints")
	u.waitUI("endpoint rows", `document.querySelectorAll('#endpointsBody > tr[data-endpoint-id]').length===3`)

	// Endpoints with something untested sort first and say so.
	if !u.evalBool(`document.querySelector('#endpointsBody > tr[data-endpoint-id="` + string(w.search) + `"] .pill.gap')`) {
		t.Fatal("the /search endpoint must be flagged as having gaps")
	}
	if !u.evalBool(`/parameters: \d+ tested/.test(document.querySelector('.coverage-summary').textContent)`) {
		t.Fatalf("summary: %q", u.evalStr(`document.querySelector('.coverage-summary').textContent`))
	}

	// Open it with the keyboard-reachable toggle: every parameter and DOM source, with reasons.
	sel := `#endpointsBody > tr[data-endpoint-id="` + string(w.search) + `"] button.row-toggle`
	if !u.evalBool(`document.querySelector('` + sel + `').getAttribute('aria-expanded')==='false'`) {
		t.Fatal("the toggle must start collapsed and expose aria-expanded")
	}
	u.eval(`document.querySelector('` + sel + `').click(); true`)
	u.waitUI("detail open", `document.querySelector('#endpointsBody tr.detail-row .endpoint-detail')`)
	detail := u.evalStr(`document.querySelector('#endpointsBody tr.detail-row').textContent`)
	for _, want := range []string{
		"page", "no test job was ever created for it", // discovered, never given a job
		"tok", "its job failed permanently",
		"lang", "state-changing methods are disabled",
		"route", // the fragment parameter
		"postMessage", "the browser engine is not enabled",
		"DOM XSS sources (per page, not per parameter)",
	} {
		if !strings.Contains(detail, want) {
			t.Errorf("the expanded endpoint is missing %q in:\n%s", want, detail)
		}
	}
	if !u.evalBool(`document.querySelector('` + sel + `').getAttribute('aria-expanded')==='true'`) {
		t.Fatal("aria-expanded must follow the open state")
	}

	// The open row survives a live refresh instead of collapsing.
	u.eval(`refreshNow(); true`)
	time.Sleep(700 * time.Millisecond)
	if !u.evalBool(`document.querySelector('#endpointsBody tr.detail-row .endpoint-detail')`) {
		t.Fatal("an expanded endpoint collapsed on refresh")
	}

	// Filters: gaps-only, URL search.
	u.mustClickText(".filter-bar button", "With gaps only")
	u.waitUI("gaps filter", `document.querySelectorAll('#endpointsBody > tr[data-endpoint-id]').length===2 && !document.querySelector('#endpointsBody tr[data-endpoint-id="`+string(w.login)+`"]')`)
	u.mustClickText(".filter-bar button", "All")
	u.waitUI("all again", `document.querySelectorAll('#endpointsBody > tr[data-endpoint-id]').length===3`)
	u.setVal("endpointSearch", "login")
	u.waitUI("search filter", `document.querySelectorAll('#endpointsBody > tr[data-endpoint-id]').length===1`)
}

func TestUIOverviewLinksUntestedParametersToTheExplorer(t *testing.T) {
	u, w := explorerUIWorld(t, web.Capabilities{BrowserEnabled: true})
	u.openScanTab(w.scan, "overview")
	u.waitUI("untested banner", `document.querySelector('#coverageHost .banner[data-code="parameters_untested"] a')`)
	if !u.evalBool(`document.querySelector('#coverageHost .banner[data-code="parameters_untested"] a').getAttribute('href').endsWith('/endpoints')`) {
		t.Fatal("the warning must link to the Endpoints tab")
	}
}

func TestUIEndpointsTabStacksAtPhoneWidthWithoutOverflow(t *testing.T) {
	u, w := explorerUIWorld(t, web.Capabilities{})
	u.eval(layoutJS)
	u.eval(`(async () => { await loadProjects(); setProject(ctx.projects[0].id); })(); true`)
	u.waitUI("project selected", `currentProject()`)
	u.eval(`(function(){ var f = document.createElement('iframe'); f.id = 'narrow';
	  f.style.cssText = 'position:fixed;left:0;top:0;width:390px;height:800px;border:0;z-index:99999;background:#000';
	  f.src = location.pathname + '#/scans/` + string(w.scan) + `/endpoints'; document.body.appendChild(f); return true; })()`)
	u.waitUI("narrow rows", `document.getElementById('narrow').contentDocument.querySelectorAll('#endpointsBody > tr[data-endpoint-id]').length===3`)
	u.eval(`document.getElementById('narrow').contentDocument.querySelector('#endpointsBody tr[data-endpoint-id="` + string(w.search) + `"] button.row-toggle').click(); true`)
	u.waitUI("narrow detail", `document.getElementById('narrow').contentDocument.querySelector('#endpointsBody tr.detail-row .endpoint-detail')`)
	time.Sleep(500 * time.Millisecond)
	u.eval(layoutJS)
	if v := u.violations("narrow"); len(v) > 0 {
		t.Fatalf("endpoints tab at phone width:\n  %s", strings.Join(v, "\n  "))
	}
	_ = domain.ScanCompleted
}

// ---- from the independent review: the UI must not say "all tested"/"clean" it cannot know ----

func TestUIEndpointsLiveRefreshKeepsKeyboardFocus(t *testing.T) {
	u, w := explorerUIWorld(t, web.Capabilities{})
	u.openScanTab(w.scan, "endpoints")
	u.waitUI("rows", `document.querySelectorAll('#endpointsBody > tr[data-endpoint-id]').length===3`)
	u.eval(`window.__exp = 0; window.__expDone = 0; (function(){ var of = window.fetch; window.fetch = function(u){
	  var p = of.apply(this, arguments);
	  if (String(u).indexOf('/explorer') >= 0) { window.__exp++; p.then(function(){ window.__expDone++; }); }
	  return p; }; })(); true`)
	sel := `#endpointsBody > tr[data-endpoint-id="` + string(w.search) + `"] button.row-toggle`
	u.eval(`window.__btn = document.querySelector('` + sel + `'); window.__btn.focus(); true`)
	u.eval(`refreshNow(); true`)
	u.waitUI("the refresh request finished", `window.__expDone >= 1`)
	time.Sleep(300 * time.Millisecond) // let the (skipped) re-render, if any, happen
	if !u.evalBool(`window.__btn.isConnected && document.activeElement === window.__btn`) {
		t.Fatal("a live refresh with unchanged data must not rebuild the table and drop keyboard focus")
	}
}

func TestUIRunningScanNeverReadsAsAllTested(t *testing.T) {
	u := newUIHarnessWith(t, "", web.Capabilities{BrowserEnabled: true})
	scanID := uiFindingsScan(t, u)
	w := &explorerWorld{a: api{t: t, st: u.st}, scan: scanID}
	w.setState(domain.ScanRunning)
	e := w.endpoint(domain.MethodPOST, "http://127.0.0.1:1/q")
	_, ip := w.param(e, "x", domain.LocationForm, "1")
	j := w.job(domain.JobTest, domain.JobSucceeded, e, ip, "")
	w.tcase(j, ip, domain.VulnReflectedXSS, domain.TestCaseCompleted, domain.OutcomeSuccess, "reflected")
	w.job(domain.JobVerify, domain.JobQueued, e, ip, "")

	u.openScanTab(scanID, "endpoints")
	u.waitUI("summary", `document.querySelector('.coverage-summary strong')`)
	head := u.evalStr(`document.querySelector('.coverage-summary strong').textContent`)
	if strings.Contains(head, "Every discovered endpoint was tested") || !strings.Contains(head, "Testing in progress") {
		t.Fatalf("headline on a running scan = %q", head)
	}
	u.waitUI("row", `document.querySelector('#endpointsBody > tr[data-endpoint-id]')`)
	if row := u.evalStr(`document.querySelector('#endpointsBody > tr[data-endpoint-id]').textContent`); strings.Contains(row, "all tested") || !strings.Contains(row, "1 pending") || !strings.Contains(row, "1 parameter ") {
		t.Fatalf("a pending parameter must not read as 'all tested' (and 1 is singular): %q", row)
	}

	u.mustClickText(".tabs a", "Coverage")
	u.waitUI("coverage summary", `document.querySelector('.coverage-summary strong')`)
	if u.evalBool(`document.querySelector('.coverage-summary.clean')`) || !u.evalBool(`/still running/.test(document.querySelector('.coverage-summary strong').textContent)`) {
		t.Fatalf("a running scan is not 'clean' yet: %q", u.evalStr(`document.querySelector('.coverage-summary').textContent`))
	}
}

func TestUIFailedScanOverviewWarnsEvenThoughEverythingRecordedPassed(t *testing.T) {
	u := newUIHarnessWith(t, "", web.Capabilities{BrowserEnabled: true})
	scanID := uiFindingsScan(t, u)
	w := &explorerWorld{a: api{t: t, st: u.st}, scan: scanID}
	w.setState(domain.ScanFailed)
	seedUITest(t, u, scanID, domain.VulnReflectedXSS, domain.TestCaseCompleted, domain.OutcomeSuccess, "http://127.0.0.1:9/x?q=1", "not reflected")
	u.openScanTab(scanID, "overview")
	u.waitUI("failed banner", `document.querySelector('#coverageHost .banner[data-code="scan_failed"]')`)
	u.waitUI("gap badge", `document.querySelector('.page-head .gap-badge')`)
}
