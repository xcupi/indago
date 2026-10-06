package web_test

// Real-browser tests for the scan-detail live-refresh architecture: the
// Findings and Evidence tabs must update in place (no teardown, no flicker, no
// lost expand/scroll state), refresh must not race route changes, the timer
// must stop on leave, the interval setting (incl. Off + manual refresh) must be
// honored, and changed data must patch the existing rows rather than replace
// the view.

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/scan"
)

// seedScanWithFindings creates a (created-state, quiescent) scan with n seeded
// pending findings in the harness store, and returns its ID. A created scan
// enqueues no jobs, so status/findings are fully static — ideal for asserting
// that refresh changes nothing in the DOM.
func (u *uiHarness) seedScanWithFindings(n int) (string, []*domain.Finding) {
	u.t.Helper()
	ctx := context.Background()
	now := time.Now()
	proj := &domain.Project{ID: domain.NewID(), Name: "Refresh Project", CreatedAt: now, UpdatedAt: now}
	if err := u.st.Projects().Create(ctx, proj); err != nil {
		u.t.Fatal(err)
	}
	scope := &domain.Scope{ID: domain.NewID(), ProjectID: proj.ID, IncludeHosts: []string{"127.0.0.1"}, CreatedAt: now, UpdatedAt: now}
	if err := u.st.Scopes().Create(ctx, scope); err != nil {
		u.t.Fatal(err)
	}
	tgt := &domain.Target{ID: domain.NewID(), ProjectID: proj.ID, Name: "t", BaseURL: "http://127.0.0.1/", CreatedAt: now, UpdatedAt: now}
	if err := u.st.Targets().Create(ctx, tgt); err != nil {
		u.t.Fatal(err)
	}
	sc, err := u.ctrl.CreateScan(ctx, scan.CreateScanParams{ProjectID: proj.ID, TargetID: tgt.ID, Name: "refresh"})
	if err != nil {
		u.t.Fatal(err)
	}
	var findings []*domain.Finding
	for i := 0; i < n; i++ {
		f, _, _ := seedFinding(u.t, api{t: u.t, st: u.st, ev: u.ev}, sc.ID)
		findings = append(findings, f)
	}
	return string(sc.ID), findings
}

func (u *uiHarness) setRefreshPref(v string) {
	u.eval(fmt.Sprintf(`try{localStorage.setItem('indago.refreshMs',%q)}catch(e){}`, v))
}
func (u *uiHarness) goHash(h string) {
	b, _ := json.Marshal(h)
	u.eval("location.hash=" + string(b))
}

func TestUIScanDetailRefreshStable(t *testing.T) {
	u := newUIHarness(t)
	u.setRefreshPref("5000") // 5s so a tick fires within the test
	scanID, findings := u.seedScanWithFindings(2)

	// --- Findings tab: stable across a refresh tick ---
	u.goHash("#/scans/" + scanID + "/findings")
	u.waitUI("findings rows", `document.querySelectorAll('#findingsBody tr[data-fid]').length===2`)
	// Expand the first finding and tag the row + tbody to detect any rebuild.
	u.eval(`document.querySelector('#findingsBody tr[data-fid] td.clickable').click()`)
	u.waitUI("detail expanded", `document.querySelectorAll('#findingsBody tr.finding-detail').length===1`)
	u.eval(`document.querySelector('#findingsBody tr[data-fid]').dataset.mark='row';document.getElementById('findingsBody').dataset.mark='body'`)
	time.Sleep(6500 * time.Millisecond) // span a refresh tick
	if u.evalStr(`document.querySelectorAll('#findingsBody tr[data-fid]').length`) != "2" {
		t.Fatal("findings row count changed across refresh")
	}
	if !u.evalBool(`document.getElementById('findingsBody').dataset.mark==='body'`) {
		t.Fatal("findings tbody was rebuilt across refresh (full re-render)")
	}
	if !u.evalBool(`document.querySelector('#findingsBody tr[data-fid]').dataset.mark==='row'`) {
		t.Fatal("finding row node was replaced across refresh (DOM churn)")
	}
	if u.evalStr(`document.querySelectorAll('#findingsBody tr.finding-detail').length`) != "1" {
		t.Fatal("expanded detail row lost across refresh")
	}
	if u.evalBool(`/loading/.test(document.getElementById('tabPanel').textContent)`) {
		t.Fatal("loading placeholder flashed during refresh")
	}

	// --- Changed data patches in place (verdict promotion) ---
	f0 := findings[0]
	f0.Verdict = domain.VerdictConfirmed
	f0.UpdatedAt = time.Now()
	if err := u.st.Findings().Update(context.Background(), f0); err != nil {
		t.Fatal(err)
	}
	u.waitUI("verdict promoted in place",
		`[...document.querySelectorAll('#findingsBody tr[data-fid]')].some(tr=>tr.dataset.verdict==='confirmed')`)
	// The tbody must NOT have been rebuilt to show the change.
	if !u.evalBool(`document.getElementById('findingsBody').dataset.mark==='body'`) {
		t.Fatal("findings tbody rebuilt to reflect a verdict change (should patch in place)")
	}

	// --- Switching tabs while refresh is active ---
	u.mustClickText(".tabs a", "Jobs")
	u.waitUI("jobs tab", `/Test outcomes/.test(document.getElementById('tabPanel').textContent)`)
	time.Sleep(5500 * time.Millisecond) // a tick on the jobs tab
	if u.evalBool(`document.getElementById('findingsBody')!==null`) {
		t.Fatal("stale findings tab reappeared after switching tabs")
	}
	if !u.evalBool(`/Test outcomes/.test(document.getElementById('tabPanel').textContent)`) {
		t.Fatal("active tab not stable under refresh")
	}

	// --- Evidence tab: stable across a refresh tick ---
	u.mustClickText(".tabs a", "Evidence")
	u.waitUI("evidence rows", `document.querySelectorAll('#evidenceBody tr[data-eid]').length>=1`)
	u.eval(`document.getElementById('evidenceBody').dataset.mark='ev'`)
	time.Sleep(6500 * time.Millisecond)
	if !u.evalBool(`document.getElementById('evidenceBody').dataset.mark==='ev'`) {
		t.Fatal("evidence tbody rebuilt across refresh")
	}

	// --- Leaving and re-entering the scan view ---
	u.mustClickText("#sidebar a", "Scans")
	u.waitUI("on scans list", `document.getElementById('view').dataset.view==='scans'`)
	u.goHash("#/scans/" + scanID + "/findings")
	u.waitUI("findings render again", `document.querySelectorAll('#findingsBody tr[data-fid]').length===2`)
}

func TestUIRefreshSettingOffAndInterval(t *testing.T) {
	u := newUIHarness(t)
	scanID, findings := u.seedScanWithFindings(1)

	// --- Off: no polling timer; a data change does NOT appear on its own ---
	u.setRefreshPref("0")
	u.goHash("#/scans/" + scanID + "/overview")
	u.waitUI("overview rendered", `/State/.test(document.getElementById('tabPanel').textContent)`)
	if !u.evalBool(`currentView.timer===null`) {
		t.Fatal("a refresh timer was created while the setting is Off")
	}
	// Promote the finding in the store; with Off, the Overview findings metric
	// must not change on its own.
	f := findings[0]
	f.Verdict = domain.VerdictConfirmed
	f.UpdatedAt = time.Now()
	if err := u.st.Findings().Update(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	time.Sleep(3 * time.Second)
	if u.evalBool(`/C\s*1/.test(document.getElementById('tabPanel').textContent)`) {
		t.Fatal("view updated while refresh is Off (a timer must be running)")
	}
	// Manual Refresh works with the setting Off.
	u.mustClickText(".page-head button", "Refresh")
	u.waitUI("manual refresh applied", `/C\s*1/.test(document.getElementById('tabPanel').textContent)`)

	// --- Interval change persists as a browser-local preference ---
	u.mustClickText("#sidebar a", "Settings")
	u.waitUI("settings view", `document.getElementById('set_refresh')!==null`)
	u.setVal("set_refresh", "30000")
	u.waitUI("pref stored", `(function(){try{return localStorage.getItem('indago.refreshMs')==='30000'}catch(e){return false}})()`)
	// Options offered are exactly Off/5/10/30/60s.
	got := u.evalStr(`[...document.getElementById('set_refresh').options].map(o=>o.value).join(',')`)
	if got != "0,5000,10000,30000,60000" {
		t.Fatalf("refresh options = %q, want 0,5000,10000,30000,60000", got)
	}
}
