package web_test

import (
	"os/exec"
	"testing"
	"time"
)

func TestUICooldownClock(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node.js unavailable for controlled-clock JavaScript tests")
	}
	out, err := exec.Command(node, "--test", "testdata/ui_cooldown_test.cjs").CombinedOutput()
	if err != nil {
		t.Fatalf("UI cooldown tests: %v\n%s", err, out)
	}
	t.Log(string(out))
}

func TestUIPollDoesNotOverlapPendingRefresh(t *testing.T) {
	u := newUIHarness(t)
	u.waitUI("dashboard ready", `document.querySelector('#view h1')?.textContent === 'Dashboard'`)
	u.eval(`prefs.set('refreshMs','500');window.pollCount=0;window.pollReleases=[];defineRoute('poll-test', /^\/poll-test$/, async()=>async()=>{window.pollCount++;await new Promise(r=>pollReleases.push(r));});navigate('#/poll-test');true`)
	u.waitUI("first poll pending", `pollCount>=1`)
	time.Sleep(1600 * time.Millisecond)
	if got := u.evalStr(`pollCount`); got != "1" {
		t.Fatalf("polling accumulated pending refreshes: %s", got)
	}
	u.eval(`navigate('#/projects');pollReleases.forEach(r=>r());true`)
}

func TestUIThrottledInitialScanLoadOffersRetry(t *testing.T) {
	u := newUIHarness(t)
	scanID := uiFindingsScan(t, u)
	u.eval(`prefs.set('refreshMs','off');window.nativeFetch=window.fetch;window.fetch=(url,opts)=>String(url).endsWith('/status')?Promise.resolve(new Response('{}',{status:429,headers:{'Retry-After':'1'}})):nativeFetch(url,opts);true`)
	u.openScanTab(scanID, "overview")
	u.waitUI("initial read retries exhausted", `document.querySelector('#view').textContent.includes('Scan')`)
	if u.evalBool(`document.querySelector('#view').textContent.includes('Scan not found')`) {
		t.Fatal("throttled scan presented as missing")
	}
	if !u.evalBool(`!document.querySelector('#refreshNow').classList.contains('hidden')`) {
		t.Fatal("no actionable Refresh after retry limit")
	}
}

func TestUIRouteIgnoresLateRender(t *testing.T) {
	u := newUIHarness(t)
	u.waitUI("initial dashboard", `document.querySelector('#view h1')?.textContent === 'Dashboard'`)
	u.eval(`defineRoute('slow-test', /^\/slow-test$/, async (_p,v)=>{await new Promise(r=>window.releaseSlow=r);v.appendChild(el('p','STALE ROUTE'));});defineRoute('fast-test', /^\/fast-test$/, async (_p,v)=>v.appendChild(el('h1','CURRENT ROUTE')));navigate('#/slow-test');true`)
	u.waitUI("slow render started", `typeof window.releaseSlow === 'function'`)
	u.eval(`navigate('#/fast-test');true`)
	u.waitUI("new route", `document.querySelector('#view h1')?.textContent === 'CURRENT ROUTE'`)
	u.eval(`window.releaseSlow();true`)
	// Evaluation awaits a turn after the slow promise resumes.
	if u.evalBool(`document.querySelector('#view').textContent.includes('STALE ROUTE')`) {
		t.Fatal("late prior route rendered into current view")
	}
}
