//go:build browser_integration

package scan

// Timing contract for the async-sink settle, measured against real Chromium.
//
//   - quiet window == the URL source's existing fixed observation window
//     (250ms), so a synchronous page keeps paying what it always paid;
//   - hard ceiling == quiet + domXSSNetworkSettleBudget (1.25s), so a request
//     that never answers cannot hold a DOM probe longer than that;
//   - an in-flight XHR is actually waited for before the observation.
//
// This file uses the new settle identifiers on purpose: it is not part of the
// pre-fix RED run (the behavioural fixture in
// domxss_async_settle_integration_test.go is). The lab is loopback httptest.

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/domain"
)

// asyncLabSettleCeiling is the per-observation hard bound the fix promises.
const asyncLabSettleCeiling = domXSSURLSourceObservationWindow + domXSSNetworkSettleBudget

func newAsyncLabPage(t *testing.T, labURL, path string) (*browser.Manager, *browser.Page) {
	t.Helper()
	mgr := newSourceSelectionBrowser(t)
	bctx, err := mgr.NewContext(context.Background(), browser.ContextOptions{})
	if err != nil {
		mgr.Close()
		t.Fatalf("create browser context: %v", err)
	}
	t.Cleanup(func() {
		_ = bctx.Close()
		_ = mgr.Close()
	})
	page, err := bctx.NewPage(context.Background())
	if err != nil {
		t.Fatalf("create page: %v", err)
	}
	t.Cleanup(func() { _ = page.Close() })
	if _, err := page.Navigate(context.Background(), labURL+path+"?search=probe", browser.NavOptions{WaitUntil: browser.WaitLoad}); err != nil {
		t.Fatalf("navigate %s: %v", path, err)
	}
	return mgr, page
}

// TestDOMXSSNetworkSettleSynchronousPageDoesNotPayFullBound measures the
// settle directly: a page with no async activity reaches quiet after the
// ordinary window and must return long before the hard ceiling.
func TestDOMXSSNetworkSettleSynchronousPageDoesNotPayFullBound(t *testing.T) {
	lab := newAsyncSinkLab(t)
	_, page := newAsyncLabPage(t, lab.URL, "/sync")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	settled, err := page.WaitNetworkIdle(ctx, domXSSURLSourceObservationWindow, asyncLabSettleCeiling)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("wait network idle: %v", err)
	}
	if !settled {
		t.Fatalf("a synchronous page must settle, got settled=false after %s", elapsed)
	}
	if elapsed >= asyncLabSettleCeiling {
		t.Fatalf("a page with no async activity paid the full ceiling (%s >= %s); the settle must return at the quiet window", elapsed, asyncLabSettleCeiling)
	}
	if elapsed > domXSSURLSourceObservationWindow+600*time.Millisecond {
		t.Fatalf("synchronous settle took %s, want about the %s quiet window and well under the %s ceiling", elapsed, domXSSURLSourceObservationWindow, asyncLabSettleCeiling)
	}
}

// TestDOMXSSNetworkSettleWaitsForInFlightRequest proves the quiet wait is not
// just a sleep: the slow XHR is still in flight after `load`, and the settle
// must not return until it has finished.
func TestDOMXSSNetworkSettleWaitsForInFlightRequest(t *testing.T) {
	lab := newAsyncSinkLab(t)
	_, page := newAsyncLabPage(t, lab.URL, "/slow")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	settled, err := page.WaitNetworkIdle(ctx, domXSSURLSourceObservationWindow, asyncLabSettleCeiling)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("wait network idle: %v", err)
	}
	if !settled {
		t.Fatalf("the slow XHR completes inside the ceiling, want settled=true (waited %s)", elapsed)
	}
	if elapsed < asyncLabSlowResponse/2 {
		t.Fatalf("settle returned after %s although the XHR response takes %s: it did not wait for in-flight work", elapsed, asyncLabSlowResponse)
	}
	if elapsed > asyncLabSettleCeiling {
		t.Fatalf("settle took %s, above its hard ceiling %s", elapsed, asyncLabSettleCeiling)
	}
}

// TestDOMXSSNetworkSettleGivesUpAtCeiling covers a request that never answers:
// the probe still returns, bounded, and reports that quiet was not observed.
func TestDOMXSSNetworkSettleGivesUpAtCeiling(t *testing.T) {
	lab := newAsyncSinkLab(t)
	_, page := newAsyncLabPage(t, lab.URL, "/hang")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	bounded := 600 * time.Millisecond
	start := time.Now()
	settled, err := page.WaitNetworkIdle(ctx, domXSSURLSourceObservationWindow, bounded)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("wait network idle: %v", err)
	}
	if settled {
		t.Fatalf("a hung request must not report quiet (waited %s)", elapsed)
	}
	if elapsed < bounded-100*time.Millisecond || elapsed > bounded+700*time.Millisecond {
		t.Fatalf("bound was not the requested %s: took %s", bounded, elapsed)
	}
}

// TestDOMXSSSynchronousPageKeepsItsNegativeResult keeps the behaviour
// assertion next to the timing one: a page with no async work and no marker in
// a sink stays a clean negative.
func TestDOMXSSSynchronousPageKeepsItsNegativeResult(t *testing.T) {
	mgr := newSourceSelectionBrowser(t)
	defer mgr.Close()
	lab := newAsyncSinkLab(t)
	env := newScanEnv(t)

	ep := env.endpoint(lab.URL+"/sync", domain.MethodGET)
	env.param(ep, "search", domain.LocationQuery, "unused")
	ex := newDOMXSSExecutor(env.st, mgr, env.ev, sourceSelectionScope(t, lab.URL), execLog(), &sync.Mutex{})
	if err := ex.Handle(context.Background(), sourceSelectionJob(t, env.scanID, ep, "location.search")); err != nil {
		t.Fatalf("dom-xss job: %v", err)
	}
	if findings := sourceSelectionFindings(t, env.st, env.scanID, ep.ID); len(findings) != 0 {
		t.Fatalf("a synchronous page with no sink must stay negative: %+v", findings)
	}
	cases, err := env.st.TestCases().ListByScan(context.Background(), env.scanID)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		if asyncLabPath(tc.URL) == "/sync" && strings.Contains(tc.Note, "no implemented DOM-XSS sink reachable") {
			if tc.Note != "" && strings.Contains(tc.Note, "settle") {
				t.Fatalf("a synchronous page must settle cleanly, note = %q", tc.Note)
			}
			return
		}
	}
	t.Fatalf("no negative reachability diagnostic for the synchronous page, cases=%+v", cases)
}
