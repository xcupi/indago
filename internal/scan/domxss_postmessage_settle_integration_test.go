//go:build browser_integration

package scan

// Regression coverage for the postMessage probe that could hang a whole browser
// worker: it resolved ONLY from the sender frame's load event, so a document
// that never lets that frame load (a sanitizer or SPA re-render that strips it,
// a root that stops accepting children, a document replaced mid-probe) left the
// promise pending. Page.Evaluate then blocked until the worker pool's job
// deadline (15 minutes by default), and with BrowserConcurrency: 1 the entire
// browser group stopped with it.
//
// The probe now has two independent settle guarantees, and both are covered
// here:
//  1. the script's own fallback bound (a page that never loads the frame);
//  2. the scan-side per-call Evaluate deadline, which still holds when the page
//     sabotages the timer functions the fallback needs.
//
// These tests deliberately avoid the fix's new Go identifiers (they assert on
// behaviour and on the wire status string), so the same test file compiles
// against the pre-fix code and fails there as an ASSERTION: the probe never
// settles, Evaluate returns the test's own context deadline, and the elapsed
// assertion reports how long it took.
//
// Every fixture is local (httptest) and no external target is ever contacted.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/domain"
)

// domXSSIndeterminateStatus is the wire status a bounded, non-delivered probe
// must report. Spelled as a literal on purpose (see the file comment).
const domXSSIndeterminateStatus = "indago-domxss-postmessage-indeterminate"

// postMessageSettleBound is how long the probe may take to answer. It is far
// below any worker deadline and well above both settle guarantees.
const postMessageSettleBound = 10 * time.Second

// postMessageProbeDeadline bounds the test itself so a pre-fix hang is reported
// as a failing assertion instead of a hung test binary.
const postMessageProbeDeadline = 20 * time.Second

const postMessageSinkPage = `<!doctype html><body><div id="sink"></div><script>
window.addEventListener('message', function (e) { document.getElementById('sink').innerHTML = e.data; });
</script>`

// stripSenderFrame removes any appended iframe before its load event can run:
// a page sanitizer, or an SPA that re-renders its body right after load.
const stripSenderFrame = `new MutationObserver(function (records) {
  for (const record of records) for (const node of record.addedNodes) {
    if (node.tagName === 'IFRAME') node.remove();
  }
}).observe(document.documentElement, {childList: true, subtree: true});`

func newPostMessageSettleLab(t *testing.T) string {
	t.Helper()
	lab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		switch r.URL.Path {
		case "/iframe-stripped":
			fmt.Fprint(w, `<!doctype html><body><div id="sink"></div><script>`+stripSenderFrame+`</script>`)
		case "/append-dropped":
			// A stub that never fires load: the root silently refuses the
			// sender frame, so no load (and no error) can ever be observed.
			fmt.Fprint(w, `<!doctype html><body><div id="sink"></div><script>
const nativeAppend = Node.prototype.appendChild;
Node.prototype.appendChild = function (node) {
  if (node && node.tagName === 'IFRAME') return node;
  return nativeAppend.call(this, node);
};
</script>`)
		case "/timer-frozen":
			// Neutralizes the timer functions the script-level fallback relies
			// on (fake timers) AND strips the sender frame. Only the scan-side
			// per-call deadline can settle this probe.
			fmt.Fprint(w, `<!doctype html><body><div id="sink"></div><script>
window.setTimeout = function () { return 0; };
`+stripSenderFrame+`</script>`)
		case "/healthy":
			fmt.Fprint(w, postMessageSinkPage)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(lab.Close)
	return lab.URL
}

// TestDOMXSSPostMessageProbeAlwaysSettles covers the script-level guarantee for
// every document shape in which the sender frame cannot load. The probe must
// answer, and the answer must be the distinct indeterminate status — never
// "sent", which would make an absent sink look like a clean negative.
func TestDOMXSSPostMessageProbeAlwaysSettles(t *testing.T) {
	base := newPostMessageSettleLab(t)

	mgr := newSourceSelectionBrowser(t)
	defer mgr.Close()
	bctx, err := mgr.NewContext(context.Background(), browser.ContextOptions{})
	if err != nil {
		t.Fatalf("create browser context: %v", err)
	}
	defer bctx.Close()

	run := func(path string) (status any, elapsed time.Duration, err error) {
		page, err := bctx.NewPage(context.Background())
		if err != nil {
			return nil, 0, err
		}
		defer page.Close()
		if _, err := page.Navigate(context.Background(), base+path, browser.NavOptions{WaitUntil: browser.WaitLoad}); err != nil {
			return nil, 0, fmt.Errorf("navigate %s: %w", path, err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), postMessageProbeDeadline)
		defer cancel()
		start := time.Now()
		status, err = page.Evaluate(ctx, postMessageScript("PAYLOAD-"+path[1:]))
		return status, time.Since(start), err
	}

	for _, path := range []string{"/iframe-stripped", "/append-dropped"} {
		t.Run(path, func(t *testing.T) {
			status, elapsed, err := run(path)
			if err != nil {
				t.Fatalf("postMessage probe did not settle: %v (after %s) — a probe that never resolves blocks Evaluate until the worker's job deadline", err, elapsed)
			}
			if elapsed > postMessageSettleBound {
				t.Fatalf("probe settled after %s, want under %s: the bound must be probe-local, not a job-scale timeout", elapsed, postMessageSettleBound)
			}
			got, _ := status.(string)
			if got == domXSSPostMessageSent {
				t.Fatalf("probe reported a delivery after %s although the sender frame never loaded (status %q)", elapsed, got)
			}
			if got != domXSSIndeterminateStatus {
				t.Fatalf("probe status = %q (%T), want the distinct indeterminate outcome %q", got, status, domXSSIndeterminateStatus)
			}
		})
	}

	t.Run("/healthy", func(t *testing.T) {
		// The good path must be untouched: a page where the frame loads still
		// resolves as sent.
		status, elapsed, err := run("/healthy")
		if err != nil {
			t.Fatalf("healthy probe: %v", err)
		}
		if status != domXSSPostMessageSent {
			t.Fatalf("healthy page status = %q, want %q", status, domXSSPostMessageSent)
		}
		if elapsed > 5*time.Second {
			t.Fatalf("healthy probe took %s, want a prompt settle", elapsed)
		}
	})
}

// TestDOMXSSPostMessageIndeterminateIsRecordedNotNegative proves the ENGINE's
// handling: an undeterminable delivery is recorded as its own skipped outcome
// naming the missing coverage, no Finding is created (so it can never become
// Confirmed), and the job completes instead of retrying a deterministic refusal
// for the whole deadline.
//
// The timer-frozen document additionally proves the scan-side deadline: its
// script-level fallback cannot fire, so only evaluateDOMXSSScript's own bound
// can free the worker — and it does, in seconds.
func TestDOMXSSPostMessageIndeterminateIsRecordedNotNegative(t *testing.T) {
	base := newPostMessageSettleLab(t)

	mgr := newSourceSelectionBrowser(t)
	defer mgr.Close()

	for _, tc := range []struct {
		path string
		// minElapsed proves WHICH guarantee settled the probe: the frozen-timer
		// page cannot have used the script-level fallback.
		minElapsed time.Duration
		note       string
	}{
		{path: "/iframe-stripped", note: "script-level fallback"},
		{path: "/timer-frozen", minElapsed: 5 * time.Second, note: "scan-side per-call deadline"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			env := newScanEnv(t)
			ep := domXSSLabEndpoint(t, env, base+tc.path, "text/html")
			ex := newDOMXSSExecutor(env.st, mgr, env.ev, sourceSelectionScope(t, base), execLog(), &sync.Mutex{})

			ctx, cancel := context.WithTimeout(context.Background(), postMessageProbeDeadline)
			defer cancel()
			start := time.Now()
			err := ex.Handle(ctx, sourceSelectionJob(t, env.scanID, ep, "postMessage"))
			elapsed := time.Since(start)
			if err != nil {
				t.Fatalf("an undeterminable postMessage delivery must be recorded, not surfaced as a failure: %v (after %s, via %s)", err, elapsed, tc.note)
			}
			if elapsed > postMessageSettleBound {
				t.Fatalf("job took %s, want under %s", elapsed, postMessageSettleBound)
			}
			if elapsed < tc.minElapsed {
				t.Fatalf("job settled in %s, expected at least %s (%s)", elapsed, tc.minElapsed, tc.note)
			}

			if findings := sourceSelectionFindings(t, env.st, env.scanID, ep.ID); len(findings) != 0 {
				t.Fatalf("an undelivered probe must never create a finding (it could otherwise be confirmed): %+v", findings)
			}
			cases := domXSSTestCases(t, env)
			if len(cases) != 1 {
				t.Fatalf("want exactly one recorded probe outcome, got %d: %+v", len(cases), cases)
			}
			outcome := cases[0]
			if outcome.Status != domain.TestCaseSkipped {
				t.Fatalf("undeterminable delivery must be its own skip, got status %q (note %q, error %q)", outcome.Status, outcome.Note, outcome.Error)
			}
			for _, want := range []string{"could not be determined", "postMessage", "not a clean negative"} {
				if !strings.Contains(outcome.Note, want) {
					t.Fatalf("outcome note must explain %q, got %q", want, outcome.Note)
				}
			}
			if strings.Contains(outcome.Note, "no implemented DOM-XSS sink reachable") {
				t.Fatalf("an undelivered probe must not be recorded as a reachability negative: %q", outcome.Note)
			}
			if strings.Contains(outcome.Note, "confirmed") || strings.Contains(outcome.Note, "rejected") {
				t.Fatalf("an undelivered probe must not state a verdict: %q", outcome.Note)
			}
		})
	}
}

// TestDOMXSSPostMessageIndeterminateNeverReachesVerify proves the source-level
// contract the engine relies on: an undeterminable probe is its OWN error, so
// the caller can never mistake it for a delivered message (a clean negative) or
// for a page failure it should retry as if the payload had been delivered.
func TestDOMXSSPostMessageIndeterminateNeverReachesVerify(t *testing.T) {
	base := newPostMessageSettleLab(t)
	mgr := newSourceSelectionBrowser(t)
	defer mgr.Close()
	bctx, err := mgr.NewContext(context.Background(), browser.ContextOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer bctx.Close()

	ctx, cancel := context.WithTimeout(context.Background(), postMessageProbeDeadline)
	defer cancel()
	start := time.Now()
	_, err = (&domXSSExecutor{}).navigateWithPostMessage(ctx, bctx, base+"/iframe-stripped", "indagopostmessageindeterminate", "PAYLOAD", domXSSActivateNone)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("an undelivered probe must report an error, not a silent success")
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		t.Fatalf("the probe was still running when the caller gave up (%s after %s): it must settle itself", err, elapsed)
	}
	if elapsed > postMessageSettleBound {
		t.Fatalf("probe took %s, want under %s", elapsed, postMessageSettleBound)
	}
	if !strings.Contains(err.Error(), "indeterminate") || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("the error must state that delivery is unknown, got %q", err)
	}
}
