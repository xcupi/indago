package web_test

import (
	"testing"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/web"
)

// DOM-XSS verification now fails the job so the worker's bounded retry owns
// recovery. The explorer must read the job's FINAL state, not just the last
// completed test: a transient failure is progress while the scan runs, a
// recovered retry is tested even though history contains an error, and a
// dead/canceled job behind a completed canary is partial.

func TestExplorerDOMRetryPendingIsProgressNotAGap(t *testing.T) {
	a, id := coverageAPI(t, web.Capabilities{BrowserEnabled: true})
	w := &explorerWorld{a: a, scan: id}
	w.setState(domain.ScanRunning)
	e := w.endpoint(domain.MethodGET, "http://127.0.0.1:1/retry")
	j := w.job(domain.JobDOMXSS, domain.JobFailed, e, nil, srcHash)
	w.tcase(j, nil, domain.VulnDOMXSS, domain.TestCaseCompleted, domain.OutcomeSuccess, "reachable sink: innerHTML from location.hash")
	w.tcase(j, nil, domain.VulnDOMXSS, domain.TestCaseFailed, domain.OutcomeError, `verification navigation for location.hash`)
	d := w.get("").find(string(e.ID)).dom("location.hash")
	if d == nil || d.Status != "pending" || d.Gap || d.ReasonCode != "job_failed" {
		t.Fatalf("a retryable failed job on a running scan is pending progress, not a gap: %+v", d)
	}
}

func TestExplorerDOMRetryRecoveredIsTestedAndKeepsErrorHistory(t *testing.T) {
	a, id := coverageAPI(t, web.Capabilities{BrowserEnabled: true})
	w := &explorerWorld{a: a, scan: id}
	w.setState(domain.ScanCompleted)
	e := w.endpoint(domain.MethodGET, "http://127.0.0.1:1/recovered")
	j := w.job(domain.JobDOMXSS, domain.JobSucceeded, e, nil, srcHash)
	w.tcase(j, nil, domain.VulnDOMXSS, domain.TestCaseCompleted, domain.OutcomeSuccess, "reachable sink: innerHTML from location.hash")
	w.tcase(j, nil, domain.VulnDOMXSS, domain.TestCaseFailed, domain.OutcomeError, `verification navigation for location.hash`)
	w.tcase(j, nil, domain.VulnDOMXSS, domain.TestCaseCompleted, domain.OutcomeSuccess, "reachable sink: innerHTML from location.hash")
	w.tcase(j, nil, domain.VulnDOMXSS, domain.TestCaseCompleted, domain.OutcomeSuccess, "the browser reported the marker as an unresolved JavaScript identifier")
	d := w.get("").find(string(e.ID)).dom("location.hash")
	if d == nil || d.Status != "tested" || d.Gap {
		t.Fatalf("a job that ultimately succeeded after a retry is tested: %+v", d)
	}
	if d.Tests.Failed != 1 || d.Tests.Completed != 3 {
		t.Fatalf("the failed first attempt must stay visible in the truthful error count: %+v", d.Tests)
	}
}

func TestExplorerDOMDeadAfterCanaryAndSelectorsIsPartial(t *testing.T) {
	a, id := coverageAPI(t, web.Capabilities{BrowserEnabled: true})
	w := &explorerWorld{a: a, scan: id}
	w.setState(domain.ScanCompleted)
	e := w.endpoint(domain.MethodGET, "http://127.0.0.1:1/dead")
	j := w.job(domain.JobDOMXSS, domain.JobDead, e, nil, srcHash)
	// Two selectors both reached the sink, then the second selector's payload
	// navigation exhausted its retries. A completed canary for one selector
	// must not hide the dead job.
	w.tcase(j, nil, domain.VulnDOMXSS, domain.TestCaseCompleted, domain.OutcomeSuccess, `reachable sink: innerHTML from location.hash parameter "a"`)
	w.tcase(j, nil, domain.VulnDOMXSS, domain.TestCaseFailed, domain.OutcomeError, `verification navigation for location.hash parameter "b"`)
	w.tcase(j, nil, domain.VulnDOMXSS, domain.TestCaseCompleted, domain.OutcomeSuccess, `reachable sink: innerHTML from location.hash parameter "b"`)
	d := w.get("").find(string(e.ID)).dom("location.hash")
	if d == nil || d.Status != "partial" || !d.Gap || d.ReasonCode != "job_dead" {
		t.Fatalf("a completed canary must not hide an exhausted verification job: %+v", d)
	}
}

func TestExplorerDOMCanceledAfterCanaryIsPartial(t *testing.T) {
	a, id := coverageAPI(t, web.Capabilities{BrowserEnabled: true})
	w := &explorerWorld{a: a, scan: id}
	w.setState(domain.ScanCompleted)
	e := w.endpoint(domain.MethodGET, "http://127.0.0.1:1/canceled")
	j := w.job(domain.JobDOMXSS, domain.JobCanceled, e, nil, srcHash)
	w.tcase(j, nil, domain.VulnDOMXSS, domain.TestCaseCompleted, domain.OutcomeSuccess, "reachable sink: innerHTML from location.hash")
	w.tcase(j, nil, domain.VulnDOMXSS, domain.TestCaseCancelled, domain.OutcomeCancelled, `verification navigation for location.hash`)
	d := w.get("").find(string(e.ID)).dom("location.hash")
	if d == nil || d.Status != "partial" || !d.Gap || d.ReasonCode != "job_canceled" {
		t.Fatalf("a canceled verification behind a completed canary is partial: %+v", d)
	}
}

func TestExplorerDeadDOMSourceDoesNotDowngradeSucceededSource(t *testing.T) {
	a, id := coverageAPI(t, web.Capabilities{BrowserEnabled: true})
	w := &explorerWorld{a: a, scan: id}
	w.setState(domain.ScanCompleted)
	e := w.endpoint(domain.MethodGET, "http://127.0.0.1:1/mixed")
	dead := w.job(domain.JobDOMXSS, domain.JobDead, e, nil, srcHash)
	w.tcase(dead, nil, domain.VulnDOMXSS, domain.TestCaseCompleted, domain.OutcomeSuccess, "reachable sink: innerHTML from location.hash")
	w.tcase(dead, nil, domain.VulnDOMXSS, domain.TestCaseFailed, domain.OutcomeError, "verification navigation for location.hash")
	ok := w.job(domain.JobDOMXSS, domain.JobSucceeded, e, nil, srcPostM)
	w.tcase(ok, nil, domain.VulnDOMXSS, domain.TestCaseCompleted, domain.OutcomeSuccess, "no implemented DOM-XSS sink reachable from postMessage (negative result)")
	got := w.get("").find(string(e.ID))
	if got == nil {
		t.Fatal("endpoint missing")
	}
	hash, post := got.dom("location.hash"), got.dom("postMessage")
	if hash == nil || hash.Status != "partial" || !hash.Gap {
		t.Fatalf("the dead source must stay partial: %+v", hash)
	}
	if post == nil || post.Status != "tested" || post.Gap {
		t.Fatalf("a different source that finished cleanly must not be downgraded: %+v", post)
	}
	if !got.Gap {
		t.Fatal("the endpoint must be flagged because one DOM source is a gap")
	}
	if r := w.get(""); r.Summary.DOMGaps != 1 {
		t.Fatalf("dom_gaps must count only the genuinely partial source: %+v", r.Summary)
	}
}
