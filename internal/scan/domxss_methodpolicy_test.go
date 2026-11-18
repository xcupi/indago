package scan

// The DOM engine's comment-form clobbering probe persists a payload through the
// page's own POST form — the only state-changing step in that engine. With the
// scan's AllowStateChanging opt-in off it must record a skipped test case
// without opening a page; the browser context's method gate would refuse the
// POST in any case (see internal/browser's method-gate tests).

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/indago/indago/internal/domain"
)

func TestDOMClobberingProbeSkippedWithoutStateChangingOptIn(t *testing.T) {
	env := newScanEnv(t)
	ep := env.endpoint("http://target.example/post", domain.MethodGET)
	job := &domain.TestJob{ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobDOMXSS, Attempts: 1}

	// A nil browser context is deliberate: the policy check must happen before
	// any page is opened, so touching it would panic if the guard regressed.
	exec := newDOMXSSExecutor(env.st, nil, env.ev,
		domain.Scope{IncludeHosts: []string{"target.example"}}, execLog(), &sync.Mutex{})
	exec.probeDOMClobbering(context.Background(), nil, job, ep, "indmarker",
		"<html>loadComments post/comment dompurify</html>")

	tc := env.only()
	if tc.Status != domain.TestCaseSkipped {
		t.Fatalf("status = %s, want skipped when AllowStateChanging is off", tc.Status)
	}
	if !strings.Contains(tc.Note, "AllowStateChanging") {
		t.Fatalf("skip note %q does not name the missing AllowStateChanging opt-in", tc.Note)
	}
	if tc.Outcome != "" || tc.Error != "" {
		t.Fatalf("skipped probe recorded outcome=%q error=%q, want neither", tc.Outcome, tc.Error)
	}
}

// SkipWriteEndpoints suppresses the same probe even when AllowStateChanging is
// on: the comment it persists outlives the scan, so a read-only scan must not
// create it.
func TestDOMClobberingProbeSkippedWithSkipWriteEndpoints(t *testing.T) {
	env := newScanEnv(t)
	ep := env.endpoint("http://target.example/post", domain.MethodGET)
	job := &domain.TestJob{ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobDOMXSS, Attempts: 1}

	// nil browser context again proves the guard runs before any page work.
	exec := newDOMXSSExecutor(env.st, nil, env.ev,
		domain.Scope{IncludeHosts: []string{"target.example"}}, execLog(), &sync.Mutex{})
	exec.allowStateChanging = true
	exec.skipWriteEndpoints = true
	exec.probeDOMClobbering(context.Background(), nil, job, ep, "indmarker",
		"<html>loadComments post/comment dompurify</html>")

	tc := env.only()
	if tc.Status != domain.TestCaseSkipped {
		t.Fatalf("status = %s, want skipped when SkipWriteEndpoints is on", tc.Status)
	}
	if !strings.Contains(tc.Note, "SkipWriteEndpoints") {
		t.Fatalf("skip note %q does not name SkipWriteEndpoints", tc.Note)
	}
	if tc.Outcome != "" || tc.Error != "" {
		t.Fatalf("skipped probe recorded outcome=%q error=%q, want neither", tc.Outcome, tc.Error)
	}
}
