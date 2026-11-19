package scan

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
)

func TestDOMClobberingWithScriptsGenericFormPolicyGate(t *testing.T) {
	env := newScanEnv(t)
	ep := env.endpoint("http://target.example/profile", domain.MethodGET)
	job := &domain.TestJob{ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobDOMXSS, Attempts: 1}

	exec := newDOMXSSExecutor(env.st, nil, env.ev,
		domain.Scope{IncludeHosts: []string{"target.example"}}, execLog(), &sync.Mutex{})

	pageScripts := domXSSPageScripts{
		HTML: `<form action="/profile/bio" method="POST"><input type="hidden" name="csrf" value="abc"><textarea name="bio"></textarea></form>`,
		Scripts: []detection.DOMXSSExternalScript{
			{URL: "http://target.example/app.js", Body: `const cfg = window.siteConfig || { themeUrl: "/default.css" };`},
		},
	}

	// nil browser context proves the policy gate fires before any page work.
	exec.probeDOMClobberingWithScripts(context.Background(), nil, job, ep, "indmarker", pageScripts, nil)

	tc := env.only()
	if tc.Status != domain.TestCaseSkipped {
		t.Fatalf("status = %s, want skipped", tc.Status)
	}
	if !strings.Contains(tc.Note, "AllowStateChanging") {
		t.Fatalf("skip note = %q, want AllowStateChanging", tc.Note)
	}
}

func TestDOMClobberingWithScriptsNoSurfaceIsNoOp(t *testing.T) {
	env := newScanEnv(t)
	ep := env.endpoint("http://target.example/clean", domain.MethodGET)
	job := &domain.TestJob{ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobDOMXSS, Attempts: 1}

	exec := newDOMXSSExecutor(env.st, nil, env.ev,
		domain.Scope{IncludeHosts: []string{"target.example"}}, execLog(), &sync.Mutex{})

	pageScripts := domXSSPageScripts{
		HTML: `<html><body><p>Hello</p></body></html>`,
	}
	exec.probeDOMClobberingWithScripts(context.Background(), nil, job, ep, "indmarker", pageScripts, nil)

	cases, err := env.st.TestCases().ListByScan(context.Background(), env.scanID)
	if err != nil {
		t.Fatalf("list test cases: %v", err)
	}
	if len(cases) != 0 {
		t.Fatalf("expected 0 test cases when no clobbering surface exists, got %d", len(cases))
	}
}
