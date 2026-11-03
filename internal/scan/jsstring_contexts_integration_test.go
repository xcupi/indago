//go:build browser_integration

package scan_test

// Real-Chromium pipeline for the three authorized PortSwigger lab shapes built
// by jsstring_fixture_test.go: discovery → reflection → context → candidate →
// real HTTP → real-browser verification → finding.
//
// Registered as a required root in scripts/ci-browser-check.py so a skip or a
// missing root fails the browser preflight.

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/evidence"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/scan"
	"github.com/indago/indago/internal/store/memory"
)

// jsStringAttempt mirrors the verification-attempt record Finding.Detail
// carries for a Reflected XSS finding.
type jsStringAttempt struct {
	CandidateValue string         `json:"candidate_value"`
	Verdict        domain.Verdict `json:"verdict"`
	Notes          string         `json:"notes"`
}

func jsStringAttempts(f *domain.Finding) []jsStringAttempt {
	var d struct {
		Attempts []jsStringAttempt `json:"attempts"`
	}
	_ = json.Unmarshal(f.Detail, &d)
	return d.Attempts
}

// TestReflectedJSStringContexts drives the full reflected pipeline against the
// three lab shapes and their controls.
func TestReflectedJSStringContexts(t *testing.T) {
	ctx := context.Background()
	lab := newJSStringLab(t)
	st, q := memory.New(), queue.NewMemory()
	ev, err := evidence.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mgr := newBrowserManagerOrSkip(t, 2)
	defer mgr.Close()

	proj, tgt := seedProject(t, st, lab.URL, domain.Scope{IncludeHosts: []string{"127.0.0.1"}})
	cfg := domain.ScanConfig{DiscoveryConcurrency: 4, HTTPConcurrency: 8, BrowserConcurrency: 4}
	ctrl := newCtrl(t, st, q, scan.Options{Browser: mgr, Evidence: ev})
	sc := createScan(t, ctrl, proj, tgt, &cfg, domain.StopPolicy{})

	if err := ctrl.Start(ctx, sc.ID); err != nil {
		t.Fatal(err)
	}
	done := waitStatus(t, ctrl, sc.ID, 180*time.Second, isCompleted)
	t.Logf("findings: breakdown=%+v", done.Findings)

	findings, err := st.Findings().ListByScan(ctx, sc.ID)
	if err != nil {
		t.Fatal(err)
	}
	byPath := map[string][]*domain.Finding{}
	for _, f := range findings {
		if ep, err := st.Endpoints().Get(ctx, f.EndpointID); err == nil {
			byPath[urlPath(ep.URL)] = append(byPath[urlPath(ep.URL)], f)
		}
	}
	// Measurement record: exactly what the candidate set produced.
	for p, fs := range byPath {
		for _, f := range fs {
			for _, a := range jsStringAttempts(f) {
				t.Logf("%s finding=%s attempt=%s %q notes=%q", p, f.Verdict, a.Verdict, a.CandidateValue, a.Notes)
			}
		}
	}

	confirmedCandidate := func(f *domain.Finding) string {
		for _, a := range jsStringAttempts(f) {
			if a.Verdict == domain.VerdictConfirmed {
				return a.CandidateValue
			}
		}
		return ""
	}

	// Labs 1 and 2 must be confirmed by the shape each reader actually needs:
	// lab 1 escapes the backslash too, so only the literal </script> breakout
	// reaches code; lab 2 encodes < >, so only the leading-backslash break does.
	for _, want := range []struct {
		path     string
		contains string
	}{
		{"/lab1", "</script><script>"},
		{"/lab2", `\';`},
	} {
		fs := byPath[want.path]
		var confirmed *domain.Finding
		for _, f := range fs {
			if f.Verdict == domain.VerdictConfirmed {
				confirmed = f
				break
			}
		}
		if confirmed == nil {
			var got []domain.Verdict
			for _, f := range fs {
				got = append(got, f.Verdict)
			}
			t.Errorf("%s: verdicts = %v, want Confirmed (a real browser execution signal)", want.path, got)
			continue
		}
		if got := confirmedCandidate(confirmed); !strings.Contains(got, want.contains) {
			t.Errorf("%s: confirming candidate = %q, want a shape containing %q", want.path, got, want.contains)
		}
	}

	// Lab 3's template literal: the existing ${MARKER} candidate DOES reach an
	// executable position — the browser raises an uncaught ReferenceError whose
	// message names the marker — but the verdict is Inconclusive, not
	// Confirmed. Verification's provenance lexer is a deliberate ASCII
	// allow-list that refuses any position in a script containing a template
	// literal (docs/verdict-provenance.md: "a regex or template literal ...
	// yields Inconclusive instead of Confirmed"), so the exception cannot be
	// attributed to the marker identifier. Escape the template literal or its
	// backtick and the candidate would be wrong; changing the verdict authority
	// is outside this slice's file scope. The positive must never read as a
	// clean negative, so that is what this asserts. If the lexer ever learns
	// template literals this assertion is the tripwire to update.
	lab3 := byPath["/lab3"]
	if len(lab3) == 0 {
		t.Fatal("/lab3: no finding; the template-literal candidate never ran")
	}
	sawExecutingSignal := false
	for _, f := range lab3 {
		if f.Verdict == domain.VerdictRejected {
			t.Errorf("/lab3: verdict Rejected; an executed template-literal candidate must not read as a clean negative")
		}
		if f.Verdict != domain.VerdictInconclusive {
			t.Logf("/lab3: verdict = %s (want the documented Inconclusive provenance boundary)", f.Verdict)
		}
		for _, a := range jsStringAttempts(f) {
			if strings.Contains(a.Notes, "names the marker") {
				sawExecutingSignal = true
			}
		}
	}
	if !sawExecutingSignal {
		t.Error("/lab3: no attempt recorded a page exception naming the marker; the candidate did not reach an executable position")
	}

	// Safe/escaped controls: they reflect (so a finding exists), but nothing
	// they were sent may ever execute.
	for _, path := range []string{"/safe-js1", "/safe-js2", "/safe-template"} {
		fs := byPath[path]
		if len(fs) == 0 {
			t.Errorf("%s: no finding; the escaped value should still have reflected", path)
			continue
		}
		for _, f := range fs {
			if f.Verdict == domain.VerdictConfirmed {
				t.Errorf("%s: escaped control confirmed (%q) — a safe reader must never execute", path, confirmedCandidate(f))
			}
		}
	}

	// Non-reflecting control: no finding at all.
	if fs := byPath["/noreflect"]; len(fs) != 0 {
		t.Errorf("/noreflect: %d finding(s), want none", len(fs))
	}
}
