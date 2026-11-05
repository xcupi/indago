//go:build browser_integration

package scan_test

// Real-Chromium pipeline for the canonical-link shape in
// canonical_link_fixture_test.go: discovery → reflection → context → candidate
// → real HTTP → real-browser verification → finding.
//
// Measured outcome, pinned here: the attribute-only vector IS planned and sent,
// so a reflecting canonical link produces a finding. Its accesskey/onclick
// vector executes only after a keypress, which the verifier now performs the way
// a victim would (docs/browser-verification.md, "keyboard" activation: one
// bounded keyboard.press('Alt+Shift+x')). The verdict is Confirmed only on the
// browser's own marker-specific execution signal observed AFTER that single
// activation; the escaped control, where no element declares the accesskey, can
// never activate and must not confirm.
//
// Registered as a required root in scripts/ci-browser-check.py.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/evidence"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/scan"
	"github.com/indago/indago/internal/store/memory"
)

func TestReflectedCanonicalLinkVectorIsPlannedButNeedsActivation(t *testing.T) {
	ctx := context.Background()
	lab := newCanonicalLinkLab(t)
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
	waitStatus(t, ctrl, sc.ID, 180*time.Second, isCompleted)

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
	for p, fs := range byPath {
		for _, f := range fs {
			for _, a := range jsStringAttempts(f) {
				t.Logf("%s finding=%s attempt=%s %q notes=%q", p, f.Verdict, a.Verdict, a.CandidateValue, a.Notes)
			}
		}
	}

	// The canonical-link position is reported, and decided by the verifier: the
	// accesskey/onclick vector is Confirmed only through the one supported
	// keyboard activation, and the verdict says so.
	var planned *domain.Finding
	for _, f := range byPath["/canonical"] {
		for _, a := range jsStringAttempts(f) {
			if a.CandidateValue != "" {
				planned = f
			}
		}
	}
	if planned == nil {
		t.Fatalf("/canonical: no finding carried an executed candidate; findings=%d", len(byPath["/canonical"]))
	}
	hasVector, activated := false, false
	for _, a := range jsStringAttempts(planned) {
		if strings.Contains(a.CandidateValue, "accesskey=x onclick=") {
			hasVector = true
			if a.Verdict == domain.VerdictConfirmed && strings.Contains(a.Notes, "keyboard.press('Alt+Shift+x')") && strings.Contains(a.Notes, "unresolved JavaScript identifier") {
				activated = true
			}
		}
	}
	if !hasVector {
		t.Fatalf("/canonical finding must record the attribute-only accesskey/onclick attempt, got %+v", jsStringAttempts(planned))
	}
	if !activated || planned.Verdict != domain.VerdictConfirmed {
		t.Fatalf("/canonical accesskey vector must be Confirmed by the marker-specific signal after the one supported keyboard activation; finding=%s attempts=%+v", planned.Verdict, jsStringAttempts(planned))
	}

	// The escaped control encodes < > " ' &, so nothing can leave the href
	// attribute; it must never be Confirmed.
	for _, f := range byPath["/safe-canonical"] {
		if f.Verdict == domain.VerdictConfirmed {
			t.Fatalf("escaped canonical control must never confirm: %+v", f.Summary)
		}
		for _, a := range jsStringAttempts(f) {
			if strings.Contains(a.Notes, "keyboard.press") && a.Verdict == domain.VerdictConfirmed {
				t.Fatalf("escaped canonical control must never confirm via activation: %+v", a)
			}
		}
	}
}
