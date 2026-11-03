//go:build browser_integration

package scan_test

// Real-Chromium pipeline for the canonical-link shape in
// canonical_link_fixture_test.go: discovery → reflection → context → candidate
// → real HTTP → real-browser verification → finding.
//
// Measured outcome, pinned here: the attribute-only vector IS planned and sent,
// so a reflecting canonical link now produces a finding (before this slice the
// URL-query context planned nothing and the position was silently unreported),
// but the lab's accesskey/onclick vector executes only after an operator
// keypress. The passive verifier never simulates activation, so the verdict
// stays Rejected — the honest result, and the reason this stays an interaction
// candidate rather than a Confirmed one.
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

	// The canonical-link position must now be REPORTED: a reflecting
	// attribute-only candidate produces a finding instead of nothing at all.
	var planned *domain.Finding
	for _, f := range byPath["/canonical"] {
		if f.Verdict == domain.VerdictConfirmed {
			t.Fatalf("the accesskey/onclick vector needs an activation keypress the passive verifier never performs; got Confirmed: %+v", f.Summary)
		}
		for _, a := range jsStringAttempts(f) {
			if a.CandidateValue != "" {
				planned = f
			}
		}
	}
	if planned == nil {
		t.Fatalf("/canonical: no finding carried an executed candidate; findings=%d", len(byPath["/canonical"]))
	}
	hasVector := false
	for _, a := range jsStringAttempts(planned) {
		if strings.Contains(a.CandidateValue, "accesskey=x onclick=") {
			hasVector = true
		}
		if a.Verdict == domain.VerdictConfirmed {
			t.Fatalf("interaction-only canonical vector must never confirm: %+v", a)
		}
	}
	if !hasVector {
		t.Fatalf("/canonical finding must record the attribute-only accesskey/onclick attempt, got %+v", jsStringAttempts(planned))
	}
	if planned.Verdict == domain.VerdictPending {
		t.Fatalf("/canonical finding must be decided by the verifier, not left Pending: %+v", planned.Verdict)
	}

	// The escaped control encodes < > " ' &, so nothing can leave the href
	// attribute; it must never be Confirmed.
	for _, f := range byPath["/safe-canonical"] {
		if f.Verdict == domain.VerdictConfirmed {
			t.Fatalf("escaped canonical control must never confirm: %+v", f.Summary)
		}
	}
}
