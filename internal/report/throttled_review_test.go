package report_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/report"
)

// One point answered 403 first and 429 later. upsertBlockFinding refreshes
// BlockDetail to the LATEST status change (200 -> 403) and keeps Throttled
// sticky, so a label that reads only block_detail tells the operator "a 403
// filter rejection can still get the bounded pass" — false for this row, which
// the gate suppresses. The review reason has to follow the sticky flag.
func TestThrottledBlockRowIsNotLabelledAsEscalatableFilterRejection(t *testing.T) {
	detail, err := json.Marshal(map[string]any{
		"block_suspected": true,
		"block_detail":    "status changed 200 -> 403 from baseline while testing this parameter",
		"throttled":       true,
	})
	if err != nil {
		t.Fatal(err)
	}
	view := report.NewFindingView(&domain.Finding{Verdict: domain.VerdictInconclusive, Detail: detail}, nil)
	if view.ReviewReason != report.ReviewThrottledPoint {
		t.Fatalf("review reason = %q, want %q for a row that recorded backpressure", view.ReviewReason, report.ReviewThrottledPoint)
	}
	label := view.ReviewReasonLabel
	if !strings.Contains(label, "429") || !strings.Contains(label, "503") {
		t.Fatalf("throttled label must name the statuses that suppress the pass: %q", label)
	}
	if !strings.Contains(strings.ToLower(label), "not escalated") {
		t.Fatalf("throttled label must say the bounded pass does not run here: %q", label)
	}
	if strings.Contains(label, "can still get the bounded pass") {
		t.Fatalf("throttled label still promises the bounded pass a 403 would get: %q", label)
	}
}

// A 403 with no backpressure anywhere stays eligible, so it keeps the block
// label — the change must not swallow the case the fallback exists for.
func TestFilterRejectionWithoutBackpressureKeepsTheBlockLabel(t *testing.T) {
	detail, err := json.Marshal(map[string]any{
		"block_suspected": true,
		"block_detail":    "status changed 200 -> 403 from baseline while testing this parameter",
	})
	if err != nil {
		t.Fatal(err)
	}
	view := report.NewFindingView(&domain.Finding{Verdict: domain.VerdictInconclusive, Detail: detail}, nil)
	if view.ReviewReason != report.ReviewPossibleBlock {
		t.Fatalf("review reason = %q, want %q for a filter rejection", view.ReviewReason, report.ReviewPossibleBlock)
	}
	if !strings.Contains(view.ReviewReasonLabel, "403") {
		t.Fatalf("filter label must mention the 403 case: %q", view.ReviewReasonLabel)
	}
}
