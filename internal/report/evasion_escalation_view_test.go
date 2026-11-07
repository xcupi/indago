package report_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/report"
)

func TestFilteredReviewLabelAcknowledgesAutomaticTechniqueFallback(t *testing.T) {
	detail, err := json.Marshal(map[string]any{
		"candidates": []map[string]any{
			{"value": "<svg onload=M>", "transformation": "html"},
			{"value": "<SvG OnLoad=M>", "technique": "case_variation", "transformation": "html"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	view := report.NewFindingView(&domain.Finding{Verdict: domain.VerdictRejected, Detail: detail}, nil)
	if view.ReviewReason != report.ReviewAllCandidatesFiltered {
		t.Fatalf("review reason = %q, want %q", view.ReviewReason, report.ReviewAllCandidatesFiltered)
	}
	if !strings.Contains(view.ReviewReasonLabel, "bounded alternate technique") {
		t.Fatalf("filtered review label hides the recorded automatic evasion attempt: %q", view.ReviewReasonLabel)
	}
	if strings.Contains(view.ReviewReasonLabel, "never alternate shapes") {
		t.Fatalf("filtered review label still claims alternate shapes were never tried: %q", view.ReviewReasonLabel)
	}
}

func TestInteractionReviewLabelExplainsBoundedActivation(t *testing.T) {
	label := report.ReviewInteractionOnly.Label()
	if !strings.Contains(label, "one declared activation") {
		t.Fatalf("interaction label hides the bounded activation: %q", label)
	}
	if strings.Contains(label, "never simulates") {
		t.Fatalf("interaction label contradicts bounded activation policy: %q", label)
	}
}

func TestPossibleBlockLabelDescribesSeparatelyGatedFallback(t *testing.T) {
	label := report.ReviewPossibleBlock.Label()
	if !strings.Contains(label, "separately gated") {
		t.Fatalf("possible-block label still claims no fallback can occur: %q", label)
	}
	if strings.Contains(label, "never retries or evades") {
		t.Fatalf("possible-block label contradicts automatic fallback policy: %q", label)
	}
	// A rate-limit/maintenance answer is not a filter decision, so the label
	// has to say the bounded bypass pass does NOT run there — while a 403
	// filter rejection still can. Matching only the "403/429/503" example
	// list would pass without saying anything about the rule.
	if !strings.Contains(label, "backpressure") || !strings.Contains(label, "403") {
		t.Fatalf("possible-block label must state that backpressure is not escalated but a 403 filter rejection can be: %q", label)
	}
}
