package web_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/report"
)

// reviewReasonResp mirrors the review-reason fields the web API must expose on
// both the list and the detail view. The UI renders an extra explanation for an
// interaction-only finding, so the machine-readable reason has to reach the
// client — the label alone cannot be compared reliably.
type reviewReasonResp struct {
	ReviewReason      string `json:"review_reason"`
	ReviewReasonLabel string `json:"review_reason_label"`
}

func seedRejectedInteractionFinding(t *testing.T, a api, scanID domain.ID) *domain.Finding {
	t.Helper()
	ctx := context.Background()
	now := time.Now()

	ep := &domain.Endpoint{ID: domain.NewID(), ScanID: scanID, URL: "http://example.test/link", Method: domain.MethodGET, Source: domain.SourceCrawler, CreatedAt: now}
	if err := a.st.Endpoints().Create(ctx, ep); err != nil {
		t.Fatal(err)
	}
	param := &domain.Parameter{ID: domain.NewID(), ScanID: scanID, EndpointID: ep.ID, Name: "returnUrl", Location: domain.LocationQuery, Source: domain.SourceCrawler, CreatedAt: now}
	if err := a.st.Parameters().Create(ctx, param); err != nil {
		t.Fatal(err)
	}

	// A raw interaction candidate is exactly what report.findingReviewReason
	// turns into ReviewInteractionOnly: it reflected unescaped but only fires
	// after an action, and verification observed no marker signal.
	detail := `{"method":"GET","parameter_name":"returnUrl","dedup_key":"k-review","occurrences":1,"candidates":[{"source":"builtin","category":"attr_url","context":"url_attr","value":"javascript:marker","trigger":"interaction","transformation":"raw","priority":90,"rationale":"needs activation"}]}`
	f := &domain.Finding{
		ID: domain.NewID(), ScanID: scanID, ProjectID: scanID, VulnClass: domain.VulnReflectedXSS,
		Verdict: domain.VerdictRejected, Severity: domain.SeverityHigh, Confidence: domain.ConfidenceLow,
		Title: "Reflected XSS candidate", EndpointID: ep.ID, ParameterID: param.ID,
		Location: domain.LocationQuery, Provenance: domain.Provenance{Engine: "reflected_xss", DetectedAt: now},
		Detail: []byte(detail), CreatedAt: now, UpdatedAt: now,
	}
	if err := a.st.Findings().Create(ctx, f); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestFindingsExposeInteractionReviewReason(t *testing.T) {
	a := newAPI(t, nil)
	scanID := createTestScan(t, a)
	f := seedRejectedInteractionFinding(t, a, scanID)

	var list []reviewReasonResp
	a.mustJSON(a.do("GET", "/api/scans/"+string(scanID)+"/findings", nil), http.StatusOK, &list)
	if len(list) != 1 {
		t.Fatalf("list findings: got %d items, want 1", len(list))
	}
	if list[0].ReviewReason != string(report.ReviewInteractionOnly) {
		t.Fatalf("list review_reason = %q, want %q (the UI compares this value; an absent reason leaves its bounded-activation note dead)",
			list[0].ReviewReason, report.ReviewInteractionOnly)
	}
	if list[0].ReviewReasonLabel == "" {
		t.Fatal("list review_reason_label is empty")
	}

	var detail reviewReasonResp
	a.mustJSON(a.do("GET", "/api/scans/"+string(scanID)+"/findings/"+string(f.ID), nil), http.StatusOK, &detail)
	if detail.ReviewReason != string(report.ReviewInteractionOnly) {
		t.Fatalf("detail review_reason = %q, want %q", detail.ReviewReason, report.ReviewInteractionOnly)
	}
	if detail.ReviewReasonLabel == "" {
		t.Fatal("detail review_reason_label is empty")
	}
}
