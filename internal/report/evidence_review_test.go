package report

import (
	"testing"

	"github.com/indago/indago/internal/domain"
)

func TestStoredBrowserEvidenceWithholdingReview(t *testing.T) {
	finding := &domain.Finding{ScanID: "scan", VulnClass: domain.VulnReflectedXSS,
		Verdict: domain.VerdictConfirmed, EvidenceIDs: []domain.ID{"summary", "dom"}}
	evidence := map[domain.ID]*domain.Evidence{
		"summary": {ID: "summary", ScanID: "scan", Kind: domain.EvidenceOther, Note: "test_case=fixture browser artifacts withheld (privacy)"},
	}
	view := NewFindingView(finding, evidence)
	if view.ReviewReason != ReviewBrowserArtifactsWithheld || view.ReviewReasonLabel == "" ||
		finding.Verdict != domain.VerdictConfirmed {
		t.Fatalf("unexpected privacy evidence review: %+v", view)
	}
	evidence["dom"] = &domain.Evidence{ID: "dom", ScanID: "scan", Kind: domain.EvidenceDOM}
	if view := NewFindingView(finding, evidence); view.ReviewReason != "" {
		t.Fatalf("annotated a finding with raw browser evidence: %+v", view)
	}
	delete(evidence, "dom")
	evidence["summary"].ScanID = "other-scan"
	if view := NewFindingView(finding, evidence); view.ReviewReason != "" {
		t.Fatalf("used a review marker from another scan: %+v", view)
	}
}
