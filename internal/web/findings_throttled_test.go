package web_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
)

// The API's parsed_detail mirrors scan.findingDetail's fields by name, so it
// silently dropped the sticky backpressure flag: a client reading JSON saw
// block_detail "200 -> 403" with no way to know the point had answered 429
// and was never escalated.
func TestFindingDetailCarriesTheStickyThrottledFlag(t *testing.T) {
	a := newAPI(t, nil)
	scanID := createTestScan(t, a)
	ctx := context.Background()
	now := time.Now()

	f := &domain.Finding{
		ID: domain.NewID(), ScanID: scanID, ProjectID: scanID, VulnClass: domain.VulnReflectedXSS,
		Verdict: domain.VerdictInconclusive, Severity: domain.SeverityInfo, Confidence: domain.ConfidenceLow,
		Title: "Diagnostic: possible WAF/rate-limit/maintenance block",
		Detail: []byte(`{"parameter_name":"q","block_suspected":true,` +
			`"block_detail":"status changed 200 -> 403 from baseline while testing this parameter",` +
			`"throttled":true,"occurrences":2}`),
		CreatedAt: now, UpdatedAt: now,
	}
	if err := a.st.Findings().Create(ctx, f); err != nil {
		t.Fatal(err)
	}

	var got struct {
		ParsedDetail struct {
			BlockSuspected bool   `json:"block_suspected"`
			BlockDetail    string `json:"block_detail"`
			Throttled      bool   `json:"throttled"`
		} `json:"parsed_detail"`
	}
	a.mustJSON(a.do("GET", "/api/scans/"+string(scanID)+"/findings/"+string(f.ID), nil), http.StatusOK, &got)
	if !got.ParsedDetail.BlockSuspected || got.ParsedDetail.BlockDetail == "" {
		t.Fatalf("parsed detail lost the block diagnostic: %+v", got.ParsedDetail)
	}
	if !got.ParsedDetail.Throttled {
		t.Fatalf("parsed detail dropped the sticky throttled flag: %+v", got.ParsedDetail)
	}
}

// A finding with no backpressure must not start reporting throttled:true.
func TestFindingDetailOmitsThrottledWhenNotThrottled(t *testing.T) {
	a := newAPI(t, nil)
	scanID := createTestScan(t, a)
	ctx := context.Background()
	now := time.Now()

	f := &domain.Finding{
		ID: domain.NewID(), ScanID: scanID, ProjectID: scanID, VulnClass: domain.VulnReflectedXSS,
		Verdict: domain.VerdictInconclusive, Severity: domain.SeverityInfo, Confidence: domain.ConfidenceLow,
		Title:     "Diagnostic: possible WAF/rate-limit/maintenance block",
		Detail:    []byte(`{"parameter_name":"q","block_suspected":true,"block_detail":"status changed 200 -> 403 from baseline"}`),
		CreatedAt: now, UpdatedAt: now,
	}
	if err := a.st.Findings().Create(ctx, f); err != nil {
		t.Fatal(err)
	}

	var got struct {
		ParsedDetail struct {
			Throttled bool `json:"throttled"`
		} `json:"parsed_detail"`
	}
	a.mustJSON(a.do("GET", "/api/scans/"+string(scanID)+"/findings/"+string(f.ID), nil), http.StatusOK, &got)
	if got.ParsedDetail.Throttled {
		t.Fatalf("a 403-only row must not be reported as throttled: %+v", got.ParsedDetail)
	}
}
