package web_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
)

// seedFinding creates an endpoint, parameter, finding, and two evidence rows
// (one linked to the finding) directly in the store, bypassing discovery and
// detection — this phase exposes already-correlated data over HTTP, it does
// not generate it.
func seedFinding(t *testing.T, a api, scanID domain.ID) (*domain.Finding, *domain.Endpoint, *domain.Evidence) {
	t.Helper()
	ctx := context.Background()
	now := time.Now()

	ep := &domain.Endpoint{ID: domain.NewID(), ScanID: scanID, URL: "http://example.test/search", Method: domain.MethodGET, Source: domain.SourceCrawler, CreatedAt: now}
	if err := a.st.Endpoints().Create(ctx, ep); err != nil {
		t.Fatal(err)
	}
	param := &domain.Parameter{ID: domain.NewID(), ScanID: scanID, EndpointID: ep.ID, Name: "q", Location: domain.LocationQuery, Source: domain.SourceCrawler, CreatedAt: now}
	if err := a.st.Parameters().Create(ctx, param); err != nil {
		t.Fatal(err)
	}

	detail := `{"method":"GET","parameter_name":"q","dedup_key":"k1","occurrences":1,"candidates":[{"source":"builtin","category":"html_text","context":"html_text","value":"<mark>","transformation":"raw","priority":10,"rationale":"survives raw"}]}`
	f := &domain.Finding{
		ID: domain.NewID(), ScanID: scanID, ProjectID: ep.ScanID, VulnClass: domain.VulnReflectedXSS,
		Verdict: domain.VerdictPending, Severity: domain.SeverityHigh, Confidence: domain.ConfidenceMedium,
		Title: "Reflected XSS candidate", EndpointID: ep.ID, ParameterID: param.ID,
		Location: domain.LocationQuery, Provenance: domain.Provenance{Engine: "reflected_xss", DetectedAt: now},
		Detail: []byte(detail), CreatedAt: now, UpdatedAt: now,
	}
	if err := a.st.Findings().Create(ctx, f); err != nil {
		t.Fatal(err)
	}

	ref, err := a.ev.Put(scanID, domain.EvidenceResponse, ".html", []byte("captured response body"))
	if err != nil {
		t.Fatal(err)
	}
	ev := &domain.Evidence{ID: domain.NewID(), ScanID: scanID, FindingID: f.ID, Kind: domain.EvidenceResponse, MediaType: "text/html", BlobPath: ref.BlobPath, Size: ref.Size, SHA256: ref.SHA256, CreatedAt: now}
	if err := a.st.Evidence().Create(ctx, ev); err != nil {
		t.Fatal(err)
	}
	// An evidence row NOT linked to any finding — must never show up under this
	// finding's evidence list.
	unlinkedRef, err := a.ev.Put(scanID, domain.EvidenceRequest, ".txt", []byte("captured request"))
	if err != nil {
		t.Fatal(err)
	}
	unlinked := &domain.Evidence{ID: domain.NewID(), ScanID: scanID, Kind: domain.EvidenceRequest, MediaType: "text/plain", BlobPath: unlinkedRef.BlobPath, Size: unlinkedRef.Size, SHA256: unlinkedRef.SHA256, CreatedAt: now}
	if err := a.st.Evidence().Create(ctx, unlinked); err != nil {
		t.Fatal(err)
	}

	f.EvidenceIDs = []domain.ID{ev.ID}
	if err := a.st.Findings().Update(ctx, f); err != nil {
		t.Fatal(err)
	}
	return f, ep, ev
}

func createTestScan(t *testing.T, a api) domain.ID {
	t.Helper()
	site := testSite(t)
	projectID, targetID := setupScan(a, site.URL)
	var sc domain.Scan
	a.mustJSON(a.do("POST", "/api/scans", map[string]any{"project_id": projectID, "target_id": targetID}), 201, &sc)
	return sc.ID
}

func TestListFindingsByScan(t *testing.T) {
	a := newAPI(t, nil)
	scanID := createTestScan(t, a)
	f, _, _ := seedFinding(t, a, scanID)

	var list []domain.Finding
	a.mustJSON(a.do("GET", "/api/scans/"+string(scanID)+"/findings", nil), http.StatusOK, &list)
	if len(list) != 1 || list[0].ID != f.ID {
		t.Fatalf("findings list = %+v", list)
	}
}

func TestListFindingsUnknownScan(t *testing.T) {
	a := newAPI(t, nil)
	rec := a.do("GET", "/api/scans/"+string(domain.NewID())+"/findings", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// findingDetailResp mirrors enough of web.findingView for assertions, without
// importing the unexported type.
type findingDetailResp struct {
	ID           domain.ID `json:"id"`
	Verdict      string    `json:"verdict"`
	ParsedDetail struct {
		Method        string `json:"method"`
		ParameterName string `json:"parameter_name"`
		Occurrences   int    `json:"occurrences"`
		Candidates    []struct {
			Category string `json:"category"`
			Context  string `json:"context"`
			Value    string `json:"value"`
		} `json:"candidates"`
	} `json:"parsed_detail"`
	Endpoint  *domain.Endpoint   `json:"endpoint"`
	Parameter *domain.Parameter  `json:"parameter"`
	Evidence  []*domain.Evidence `json:"evidence"`
}

func TestGetFindingDetailResolvesContext(t *testing.T) {
	a := newAPI(t, nil)
	scanID := createTestScan(t, a)
	f, ep, ev := seedFinding(t, a, scanID)

	var got findingDetailResp
	a.mustJSON(a.do("GET", "/api/scans/"+string(scanID)+"/findings/"+string(f.ID), nil), http.StatusOK, &got)

	if got.ID != f.ID || got.Verdict != string(domain.VerdictPending) {
		t.Fatalf("finding detail: %+v", got)
	}
	if got.ParsedDetail.Method != "GET" || got.ParsedDetail.ParameterName != "q" || got.ParsedDetail.Occurrences != 1 {
		t.Fatalf("parsed detail: %+v", got.ParsedDetail)
	}
	if len(got.ParsedDetail.Candidates) != 1 || got.ParsedDetail.Candidates[0].Category != "html_text" {
		t.Fatalf("candidates: %+v", got.ParsedDetail.Candidates)
	}
	if got.Endpoint == nil || got.Endpoint.ID != ep.ID {
		t.Fatalf("endpoint not resolved: %+v", got.Endpoint)
	}
	if got.Parameter == nil || got.Parameter.Name != "q" {
		t.Fatalf("parameter not resolved: %+v", got.Parameter)
	}
	if len(got.Evidence) != 1 || got.Evidence[0].ID != ev.ID {
		t.Fatalf("evidence should only list what's linked to this finding: %+v", got.Evidence)
	}
}

func TestGetFindingWrongScanIsNotFound(t *testing.T) {
	a := newAPI(t, nil)
	scanID := createTestScan(t, a)
	f, _, _ := seedFinding(t, a, scanID)
	otherScan := createTestScan(t, a)

	rec := a.do("GET", "/api/scans/"+string(otherScan)+"/findings/"+string(f.ID), nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestEvidenceMetadataHasNoContent(t *testing.T) {
	a := newAPI(t, nil)
	scanID := createTestScan(t, a)
	_, _, ev := seedFinding(t, a, scanID)

	var got domain.Evidence
	a.mustJSON(a.do("GET", "/api/evidence/"+string(ev.ID), nil), http.StatusOK, &got)
	if got.ID != ev.ID || got.SHA256 != ev.SHA256 {
		t.Fatalf("evidence metadata: %+v", got)
	}
}

func TestEvidenceContentServesBlob(t *testing.T) {
	a := newAPI(t, nil)
	scanID := createTestScan(t, a)
	_, _, ev := seedFinding(t, a, scanID)

	rec := a.do("GET", "/api/evidence/"+string(ev.ID)+"/content", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/html" {
		t.Fatalf("content-type = %q", ct)
	}
	if rec.Body.String() != "captured response body" {
		t.Fatalf("body = %q", rec.Body.String())
	}
	if d := rec.Header().Get("Content-Disposition"); d != "" {
		t.Fatalf("expected no Content-Disposition by default, got %q", d)
	}

	rec2 := a.do("GET", "/api/evidence/"+string(ev.ID)+"/content?download", nil)
	if d := rec2.Header().Get("Content-Disposition"); d == "" {
		t.Fatal("expected Content-Disposition with ?download")
	}
}
