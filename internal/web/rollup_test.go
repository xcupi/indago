package web_test

import (
	"net/http"
	"testing"

	"github.com/indago/indago/internal/domain"
)

// newScanInNewProject creates a project + target + scan and returns the scan ID
// and project ID.
func newScanInNewProject(t *testing.T, a api) (domain.ID, string) {
	t.Helper()
	site := testSite(t)
	projectID, targetID := setupScan(a, site.URL)
	var sc domain.Scan
	a.mustJSON(a.do("POST", "/api/scans", map[string]any{
		"project_id": projectID, "target_id": targetID,
	}), http.StatusCreated, &sc)
	return sc.ID, projectID
}

// The sidebar collections and a project page must agree: "all" spans every
// scan, a project shows exactly its own scans' findings and reports.
func TestFindingsAndReportsRollUpByProject(t *testing.T) {
	a := newAPI(t, nil)
	scanA, projectA := newScanInNewProject(t, a)
	scanB, projectB := newScanInNewProject(t, a)
	seedFinding(t, a, scanA)
	seedFinding(t, a, scanB)

	var all []domain.Finding
	a.mustJSON(a.do("GET", "/api/findings", nil), http.StatusOK, &all)
	if len(all) != 2 {
		t.Fatalf("all findings = %d, want 2", len(all))
	}

	var scopedA []domain.Finding
	a.mustJSON(a.do("GET", "/api/projects/"+projectA+"/findings", nil), http.StatusOK, &scopedA)
	if len(scopedA) != 1 || scopedA[0].ScanID != scanA {
		t.Fatalf("project A findings = %+v", scopedA)
	}

	// Scan list is filtered server-side too, so a project link can rely on it.
	var scansA []domain.Scan
	a.mustJSON(a.do("GET", "/api/scans?project_id="+projectA, nil), http.StatusOK, &scansA)
	if len(scansA) != 1 || scansA[0].ID != scanA {
		t.Fatalf("project A scans = %+v", scansA)
	}

	// A report on scan A appears in "all" and in project A only.
	rec := a.do("POST", "/api/scans/"+string(scanA)+"/reports", map[string]any{"format": "markdown"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create report = %d: %s", rec.Code, rec.Body.String())
	}
	var allReports []domain.Report
	a.mustJSON(a.do("GET", "/api/reports", nil), http.StatusOK, &allReports)
	if len(allReports) != 1 || allReports[0].ScanID != scanA {
		t.Fatalf("all reports = %+v", allReports)
	}
	var reportsA, reportsB []domain.Report
	a.mustJSON(a.do("GET", "/api/projects/"+projectA+"/reports", nil), http.StatusOK, &reportsA)
	a.mustJSON(a.do("GET", "/api/projects/"+projectB+"/reports", nil), http.StatusOK, &reportsB)
	if len(reportsA) != 1 || len(reportsB) != 0 {
		t.Fatalf("project reports = %d / %d, want 1 / 0", len(reportsA), len(reportsB))
	}
}

func TestProjectCollectionsUnknownProject(t *testing.T) {
	a := newAPI(t, nil)
	rec := a.do("GET", "/api/projects/does-not-exist/findings", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404: %s", rec.Code, rec.Body.String())
	}
}
