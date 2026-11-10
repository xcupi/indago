package web_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/indago/indago/internal/domain"
)

// Deleting a scan removes its rows (findings, evidence, endpoints...) and the
// project can only be deleted after its scans are gone.
func TestDeleteScanThenProject(t *testing.T) {
	a := newAPI(t, nil)
	scanID := createTestScan(t, a)
	f, ep, ev := seedFinding(t, a, scanID)

	var sc domain.Scan
	a.mustJSON(a.do("GET", "/api/scans/"+string(scanID), nil), http.StatusOK, &sc)

	// Project delete is refused while the scan exists.
	rec := a.do("DELETE", "/api/projects/"+string(sc.ProjectID), nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("project delete with scan = %d, want 409", rec.Code)
	}

	// Scan delete removes children.
	if rec := a.do("DELETE", "/api/scans/"+string(scanID), nil); rec.Code != http.StatusNoContent {
		t.Fatalf("scan delete = %d %s", rec.Code, rec.Body.String())
	}
	if _, err := a.st.Findings().Get(context.Background(), f.ID); err == nil {
		t.Fatal("finding survived scan deletion")
	}
	if _, err := a.st.Endpoints().Get(context.Background(), ep.ID); err == nil {
		t.Fatal("endpoint survived scan deletion")
	}
	if _, err := a.st.Evidence().Get(context.Background(), ev.ID); err == nil {
		t.Fatal("evidence row survived scan deletion")
	}

	// Targets with no scans can be edited and deleted.
	var targets []domain.Target
	a.mustJSON(a.do("GET", "/api/projects/"+string(sc.ProjectID)+"/targets", nil), http.StatusOK, &targets)
	if len(targets) != 1 {
		t.Fatalf("targets = %+v", targets)
	}
	tid := targets[0].ID
	var updated domain.Target
	a.mustJSON(a.do("PUT", "/api/projects/"+string(sc.ProjectID)+"/targets/"+string(tid),
		map[string]any{"name": "renamed", "base_url": "https://example.test/app"}), http.StatusOK, &updated)
	if updated.Name != "renamed" || updated.BaseURL != "https://example.test/app" {
		t.Fatalf("updated = %+v", updated)
	}
	if rec := a.do("DELETE", "/api/projects/"+string(sc.ProjectID)+"/targets/"+string(tid), nil); rec.Code != http.StatusNoContent {
		t.Fatalf("target delete = %d", rec.Code)
	}

	// Now the project is empty and can go.
	if rec := a.do("DELETE", "/api/projects/"+string(sc.ProjectID), nil); rec.Code != http.StatusNoContent {
		t.Fatalf("project delete = %d %s", rec.Code, rec.Body.String())
	}
	if _, err := a.st.Projects().Get(context.Background(), sc.ProjectID); err == nil {
		t.Fatal("project survived deletion")
	}
}

func TestDeleteRunningScanRefused(t *testing.T) {
	a := newAPI(t, nil)
	scanID := createTestScan(t, a)
	var sc domain.Scan
	a.mustJSON(a.do("GET", "/api/scans/"+string(scanID), nil), http.StatusOK, &sc)
	sc.State = domain.ScanRunning
	if err := a.st.Scans().Update(context.Background(), &sc); err != nil {
		t.Fatal(err)
	}
	if rec := a.do("DELETE", "/api/scans/"+string(scanID), nil); rec.Code != http.StatusConflict {
		t.Fatalf("running scan delete = %d, want 409", rec.Code)
	}
}

func TestBulkDeleteProjectsDeletesTheirScans(t *testing.T) {
	a := newAPI(t, nil)
	scan1 := createTestScan(t, a)
	scan2 := createTestScan(t, a)
	var s1, s2 domain.Scan
	a.mustJSON(a.do("GET", "/api/scans/"+string(scan1), nil), http.StatusOK, &s1)
	a.mustJSON(a.do("GET", "/api/scans/"+string(scan2), nil), http.StatusOK, &s2)
	if s1.ProjectID == s2.ProjectID {
		t.Fatal("test setup produced the same project twice")
	}

	var out struct {
		Deleted int `json:"deleted"`
		Failed  int `json:"failed"`
	}
	a.mustJSON(a.do("POST", "/api/projects/bulk-delete", map[string]any{
		"project_ids":  []string{string(s1.ProjectID), string(s2.ProjectID)},
		"delete_scans": true,
	}), http.StatusOK, &out)
	if out.Deleted != 2 || out.Failed != 0 {
		t.Fatalf("bulk delete = %+v", out)
	}
	for _, id := range []domain.ID{s1.ProjectID, s2.ProjectID} {
		if _, err := a.st.Projects().Get(context.Background(), id); err == nil {
			t.Fatalf("project %s survived", id)
		}
	}
	for _, id := range []domain.ID{scan1, scan2} {
		if _, err := a.st.Scans().Get(context.Background(), id); err == nil {
			t.Fatalf("scan %s survived", id)
		}
	}
}

func TestBulkDeleteProjectsRefusesRunningScan(t *testing.T) {
	a := newAPI(t, nil)
	scanID := createTestScan(t, a)
	var sc domain.Scan
	a.mustJSON(a.do("GET", "/api/scans/"+string(scanID), nil), http.StatusOK, &sc)
	sc.State = domain.ScanRunning
	if err := a.st.Scans().Update(context.Background(), &sc); err != nil {
		t.Fatal(err)
	}
	var out struct {
		Deleted int `json:"deleted"`
		Failed  int `json:"failed"`
	}
	a.mustJSON(a.do("POST", "/api/projects/bulk-delete", map[string]any{
		"project_ids": []string{string(sc.ProjectID)}, "delete_scans": true,
	}), http.StatusOK, &out)
	if out.Deleted != 0 || out.Failed != 1 {
		t.Fatalf("running project bulk delete = %+v", out)
	}
	if _, err := a.st.Projects().Get(context.Background(), sc.ProjectID); err != nil {
		t.Fatalf("running project should remain: %v", err)
	}
}
