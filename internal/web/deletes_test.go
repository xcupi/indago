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
