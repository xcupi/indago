package web_test

import (
	"net/http"
	"testing"

	"github.com/indago/indago/internal/domain"
)

func TestBulkDeleteScans(t *testing.T) {
	a := newAPI(t, nil)
	var proj domain.Project
	a.mustJSON(a.do("POST", "/api/projects", map[string]any{"name": "bulk-scans"}), http.StatusCreated, &proj)
	a.mustJSON(a.do("PUT", "/api/projects/"+string(proj.ID)+"/scope", map[string]any{
		"include_hosts":   []string{"example.com"},
		"allowed_origins": []string{"https://example.com"},
	}), http.StatusCreated, nil)

	var tgt domain.Target
	a.mustJSON(a.do("POST", "/api/projects/"+string(proj.ID)+"/targets", map[string]any{
		"name":     "app",
		"base_url": "https://example.com",
	}), http.StatusCreated, &tgt)

	var s1, s2, sRunning domain.Scan
	a.mustJSON(a.do("POST", "/api/scans", map[string]any{
		"project_id": proj.ID,
		"target_id":  tgt.ID,
		"name":       "completed-1",
	}), http.StatusCreated, &s1)
	a.mustJSON(a.do("POST", "/api/scans", map[string]any{
		"project_id": proj.ID,
		"target_id":  tgt.ID,
		"name":       "completed-2",
	}), http.StatusCreated, &s2)
	a.mustJSON(a.do("POST", "/api/scans", map[string]any{
		"project_id": proj.ID,
		"target_id":  tgt.ID,
		"name":       "active-one",
	}), http.StatusCreated, &sRunning)

	// Mark the third scan running so bulk delete skips it cleanly.
	sc, err := a.st.Scans().Get(t.Context(), sRunning.ID)
	if err != nil {
		t.Fatal(err)
	}
	sc.State = domain.ScanRunning
	if err := a.st.Scans().Update(t.Context(), sc); err != nil {
		t.Fatal(err)
	}

	var resp struct {
		Deleted int `json:"deleted"`
		Failed  int `json:"failed"`
		Results []struct {
			ScanID  string `json:"scan_id"`
			Deleted bool   `json:"deleted"`
			Error   string `json:"error"`
		} `json:"results"`
	}
	a.mustJSON(a.do("POST", "/api/scans/bulk-delete", map[string]any{
		"scan_ids": []domain.ID{s1.ID, s2.ID, sRunning.ID, s1.ID},
	}), http.StatusOK, &resp)

	if resp.Deleted != 2 || resp.Failed != 1 {
		t.Fatalf("got deleted=%d failed=%d, want deleted=2 failed=1 (%+v)", resp.Deleted, resp.Failed, resp.Results)
	}
	if rec := a.do("GET", "/api/scans/"+string(s1.ID), nil); rec.Code != http.StatusNotFound {
		t.Fatalf("s1 still exists: status %d", rec.Code)
	}
	if rec := a.do("GET", "/api/scans/"+string(sRunning.ID), nil); rec.Code != http.StatusOK {
		t.Fatalf("running scan should still exist: status %d", rec.Code)
	}
}
