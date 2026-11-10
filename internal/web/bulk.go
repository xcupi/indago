package web

// Bulk project deletion.
//
// The single-project endpoint refuses while scans exist, because one click
// should not silently destroy a scan history. Bulk delete is the deliberate
// alternative: the operator selects the projects, the UI states that scans and
// evidence go too, and the request must opt in with delete_scans. Active scans
// are never deleted; their projects are reported as skipped so a running scan
// cannot be pulled out from under the controller.

import (
	"net/http"
	"strings"

	"github.com/indago/indago/internal/domain"
)

type bulkDeleteProjectsReq struct {
	ProjectIDs  []string `json:"project_ids"`
	DeleteScans bool     `json:"delete_scans"`
}

type bulkDeleteProjectResult struct {
	ProjectID    string `json:"project_id"`
	Deleted      bool   `json:"deleted"`
	ScansDeleted int    `json:"scans_deleted,omitempty"`
	Error        string `json:"error,omitempty"`
}

func (s *Server) handleBulkDeleteProjects(w http.ResponseWriter, r *http.Request) {
	var req bulkDeleteProjectsReq
	if err := readJSON(r, &req); err != nil {
		writeJSONBodyError(w, err)
		return
	}
	ids := make([]domain.ID, 0, len(req.ProjectIDs))
	seen := make(map[domain.ID]bool, len(req.ProjectIDs))
	for _, raw := range req.ProjectIDs {
		id := domain.ID(strings.TrimSpace(raw))
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		writeError(w, http.StatusBadRequest, "project_ids must contain at least one project")
		return
	}
	if len(ids) > 200 {
		writeError(w, http.StatusBadRequest, "delete at most 200 projects per request")
		return
	}

	results := make([]bulkDeleteProjectResult, 0, len(ids))
	for _, id := range ids {
		res := bulkDeleteProjectResult{ProjectID: string(id)}
		if _, err := s.store.Projects().Get(r.Context(), id); err != nil {
			res.Error = "project not found"
			results = append(results, res)
			continue
		}
		scans, err := s.store.Scans().ListByProject(r.Context(), id)
		if err != nil {
			res.Error = "could not list scans"
			results = append(results, res)
			continue
		}
		if len(scans) > 0 && !req.DeleteScans {
			res.Error = "project has scans; opt in to delete_scans"
			results = append(results, res)
			continue
		}
		active := ""
		for _, sc := range scans {
			if sc.State == domain.ScanRunning || sc.State == domain.ScanCanceling {
				active = string(sc.ID)
				break
			}
		}
		if active != "" {
			res.Error = "project has an active scan; stop it before deleting"
			results = append(results, res)
			continue
		}
		for _, sc := range scans {
			if err := s.deleteScanCascade(r, sc.ID); err != nil {
				res.Error = "could not delete one of its scans"
				break
			}
			res.ScansDeleted++
		}
		if res.Error != "" {
			results = append(results, res)
			continue
		}
		if err := s.deleteProjectCascade(r, id); err != nil {
			res.Error = "could not delete the project"
			results = append(results, res)
			continue
		}
		res.Deleted = true
		results = append(results, res)
		s.log.Info("project deleted in bulk", "project", id, "scans", res.ScansDeleted)
	}

	deleted := 0
	for _, res := range results {
		if res.Deleted {
			deleted++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"results": results,
		"deleted": deleted,
		"failed":  len(results) - deleted,
	})
}
