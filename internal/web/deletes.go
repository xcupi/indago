package web

// Destructive operations, kept explicit and ordered.
//
// The schema has no foreign keys, so a delete has to walk the rows itself. The
// order below is child-first so a partial failure leaves an orphaned parent
// (harmless, visible) rather than children pointing at a row that no longer
// exists.
//
// A running scan is never deleted: it is owned by the controller, and removing
// its rows underneath it would corrupt the run. Stop it first.

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/indago/indago/internal/domain"
)

func (s *Server) handleDeleteScan(w http.ResponseWriter, r *http.Request) {
	scanID := domain.ID(r.PathValue("id"))
	sc, err := s.store.Scans().Get(r.Context(), scanID)
	if err != nil {
		s.writeLookupError(w, err)
		return
	}
	if sc.State == domain.ScanRunning || sc.State == domain.ScanCanceling {
		writeError(w, http.StatusConflict, "this scan is still active; stop it before deleting")
		return
	}
	if err := s.deleteScanCascade(r, scanID); err != nil {
		s.writeInternalError(w, "delete scan", err)
		return
	}
	s.log.Info("scan deleted", "scan", scanID)
	w.WriteHeader(http.StatusNoContent)
}

// deleteScanCascade removes a scan's reports, AI tasks, evidence and every
// child row, then the scan itself. The caller must have checked that the scan
// is not running/canceling. Operations are best-effort for child rows (a
// missing row is not a failure), except the final scan delete.
func (s *Server) deleteScanCascade(r *http.Request, scanID domain.ID) error {
	// Reports: remove the stored file, then the row.
	if reports, err := s.store.Reports().ListByScan(r.Context(), scanID); err == nil {
		for _, rpt := range reports {
			if rpt.Path != "" {
				_ = os.Remove(filepath.Join(s.reportsDir, filepath.FromSlash(rpt.Path)))
			}
			_ = s.store.Reports().Delete(r.Context(), rpt.ID)
		}
	}
	if tasks, err := s.store.AITasks().ListByScan(r.Context(), scanID); err == nil {
		for _, t := range tasks {
			_ = s.store.AITasks().Delete(r.Context(), t.ID)
		}
	}
	if evs, err := s.store.Evidence().ListByScan(r.Context(), scanID); err == nil {
		for _, ev := range evs {
			if s.evidence != nil && ev.BlobPath != "" {
				_ = s.evidence.Remove(ev.BlobPath)
			}
			_ = s.store.Evidence().Delete(r.Context(), ev.ID)
		}
	}
	// Child rows first, then the scan itself.
	s.deleteFindings(r, scanID)
	s.deleteTestCases(r, scanID)
	s.deleteJobs(r, scanID)
	s.deleteInjectionPoints(r, scanID)
	s.deleteParameters(r, scanID)
	s.deleteEndpoints(r, scanID)
	return s.store.Scans().Delete(r.Context(), scanID)
}

func idsOfFindings(rows []*domain.Finding) []domain.ID {
	out := make([]domain.ID, 0, len(rows))
	for _, f := range rows {
		out = append(out, f.ID)
	}
	return out
}

func (s *Server) deleteFindings(r *http.Request, scanID domain.ID) {
	rows, err := s.store.Findings().ListByScan(r.Context(), scanID)
	if err != nil {
		return
	}
	for _, x := range rows {
		_ = s.store.Findings().Delete(r.Context(), x.ID)
	}
}

func (s *Server) deleteTestCases(r *http.Request, scanID domain.ID) {
	rows, err := s.store.TestCases().ListByScan(r.Context(), scanID)
	if err != nil {
		return
	}
	for _, x := range rows {
		_ = s.store.TestCases().Delete(r.Context(), x.ID)
	}
}

func (s *Server) deleteJobs(r *http.Request, scanID domain.ID) {
	rows, err := s.store.Jobs().ListByScan(r.Context(), scanID)
	if err != nil {
		return
	}
	for _, x := range rows {
		_ = s.store.Jobs().Delete(r.Context(), x.ID)
	}
}

func (s *Server) deleteInjectionPoints(r *http.Request, scanID domain.ID) {
	rows, err := s.store.InjectionPoints().ListByScan(r.Context(), scanID)
	if err != nil {
		return
	}
	for _, x := range rows {
		_ = s.store.InjectionPoints().Delete(r.Context(), x.ID)
	}
}

func (s *Server) deleteParameters(r *http.Request, scanID domain.ID) {
	rows, err := s.store.Parameters().ListByScan(r.Context(), scanID)
	if err != nil {
		return
	}
	for _, x := range rows {
		_ = s.store.Parameters().Delete(r.Context(), x.ID)
	}
}

func (s *Server) deleteEndpoints(r *http.Request, scanID domain.ID) {
	rows, err := s.store.Endpoints().ListByScan(r.Context(), scanID)
	if err != nil {
		return
	}
	for _, x := range rows {
		_ = s.store.Endpoints().Delete(r.Context(), x.ID)
	}
}

// handleDeleteProject refuses while scans exist: the operator removes the work
// explicitly instead of losing a whole scan history by one click.
func (s *Server) handleDeleteProject(w http.ResponseWriter, r *http.Request) {
	projectID := domain.ID(r.PathValue("id"))
	if _, err := s.store.Projects().Get(r.Context(), projectID); err != nil {
		s.writeLookupError(w, err)
		return
	}
	scans, err := s.store.Scans().ListByProject(r.Context(), projectID)
	if err != nil {
		s.writeInternalError(w, "list scans", err)
		return
	}
	if len(scans) > 0 {
		writeError(w, http.StatusConflict, "this project still has scans; delete them first (each scan owns its evidence and reports)")
		return
	}
	if err := s.deleteProjectCascade(r, projectID); err != nil {
		s.writeInternalError(w, "delete project", err)
		return
	}
	s.log.Info("project deleted", "project", projectID)
	w.WriteHeader(http.StatusNoContent)
}

// deleteProjectCascade removes a project's remaining targets and scope, then
// the project row. It does not inspect or delete scans: callers decide that.
func (s *Server) deleteProjectCascade(r *http.Request, projectID domain.ID) error {
	targets, _ := s.store.Targets().ListByProject(r.Context(), projectID)
	for _, t := range targets {
		_ = s.store.Targets().Delete(r.Context(), t.ID)
	}
	if sc, err := s.store.Scopes().GetByProject(r.Context(), projectID); err == nil {
		_ = s.store.Scopes().Delete(r.Context(), sc.ID)
	}
	return s.store.Projects().Delete(r.Context(), projectID)
}

type updateTargetReq struct {
	Name    string `json:"name"`
	BaseURL string `json:"base_url"`
}

func (s *Server) handleUpdateTarget(w http.ResponseWriter, r *http.Request) {
	projectID := domain.ID(r.PathValue("id"))
	targetID := domain.ID(r.PathValue("targetID"))
	t, err := s.store.Targets().Get(r.Context(), targetID)
	if err != nil || t.ProjectID != projectID {
		s.writeLookupError(w, err)
		return
	}
	var req updateTargetReq
	if err := readJSON(r, &req); err != nil {
		writeJSONBodyError(w, err)
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	u, err := url.Parse(strings.TrimSpace(req.BaseURL))
	if req.Name == "" || err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		writeError(w, http.StatusBadRequest, "name and an absolute http(s) base_url are required")
		return
	}
	t.Name = req.Name
	t.BaseURL = u.String()
	if err := s.store.Targets().Update(r.Context(), t); err != nil {
		s.writeInternalError(w, "update target", err)
		return
	}
	writeJSON(w, http.StatusOK, t)
}

func (s *Server) handleDeleteTarget(w http.ResponseWriter, r *http.Request) {
	projectID := domain.ID(r.PathValue("id"))
	targetID := domain.ID(r.PathValue("targetID"))
	t, err := s.store.Targets().Get(r.Context(), targetID)
	if err != nil || t.ProjectID != projectID {
		s.writeLookupError(w, err)
		return
	}
	// A target with scans keeps its history: deleting it would orphan them.
	if scans, err := s.store.Scans().ListByProject(r.Context(), projectID); err == nil {
		for _, sc := range scans {
			if sc.TargetID == targetID {
				writeError(w, http.StatusConflict, "this target has scans; delete those scans first")
				return
			}
		}
	}
	if err := s.store.Targets().Delete(r.Context(), targetID); err != nil {
		s.writeInternalError(w, "delete target", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
