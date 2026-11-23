package web

// Cross-scan collections: the sidebar pages (Findings, Reports) and a project
// page need every finding/report in scope, not one scan at a time. These are
// read-only aggregations over the same stores the per-scan endpoints use, so no
// new persistence and no duplicated filtering rules.

import (
	"net/http"
	"sort"
	"strconv"

	"github.com/indago/indago/internal/domain"
)

// collectFindings returns every finding for the given scans, newest first.
func (s *Server) collectFindings(r *http.Request, scans []*domain.Scan, verdict domain.Verdict) ([]*domain.Finding, error) {
	out := make([]*domain.Finding, 0, len(scans)*4)
	for _, sc := range scans {
		findings, err := s.store.Findings().ListByScan(r.Context(), sc.ID)
		if err != nil {
			return nil, err
		}
		for _, finding := range findings {
			if verdict == "" || finding.Verdict == verdict {
				out = append(out, finding)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

// collectReports returns every report for the given scans, newest first.
func (s *Server) collectReports(r *http.Request, scans []*domain.Scan) ([]*domain.Report, error) {
	out := make([]*domain.Report, 0, len(scans))
	for _, sc := range scans {
		reports, err := s.store.Reports().ListByScan(r.Context(), sc.ID)
		if err != nil {
			return nil, err
		}
		out = append(out, reports...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (s *Server) handleListAllFindings(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	verdict := domain.Verdict(query.Get("verdict"))
	if verdict != "" && !verdict.IsValid() {
		writeError(w, http.StatusBadRequest, "invalid finding verdict")
		return
	}
	limit := 0
	if raw := query.Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 100 {
			writeError(w, http.StatusBadRequest, "finding limit must be between 1 and 100")
			return
		}
		limit = n
	}
	scans, err := s.store.Scans().List(r.Context())
	if err != nil {
		s.writeInternalError(w, "list scans", err)
		return
	}
	findings, err := s.collectFindings(r, scans, verdict)
	if err != nil {
		s.writeInternalError(w, "list findings", err)
		return
	}
	if limit > 0 && len(findings) > limit {
		findings = findings[:limit]
	}
	writeJSON(w, http.StatusOK, nonNil(findings))
}

func (s *Server) handleListAllReports(w http.ResponseWriter, r *http.Request) {
	scans, err := s.store.Scans().List(r.Context())
	if err != nil {
		s.writeInternalError(w, "list scans", err)
		return
	}
	reports, err := s.collectReports(r, scans)
	if err != nil {
		s.writeInternalError(w, "list reports", err)
		return
	}
	writeJSON(w, http.StatusOK, nonNil(reports))
}

func (s *Server) handleListProjectFindings(w http.ResponseWriter, r *http.Request) {
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
	findings, err := s.collectFindings(r, scans, "")
	if err != nil {
		s.writeInternalError(w, "list findings", err)
		return
	}
	writeJSON(w, http.StatusOK, nonNil(findings))
}

func (s *Server) handleListProjectReports(w http.ResponseWriter, r *http.Request) {
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
	reports, err := s.collectReports(r, scans)
	if err != nil {
		s.writeInternalError(w, "list reports", err)
		return
	}
	writeJSON(w, http.StatusOK, nonNil(reports))
}
