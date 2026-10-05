package web

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/report"
)

// --- reports ---

// handleListReports lists every report previously generated for a scan.
func (s *Server) handleListReports(w http.ResponseWriter, r *http.Request) {
	scanID := domain.ID(r.PathValue("id"))
	if _, err := s.store.Scans().Get(r.Context(), scanID); err != nil {
		s.writeLookupError(w, err)
		return
	}
	reports, err := s.store.Reports().ListByScan(r.Context(), scanID)
	if err != nil {
		s.writeInternalError(w, "list reports", err)
		return
	}
	writeJSON(w, http.StatusOK, nonNil(reports))
}

type createReportReq struct {
	Format     string   `json:"format"`
	FindingIDs []string `json:"finding_ids,omitempty"` // empty/absent = every finding in the scan
}

// handleCreateReport renders a report over the selected (or, if none given,
// every) finding of a scan, in the requested format, and persists it as a
// domain.Report (index entry + file on disk under the server's reports root).
// Generation is deterministic: see report.sortedFindings.
func (s *Server) handleCreateReport(w http.ResponseWriter, r *http.Request) {
	if s.reportsDir == "" {
		writeError(w, http.StatusServiceUnavailable, "report generation not configured")
		return
	}
	scanID := domain.ID(r.PathValue("id"))
	sc, err := s.store.Scans().Get(r.Context(), scanID)
	if err != nil {
		s.writeLookupError(w, err)
		return
	}
	proj, err := s.store.Projects().Get(r.Context(), sc.ProjectID)
	if err != nil {
		s.writeInternalError(w, "load project", err)
		return
	}

	var req createReportReq
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	format := domain.ReportFormat(strings.TrimSpace(req.Format))
	if !format.IsValid() {
		writeError(w, http.StatusBadRequest, "unknown format "+req.Format)
		return
	}
	gen, err := report.For(format)
	if err != nil {
		s.writeInternalError(w, "report generator", err)
		return
	}

	all, err := s.store.Findings().ListByScan(r.Context(), scanID)
	if err != nil {
		s.writeInternalError(w, "list findings", err)
		return
	}
	findings, msg := selectFindings(all, req.FindingIDs)
	if msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}

	now := time.Now()
	var buf bytes.Buffer
	if err := gen.Generate(&buf, report.Data{
		Project:     *proj,
		Scan:        *sc,
		Findings:    findings,
		GeneratedAt: now,
		ToolVersion: s.version,
	}); err != nil {
		s.writeInternalError(w, "generate report", err)
		return
	}

	rpt := &domain.Report{
		ID:        domain.NewID(),
		ScanID:    scanID,
		ProjectID: sc.ProjectID,
		Format:    format,
		Summary:   report.Summarize(scanID, findings),
		CreatedAt: now,
	}
	relPath := filepath.ToSlash(filepath.Join(string(scanID), string(rpt.ID)+reportExt(format)))
	abs := filepath.Join(s.reportsDir, filepath.FromSlash(relPath))
	if err := os.MkdirAll(filepath.Dir(abs), 0o750); err != nil {
		s.writeInternalError(w, "store report", err)
		return
	}
	if err := os.WriteFile(abs, buf.Bytes(), 0o640); err != nil {
		s.writeInternalError(w, "store report", err)
		return
	}
	rpt.Path = relPath

	if err := s.store.Reports().Create(r.Context(), rpt); err != nil {
		s.writeInternalError(w, "create report", err)
		return
	}
	writeJSON(w, http.StatusCreated, rpt)
}

// selectFindings filters all to the requested ids, preserving all's order. An
// empty/nil ids selects everything. It reports a user-facing message (and a
// nil slice) if any requested id is not a finding of this scan.
func selectFindings(all []*domain.Finding, ids []string) ([]*domain.Finding, string) {
	if len(ids) == 0 {
		return all, ""
	}
	want := make(map[domain.ID]bool, len(ids))
	for _, id := range ids {
		want[domain.ID(id)] = true
	}
	out := make([]*domain.Finding, 0, len(ids))
	for _, f := range all {
		if want[f.ID] {
			out = append(out, f)
			delete(want, f.ID)
		}
	}
	if len(want) > 0 {
		return nil, "one or more finding_ids are not findings of this scan"
	}
	return out, ""
}

func reportExt(format domain.ReportFormat) string {
	switch format {
	case domain.ReportMarkdown:
		return ".md"
	case domain.ReportHTML:
		return ".html"
	default:
		return ".json"
	}
}

func reportContentType(format domain.ReportFormat) string {
	switch format {
	case domain.ReportMarkdown:
		return "text/markdown; charset=utf-8"
	case domain.ReportHTML:
		return "text/html; charset=utf-8"
	default:
		return "application/json; charset=utf-8"
	}
}

// handleGetReport returns a report's index entry (format, summary, timestamps)
// — not its rendered content; see handleGetReportContent.
func (s *Server) handleGetReport(w http.ResponseWriter, r *http.Request) {
	rpt, err := s.store.Reports().Get(r.Context(), domain.ID(r.PathValue("id")))
	if err != nil {
		s.writeLookupError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rpt)
}

// handleGetReportContent streams a previously generated report's rendered
// bytes. "?download" sets Content-Disposition to attachment; by default the
// response is inline, suitable for viewing in a browser tab.
func (s *Server) handleGetReportContent(w http.ResponseWriter, r *http.Request) {
	if s.reportsDir == "" {
		writeError(w, http.StatusServiceUnavailable, "report generation not configured")
		return
	}
	rpt, err := s.store.Reports().Get(r.Context(), domain.ID(r.PathValue("id")))
	if err != nil {
		s.writeLookupError(w, err)
		return
	}
	abs, err := s.safeReportPath(rpt.Path)
	if err != nil {
		s.writeInternalError(w, "resolve report path", err)
		return
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "report file unavailable")
		return
	}
	w.Header().Set("Content-Type", reportContentType(rpt.Format))
	disposition := "inline"
	if r.URL.Query().Has("download") {
		disposition = "attachment"
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf(`%s; filename="%s%s"`, disposition, rpt.ID, reportExt(rpt.Format)))
	_, _ = w.Write(data)
}

// safeReportPath resolves a report's stored relative path against the
// server's reports root, rejecting anything that would escape it. Report
// paths are always server-generated (scan/report IDs, never user input used
// directly as path segments), but this guards against a tampered-with or
// corrupted index row the same way internal/evidence guards blob paths.
func (s *Server) safeReportPath(relPath string) (string, error) {
	clean := filepath.Clean(filepath.FromSlash(relPath))
	if filepath.IsAbs(clean) || strings.HasPrefix(clean, "..") {
		return "", errors.New("illegal report path")
	}
	abs := filepath.Join(s.reportsDir, clean)
	if abs != s.reportsDir && !strings.HasPrefix(abs, s.reportsDir+string(os.PathSeparator)) {
		return "", errors.New("report path escapes root")
	}
	return abs, nil
}
