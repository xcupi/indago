package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/indago/indago/internal/ai"
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
	Format string `json:"format"`
	// Mode is "all", "confirmed", or "selected". Empty keeps the original
	// contract: "selected" when FindingIDs is non-empty, otherwise "all".
	Mode       string   `json:"mode,omitempty"`
	FindingIDs []string `json:"finding_ids,omitempty"`
	// Template selects the deliverable layout for markdown/html/pdf:
	// "pentest" (default for pdf), "bug_bounty", or "technical" (the default
	// evidence-first layout). JSON ignores it.
	Template string `json:"template,omitempty"`
	// AISummary requests an advisory executive-summary paragraph from the
	// AI Gateway, prepended to the report and clearly labeled as such (see
	// report.Data.AISummary). Ignored (no error) when AI is disabled or
	// unconfigured — report creation always succeeds either way; a failed
	// or skipped advisory call just means no AI section in the output.
	AISummary bool `json:"ai_summary,omitempty"`
	// AIProvider / AIModel select the model used for that advisory paragraph.
	// Empty uses the provider saved in Settings (or INDAGO_LLM_KEY_* env
	// credentials). A provider with no credential is a 400 naming the env var;
	// the report itself is never blocked by AI.
	AIProvider string `json:"ai_provider,omitempty"`
	AIModel    string `json:"ai_model,omitempty"`
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
	coverage, err := s.scanCompleteness(r.Context(), scanID, sc.State)
	if err != nil {
		s.writeInternalError(w, "scan completeness", err)
		return
	}

	var req createReportReq
	if err := readJSON(r, &req); err != nil {
		writeJSONBodyError(w, err)
		return
	}
	format := domain.ReportFormat(strings.TrimSpace(req.Format))
	if !format.IsValid() {
		writeError(w, http.StatusBadRequest, "unknown format "+req.Format)
		return
	}
	tmpl := report.Template(strings.TrimSpace(req.Template))
	if !tmpl.IsValid() {
		writeError(w, http.StatusBadRequest, "unknown template "+req.Template)
		return
	}
	// A PDF is a print deliverable, so it defaults to the pentest layout; the
	// technical evidence dump remains available explicitly as template
	// "technical" but is not what "give me a PDF" should mean by default.
	if format == domain.ReportPDF && tmpl == report.TemplateTechnical {
		tmpl = report.TemplatePentest
	}
	if format == domain.ReportPDF && s.pdf == nil {
		writeError(w, http.StatusServiceUnavailable, "pdf export requires Chromium: start the server with -chromium PATH or INDAGO_CHROMIUM_PATH")
		return
	}
	var gen report.Generator
	if format != domain.ReportPDF {
		gen, err = report.For(format)
		if err != nil {
			s.writeInternalError(w, "report generator", err)
			return
		}
	}

	all, err := s.store.Findings().ListByScan(r.Context(), scanID)
	if err != nil {
		s.writeInternalError(w, "list findings", err)
		return
	}
	findings, mode, msg := resolveSelection(all, req.Mode, req.FindingIDs)
	if msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}

	lookup, err := s.loadEvidence(r.Context(), scanID)
	if err != nil {
		s.writeInternalError(w, "list evidence", err)
		return
	}
	seenEv := map[domain.ID]bool{}
	var evMeta []*domain.Evidence // metadata only, for roles and the verified candidate's artifacts
	for _, f := range findings {
		for _, ev := range lookup.metadata(f) {
			if !seenEv[ev.ID] {
				seenEv[ev.ID] = true
				evMeta = append(evMeta, ev)
			}
		}
	}

	now := time.Now()
	var aiSummary string
	if req.AISummary {
		aiSummary = s.draftAISummary(r.Context(), scanID, proj, sc, findings, len(all), req.AIProvider, req.AIModel)
	}
	var buf bytes.Buffer
	data := report.Data{
		Project:      *proj,
		Scan:         *sc,
		Findings:     findings,
		Evidence:     evMeta,
		GeneratedAt:  now,
		ToolVersion:  s.version,
		Selection:    mode,
		ScanFindings: len(all),
		Completeness: coverage,
		AISummary:    aiSummary,
		Template:     tmpl,
	}
	if format == domain.ReportPDF {
		// Render the chosen template as HTML, then print it. The HTML is
		// never persisted: only the PDF is the report artifact.
		var htmlBuf bytes.Buffer
		if err := (report.HTMLGenerator{}).Generate(&htmlBuf, data); err != nil {
			s.writeInternalError(w, "generate report", err)
			return
		}
		pdfBytes, err := s.pdf.Render(r.Context(), htmlBuf.Bytes())
		if err != nil {
			s.log.Error("pdf export failed", "scan", scanID, "err", err)
			writeError(w, http.StatusBadGateway, "pdf export failed: "+err.Error())
			return
		}
		buf.Write(pdfBytes)
	} else if err := gen.Generate(&buf, data); err != nil {
		s.writeInternalError(w, "generate report", err)
		return
	}

	// Persist the layout that actually produced the file. JSON is a machine
	// format with no layout, and an empty non-JSON template means the
	// technical layout (the pre-template default).
	storedTemplate := string(tmpl)
	if format == domain.ReportJSON {
		storedTemplate = ""
	} else if storedTemplate == "" {
		storedTemplate = string(report.TemplateTechnical)
	}
	rpt := &domain.Report{
		ID:        domain.NewID(),
		ScanID:    scanID,
		ProjectID: sc.ProjectID,
		Format:    format,
		Template:  storedTemplate,
		Summary:   selectionSummary(scanID, findings, mode, len(all)),
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

// draftAISummaryTimeout bounds the advisory call specifically, separate
// from the gateway's own per-request HTTP timeout: a slow or unreachable
// provider must make report creation merely slower-then-skip the AI
// section, never hang the whole request for the gateway's full budget.
const draftAISummaryTimeout = 30 * time.Second

// draftAISummary asks the AI Gateway for an advisory executive-summary
// paragraph over the report's findings, persisting the attempt as a
// domain.AITask (succeeded or failed) for audit regardless of outcome.
// Returns "" on any error or when AI is disabled — the caller always
// still produces a complete, correct report; this is best-effort, never a
// precondition. See AGENTS.md §2.5 and report.Data.AISummary's doc comment:
// AI output here is prose only, never a finding, verdict, or evidence.
func (s *Server) draftAISummary(ctx context.Context, scanID domain.ID, proj *domain.Project, sc *domain.Scan, findings []*domain.Finding, totalInScan int, provider, model string) string {
	gw, err := s.aiGatewayFor(provider, model)
	if err != nil {
		s.log.Warn("ai: provider unavailable for report summary", "err", err)
		return ""
	}
	if !gw.Enabled() {
		return ""
	}

	byVerdict := map[domain.Verdict]int{}
	var confirmedTitles []string
	for _, f := range findings {
		byVerdict[f.Verdict]++
		if f.Verdict == domain.VerdictConfirmed {
			title := f.Title
			if title == "" {
				title = string(f.ID)
			}
			confirmedTitles = append(confirmedTitles, title)
		}
	}
	prompt := "Draft a short (3-6 sentence) executive summary paragraph for a web security assessment report. " +
		"Plain prose, no markdown headings, no bullet lists. State the overall posture and call out the " +
		"confirmed findings by name if there are any; otherwise say none were confirmed. " +
		"Do not invent findings, severities or affected assets beyond those listed. Advisory only."
	scanName := sc.Name
	if scanName == "" {
		scanName = string(sc.ID)
	}
	reqCtx := map[string]any{
		"project":          proj.Name,
		"scan":             scanName,
		"total_in_scan":    totalInScan,
		"in_report":        len(findings),
		"by_verdict":       byVerdict,
		"confirmed_titles": confirmedTitles,
	}

	task := &domain.AITask{
		ID:        domain.NewID(),
		ScanID:    scanID,
		Kind:      domain.AIDraftReport,
		State:     domain.AIRunning,
		Advisory:  true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if reqJSON, err := json.Marshal(reqCtx); err == nil {
		task.Request = reqJSON
	}
	if err := s.store.AITasks().Create(ctx, task); err != nil {
		s.log.Warn("ai: record task", "err", err)
		// Not fatal to the summary attempt itself — persistence failing
		// doesn't mean the advisory call shouldn't still be tried.
	}

	callCtx, cancel := context.WithTimeout(ctx, draftAISummaryTimeout)
	defer cancel()
	resp, err := gw.Advise(callCtx, ai.Request{Kind: domain.AIDraftReport, Prompt: prompt, Context: reqCtx})
	task.UpdatedAt = time.Now()
	if err != nil {
		s.log.Warn("ai: draft report summary failed", "err", err)
		task.State = domain.AIFailed
		task.Error = err.Error()
		_ = s.store.AITasks().Update(ctx, task)
		return ""
	}
	task.State = domain.AISucceeded
	task.Provider = resp.Provider
	task.Model = resp.Model
	task.Response = []byte(resp.Text)
	if err := s.store.AITasks().Update(ctx, task); err != nil {
		s.log.Warn("ai: record task result", "err", err)
	}
	return resp.Text
}

// resolveSelection applies a report selection mode to the scan's findings
// and returns the chosen findings, the effective mode, and a user-facing
// error message ("" when valid). "confirmed" filters on the stored verdict
// only — it never infers or upgrades a verdict. Mixing finding_ids with a mode
// that ignores them is rejected rather than silently dropping the IDs.
func resolveSelection(all []*domain.Finding, rawMode string, ids []string) ([]*domain.Finding, domain.ReportSelection, string) {
	mode := domain.ReportSelection(strings.TrimSpace(rawMode))
	if mode == "" {
		mode = domain.ReportSelectAll
		if len(ids) > 0 {
			mode = domain.ReportSelectSelected
		}
	}
	switch mode {
	case domain.ReportSelectAll, domain.ReportSelectConfirmed:
		if len(ids) > 0 {
			return nil, mode, "finding_ids is only valid with mode \"selected\""
		}
		if mode == domain.ReportSelectAll {
			return all, mode, ""
		}
		out := make([]*domain.Finding, 0, len(all))
		for _, f := range all {
			if f.Verdict == domain.VerdictConfirmed {
				out = append(out, f)
			}
		}
		return out, mode, ""
	case domain.ReportSelectSelected:
		if len(ids) == 0 {
			return nil, mode, "mode \"selected\" requires at least one finding_id"
		}
		out, msg := selectFindings(all, ids)
		return out, mode, msg
	default:
		return nil, mode, "unknown mode " + rawMode + " (want all, confirmed, or selected)"
	}
}

// scanCompleteness summarizes how much of the scan actually ran, from the
// scan's own persisted jobs and test cases. A report over a scan that is not
// finished — or that left dead/failed/canceled jobs or errored/timed-out test
// cases behind — must say so: an empty result from such a scan is not evidence
// the target is clean. A store error propagates so the handler fails the
// report instead of silently claiming complete coverage.
func (s *Server) scanCompleteness(ctx context.Context, scanID domain.ID, state domain.ScanState) (report.Completeness, error) {
	c := report.Completeness{State: state}
	jobs, err := s.store.Jobs().ListByScan(ctx, scanID)
	if err != nil {
		return c, fmt.Errorf("list jobs: %w", err)
	}
	for _, j := range jobs {
		switch j.State {
		case domain.JobDead:
			c.DeadJobs++
		case domain.JobFailed:
			c.FailedJobs++
		case domain.JobCanceled:
			c.CanceledJobs++
		}
	}
	cases, err := s.store.TestCases().ListByScan(ctx, scanID)
	if err != nil {
		return c, fmt.Errorf("list test cases: %w", err)
	}
	for _, tc := range cases {
		switch tc.Outcome {
		case domain.OutcomeError:
			c.ErrorTestCases++
		case domain.OutcomeTimeout:
			c.TimeoutTestCases++
		}
	}
	return c, nil
}

// selectionSummary is the report summary plus how its findings were chosen.
func selectionSummary(scanID domain.ID, findings []*domain.Finding, mode domain.ReportSelection, scanTotal int) domain.ReportSummary {
	sum := report.Summarize(scanID, findings)
	sum.Selection = mode
	sum.ScanFindings = scanTotal
	return sum
}

// handlePreviewReport reports exactly which findings a generate request with
// the same mode/finding_id parameters would include — count and verdict
// breakdown — without writing anything, so the UI can show it beforehand.
// Query: ?mode=all|confirmed|selected&finding_id=ID (repeatable).
func (s *Server) handlePreviewReport(w http.ResponseWriter, r *http.Request) {
	scanID := domain.ID(r.PathValue("id"))
	if _, err := s.store.Scans().Get(r.Context(), scanID); err != nil {
		s.writeLookupError(w, err)
		return
	}
	all, err := s.store.Findings().ListByScan(r.Context(), scanID)
	if err != nil {
		s.writeInternalError(w, "list findings", err)
		return
	}
	q := r.URL.Query()
	findings, mode, msg := resolveSelection(all, q.Get("mode"), q["finding_id"])
	if msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	writeJSON(w, http.StatusOK, selectionSummary(scanID, findings, mode, len(all)))
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
	case domain.ReportPDF:
		return ".pdf"
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
	case domain.ReportPDF:
		return "application/pdf"
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
	setSafeContentHeaders(w) // reports embed target-derived strings; see findings.go
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
