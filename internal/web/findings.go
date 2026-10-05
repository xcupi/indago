package web

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/indago/indago/internal/domain"
)

// --- findings ---

// handleListFindings lists every finding recorded for a scan.
func (s *Server) handleListFindings(w http.ResponseWriter, r *http.Request) {
	scanID := domain.ID(r.PathValue("id"))
	if _, err := s.store.Scans().Get(r.Context(), scanID); err != nil {
		s.writeLookupError(w, err)
		return
	}
	findings, err := s.store.Findings().ListByScan(r.Context(), scanID)
	if err != nil {
		s.writeInternalError(w, "list findings", err)
		return
	}
	writeJSON(w, http.StatusOK, nonNil(findings))
}

// findingCandidate mirrors detection.Candidate's JSON shape (by field name)
// for display purposes only. Like markdownDetail in internal/report, it
// exists so this package decodes Finding.Detail without importing
// internal/detection or internal/scan.
type findingCandidate struct {
	Source           string `json:"source,omitempty"`
	Category         string `json:"category,omitempty"`
	Parameter        string `json:"parameter,omitempty"`
	Location         string `json:"location,omitempty"`
	Context          string `json:"context,omitempty"`
	ContextSub       string `json:"context_sub,omitempty"`
	Value            string `json:"value,omitempty"`
	Transformation   string `json:"transformation,omitempty"`
	Priority         int    `json:"priority,omitempty"`
	Rationale        string `json:"rationale,omitempty"`
	DedupKey         string `json:"dedup_key,omitempty"`
	InjectionPointID string `json:"injection_point_id,omitempty"`
}

// findingDetail mirrors scan.findingDetail's JSON shape (by field name) for
// display purposes only; see findingCandidate.
type findingDetail struct {
	Method        string             `json:"method,omitempty"`
	ParameterName string             `json:"parameter_name,omitempty"`
	DedupKey      string             `json:"dedup_key,omitempty"`
	Occurrences   int                `json:"occurrences,omitempty"`
	TestCaseIDs   []domain.ID        `json:"test_case_ids,omitempty"`
	Candidates    []findingCandidate `json:"candidates,omitempty"`
}

func decodeFindingDetail(b []byte) findingDetail {
	var d findingDetail
	if len(b) > 0 {
		_ = json.Unmarshal(b, &d)
	}
	return d
}

// findingView is a finding plus the context, candidate, provenance, and
// evidence-metadata detail the operator needs to assess it, without exposing
// evidence secrets: Evidence here is metadata only (see domain.Evidence) —
// the raw content behind BlobPath is only ever served by
// handleGetEvidenceContent, a deliberate, separate action.
type findingView struct {
	*domain.Finding
	ParsedDetail findingDetail      `json:"parsed_detail"`
	Endpoint     *domain.Endpoint   `json:"endpoint,omitempty"`
	Parameter    *domain.Parameter  `json:"parameter,omitempty"`
	Evidence     []*domain.Evidence `json:"evidence,omitempty"`
}

// handleGetFinding returns a finding's full detail view, scoped to the scan
// in the path (a finding ID from a different scan is reported as not found).
func (s *Server) handleGetFinding(w http.ResponseWriter, r *http.Request) {
	scanID := domain.ID(r.PathValue("id"))
	if _, err := s.store.Scans().Get(r.Context(), scanID); err != nil {
		s.writeLookupError(w, err)
		return
	}
	f, err := s.store.Findings().Get(r.Context(), domain.ID(r.PathValue("fid")))
	if err != nil {
		s.writeLookupError(w, err)
		return
	}
	if f.ScanID != scanID {
		writeError(w, http.StatusNotFound, "not found")
		return
	}

	view := &findingView{Finding: f, ParsedDetail: decodeFindingDetail(f.Detail)}
	if f.EndpointID != "" {
		if ep, err := s.store.Endpoints().Get(r.Context(), f.EndpointID); err == nil {
			view.Endpoint = ep
		}
	}
	if f.ParameterID != "" {
		if p, err := s.store.Parameters().Get(r.Context(), f.ParameterID); err == nil {
			view.Parameter = p
		}
	}
	if ev, err := s.store.Evidence().ListByFinding(r.Context(), f.ID); err == nil {
		view.Evidence = nonNil(ev)
	}
	writeJSON(w, http.StatusOK, view)
}

// --- evidence ---

// handleGetEvidence returns evidence metadata only — no blob content, so no
// secrets a captured request/response might carry (e.g. a session cookie).
func (s *Server) handleGetEvidence(w http.ResponseWriter, r *http.Request) {
	ev, err := s.store.Evidence().Get(r.Context(), domain.ID(r.PathValue("id")))
	if err != nil {
		s.writeLookupError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ev)
}

// handleGetEvidenceContent serves the raw evidence blob. Unlike
// handleGetEvidence, this may contain sensitive data (e.g. a session cookie in
// a captured request) — it exists so the operator can deliberately open their
// own evidence, not for inclusion in findings/evidence listings.
func (s *Server) handleGetEvidenceContent(w http.ResponseWriter, r *http.Request) {
	ev, err := s.store.Evidence().Get(r.Context(), domain.ID(r.PathValue("id")))
	if err != nil {
		s.writeLookupError(w, err)
		return
	}
	if s.evidence == nil {
		writeError(w, http.StatusServiceUnavailable, "evidence store not configured")
		return
	}
	rc, err := s.evidence.Open(ev.BlobPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "evidence blob unavailable")
		return
	}
	defer rc.Close()

	ct := ev.MediaType
	if ct == "" {
		ct = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ct)
	if r.URL.Query().Has("download") {
		w.Header().Set("Content-Disposition", `attachment; filename="`+string(ev.ID)+evidenceExt(ev)+`"`)
	}
	_, _ = io.Copy(w, rc)
}

func evidenceExt(ev *domain.Evidence) string {
	for i := len(ev.BlobPath) - 1; i >= 0; i-- {
		switch ev.BlobPath[i] {
		case '.':
			return ev.BlobPath[i:]
		case '/':
			return ""
		}
	}
	return ""
}
