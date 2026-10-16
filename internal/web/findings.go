package web

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/report"
)

// --- findings ---

// handleListFindings lists the findings recorded for a scan, in presentation
// order (confirmed first, then needs-review, then diagnostics; oldest first
// within each). ?verdict= narrows them: a comma-separated list of verdicts, or
// "all" (the default, so existing clients are unaffected). Each item carries
// its section, the endpoint, and — for a confirmed finding — the candidate
// whose browser verification succeeded.
func (s *Server) handleListFindings(w http.ResponseWriter, r *http.Request) {
	scanID := domain.ID(r.PathValue("id"))
	if _, err := s.store.Scans().Get(r.Context(), scanID); err != nil {
		s.writeLookupError(w, err)
		return
	}
	want, msg := parseVerdictFilter(r.URL.Query().Get("verdict"))
	if msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	findings, err := s.store.Findings().ListByScan(r.Context(), scanID)
	if err != nil {
		s.writeInternalError(w, "list findings", err)
		return
	}
	lookup, err := s.loadEvidence(r.Context(), scanID)
	if err != nil {
		s.writeInternalError(w, "list evidence", err)
		return
	}
	items := make([]findingListItem, 0, len(findings))
	endpoints := map[domain.ID]*domain.Endpoint{}
	for _, f := range report.Prioritized(findings) {
		if want != nil && !want[f.Verdict] {
			continue
		}
		v := lookup.view(f)
		item := findingListItem{
			Finding: f, Section: v.Section, ParameterName: v.ParamName,
			Verified: v.Verified, AttemptCount: len(v.Attempts), ReviewReasonLabel: v.ReviewReasonLabel,
		}
		if len(v.Candidates) > 0 {
			item.Context = v.Candidates[0].Context
		}
		if f.EndpointID != "" {
			ep, ok := endpoints[f.EndpointID]
			if !ok {
				ep, _ = s.store.Endpoints().Get(r.Context(), f.EndpointID)
				endpoints[f.EndpointID] = ep
			}
			if ep != nil {
				item.EndpointMethod, item.EndpointURL = string(ep.Method), ep.URL
			}
		}
		items = append(items, item)
	}
	writeJSON(w, http.StatusOK, items)
}

// parseVerdictFilter parses ?verdict=. nil means "no filter".
func parseVerdictFilter(raw string) (map[domain.Verdict]bool, string) {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "all" {
		return nil, ""
	}
	want := map[domain.Verdict]bool{}
	for _, part := range strings.Split(raw, ",") {
		v := domain.Verdict(strings.TrimSpace(part))
		if !v.IsValid() {
			return nil, "unknown verdict " + strings.TrimSpace(part) + " (want confirmed, rejected, inconclusive, pending, or all)"
		}
		want[v] = true
	}
	return want, ""
}

// findingListItem is a finding plus where it is (endpoint, parameter,
// execution context), which section it belongs in, and the verified candidate
// (confirmed findings only). Without the endpoint, findings for the same
// parameter and context on different endpoints are indistinguishable in a
// list. Additive fields: a client decoding plain domain.Finding values (the
// CLI) is unaffected.
type findingListItem struct {
	*domain.Finding
	EndpointMethod    string              `json:"endpoint_method,omitempty"`
	EndpointURL       string              `json:"endpoint_url,omitempty"`
	Section           report.Section      `json:"section"`
	ParameterName     string              `json:"parameter_name,omitempty"`
	Context           string              `json:"context,omitempty"`
	Verified          *report.AttemptView `json:"verified_candidate,omitempty"`
	AttemptCount      int                 `json:"attempt_count"`
	ReviewReasonLabel string              `json:"review_reason_label,omitempty"`
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
	Technique        string `json:"technique,omitempty"`
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
	Attempts      []findingAttempt   `json:"attempts,omitempty"`
}

// findingAttempt mirrors scan.verificationAttempt (by field name): one
// verification attempt's own verdict and evidence; see findingCandidate.
type findingAttempt struct {
	CandidateValue      string      `json:"candidate_value"`
	URL                 string      `json:"url,omitempty"`
	CandidateTestCaseID domain.ID   `json:"candidate_test_case_id,omitempty"`
	VerifyTestCaseID    domain.ID   `json:"verify_test_case_id,omitempty"`
	Verdict             string      `json:"verdict"`
	Confidence          string      `json:"confidence,omitempty"`
	Notes               string      `json:"notes,omitempty"`
	EvidenceIDs         []domain.ID `json:"evidence_ids,omitempty"`
	At                  time.Time   `json:"at"`
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
// handleGetEvidenceContent, a deliberate, separate action. Evidence is
// role-labelled and ordered (browser verification, then the candidate's
// request/response, then the baseline reference last).
type findingView struct {
	*domain.Finding
	ParsedDetail      findingDetail         `json:"parsed_detail"`
	Endpoint          *domain.Endpoint      `json:"endpoint,omitempty"`
	Parameter         *domain.Parameter     `json:"parameter,omitempty"`
	Section           report.Section        `json:"section"`
	Verified          *report.AttemptView   `json:"verified_candidate,omitempty"`
	Attempts          []report.AttemptView  `json:"attempts,omitempty"`
	Evidence          []report.EvidenceView `json:"evidence"`
	ReviewReasonLabel string                `json:"review_reason_label,omitempty"`
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

	lookup, err := s.loadEvidence(r.Context(), scanID)
	if err != nil {
		s.writeInternalError(w, "list evidence", err)
		return
	}
	rv := lookup.view(f)
	view := &findingView{
		Finding: f, ParsedDetail: decodeFindingDetail(f.Detail),
		Section: rv.Section, Verified: rv.Verified, Attempts: rv.Attempts, Evidence: nonNil(rv.Evidence),
		ReviewReasonLabel: rv.ReviewReasonLabel,
	}
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
	writeJSON(w, http.StatusOK, view)
}

// evidenceLookup resolves a scan's evidence metadata for its findings. The
// authoritative finding→evidence link is Finding.EvidenceIDs — correlation
// unions every attempt's request/response and browser evidence there, while
// the evidence rows themselves are written by the executors before any finding
// exists and so never carry a finding_id. Rows that DO carry one are unioned
// in too. Only THIS scan's rows are indexed, so an ID that no longer resolves
// or belongs to another scan is skipped, never fabricated or leaked.
type evidenceLookup struct {
	byID      map[domain.ID]*domain.Evidence
	byFinding map[domain.ID][]domain.ID
}

func (s *Server) loadEvidence(ctx context.Context, scanID domain.ID) (*evidenceLookup, error) {
	rows, err := s.store.Evidence().ListByScan(ctx, scanID)
	if err != nil {
		return nil, err
	}
	l := &evidenceLookup{byID: make(map[domain.ID]*domain.Evidence, len(rows)), byFinding: map[domain.ID][]domain.ID{}}
	for _, ev := range rows {
		l.byID[ev.ID] = ev
		if ev.FindingID != "" {
			l.byFinding[ev.FindingID] = append(l.byFinding[ev.FindingID], ev.ID)
		}
	}
	return l, nil
}

// ids returns f.EvidenceIDs plus any rows linked by finding_id, deduplicated.
func (l *evidenceLookup) ids(f *domain.Finding) []domain.ID {
	seen := map[domain.ID]bool{}
	var out []domain.ID
	for _, id := range append(append([]domain.ID(nil), f.EvidenceIDs...), l.byFinding[f.ID]...) {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

// view derives the finding's presentation (section, verified candidate,
// attempts, role-ordered evidence).
func (l *evidenceLookup) view(f *domain.Finding) report.FindingView {
	withLinked := *f
	withLinked.EvidenceIDs = l.ids(f)
	return report.NewFindingView(&withLinked, l.byID)
}

// metadata returns the resolvable evidence rows for f, for report generation.
func (l *evidenceLookup) metadata(f *domain.Finding) []*domain.Evidence {
	var out []*domain.Evidence
	for _, id := range l.ids(f) {
		if ev := l.byID[id]; ev != nil {
			out = append(out, ev)
		}
	}
	return out
}

// scanEvidenceGroup is one finding's evidence, as listed by the Evidence tab.
type scanEvidenceGroup struct {
	FindingID         domain.ID             `json:"finding_id"`
	FindingTitle      string                `json:"finding_title"`
	Verdict           domain.Verdict        `json:"verdict"`
	Section           report.Section        `json:"section"`
	VerifiedCandidate string                `json:"verified_candidate,omitempty"`
	Evidence          []report.EvidenceView `json:"evidence"`
}

// handleListScanEvidence returns evidence metadata (never content) for every
// finding in a scan, grouped by finding, confirmed findings first. One request
// instead of the UI fetching each finding's detail.
func (s *Server) handleListScanEvidence(w http.ResponseWriter, r *http.Request) {
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
	lookup, err := s.loadEvidence(r.Context(), scanID)
	if err != nil {
		s.writeInternalError(w, "list evidence", err)
		return
	}
	groups := make([]scanEvidenceGroup, 0, len(findings))
	for _, f := range report.Prioritized(findings) {
		v := lookup.view(f)
		g := scanEvidenceGroup{FindingID: f.ID, FindingTitle: f.Title, Verdict: f.Verdict, Section: v.Section, Evidence: nonNil(v.Evidence)}
		if v.Verified != nil {
			g.VerifiedCandidate = v.Verified.CandidateValue
		}
		groups = append(groups, g)
	}
	writeJSON(w, http.StatusOK, groups)
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

	setSafeContentHeaders(w)
	w.Header().Set("Content-Type", viewableMediaType(ev.MediaType))
	disposition := "inline"
	if r.URL.Query().Has("download") {
		disposition = "attachment"
	}
	w.Header().Set("Content-Disposition", disposition+`; filename="`+string(ev.ID)+evidenceExt(ev)+`"`)
	_, _ = io.Copy(w, rc)
}

// setSafeContentHeaders applies to every response that serves captured or
// generated content (evidence blobs, rendered reports) from this origin.
// Evidence is attacker-influenced by construction: a captured response or a
// rendered DOM is the TARGET's markup, including its scripts and any reflected
// candidate. Served inline on the control plane's own origin, that markup
// would run with the operator UI's privileges — and same-origin script can
// set X-Indago-Client and drive the API. The CSP "sandbox" directive (without
// allow-scripts) puts the document in a unique opaque origin with scripts,
// forms, and plugins disabled; default-src 'none' blocks every fetch it could
// make (images only as data: URIs, inline styles allowed so captured pages
// still render legibly). nosniff stops a non-HTML type being sniffed into HTML.
func setSafeContentHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Security-Policy", "sandbox; default-src 'none'; img-src data:; style-src 'unsafe-inline'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
}

// viewableMediaType maps a stored evidence media type to what is served for
// viewing. HTTP-message dumps (message/http) and logs are shown as plain text
// — browsers otherwise download message/http, and plain text can never be
// interpreted as markup. HTML (a rendered DOM) and PNG keep their types: they
// are rendered under the sandbox CSP above. Anything else unknown is served
// as an opaque download type.
func viewableMediaType(mt string) string {
	base := strings.ToLower(strings.TrimSpace(strings.SplitN(mt, ";", 2)[0]))
	switch base {
	case "message/http", "text/plain":
		return "text/plain; charset=utf-8"
	case "text/html":
		return "text/html; charset=utf-8"
	case "image/png", "image/jpeg":
		return base
	default:
		return "application/octet-stream"
	}
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
