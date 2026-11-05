package web

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/indago/indago/internal/domain"
)

// Capabilities is what this server instance can actually do. The UI and API
// consumers read it so a scan that could not run browser verification is never
// mistaken for a clean one. The zero value reports everything off.
type Capabilities struct {
	BrowserEnabled       bool `json:"browser_enabled"`
	BrowserSandbox       bool `json:"browser_sandbox"`
	StateChangingAllowed bool `json:"state_changing_allowed"`
}

// SetCapabilities records what the server was started with. cmd/indago calls it
// from the real flags; a Server that never does reports the browser as off.
func (s *Server) SetCapabilities(c Capabilities) { s.caps = c }

func (s *Server) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"version":                s.version,
		"browser_enabled":        s.caps.BrowserEnabled,
		"browser_sandbox":        s.caps.BrowserEnabled && s.caps.BrowserSandbox,
		"state_changing_allowed": s.caps.StateChangingAllowed,
		"interactive_login":      s.login != nil,
	})
}

// ---------------------------------------------------------------------------
// Skip reasons
// ---------------------------------------------------------------------------

// Severities of a coverage reason or warning. "info" never counts as a gap.
const (
	sevHigh   = "high"
	sevMedium = "medium"
	sevInfo   = "info"
)

type skipReason struct {
	Code     string
	Severity string
	Title    string
	Advice   string
}

// classifySkip maps the free-text note a skipped test case carries to a stable
// reason. The notes are written by the executors (internal/scan) and are the
// only record of why a probe did not run, so the patterns here are pinned by a
// test against the strings those executors emit. An unrecognised note is never
// dropped silently: it is reported as "other" with a medium severity so an
// operator looks at it.
func classifySkip(note string) skipReason {
	n := strings.ToLower(note)
	switch {
	case strings.Contains(n, "no browser configured"):
		return skipReason{"browser_unavailable", sevHigh, "Browser engine not enabled",
			"Start the server with -browser (and -chromium PATH if Chrome is not found) to run DOM XSS probes and browser confirmation."}
	case strings.Contains(n, "allowstatechanging is off"):
		return skipReason{"state_changing_disabled", sevMedium, "State-changing methods are disabled (POST/PUT/PATCH/DELETE not tested)",
			"Start the server with -allow-state-changing only for a target and scope where sending those requests is authorized."}
	case strings.Contains(n, "browser verification supports") || strings.Contains(n, "not supported for browser document replay"):
		return skipReason{"verification_unsupported", sevMedium, "Browser verification does not support this request shape",
			"Candidates were not confirmed in a browser. Verify these endpoints manually."}
	case strings.Contains(n, "source not tested:"):
		return skipReason{"source_not_applicable", sevInfo, "DOM source had nothing to test on this endpoint",
			"No query parameter, storage key or other input of that kind was found on the endpoint. Usually expected."}
	}
	return skipReason{"other", sevMedium, "Skipped for another reason", "Open the test log and read the note."}
}

// ---------------------------------------------------------------------------
// Coverage
// ---------------------------------------------------------------------------

type coverageReason struct {
	Code     string   `json:"code"`
	Severity string   `json:"severity"`
	Title    string   `json:"title"`
	Advice   string   `json:"advice"`
	Count    int      `json:"count"`
	Examples []string `json:"examples,omitempty"`
}

type coverageWarning struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

type coverageTests struct {
	Total     int `json:"total"`
	Completed int `json:"completed"`
	Skipped   int `json:"skipped"`
	Failed    int `json:"failed"`
	// Incomplete is every other state (cancelled, still pending or running).
	// total == completed + skipped + failed + incomplete, always.
	Incomplete int `json:"incomplete"`
}

// coverageParams is how many discovered parameters ended in each state. Unlike
// Tests it counts what was FOUND, so a parameter that never got a test shows up.
type coverageParams struct {
	Total   int `json:"total"`
	Tested  int `json:"tested"`
	Skipped int `json:"skipped"`
	Errored int `json:"errored"`
	NotRun  int `json:"not_run"`
	Partial int `json:"partial"`
	Pending int `json:"pending"`
}

type scanCoverage struct {
	ScanID         domain.ID         `json:"scan_id"`
	State          domain.ScanState  `json:"state"`
	BrowserEnabled bool              `json:"browser_enabled"`
	CoverageGaps   bool              `json:"coverage_gaps"`
	Tests          coverageTests     `json:"tests"`
	Parameters     coverageParams    `json:"parameters"`
	Reasons        []coverageReason  `json:"reasons"`
	Warnings       []coverageWarning `json:"warnings"`
}

const coverageExamples = 3

// handleScanCoverage answers "what did this scan actually test?". A completed
// scan with no findings and every probe skipped must not look the same as a
// completed scan that tested everything, so it reports skipped probes grouped
// by reason, errored tests, failed jobs and whether the browser was available.
func (s *Server) handleScanCoverage(w http.ResponseWriter, r *http.Request) {
	id := domain.ID(r.PathValue("id"))
	st, err := s.ctrl.Status(r.Context(), id)
	if err != nil {
		s.writeLookupError(w, err)
		return
	}
	cases, err := s.store.TestCases().ListByScan(r.Context(), id)
	if err != nil {
		s.writeInternalError(w, "list test cases", err)
		return
	}

	out := scanCoverage{ScanID: id, State: st.Scan.State, BrowserEnabled: s.caps.BrowserEnabled,
		Reasons: []coverageReason{}, Warnings: []coverageWarning{}}
	groups := map[string]*coverageReason{}
	seen := map[string]map[string]bool{}
	for _, tc := range cases {
		out.Tests.Total++
		switch {
		case tc.Status == domain.TestCaseSkipped:
			out.Tests.Skipped++
			rs := classifySkip(tc.Note)
			g := groups[rs.Code]
			if g == nil {
				g = &coverageReason{Code: rs.Code, Severity: rs.Severity, Title: rs.Title, Advice: rs.Advice}
				groups[rs.Code] = g
				seen[rs.Code] = map[string]bool{}
			}
			g.Count++
			if tc.URL != "" && len(g.Examples) < coverageExamples && !seen[rs.Code][tc.URL] {
				seen[rs.Code][tc.URL] = true
				g.Examples = append(g.Examples, tc.URL)
			}
		case tc.Outcome == domain.OutcomeError || tc.Outcome == domain.OutcomeTimeout || tc.Status == domain.TestCaseFailed:
			out.Tests.Failed++
		case tc.Status == domain.TestCaseCompleted:
			out.Tests.Completed++
		default:
			out.Tests.Incomplete++
		}
	}
	for _, g := range groups {
		out.Reasons = append(out.Reasons, *g)
	}
	sort.Slice(out.Reasons, func(i, j int) bool {
		if ri, rj := sevRank(out.Reasons[i].Severity), sevRank(out.Reasons[j].Severity); ri != rj {
			return ri > rj
		}
		return out.Reasons[i].Code < out.Reasons[j].Code
	})

	if !s.caps.BrowserEnabled {
		out.Warnings = append(out.Warnings, coverageWarning{"browser_disabled", sevHigh,
			"The browser engine is not enabled on this server. DOM XSS probes are not run and reflected-XSS candidates cannot be confirmed in a browser, so zero findings does not mean the target is clean."})
	}
	for _, rs := range out.Reasons {
		if rs.Severity == sevInfo || (rs.Code == "browser_unavailable" && !s.caps.BrowserEnabled) {
			continue // informational, or already covered by the browser_disabled warning
		}
		out.Warnings = append(out.Warnings, coverageWarning{rs.Code, rs.Severity,
			strconv.Itoa(rs.Count) + " test(s) skipped: " + rs.Title + ". " + rs.Advice})
	}
	if out.Tests.Failed > 0 {
		out.Warnings = append(out.Warnings, coverageWarning{"tests_errored", sevMedium,
			strconv.Itoa(out.Tests.Failed) + " test(s) ended in an error or timeout. Those targets are untested, not negative."})
	}
	terminal := st.Scan.State.IsTerminal()
	switch st.Scan.State {
	case domain.ScanFailed:
		out.Warnings = append(out.Warnings, coverageWarning{"scan_failed", sevHigh,
			"The scan failed before it finished. Whatever it recorded is partial; zero findings says nothing about the rest of the target."})
	case domain.ScanCanceled:
		out.Warnings = append(out.Warnings, coverageWarning{"scan_canceled", sevMedium,
			"The scan was canceled before it finished. Work that had not run is untested."})
	}
	if terminal && out.Tests.Incomplete > 0 {
		out.Warnings = append(out.Warnings, coverageWarning{"tests_incomplete", sevMedium,
			strconv.Itoa(out.Tests.Incomplete) + " test(s) were cancelled or never finished."})
	}
	if model, err := s.buildExplorer(r.Context(), id, terminal, cases); err != nil {
		// Fail closed: a coverage view that cannot be computed must not read as clean.
		s.log.Warn("coverage: build explorer", "scan", id, "err", err)
		out.Warnings = append(out.Warnings, coverageWarning{"coverage_unavailable", sevMedium,
			"Parameter and page coverage could not be computed, so this view is incomplete."})
	} else {
		bs := model.Summary.ByStatus
		out.Parameters = coverageParams{Total: model.Summary.Parameters, Tested: bs[stTested], Skipped: bs[stSkipped],
			Errored: bs[stErrored], NotRun: bs[stNotRun], Partial: bs[stPartial], Pending: bs[stPending]}
		// Skipped work is already explained by its skip reason above; these are the
		// states nothing else accounts for.
		if terminal {
			if n := bs[stErrored] + bs[stNotRun] + bs[stPartial]; n > 0 {
				out.Warnings = append(out.Warnings, coverageWarning{"parameters_untested", sevMedium,
					strconv.Itoa(n) + " of " + strconv.Itoa(model.Summary.Parameters) + " discovered parameter(s) are not fully tested (errored, never run, or only partly completed). Open the Endpoints tab to see which."})
			}
			ds := model.Summary.DOMByStatus
			if n := ds[stErrored] + ds[stNotRun] + ds[stPartial]; n > 0 {
				out.Warnings = append(out.Warnings, coverageWarning{"dom_sources_untested", sevMedium,
					strconv.Itoa(n) + " DOM XSS source probe(s) errored, never ran, or only partly completed. Open the Endpoints tab to see which pages."})
			}
		}
	}
	if bad := st.Jobs.Failed + st.Jobs.Dead + st.Jobs.Canceled; bad > 0 {
		out.Warnings = append(out.Warnings, coverageWarning{"jobs_failed", sevMedium,
			strconv.Itoa(bad) + " job(s) failed, died or were canceled. Their work did not complete."})
	}
	for _, wn := range out.Warnings {
		if wn.Severity == sevHigh || wn.Severity == sevMedium {
			out.CoverageGaps = true
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func sevRank(s string) int {
	switch s {
	case sevHigh:
		return 3
	case sevMedium:
		return 2
	}
	return 1
}

// ---------------------------------------------------------------------------
// Test log
// ---------------------------------------------------------------------------

const (
	testsDefaultLimit = 100
	testsMaxLimit     = 500
	testsNoteMax      = 500
)

type testListItem struct {
	ID         domain.ID             `json:"id"`
	JobID      domain.ID             `json:"job_id"`
	VulnClass  domain.VulnClass      `json:"vuln_class,omitempty"`
	Status     domain.TestCaseStatus `json:"status"`
	Outcome    domain.TestOutcome    `json:"outcome,omitempty"`
	Method     string                `json:"method,omitempty"`
	URL        string                `json:"url,omitempty"`
	HTTPStatus int                   `json:"http_status,omitempty"`
	DurationMS int64                 `json:"duration_ms,omitempty"`
	Note       string                `json:"note,omitempty"`
	Error      string                `json:"error,omitempty"`
	ReasonCode string                `json:"reason_code,omitempty"`
	FinishedAt *time.Time            `json:"finished_at,omitempty"`
	CreatedAt  time.Time             `json:"created_at"`
}

type testListResponse struct {
	Total  int            `json:"total"`
	Limit  int            `json:"limit"`
	Offset int            `json:"offset"`
	Items  []testListItem `json:"items"`
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// handleListScanTests lists a scan's test cases with filters and paging, so the
// operator can see which URL was tested or skipped and why without reading the
// database. It deliberately omits the engine-specific Detail blob.
func (s *Server) handleListScanTests(w http.ResponseWriter, r *http.Request) {
	id := domain.ID(r.PathValue("id"))
	if _, err := s.store.Scans().Get(r.Context(), id); err != nil {
		s.writeLookupError(w, err)
		return
	}
	q := r.URL.Query()
	limit, offset := testsDefaultLimit, 0
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			writeError(w, http.StatusBadRequest, "limit must be a positive integer")
			return
		}
		limit = n
	}
	if limit > testsMaxLimit {
		limit = testsMaxLimit
	}
	if v := q.Get("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			writeError(w, http.StatusBadRequest, "offset must be a non-negative integer")
			return
		}
		offset = n
	}
	var statusFilter domain.TestCaseStatus
	if v := q.Get("status"); v != "" {
		statusFilter = domain.TestCaseStatus(v)
		if !statusFilter.IsValid() {
			writeError(w, http.StatusBadRequest, "unknown status "+strconv.Quote(v))
			return
		}
	}
	outcomes := map[string]bool{}
	for _, o := range strings.Split(q.Get("outcome"), ",") {
		if o = strings.TrimSpace(o); o != "" {
			outcomes[o] = true
		}
	}
	reason := q.Get("reason")

	cases, err := s.store.TestCases().ListByScan(r.Context(), id)
	if err != nil {
		s.writeInternalError(w, "list test cases", err)
		return
	}
	sort.SliceStable(cases, func(i, j int) bool { return cases[i].CreatedAt.After(cases[j].CreatedAt) })

	matched := make([]*domain.TestCase, 0, len(cases))
	for _, tc := range cases {
		if statusFilter != "" && tc.Status != statusFilter {
			continue
		}
		if len(outcomes) > 0 && !outcomes[string(tc.Outcome)] {
			continue
		}
		if reason != "" && (tc.Status != domain.TestCaseSkipped || classifySkip(tc.Note).Code != reason) {
			continue
		}
		matched = append(matched, tc)
	}

	resp := testListResponse{Total: len(matched), Limit: limit, Offset: offset, Items: []testListItem{}}
	for i := offset; i < len(matched) && i < offset+limit; i++ {
		tc := matched[i]
		item := testListItem{
			ID: tc.ID, JobID: tc.JobID, VulnClass: tc.VulnClass, Status: tc.Status, Outcome: tc.Outcome,
			Method: tc.Method, URL: tc.URL, HTTPStatus: tc.HTTPStatus, DurationMS: tc.DurationMS,
			Note: clip(tc.Note, testsNoteMax), Error: clip(tc.Error, testsNoteMax), FinishedAt: tc.FinishedAt, CreatedAt: tc.CreatedAt,
		}
		if tc.Status == domain.TestCaseSkipped {
			item.ReasonCode = classifySkip(tc.Note).Code
		}
		resp.Items = append(resp.Items, item)
	}
	writeJSON(w, http.StatusOK, resp)
}
