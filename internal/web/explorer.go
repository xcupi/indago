package web

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
)

// ---------------------------------------------------------------------------
// Endpoint / parameter explorer
//
// Answers "what did discovery find, and was each of it tested?". The test log
// lists what ran; this lists what was FOUND and joins it to what ran, so a
// discovered parameter that was never tested is visible instead of absent.
//
// The joins mirror how the pipeline records work:
//   - reflected tests carry TestCase.InjectionPointID, and an injection point
//     maps to exactly one parameter;
//   - DOM probes are one job per (endpoint URL, source), deduplicated by URL
//     (scan.selectDOMXSSEndpoints), so DOM coverage is per endpoint URL and
//     per source, never per parameter;
//   - a fragment-route parameter is not an injection point; only the
//     location.hash DOM source reads it.
// ---------------------------------------------------------------------------

// Parameter / DOM-source coverage statuses.
const (
	stTested  = "tested"  // at least one test completed
	stSkipped = "skipped" // every test was skipped (reason_code says why)
	stErrored = "errored" // tests ran but ended in an error or timeout
	stNotRun  = "not_run" // nothing ran: no job, or the job never produced a test
	stPending = "pending" // the scan is still running; work is queued (not a gap)
	stPartial = "partial" // some tests completed, but the job behind them did not finish
	// endpoint-only
	stGap      = "gap"
	stNoInputs = "no_inputs"
)

const (
	explorerDefaultLimit = 50
	explorerMaxLimit     = 200
	explorerExampleMax   = 120
)

type testTally struct {
	Total     int `json:"total"`
	Completed int `json:"completed"`
	Skipped   int `json:"skipped"`
	Failed    int `json:"failed"`
}

type explorerParam struct {
	ID         domain.ID              `json:"id"`
	Name       string                 `json:"name"`
	Location   domain.ParamLocation   `json:"location"`
	Source     domain.DiscoverySource `json:"source,omitempty"`
	Example    string                 `json:"example,omitempty"`
	Status     string                 `json:"status"`
	ReasonCode string                 `json:"reason_code,omitempty"`
	Gap        bool                   `json:"gap"`
	Tests      testTally              `json:"tests"`
}

type explorerDOM struct {
	Source     string    `json:"source"`
	Status     string    `json:"status"`
	ReasonCode string    `json:"reason_code,omitempty"`
	Gap        bool      `json:"gap"`
	Tests      testTally `json:"tests"`
}

type explorerEndpoint struct {
	ID           domain.ID              `json:"id"`
	Method       domain.HTTPMethod      `json:"method"`
	URL          string                 `json:"url"`
	Source       domain.DiscoverySource `json:"source,omitempty"`
	ContentType  string                 `json:"content_type,omitempty"`
	Status       string                 `json:"status"`
	Gap          bool                   `json:"gap"`
	DOMScheduled bool                   `json:"dom_scheduled"`
	Params       []explorerParam        `json:"parameters"`
	DOM          []explorerDOM          `json:"dom"`
}

type explorerSummary struct {
	Endpoints         int            `json:"endpoints"`
	EndpointsWithGaps int            `json:"endpoints_with_gaps"`
	Parameters        int            `json:"parameters"`
	GapParameters     int            `json:"gap_parameters"`
	ByStatus          map[string]int `json:"by_status"`
	DOMGaps           int            `json:"dom_gaps"`
	DOMByStatus       map[string]int `json:"dom_by_status"`
	EndpointsPending  int            `json:"endpoints_pending"`
}

type explorerModel struct {
	Endpoints []*explorerEndpoint
	Summary   explorerSummary
}

// tally accumulates the test cases behind one parameter or one DOM source.
type tally struct {
	testTally
	cancelled int
	outcome   string // "error" or "timeout" when something failed
	skip      skipReason
	hasSkip   bool
}

func (t *tally) add(tc *domain.TestCase) {
	t.Total++
	switch {
	case tc.Status == domain.TestCaseSkipped:
		t.Skipped++
		rs := classifySkip(tc.Note)
		if !t.hasSkip || sevRank(rs.Severity) > sevRank(t.skip.Severity) {
			t.skip, t.hasSkip = rs, true
		}
	case tc.Status == domain.TestCaseCancelled || tc.Outcome == domain.OutcomeCancelled:
		t.cancelled++
	case tc.Status == domain.TestCaseFailed || tc.Outcome == domain.OutcomeError || tc.Outcome == domain.OutcomeTimeout:
		t.Failed++
		if tc.Outcome == domain.OutcomeTimeout || t.outcome == "" {
			t.outcome = string(tc.Outcome)
			if t.outcome == "" {
				t.outcome = "error"
			}
		}
	case tc.Status == domain.TestCaseCompleted:
		t.Completed++
	}
}

// jobPriority picks the most informative job when several share a target:
// something still active beats a terminal failure beats a success.
func jobPriority(s domain.JobState) int {
	switch s {
	case domain.JobRunning, domain.JobLeased, domain.JobQueued:
		return 4
	case domain.JobDead:
		return 3
	case domain.JobFailed:
		return 2
	case domain.JobCanceled:
		return 1
	}
	return 0
}

func bestJob(jobs []*domain.TestJob) *domain.TestJob {
	var best *domain.TestJob
	for _, j := range jobs {
		if best == nil || jobPriority(j.State) > jobPriority(best.State) {
			best = j
		}
	}
	return best
}

// classify turns what ran (and what was scheduled) into a status. terminal is
// whether the scan has ended: queued work on a running scan is progress, but on
// an ended scan it is work that never happened.
func classify(t tally, jobs []*domain.TestJob, terminal bool) (status, reason string, gap bool) {
	switch {
	case t.Completed > 0:
		// A completed test does not prove the job behind it finished: storage key
		// discovery completes, then a per-key probe fails and the job dies. Only a
		// job that ultimately succeeded (a retry after a timeout counts) is tested.
		if j := bestJob(jobs); j != nil {
			switch j.State {
			case domain.JobQueued, domain.JobLeased, domain.JobRunning, domain.JobFailed:
				// failed = transient, may still be retried while the scan runs
				if !terminal {
					return stPending, "job_" + string(j.State), false
				}
				return stPartial, "job_" + string(j.State), true
			case domain.JobDead, domain.JobCanceled:
				return stPartial, "job_" + string(j.State), true
			}
		}
		return stTested, "", false
	case t.Failed > 0:
		return stErrored, t.outcome, true
	case t.Skipped > 0:
		return stSkipped, t.skip.Code, t.skip.Severity != sevInfo
	case t.cancelled > 0:
		return stNotRun, "cancelled", true
	}
	j := bestJob(jobs)
	if j == nil {
		if !terminal {
			return stPending, "no_job", false
		}
		return stNotRun, "no_job", true
	}
	switch j.State {
	case domain.JobQueued, domain.JobLeased, domain.JobRunning:
		if !terminal {
			return stPending, "job_" + string(j.State), false
		}
		return stNotRun, "job_" + string(j.State), true
	case domain.JobSucceeded:
		return stNotRun, "no_test_recorded", true
	case domain.JobFailed:
		// transient failure, still retryable while the scan runs
		if !terminal {
			return stPending, "job_failed", false
		}
		return stNotRun, "job_failed", true
	default:
		return stNotRun, "job_" + string(j.State), true
	}
}

func clipExample(s string) string {
	if len(s) <= explorerExampleMax {
		return s
	}
	return s[:explorerExampleMax] + "…"
}

func domSourceOf(j *domain.TestJob) string {
	var p struct {
		Source string `json:"source"`
	}
	if json.Unmarshal(j.Payload, &p) != nil {
		return ""
	}
	return p.Source
}

func domNavigable(m domain.HTTPMethod) bool {
	return m == domain.MethodGET || m == domain.MethodHEAD || m == ""
}

// buildExplorer joins a scan's discovery results to its jobs and test cases.
//
// cases may carry the scan's already-loaded test cases (the coverage handler
// has them); nil loads them. The test cases are the expensive part.
func (s *Server) buildExplorer(ctx context.Context, scanID domain.ID, terminal bool, cases []*domain.TestCase) (*explorerModel, error) {
	endpoints, err := s.store.Endpoints().ListByScan(ctx, scanID)
	if err != nil {
		return nil, err
	}
	params, err := s.store.Parameters().ListByScan(ctx, scanID)
	if err != nil {
		return nil, err
	}
	ips, err := s.store.InjectionPoints().ListByScan(ctx, scanID)
	if err != nil {
		return nil, err
	}
	jobs, err := s.store.Jobs().ListByScan(ctx, scanID)
	if err != nil {
		return nil, err
	}
	if cases == nil {
		if cases, err = s.store.TestCases().ListByScan(ctx, scanID); err != nil {
			return nil, err
		}
	}

	ipByParam := map[domain.ID]domain.ID{} // parameter -> injection point
	for _, ip := range ips {
		ipByParam[ip.ParameterID] = ip.ID
	}
	casesByIP := map[domain.ID][]*domain.TestCase{}
	casesByJob := map[domain.ID][]*domain.TestCase{}
	for _, tc := range cases {
		if !tc.InjectionPointID.Empty() {
			casesByIP[tc.InjectionPointID] = append(casesByIP[tc.InjectionPointID], tc)
		}
		casesByJob[tc.JobID] = append(casesByJob[tc.JobID], tc)
	}
	jobsByIP := map[domain.ID][]*domain.TestJob{}
	type domKey struct{ url, source string }
	domJobs := map[domKey][]*domain.TestJob{}
	domSources := map[string][]string{} // url -> sources, in first-seen order
	for _, j := range jobs {
		switch j.Type {
		case domain.JobTest, domain.JobVerify:
			if !j.Target.InjectionPointID.Empty() {
				jobsByIP[j.Target.InjectionPointID] = append(jobsByIP[j.Target.InjectionPointID], j)
			}
		case domain.JobDOMXSS:
			src := domSourceOf(j)
			if src == "" || j.Target.URL == "" {
				continue
			}
			k := domKey{j.Target.URL, src}
			if _, seen := domJobs[k]; !seen {
				domSources[j.Target.URL] = append(domSources[j.Target.URL], src)
			}
			domJobs[k] = append(domJobs[k], j)
		}
	}
	paramsByEndpoint := map[domain.ID][]*domain.Parameter{}
	for _, p := range params {
		paramsByEndpoint[p.EndpointID] = append(paramsByEndpoint[p.EndpointID], p)
	}

	model := &explorerModel{Summary: explorerSummary{ByStatus: map[string]int{}, DOMByStatus: map[string]int{}}}
	for _, e := range endpoints {
		ee := &explorerEndpoint{ID: e.ID, Method: e.Method, URL: e.URL, Source: e.Source, ContentType: e.ContentType,
			Params: []explorerParam{}, DOM: []explorerDOM{}}

		if domNavigable(e.Method) {
			sources := append([]string(nil), domSources[e.URL]...)
			sort.Strings(sources)
			for _, src := range sources {
				var t tally
				js := domJobs[domKey{e.URL, src}]
				for _, j := range js {
					for _, tc := range casesByJob[j.ID] {
						t.add(tc)
					}
				}
				st, reason, gap := classify(t, js, terminal)
				ee.DOM = append(ee.DOM, explorerDOM{Source: src, Status: st, ReasonCode: reason, Gap: gap, Tests: t.testTally})
			}
			ee.DOMScheduled = len(ee.DOM) > 0
			if !ee.DOMScheduled {
				// A GET page that no DOM probe was ever scheduled for.
				st, reason, gap := classify(tally{}, nil, terminal)
				ee.DOM = append(ee.DOM, explorerDOM{Source: "all", Status: st, ReasonCode: reason, Gap: gap})
			}
		}

		ps := paramsByEndpoint[e.ID]
		sort.SliceStable(ps, func(i, j int) bool {
			if ps[i].Location != ps[j].Location {
				return ps[i].Location < ps[j].Location
			}
			return ps[i].Name < ps[j].Name
		})
		for _, p := range ps {
			ep := explorerParam{ID: p.ID, Name: p.Name, Location: p.Location, Source: p.Source, Example: clipExample(p.Example)}
			if p.Location == domain.LocationFragment {
				// DOM-only: covered by the location.hash probe of this URL.
				found := false
				for _, d := range ee.DOM {
					if d.Source == string(detection.DOMSourceHash) {
						ep.Status, ep.ReasonCode, ep.Gap, ep.Tests = d.Status, d.ReasonCode, d.Gap, d.Tests
						found = true
					}
				}
				if !found {
					ep.Status, ep.ReasonCode, ep.Gap = classify(tally{}, nil, terminal)
				}
			} else {
				var t tally
				ipID := ipByParam[p.ID]
				for _, tc := range casesByIP[ipID] {
					t.add(tc)
				}
				ep.Status, ep.ReasonCode, ep.Gap = classify(t, jobsByIP[ipID], terminal)
				ep.Tests = t.testTally
			}
			ee.Params = append(ee.Params, ep)
			model.Summary.Parameters++
			model.Summary.ByStatus[ep.Status]++
			if ep.Gap {
				model.Summary.GapParameters++
			}
		}

		pending := false
		for _, p := range ee.Params {
			ee.Gap = ee.Gap || p.Gap
			pending = pending || p.Status == stPending
		}
		for _, d := range ee.DOM {
			model.Summary.DOMByStatus[d.Status]++
			if d.Gap {
				ee.Gap = true
				model.Summary.DOMGaps++
			}
			pending = pending || d.Status == stPending
		}
		switch {
		case ee.Gap:
			ee.Status = stGap
			model.Summary.EndpointsWithGaps++
		case pending:
			ee.Status = stPending
			model.Summary.EndpointsPending++
		case len(ee.Params) == 0 && len(ee.DOM) == 0:
			ee.Status = stNoInputs
		default:
			ee.Status = stTested
		}
		model.Endpoints = append(model.Endpoints, ee)
	}
	model.Summary.Endpoints = len(model.Endpoints)
	sort.SliceStable(model.Endpoints, func(i, j int) bool {
		a, b := model.Endpoints[i], model.Endpoints[j]
		if a.Gap != b.Gap {
			return a.Gap
		}
		if a.URL != b.URL {
			return a.URL < b.URL
		}
		if a.Method != b.Method {
			return a.Method < b.Method
		}
		return a.ID < b.ID
	})
	return model, nil
}

type explorerResponse struct {
	Total   int                 `json:"total"`
	Limit   int                 `json:"limit"`
	Offset  int                 `json:"offset"`
	Summary explorerSummary     `json:"summary"`
	Items   []*explorerEndpoint `json:"items"`
}

func (s *Server) handleScanExplorer(w http.ResponseWriter, r *http.Request) {
	id := domain.ID(r.PathValue("id"))
	sc, err := s.store.Scans().Get(r.Context(), id)
	if err != nil {
		s.writeLookupError(w, err)
		return
	}
	q := r.URL.Query()
	limit, offset := explorerDefaultLimit, 0
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			writeError(w, http.StatusBadRequest, "limit must be a positive integer")
			return
		}
		limit = n
	}
	if limit > explorerMaxLimit {
		limit = explorerMaxLimit
	}
	if v := q.Get("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			writeError(w, http.StatusBadRequest, "offset must be a non-negative integer")
			return
		}
		offset = n
	}
	onlyGaps := false
	switch v := q.Get("gaps"); v {
	case "", "0", "false":
	case "1", "true":
		onlyGaps = true
	default:
		writeError(w, http.StatusBadRequest, "gaps must be 1 or 0")
		return
	}
	needle := strings.ToLower(strings.TrimSpace(q.Get("q")))
	method := strings.ToUpper(strings.TrimSpace(q.Get("method")))

	model, err := s.buildExplorer(r.Context(), id, sc.State.IsTerminal(), nil)
	if err != nil {
		s.writeInternalError(w, "build endpoint explorer", err)
		return
	}
	matched := make([]*explorerEndpoint, 0, len(model.Endpoints))
	for _, e := range model.Endpoints {
		if onlyGaps && !e.Gap {
			continue
		}
		if needle != "" && !strings.Contains(strings.ToLower(e.URL), needle) {
			continue
		}
		if method != "" && string(e.Method) != method {
			continue
		}
		matched = append(matched, e)
	}
	resp := explorerResponse{Total: len(matched), Limit: limit, Offset: offset, Summary: model.Summary, Items: []*explorerEndpoint{}}
	for i := offset; i < len(matched) && i < offset+limit; i++ {
		resp.Items = append(resp.Items, matched[i])
	}
	writeJSON(w, http.StatusOK, resp)
}
