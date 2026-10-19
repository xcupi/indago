package web_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/web"
)

// explorerWorld seeds one scan the way the pipeline leaves it, covering every
// way a discovered parameter can end up: tested, skipped, errored, never given
// a job, job failed, and DOM-only fragment parameters.
type explorerWorld struct {
	a    api
	scan domain.ID
	// endpoint ids
	search, login, dup domain.ID
}

func (w *explorerWorld) endpoint(method domain.HTTPMethod, url string) *domain.Endpoint {
	w.a.t.Helper()
	e := &domain.Endpoint{ID: domain.NewID(), ScanID: w.scan, URL: url, Method: method, Source: domain.SourceCrawler, CreatedAt: time.Now()}
	if err := w.a.st.Endpoints().Create(context.Background(), e); err != nil {
		w.a.t.Fatal(err)
	}
	return e
}

// param registers a parameter and, unless it is fragment-only, its injection
// point, exactly like discovery.Collector.registerParam.
func (w *explorerWorld) param(e *domain.Endpoint, name string, loc domain.ParamLocation, example string) (*domain.Parameter, *domain.InjectionPoint) {
	w.a.t.Helper()
	p := &domain.Parameter{ID: domain.NewID(), ScanID: w.scan, EndpointID: e.ID, Name: name, Location: loc, Example: example, Source: domain.SourceCrawler, CreatedAt: time.Now()}
	if err := w.a.st.Parameters().Create(context.Background(), p); err != nil {
		w.a.t.Fatal(err)
	}
	if loc == domain.LocationFragment {
		return p, nil
	}
	ip := &domain.InjectionPoint{ID: domain.NewID(), ScanID: w.scan, EndpointID: e.ID, ParameterID: p.ID, Location: loc, CreatedAt: time.Now()}
	if err := w.a.st.InjectionPoints().Create(context.Background(), ip); err != nil {
		w.a.t.Fatal(err)
	}
	return p, ip
}

func (w *explorerWorld) job(typ domain.JobType, state domain.JobState, e *domain.Endpoint, ip *domain.InjectionPoint, payload string) *domain.TestJob {
	w.a.t.Helper()
	now := time.Now()
	j := &domain.TestJob{ID: domain.NewID(), ScanID: w.scan, Type: typ, State: state, MaxAttempts: 2, AvailableAt: now, CreatedAt: now, UpdatedAt: now,
		Target: domain.JobTarget{EndpointID: e.ID, URL: e.URL}, Payload: []byte(payload)}
	if ip != nil {
		j.Target.InjectionPointID = ip.ID
	}
	if err := w.a.st.Jobs().Create(context.Background(), j); err != nil {
		w.a.t.Fatal(err)
	}
	return j
}

func (w *explorerWorld) tcase(j *domain.TestJob, ip *domain.InjectionPoint, class domain.VulnClass, status domain.TestCaseStatus, outcome domain.TestOutcome, note string) {
	w.a.t.Helper()
	now := time.Now()
	tc := &domain.TestCase{ID: domain.NewID(), ScanID: w.scan, JobID: j.ID, VulnClass: class, Status: status, Outcome: outcome, Method: "GET", URL: j.Target.URL, Note: note, CreatedAt: now, UpdatedAt: now}
	if ip != nil {
		tc.InjectionPointID = ip.ID
	}
	if err := w.a.st.TestCases().Create(context.Background(), tc); err != nil {
		w.a.t.Fatal(err)
	}
}

func (w *explorerWorld) setState(s domain.ScanState) {
	w.a.t.Helper()
	sc, err := w.a.st.Scans().Get(context.Background(), w.scan)
	if err != nil {
		w.a.t.Fatal(err)
	}
	sc.State = s
	if err := w.a.st.Scans().Update(context.Background(), sc); err != nil {
		w.a.t.Fatal(err)
	}
}

const (
	srcQuery  = `{"source":"location.search"}`
	srcHash   = `{"source":"location.hash"}`
	srcName   = `{"source":"window.name"}`
	srcPostM  = `{"source":"postMessage"}`
	noteInfo  = "window.name source not tested: no discovered query parameter on this endpoint"
	noteNoBrw = "dom-xss probe skipped: no browser configured for this scan"
	noteState = "reflection test skipped: POST is state-changing and AllowStateChanging is off"
)

func newExplorerWorld(t *testing.T, caps web.Capabilities) *explorerWorld {
	a, id := coverageAPI(t, caps)
	return seedExplorerWorld(a, id)
}

// seedExplorerWorld fills an existing scan (HTTP api or UI-harness store) and
// marks it completed.
func seedExplorerWorld(a api, id domain.ID) *explorerWorld {
	w := &explorerWorld{a: a, scan: id}
	w.setState(domain.ScanCompleted)

	// --- GET /search: one parameter of every kind + a fragment route param ---
	e := w.endpoint(domain.MethodGET, "http://127.0.0.1:1/search?q=hello")
	w.search = e.ID
	_, ipQ := w.param(e, "q", domain.LocationQuery, strings.Repeat("x", 400))
	_, ipLang := w.param(e, "lang", domain.LocationQuery, "en")
	_, ipID := w.param(e, "id", domain.LocationQuery, "7")
	_, _ = w.param(e, "page", domain.LocationQuery, "1") // no job at all
	_, ipTok := w.param(e, "tok", domain.LocationQuery, "t")
	w.param(e, "route", domain.LocationFragment, "")

	jq := w.job(domain.JobTest, domain.JobSucceeded, e, ipQ, "")
	w.tcase(jq, ipQ, domain.VulnReflectedXSS, domain.TestCaseCompleted, domain.OutcomeSuccess, "not reflected")
	jl := w.job(domain.JobTest, domain.JobSucceeded, e, ipLang, "")
	w.tcase(jl, ipLang, domain.VulnReflectedXSS, domain.TestCaseSkipped, "", noteState)
	ji := w.job(domain.JobTest, domain.JobSucceeded, e, ipID, "")
	w.tcase(ji, ipID, domain.VulnReflectedXSS, domain.TestCaseFailed, domain.OutcomeError, "")
	w.job(domain.JobTest, domain.JobDead, e, ipTok, "")

	// DOM: one job per (endpoint URL, source)
	dq := w.job(domain.JobDOMXSS, domain.JobSucceeded, e, nil, srcQuery)
	w.tcase(dq, nil, domain.VulnDOMXSS, domain.TestCaseCompleted, domain.OutcomeSuccess, "")
	dh := w.job(domain.JobDOMXSS, domain.JobSucceeded, e, nil, srcHash)
	w.tcase(dh, nil, domain.VulnDOMXSS, domain.TestCaseCompleted, domain.OutcomeSuccess, "")
	dn := w.job(domain.JobDOMXSS, domain.JobSucceeded, e, nil, srcName)
	w.tcase(dn, nil, domain.VulnDOMXSS, domain.TestCaseSkipped, "", noteInfo)
	dp := w.job(domain.JobDOMXSS, domain.JobSucceeded, e, nil, srcPostM)
	w.tcase(dp, nil, domain.VulnDOMXSS, domain.TestCaseSkipped, "", noteNoBrw)

	// --- POST /login: fully tested, and not navigable so no DOM probe exists ---
	lg := w.endpoint(domain.MethodPOST, "http://127.0.0.1:1/login")
	w.login = lg.ID
	_, ipU := w.param(lg, "user", domain.LocationForm, "")
	ju := w.job(domain.JobTest, domain.JobSucceeded, lg, ipU, "")
	w.tcase(ju, ipU, domain.VulnReflectedXSS, domain.TestCaseCompleted, domain.OutcomeSuccess, "not reflected")

	// --- a second GET endpoint with the SAME URL as /search: the DOM pass
	// dedups by URL, so its probes hang off the first endpoint's job ---
	d := w.endpoint(domain.MethodGET, "http://127.0.0.1:1/search?q=hello")
	w.dup = d.ID
	return w
}

type explorerParam struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Location   string `json:"location"`
	Example    string `json:"example"`
	Status     string `json:"status"`
	ReasonCode string `json:"reason_code"`
	Gap        bool   `json:"gap"`
	Tests      struct {
		Total, Completed, Skipped, Failed int
	} `json:"tests"`
}

type explorerDOM struct {
	Source     string `json:"source"`
	Status     string `json:"status"`
	ReasonCode string `json:"reason_code"`
	Gap        bool   `json:"gap"`
}

type explorerEndpoint struct {
	ID           string          `json:"id"`
	Method       string          `json:"method"`
	URL          string          `json:"url"`
	Status       string          `json:"status"`
	Gap          bool            `json:"gap"`
	DOMScheduled bool            `json:"dom_scheduled"`
	Params       []explorerParam `json:"parameters"`
	DOM          []explorerDOM   `json:"dom"`
}

type explorerResp struct {
	Total   int `json:"total"`
	Limit   int `json:"limit"`
	Offset  int `json:"offset"`
	Summary struct {
		Endpoints         int            `json:"endpoints"`
		EndpointsWithGaps int            `json:"endpoints_with_gaps"`
		Parameters        int            `json:"parameters"`
		GapParameters     int            `json:"gap_parameters"`
		ByStatus          map[string]int `json:"by_status"`
		DOMGaps           int            `json:"dom_gaps"`
		EndpointsPending  int            `json:"endpoints_pending"`
	} `json:"summary"`
	Items []explorerEndpoint `json:"items"`
}

func (r explorerResp) find(id string) *explorerEndpoint {
	for i := range r.Items {
		if r.Items[i].ID == id {
			return &r.Items[i]
		}
	}
	return nil
}

func (e *explorerEndpoint) param(name string) *explorerParam {
	for i := range e.Params {
		if e.Params[i].Name == name {
			return &e.Params[i]
		}
	}
	return nil
}

func (e *explorerEndpoint) dom(source string) *explorerDOM {
	for i := range e.DOM {
		if e.DOM[i].Source == source {
			return &e.DOM[i]
		}
	}
	return nil
}

func (w *explorerWorld) get(query string) explorerResp {
	w.a.t.Helper()
	var r explorerResp
	w.a.mustJSON(w.a.do("GET", "/api/scans/"+string(w.scan)+"/explorer"+query, nil), 200, &r)
	return r
}

func TestExplorerClassifiesEveryParameterOutcome(t *testing.T) {
	w := newExplorerWorld(t, web.Capabilities{BrowserEnabled: false})
	r := w.get("")
	s := r.find(string(w.search))
	if s == nil {
		t.Fatalf("endpoint missing: %+v", r.Items)
	}
	want := map[string]struct {
		status, reason string
		gap            bool
	}{
		"q":    {"tested", "", false},
		"lang": {"skipped", "state_changing_disabled", true},
		"id":   {"errored", "error", true},
		"page": {"not_run", "no_job", true},
		"tok":  {"not_run", "job_dead", true},
	}
	for name, exp := range want {
		p := s.param(name)
		if p == nil {
			t.Errorf("parameter %q missing", name)
			continue
		}
		if p.Status != exp.status || p.ReasonCode != exp.reason || p.Gap != exp.gap {
			t.Errorf("%s = status %q reason %q gap %v, want %q %q %v", name, p.Status, p.ReasonCode, p.Gap, exp.status, exp.reason, exp.gap)
		}
	}
	if q := s.param("q"); q != nil {
		if q.Tests.Total != 1 || q.Tests.Completed != 1 {
			t.Errorf("q test counts = %+v", q.Tests)
		}
		if len(q.Example) > 130 {
			t.Errorf("an example value must be clipped, got %d bytes", len(q.Example))
		}
	}
}

func TestExplorerFragmentParameterFollowsTheHashDOMSource(t *testing.T) {
	w := newExplorerWorld(t, web.Capabilities{BrowserEnabled: true})
	s := w.get("").find(string(w.search))
	p := s.param("route")
	if p == nil {
		t.Fatal("fragment parameter missing")
	}
	if p.Location != "fragment" || p.Status != "tested" || p.Gap {
		t.Fatalf("a fragment parameter is tested by the location.hash DOM probe: %+v", p)
	}
}

func TestExplorerDOMIsPerEndpointAndDistinguishesInfoFromGaps(t *testing.T) {
	w := newExplorerWorld(t, web.Capabilities{BrowserEnabled: false})
	s := w.get("").find(string(w.search))
	if !s.DOMScheduled || len(s.DOM) != 4 {
		t.Fatalf("dom = scheduled %v %+v", s.DOMScheduled, s.DOM)
	}
	if d := s.dom("location.search"); d == nil || d.Status != "tested" || d.Gap {
		t.Errorf("location.search = %+v", d)
	}
	if d := s.dom("window.name"); d == nil || d.Status != "skipped" || d.ReasonCode != "source_not_applicable" || d.Gap {
		t.Errorf("an informational skip is not a gap: %+v", d)
	}
	if d := s.dom("postMessage"); d == nil || d.Status != "skipped" || d.ReasonCode != "browser_unavailable" || !d.Gap {
		t.Errorf("a browser-less skip is a gap: %+v", d)
	}
}

func TestExplorerPostEndpointHasNoDOMProbeAndThatIsNotAGap(t *testing.T) {
	w := newExplorerWorld(t, web.Capabilities{BrowserEnabled: true})
	l := w.get("").find(string(w.login))
	if l.DOMScheduled || len(l.DOM) != 0 {
		t.Fatalf("a POST endpoint is not DOM-navigable: %+v", l)
	}
	if l.Gap || l.Status != "tested" {
		t.Fatalf("a fully tested POST endpoint must not be flagged: %+v", l)
	}
}

func TestExplorerEndpointWithSameURLSharesTheDOMJob(t *testing.T) {
	w := newExplorerWorld(t, web.Capabilities{BrowserEnabled: true})
	d := w.get("").find(string(w.dup))
	if d == nil {
		t.Fatal("duplicate-URL endpoint missing")
	}
	if !d.DOMScheduled || len(d.DOM) != 4 {
		t.Fatalf("the DOM pass dedups by URL, so this endpoint is covered by its twin's jobs: %+v", d)
	}
}

func TestExplorerFiltersSortsAndPaginates(t *testing.T) {
	w := newExplorerWorld(t, web.Capabilities{BrowserEnabled: false})
	all := w.get("")
	if all.Total != 3 || all.Summary.Endpoints != 3 {
		t.Fatalf("total = %d summary = %+v", all.Total, all.Summary)
	}
	// /search and its same-URL twin both have gaps and tie on URL and method, so
	// their relative order is not specified; what is: gaps first, clean last.
	if !all.Items[0].Gap || !all.Items[1].Gap || all.Items[2].Gap || all.Items[2].ID != string(w.login) {
		t.Fatalf("endpoints with gaps must come first and the clean one last: %+v", all.Items)
	}
	gaps := w.get("?gaps=1")
	for _, it := range gaps.Items {
		if !it.Gap {
			t.Errorf("gaps=1 returned a clean endpoint %s", it.URL)
		}
	}
	if gaps.Total >= all.Total || gaps.Total == 0 {
		t.Errorf("gaps filter total = %d of %d", gaps.Total, all.Total)
	}
	if got := w.get("?q=LOGIN"); got.Total != 1 || got.Items[0].ID != string(w.login) {
		t.Errorf("q filter is a case-insensitive URL match: %+v", got.Items)
	}
	if got := w.get("?method=post"); got.Total != 1 {
		t.Errorf("method filter: %d", got.Total)
	}
	page := w.get("?limit=2&offset=2")
	if page.Total != 3 || len(page.Items) != 1 || page.Limit != 2 || page.Offset != 2 {
		t.Errorf("paging = %+v", page)
	}
	if got := w.get("?limit=100000"); got.Limit != 200 {
		t.Errorf("limit must be capped at 200, got %d", got.Limit)
	}
	for _, bad := range []string{"?limit=0", "?limit=x", "?offset=-3", "?gaps=maybe"} {
		if rec := w.a.do("GET", "/api/scans/"+string(w.scan)+"/explorer"+bad, nil); rec.Code != http.StatusBadRequest {
			t.Errorf("%s status = %d, want 400", bad, rec.Code)
		}
	}
}

func TestExplorerSummaryCountsMatchTheItems(t *testing.T) {
	w := newExplorerWorld(t, web.Capabilities{BrowserEnabled: false})
	r := w.get("?limit=200")
	params, gaps := 0, 0
	by := map[string]int{}
	for _, it := range r.Items {
		for _, p := range it.Params {
			params++
			by[p.Status]++
			if p.Gap {
				gaps++
			}
		}
	}
	if r.Summary.Parameters != params || r.Summary.GapParameters != gaps {
		t.Errorf("summary %+v disagrees with items (params %d gaps %d)", r.Summary, params, gaps)
	}
	for k, n := range by {
		if r.Summary.ByStatus[k] != n {
			t.Errorf("by_status[%s] = %d, items say %d", k, r.Summary.ByStatus[k], n)
		}
	}
}

// While a scan is still running, a queued job is progress, not a gap.
func TestExplorerQueuedJobsAreNotGapsWhileTheScanRuns(t *testing.T) {
	a, id := coverageAPI(t, web.Capabilities{BrowserEnabled: true})
	w := &explorerWorld{a: a, scan: id}
	w.setState(domain.ScanRunning)
	e := w.endpoint(domain.MethodGET, "http://127.0.0.1:1/q?x=1")
	_, ip := w.param(e, "x", domain.LocationQuery, "1")
	w.job(domain.JobTest, domain.JobQueued, e, ip, "")
	r := w.get("")
	p := r.find(string(e.ID)).param("x")
	if p.Status != "pending" || p.Gap {
		t.Fatalf("a queued job on a running scan is pending, not a gap: %+v", p)
	}

	// The same job on a finished scan was never run: that IS a gap.
	w.setState(domain.ScanCanceled)
	p = w.get("").find(string(e.ID)).param("x")
	if p.Status != "not_run" || !p.Gap || p.ReasonCode != "job_queued" {
		t.Fatalf("after the scan ended the queued job never ran: %+v", p)
	}
}

func TestExplorerUnknownScanIsNotFound(t *testing.T) {
	a, _ := coverageAPI(t, web.Capabilities{})
	if rec := a.do("GET", "/api/scans/nope/explorer", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestCoverageWarnsAboutUntestedParametersOnlyWhenTheScanEnded(t *testing.T) {
	w := newExplorerWorld(t, web.Capabilities{BrowserEnabled: true})
	var c coverageResp
	w.a.mustJSON(w.a.do("GET", "/api/scans/"+string(w.scan)+"/coverage", nil), 200, &c)
	if !c.warning("parameters_untested") || !c.CoverageGaps {
		t.Fatalf("a finished scan with never-run parameters must warn: %+v", c.Warnings)
	}
	var raw map[string]json.RawMessage
	w.a.mustJSON(w.a.do("GET", "/api/scans/"+string(w.scan)+"/coverage", nil), 200, &raw)
	if _, ok := raw["parameters"]; !ok {
		t.Error("coverage must carry the parameter totals it warned about")
	}

	w.setState(domain.ScanRunning)
	var running coverageResp
	w.a.mustJSON(w.a.do("GET", "/api/scans/"+string(w.scan)+"/coverage", nil), 200, &running)
	if running.warning("parameters_untested") {
		t.Fatal("a running scan has not finished its work; no untested-parameter warning yet")
	}
	_ = fmt.Sprint()
}

// ---- gaps found by the independent review: no way to look clean while work was not done ----

type covFull struct {
	CoverageGaps bool `json:"coverage_gaps"`
	Tests        struct {
		Total, Completed, Skipped, Failed, Incomplete int
	} `json:"tests"`
	Warnings []struct {
		Code     string `json:"code"`
		Severity string `json:"severity"`
	} `json:"warnings"`
}

func (c covFull) has(code string) bool {
	for _, w := range c.Warnings {
		if w.Code == code {
			return true
		}
	}
	return false
}

func (w *explorerWorld) coverage() covFull {
	w.a.t.Helper()
	var c covFull
	w.a.mustJSON(w.a.do("GET", "/api/scans/"+string(w.scan)+"/coverage", nil), 200, &c)
	return c
}

// A scan that failed or was canceled is partial no matter how many of the tests
// that did run were fine; with nothing registered there are no parameters to flag.
func TestCoverageFlagsFailedAndCanceledScansEvenWhenEveryRecordedTestPassed(t *testing.T) {
	for _, tc := range []struct {
		state domain.ScanState
		code  string
	}{{domain.ScanFailed, "scan_failed"}, {domain.ScanCanceled, "scan_canceled"}} {
		a, id := coverageAPI(t, web.Capabilities{BrowserEnabled: true})
		w := &explorerWorld{a: a, scan: id}
		w.setState(tc.state)
		seedTest(t, a, id, domain.VulnReflectedXSS, domain.TestCaseCompleted, domain.OutcomeSuccess, "http://127.0.0.1:1/x?q=1", "not reflected")
		c := w.coverage()
		if !c.CoverageGaps || !c.has(tc.code) {
			t.Errorf("%s: a %s scan must be flagged as partial: %+v", tc.code, tc.state, c.Warnings)
		}
	}
}

func TestCoverageCountsCanceledJobsAndUnfinishedTests(t *testing.T) {
	a, id := coverageAPI(t, web.Capabilities{BrowserEnabled: true})
	w := &explorerWorld{a: a, scan: id}
	w.setState(domain.ScanCompleted)
	e := w.endpoint(domain.MethodPOST, "http://127.0.0.1:1/f")
	_, ip := w.param(e, "x", domain.LocationForm, "1")
	j := w.job(domain.JobTest, domain.JobCanceled, e, ip, "")
	w.tcase(j, ip, domain.VulnReflectedXSS, domain.TestCaseCancelled, "", "")
	w.tcase(j, ip, domain.VulnReflectedXSS, domain.TestCaseRunning, "", "")
	c := w.coverage()
	if c.Tests.Incomplete != 2 || c.Tests.Total != c.Tests.Completed+c.Tests.Skipped+c.Tests.Failed+c.Tests.Incomplete {
		t.Errorf("every test case must land in exactly one bucket: %+v", c.Tests)
	}
	// (jobs_failed is fed by the queue's counters, not the store, so a store-seeded job
	// cannot exercise it here.)
	if !c.has("tests_incomplete") || !c.has("parameters_untested") || !c.CoverageGaps {
		t.Errorf("cancelled work is a gap: %+v", c.Warnings)
	}
}

// The explorer flagged this page red while /coverage said everything was fine.
func TestCoverageAgreesWithTheExplorerOnPagesNoDOMProbeEverRan(t *testing.T) {
	a, id := coverageAPI(t, web.Capabilities{BrowserEnabled: true})
	w := &explorerWorld{a: a, scan: id}
	w.setState(domain.ScanCompleted)
	e := w.endpoint(domain.MethodGET, "http://127.0.0.1:1/plain")
	if got := w.get("").find(string(e.ID)); got == nil || !got.Gap {
		t.Fatalf("setup: the explorer must flag a GET page with no DOM job on an ended scan: %+v", got)
	}
	c := w.coverage()
	if !c.CoverageGaps || !c.has("dom_sources_untested") {
		t.Fatalf("/coverage must agree with the explorer: %+v", c.Warnings)
	}
}

func TestExplorerDOMSourceWhoseJobDiedIsPartialNotTested(t *testing.T) {
	a, id := coverageAPI(t, web.Capabilities{BrowserEnabled: true})
	w := &explorerWorld{a: a, scan: id}
	w.setState(domain.ScanCompleted)
	e := w.endpoint(domain.MethodGET, "http://127.0.0.1:1/s")
	// Storage discovery completes, then a per-key probe fails: the job is retried and dies.
	j := w.job(domain.JobDOMXSS, domain.JobDead, e, nil, `{"source":"localStorage"}`)
	w.tcase(j, nil, domain.VulnDOMXSS, domain.TestCaseCompleted, domain.OutcomeSuccess, "localStorage key discovery observed 2 distinct key(s)")
	w.tcase(j, nil, domain.VulnDOMXSS, domain.TestCaseFailed, domain.OutcomeError, "")
	d := w.get("").find(string(e.ID)).dom("localStorage")
	if d == nil || d.Status != "partial" || !d.Gap || d.ReasonCode != "job_dead" {
		t.Fatalf("one completed test must not hide a dead job: %+v", d)
	}
	if c := w.coverage(); !c.CoverageGaps || !c.has("dom_sources_untested") {
		t.Fatalf("coverage must say so too: %+v", c.Warnings)
	}
}

// A timeout on the first attempt that succeeds on the retry is NOT a gap.
func TestExplorerRetriedThenSucceededParameterIsStillTested(t *testing.T) {
	a, id := coverageAPI(t, web.Capabilities{BrowserEnabled: true})
	w := &explorerWorld{a: a, scan: id}
	w.setState(domain.ScanCompleted)
	e := w.endpoint(domain.MethodPOST, "http://127.0.0.1:1/r")
	_, ip := w.param(e, "x", domain.LocationForm, "1")
	j := w.job(domain.JobTest, domain.JobSucceeded, e, ip, "")
	w.tcase(j, ip, domain.VulnReflectedXSS, domain.TestCaseFailed, domain.OutcomeTimeout, "")
	w.tcase(j, ip, domain.VulnReflectedXSS, domain.TestCaseCompleted, domain.OutcomeSuccess, "not reflected")
	if p := w.get("").find(string(e.ID)).param("x"); p.Status != "tested" || p.Gap {
		t.Fatalf("a retry that succeeded is tested: %+v", p)
	}
}

func TestExplorerParameterWithFurtherWorkQueuedIsPendingWhileTheScanRuns(t *testing.T) {
	a, id := coverageAPI(t, web.Capabilities{BrowserEnabled: true})
	w := &explorerWorld{a: a, scan: id}
	w.setState(domain.ScanRunning)
	e := w.endpoint(domain.MethodPOST, "http://127.0.0.1:1/q")
	_, ip := w.param(e, "x", domain.LocationForm, "1")
	j := w.job(domain.JobTest, domain.JobSucceeded, e, ip, "")
	w.tcase(j, ip, domain.VulnReflectedXSS, domain.TestCaseCompleted, domain.OutcomeSuccess, "reflected at html_text")
	w.job(domain.JobVerify, domain.JobQueued, e, ip, "")
	r := w.get("")
	if p := r.find(string(e.ID)).param("x"); p.Status != "pending" || p.Gap {
		t.Fatalf("queued verification means not finished yet: %+v", p)
	}
	if r.Summary.EndpointsPending != 1 {
		t.Fatalf("the summary must count pending endpoints so the UI cannot say 'all tested': %+v", r.Summary)
	}
	// Once the scan has ended the same queued job never ran: partial.
	w.setState(domain.ScanCompleted)
	if p := w.get("").find(string(e.ID)).param("x"); p.Status != "partial" || !p.Gap || p.ReasonCode != "job_queued" {
		t.Fatalf("after the scan ended: %+v", p)
	}
}
