package scan

// Regression tests for the logical-finding model and candidate profiles:
// one finding per vulnerability LOCATION (scan + injection point + vuln class +
// execution context), with every candidate attempt kept as a child; the
// strongest verified verdict wins; baseline values are never candidates; and a
// scan's candidate profile bounds how many candidate jobs a reflection step
// enqueues, deterministically.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/httpengine"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/verification"
)

func (e *scanEnv) setScanConfig(mut func(*domain.ScanConfig)) {
	e.t.Helper()
	sc, err := e.st.Scans().Get(context.Background(), e.scanID)
	if err != nil {
		e.t.Fatal(err)
	}
	mut(&sc.Config)
	if err := e.st.Scans().Update(context.Background(), sc); err != nil {
		e.t.Fatal(err)
	}
}

func (e *scanEnv) verify(ep *domain.Endpoint, ip *domain.InjectionPoint, cand detection.Candidate, f *domain.Finding, tc *domain.TestCase, v verification.Verifier) {
	e.t.Helper()
	job := buildVerifyJob(e.t, e.scanID, domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID}, cand, f.ID, tc.ID)
	if err := e.verifyExec(v, openScope(), ExecutorConfig{}).Handle(context.Background(), job); err != nil {
		e.t.Fatal(err)
	}
}

func (e *scanEnv) findings() []*domain.Finding {
	e.t.Helper()
	fs, err := e.st.Findings().ListByScan(context.Background(), e.scanID)
	if err != nil {
		e.t.Fatal(err)
	}
	return fs
}

// Confirmed and rejected candidates at the SAME injection point and context are
// ONE logical finding: it is confirmed, it names the candidate whose browser
// verification succeeded, and the rejected candidate survives as a child
// attempt with its own evidence. Order of arrival must not matter.
func TestConfirmedAndRejectedCandidatesAtOneLocationAreOneFinding(t *testing.T) {
	for _, rejectedFirst := range []bool{true, false} {
		name := map[bool]string{true: "rejected first", false: "confirmed first"}[rejectedFirst]
		t.Run(name, func(t *testing.T) {
			srv := newOKServer(t)
			env := newScanEnv(t)
			ep := env.endpoint(srv, domain.MethodGET)
			focus := env.param(ep, "q", domain.LocationQuery, "hello")
			ip := env.injection(ep, focus)
			good := candAt(detection.CatHTMLText, detection.CtxHTMLText, "<svg onload=m>")
			probe := candAt(detection.CatHTMLText, detection.CtxHTMLText, "<mx>")
			goodReq, probeReq := env.evidenceRow(domain.EvidenceRequest), env.evidenceRow(domain.EvidenceRequest)
			goodTC, probeTC := env.candidateTestCase(ip, goodReq), env.candidateTestCase(ip, probeReq)
			f, _ := upsertPendingFinding(context.Background(), env.st, env.scanID, ep, ip.ID, focus, good, goodTC.ID)
			if g, _ := upsertPendingFinding(context.Background(), env.st, env.scanID, ep, ip.ID, focus, probe, probeTC.ID); g.ID != f.ID {
				t.Fatal("two candidates at one injection point/context must share one finding")
			}

			confirm := func() {
				env.verify(ep, ip, good, f, goodTC, &fakeVerifier{result: confirmedResult(verification.SignalPageError)})
			}
			reject := func() { env.verify(ep, ip, probe, f, probeTC, &fakeVerifier{result: rejectedResult()}) }
			if rejectedFirst {
				reject()
				confirm()
			} else {
				confirm()
				reject()
			}

			all := env.findings()
			if len(all) != 1 {
				t.Fatalf("%d findings; a rejected candidate must not create its own", len(all))
			}
			got := all[0]
			if got.Verdict != domain.VerdictConfirmed {
				t.Fatalf("verdict = %s, want the strongest verified verdict (confirmed)", got.Verdict)
			}
			if strings.Contains(got.Title, "candidate") {
				t.Fatalf("a confirmed finding is not a candidate: %q", got.Title)
			}
			d := decodeFindingDetail(got.Detail)
			v := d.verifiedAttempt()
			if v == nil || v.CandidateValue != good.Value || !containsID(v.EvidenceIDs, goodReq) {
				t.Fatalf("verified attempt = %+v, want the confirming candidate %q with its evidence", v, good.Value)
			}
			if len(d.Attempts) != 2 {
				t.Fatalf("attempts = %+v, want both kept as diagnostics", d.Attempts)
			}
			for _, a := range d.Attempts {
				if a.CandidateValue == probe.Value && (a.Verdict != domain.VerdictRejected || !containsID(a.EvidenceIDs, probeReq)) {
					t.Fatalf("rejected attempt lost its verdict/evidence: %+v", a)
				}
			}
			if !containsID(got.EvidenceIDs, probeReq) || !containsID(got.EvidenceIDs, goodReq) {
				t.Fatalf("finding evidence must keep every attempt's evidence: %v", got.EvidenceIDs)
			}
		})
	}
}

// The same parameter reflecting in two execution contexts, and two different
// parameters, are different locations: separate logical findings, each with its
// own verdict.
func TestDistinctParametersAndExecutionContextsAreSeparateFindings(t *testing.T) {
	srv := newOKServer(t)
	env := newScanEnv(t)
	ctx := context.Background()
	ep := env.endpoint(srv, domain.MethodGET)
	q := env.param(ep, "q", domain.LocationQuery, "hello")
	r := env.param(ep, "r", domain.LocationQuery, "hello")
	ipQ, ipR := env.injection(ep, q), env.injection(ep, r)

	htmlText := candAt(detection.CatHTMLText, detection.CtxHTMLText, "<svg onload=m>")
	jsString := candAt(detection.CatJS, detection.CtxJSString, `";m//`)
	jsCode := candAt(detection.CatJS, detection.CtxJSCode, `;m;`)

	fQHTML, _ := upsertPendingFinding(ctx, env.st, env.scanID, ep, ipQ.ID, q, htmlText, domain.NewID())
	fQJS, _ := upsertPendingFinding(ctx, env.st, env.scanID, ep, ipQ.ID, q, jsString, domain.NewID())
	fQCode, _ := upsertPendingFinding(ctx, env.st, env.scanID, ep, ipQ.ID, q, jsCode, domain.NewID())
	fRHTML, _ := upsertPendingFinding(ctx, env.st, env.scanID, ep, ipR.ID, r, htmlText, domain.NewID())
	ids := map[domain.ID]bool{fQHTML.ID: true, fQJS.ID: true, fQCode.ID: true, fRHTML.ID: true}
	if len(ids) != 4 || len(env.findings()) != 4 {
		t.Fatalf("2 parameters x contexts must be 4 locations, got %d findings", len(env.findings()))
	}

	// Verdicts are per location: confirming one does not touch the others.
	tc := env.candidateTestCase(ipQ)
	env.verify(ep, ipQ, jsString, fQJS, tc, &fakeVerifier{result: confirmedResult(verification.SignalPageError)})
	byID := map[domain.ID]domain.Verdict{}
	for _, f := range env.findings() {
		byID[f.ID] = f.Verdict
	}
	if byID[fQJS.ID] != domain.VerdictConfirmed {
		t.Fatalf("verified location = %s", byID[fQJS.ID])
	}
	for _, other := range []domain.ID{fQHTML.ID, fQCode.ID, fRHTML.ID} {
		if byID[other] != domain.VerdictPending {
			t.Fatalf("an unrelated location changed verdict: %s", byID[other])
		}
	}
}

// Without any confirming attempt there is no verified candidate to present.
func TestUnconfirmedFindingHasNoVerifiedAttempt(t *testing.T) {
	srv := newOKServer(t)
	env := newScanEnv(t)
	ep := env.endpoint(srv, domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "hello")
	ip := env.injection(ep, focus)
	cand := candAt(detection.CatHTMLText, detection.CtxHTMLText, "<svg onload=m>")
	tc := env.candidateTestCase(ip)
	f, _ := upsertPendingFinding(context.Background(), env.st, env.scanID, ep, ip.ID, focus, cand, tc.ID)
	env.verify(ep, ip, cand, f, tc, &fakeVerifier{result: rejectedResult()})
	got := env.findings()[0]
	if got.Verdict != domain.VerdictRejected || decodeFindingDetail(got.Detail).verifiedAttempt() != nil {
		t.Fatalf("a rejected finding must carry no verified attempt: %s", got.Verdict)
	}
	if !strings.Contains(got.Title, "candidate") {
		t.Fatalf("an unconfirmed finding keeps its candidate wording: %q", got.Title)
	}
}

// The selection of the confirming attempt never depends on completion order.
func TestVerifiedAttemptIsDeterministic(t *testing.T) {
	t0 := time.Now()
	d := findingDetail{Attempts: []verificationAttempt{
		{CandidateValue: "later", VerifyTestCaseID: "b", Verdict: domain.VerdictConfirmed, At: t0.Add(time.Second)},
		{CandidateValue: "rejected", VerifyTestCaseID: "c", Verdict: domain.VerdictRejected, At: t0.Add(-time.Hour)},
		{CandidateValue: "first", VerifyTestCaseID: "a", Verdict: domain.VerdictConfirmed, At: t0},
	}}
	for i := 0; i < 6; i++ {
		d.Attempts[0], d.Attempts[2] = d.Attempts[2], d.Attempts[0]
		if v := d.verifiedAttempt(); v == nil || v.CandidateValue != "first" {
			t.Fatalf("verified attempt = %+v, want the earliest confirming one", v)
		}
	}
}

// A baseline value (the ordinary observed "hello") is not a breakout and must
// never create a finding, even if something hands it to the verification path.
func TestBaselineValueNeverBecomesACandidateFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<p>"+r.URL.Query().Get("q")+"</p>")
	}))
	defer srv.Close()
	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/s", domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "hello")
	ip := env.injection(ep, focus)
	job := &domain.TestJob{ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobTest,
		Target: domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID}, MaxAttempts: 3}
	ex := env.executor(scopedClient(t, openScope()), ExecutorConfig{})

	ex.enqueueVerification(context.Background(), job, ep, candAt(detection.CatHTMLText, detection.CtxHTMLText, "hello"), focus, domain.NewID())
	if n := len(env.findings()); n != 0 {
		t.Fatalf("a candidate with no marker (the baseline value) created %d finding(s)", n)
	}
	real := detection.Candidate{Source: detection.SourceBuiltin, Category: detection.CatHTMLText, Context: detection.CtxHTMLText,
		Value: "<svg onload=" + marker(env.scanID, ip.ID) + ">", DedupKey: "k"}
	ex.enqueueVerification(context.Background(), job, ep, real, focus, domain.NewID())
	fs := env.findings()
	if len(fs) != 1 {
		t.Fatalf("a real candidate must create its finding, got %d", len(fs))
	}
	for _, c := range decodeFindingDetail(fs[0].Detail).Candidates {
		if c.Value == "hello" {
			t.Fatal("the baseline value is listed as a candidate")
		}
	}
}

// Baseline request/response evidence is classified as baseline — the value it
// shows (q=hello) is the ORIGINAL request, never a payload — and the candidate's
// own evidence and browser artifacts are told apart from it.
func TestEvidenceRolesSeparateBaselineFromCandidateAndBrowser(t *testing.T) {
	env := newExecEnv(t)
	ex := env.executor(scopedClient(t, openScope()), ExecutorConfig{})
	baseReq := &httpengine.Request{Method: "GET", URL: "http://x/s?q=hello"}
	baseResp := &httpengine.Response{Status: 200, Headers: http.Header{"Content-Type": {"text/html"}}, Body: []byte("<p>hello</p>")}
	reqID, respID := ex.persistBaselineEvidence(context.Background(), env.scanID, baseReq, baseResp)
	own, err := ex.putEvidence(context.Background(), env.scanID, domain.EvidenceRequest, []byte("GET /?q=%3Csvg HTTP/1.1\r\n\r\n"), "test_case=x request")
	if err != nil {
		t.Fatal(err)
	}
	want := map[domain.ID]domain.EvidenceRole{reqID: domain.RoleBaseline, respID: domain.RoleBaseline, own: domain.RoleCandidate}
	for id, role := range want {
		row, err := env.st.Evidence().Get(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		if got := row.Role(); got != role {
			t.Fatalf("evidence %s (%s) role = %s, want %s", id, row.Note, got, role)
		}
	}
	for _, k := range []domain.EvidenceKind{domain.EvidenceScreenshot, domain.EvidenceDOM, domain.EvidenceBrowserLog} {
		if r := (&domain.Evidence{Kind: k, Note: "test_case=x"}).Role(); r != domain.RoleBrowser {
			t.Fatalf("%s role = %s, want browser", k, r)
		}
	}
}

// --- candidate profiles: multiple candidate jobs per injection point ---

// reflectsEverywhere echoes q into three execution contexts, so an unbounded
// plan holds several candidates per context.
func reflectsEverywhere(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, `<p>`+v+`</p><input value="`+v+`"><script>var a = "`+v+`";</script>`)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// enqueuedCandidates runs the reflection step for one injection point and
// returns the candidate children it enqueued, in lease (priority) order, with
// the marker normalized so runs in different scans compare equal.
func enqueuedCandidates(t *testing.T, env *scanEnv, srvURL string) []detection.Candidate {
	t.Helper()
	ep := env.endpoint(srvURL+"/s", domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "hello")
	ip := env.injection(ep, focus)
	q := queue.NewMemory()
	ex := env.executorQ(scopedClient(t, openScope()), q, ExecutorConfig{})
	if err := ex.Handle(context.Background(), env.job(domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID})); err != nil {
		t.Fatalf("reflection: %v", err)
	}
	m := marker(env.scanID, ip.ID)
	var out []detection.Candidate
	for {
		j, err := q.Lease(context.Background(), "t", env.scanID, []domain.JobType{domain.JobTest}, time.Minute)
		if err != nil {
			break
		}
		c, ok, err := parseCandidateJob(j)
		if err != nil || !ok {
			t.Fatalf("not a candidate job: ok=%v err=%v", ok, err)
		}
		c.Value = strings.ReplaceAll(c.Value, m, "M")
		out = append(out, c)
	}
	return out
}

func TestMultipleCandidateJobsPerInjectionPointAreBoundedByProfile(t *testing.T) {
	srv := reflectsEverywhere(t)
	count := func(mut func(*domain.ScanConfig)) []detection.Candidate {
		env := newScanEnv(t)
		env.setScanConfig(mut)
		return enqueuedCandidates(t, env, srv.URL)
	}

	standard := count(func(c *domain.ScanConfig) {}) // default profile
	thorough := count(func(c *domain.ScanConfig) { c.CandidateProfile = "thorough" })
	minimal := count(func(c *domain.ScanConfig) { c.CandidateProfile = "minimal" })
	capped := count(func(c *domain.ScanConfig) { c.CandidateProfile = "thorough"; c.MaxCandidates = 2 })

	if len(standard) < 4 || len(standard) > 8 {
		t.Fatalf("standard enqueued %d candidate jobs, want several (<= its cap of 8)", len(standard))
	}
	if len(thorough) < len(standard) {
		t.Fatalf("thorough (%d) must not send fewer than standard (%d)", len(thorough), len(standard))
	}
	if len(capped) != 2 {
		t.Fatalf("max_candidates=2 enqueued %d candidate jobs", len(capped))
	}
	if len(minimal) == 0 || len(minimal) > 3 {
		t.Fatalf("minimal enqueued %d candidate jobs, want 1..3", len(minimal))
	}
	for _, c := range minimal {
		if c.Trigger != detection.TriggerLoad {
			t.Fatalf("minimal enqueued a %q-trigger candidate %q", c.Trigger, c.Value)
		}
	}
}

func TestCandidateJobSelectionIsDeterministicAcrossRuns(t *testing.T) {
	srv := reflectsEverywhere(t)
	// Compare the selection itself: scan/injection-point IDs and the marker
	// (embedded in DedupKey/Rationale) legitimately differ between scans.
	run := func() []string {
		env := newScanEnv(t)
		env.setScanConfig(func(c *domain.ScanConfig) { c.CandidateProfile = "thorough"; c.MaxCandidates = 4 })
		var out []string
		for _, c := range enqueuedCandidates(t, env, srv.URL) {
			out = append(out, fmt.Sprintf("%s|%s|%s|%s|%d|%s", c.Context, c.Category, c.Trigger, c.Transformation, c.Priority, c.Value))
		}
		return out
	}
	first := run()
	if len(first) != 4 {
		t.Fatalf("enqueued %d, want the 4-candidate cap", len(first))
	}
	for i := 0; i < 5; i++ {
		got := run()
		if !reflect.DeepEqual(got, first) {
			t.Fatalf("run %d enqueued a different candidate set/order:\n got %v\nwant %v", i, got, first)
		}
	}
	var last = 1 << 30
	for _, c := range first {
		var prio int
		parts := strings.SplitN(c, "|", 6)
		fmt.Sscan(parts[4], &prio)
		if prio > last {
			t.Fatalf("candidate jobs not in priority order: %v", first)
		}
		last = prio
	}
}

// An unreadable or invalid stored profile falls back to the BOUNDED standard
// profile — never to an unbounded plan.
func TestInvalidStoredProfileFallsBackToBoundedStandard(t *testing.T) {
	srv := reflectsEverywhere(t)
	env := newScanEnv(t)
	env.setScanConfig(func(c *domain.ScanConfig) { c.CandidateProfile = "yolo"; c.MaxCandidates = 9999 })
	got := enqueuedCandidates(t, env, srv.URL)
	if len(got) == 0 || len(got) > 8 {
		t.Fatalf("invalid profile enqueued %d candidate jobs, want 1..8 (standard)", len(got))
	}
}

// All of an injection point's candidate jobs reflect into ONE logical finding
// per execution context; the multiple attempts are its children.
func TestMultipleCandidateJobsCorrelateIntoOneFindingPerContext(t *testing.T) {
	srv := reflectsEverywhere(t)
	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/s", domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "hello")
	ip := env.injection(ep, focus)
	q := queue.NewMemory()
	ex := env.executorQ(scopedClient(t, openScope()), q, ExecutorConfig{})
	target := domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID}
	if err := ex.Handle(context.Background(), env.job(target)); err != nil {
		t.Fatal(err)
	}
	children := 0
	for {
		j, err := q.Lease(context.Background(), "t", env.scanID, []domain.JobType{domain.JobTest}, time.Minute)
		if err != nil {
			break
		}
		children++
		if err := ex.Handle(context.Background(), j); err != nil {
			t.Fatal(err)
		}
	}
	fs := env.findings()
	// html_text, html_attr_value, js_string: three locations.
	if children < 4 || len(fs) != 3 {
		t.Fatalf("%d candidate jobs produced %d findings, want exactly 3 (one per execution context)", children, len(fs))
	}
	var attempts int
	for _, f := range fs {
		d := decodeFindingDetail(f.Detail)
		attempts += d.Occurrences
		for _, c := range d.Candidates {
			if c.Value == "hello" {
				t.Fatal("baseline value listed as a candidate")
			}
		}
	}
	if attempts != children {
		t.Fatalf("finding occurrences sum to %d, want one per candidate job (%d)", attempts, children)
	}
}
