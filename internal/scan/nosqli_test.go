package scan

// NoSQL query-operator engine tests: the two deterministic signals it may use
// (a NEW document-database error signature, a control-checked operator
// differential), the guards that keep a benign control value or a state-
// changing endpoint from being promoted to a finding, and the opt-in enqueue
// contract.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/queue"
)

// --- helpers ---------------------------------------------------------------

func nosqliExecutorFor(t *testing.T, env *scanEnv, cfg ExecutorConfig) *nosqliExecutor {
	t.Helper()
	return newNoSQLiExecutor(env.st, scopedClient(t, openScope()), env.ev, cfg, execLog(), nil)
}

func runNoSQLiJob(t *testing.T, ex *nosqliExecutor, env *scanEnv, ep *domain.Endpoint, focus *domain.Parameter, ip *domain.InjectionPoint) {
	t.Helper()
	job := &domain.TestJob{ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobNoSQLi,
		Target: domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID, URL: ep.URL}, Attempts: 1, MaxAttempts: 2}
	if err := ex.Handle(context.Background(), job); err != nil {
		t.Fatalf("handle: %v", err)
	}
}

func nosqliCase(t *testing.T, env *scanEnv) *domain.TestCase {
	t.Helper()
	cases, err := env.st.TestCases().ListByScan(context.Background(), env.scanID)
	if err != nil || len(cases) != 1 {
		t.Fatalf("expected exactly 1 test case, got %d (err %v)", len(cases), err)
	}
	return cases[0]
}

func nosqliFindingDetail(t *testing.T, f *domain.Finding) nosqliDetail {
	t.Helper()
	var detail nosqliDetail
	if err := json.Unmarshal(f.Detail, &detail); err != nil {
		t.Fatalf("finding detail: %v", err)
	}
	return detail
}

// --- confirmation ----------------------------------------------------------

// An endpoint that answers bracket/operator shapes with a document-database
// error, while the baseline and a benign nonexistent value stay clean, must be
// confirmed by two distinct probes.
func TestNoSQLiConfirmsErrorBasedInjection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		_, array := q["q[]"]
		_, ne := q["q[$ne]"]
		if array || ne {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `{"error":"MongoServerError: unknown top level operator: $ne","ok":0}`)
			return
		}
		fmt.Fprintf(w, "<html><body><p>results for %s</p></body></html>", q.Get("q"))
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/search?q=widget", domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "widget")
	ip := env.injection(ep, focus)
	runNoSQLiJob(t, nosqliExecutorFor(t, env, ExecutorConfig{}), env, ep, focus, ip)

	findings := findingsByClass(t, env, domain.VulnNoSQLi)
	if len(findings) != 1 || findings[0].Verdict != domain.VerdictConfirmed {
		t.Fatalf("findings = %+v, want one confirmed NoSQL injection", findings)
	}
	if !strings.Contains(findings[0].Title, "q") {
		t.Fatalf("finding title = %q, want the parameter name", findings[0].Title)
	}
	if len(findings[0].EvidenceIDs) == 0 {
		t.Fatal("a confirmed finding must carry request/response evidence")
	}

	var detail nosqliDetail
	if err := json.Unmarshal(nosqliCase(t, env).Detail, &detail); err != nil {
		t.Fatalf("test case detail: %v", err)
	}
	if detail.ErrorSignals != 2 || detail.ConfirmMethod != "error" {
		t.Fatalf("detail = %+v, want two error signals confirmed by error", detail)
	}
	if detail.IdentifiedProduct != "MongoDB" {
		t.Fatalf("identified product = %q, want MongoDB", detail.IdentifiedProduct)
	}
	if detail.BaselineStatus != http.StatusOK || detail.BaselineLength == 0 {
		t.Fatalf("baseline not recorded: %+v", detail)
	}
	fd := nosqliFindingDetail(t, findings[0])
	if fd.PoC == nil || !strings.Contains(fd.PoC.URL, "%5B") {
		t.Fatalf("finding PoC = %+v, want the exact bracket-shaped request", fd.PoC)
	}
	if fd.PoC.Method != "GET" {
		t.Fatalf("PoC method = %q, want GET", fd.PoC.Method)
	}
}

// A static page answers every shape with the same content: no new error
// signature appears and no differential is possible.
func TestNoSQLiCleanEndpointProducesNoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><body><h1>Catalogue</h1><p>Static page.</p></body></html>")
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/catalogue?q=widget", domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "widget")
	ip := env.injection(ep, focus)
	runNoSQLiJob(t, nosqliExecutorFor(t, env, ExecutorConfig{}), env, ep, focus, ip)

	if findings := findingsByClass(t, env, domain.VulnNoSQLi); len(findings) != 0 {
		t.Fatalf("a static page must not produce a finding: %+v", findings)
	}
	var detail nosqliDetail
	if err := json.Unmarshal(nosqliCase(t, env).Detail, &detail); err != nil {
		t.Fatalf("test case detail: %v", err)
	}
	if detail.Verdict != domain.VerdictRejected || detail.ErrorSignals != 0 || detail.DifferentialSignals != 0 {
		t.Fatalf("detail = %+v, want a clean rejection", detail)
	}
	if tc := nosqliCase(t, env); tc.Status != domain.TestCaseCompleted || tc.VulnClass != domain.VulnNoSQLi {
		t.Fatalf("test case = %+v, want one completed NoSQLi case", tc)
	}
}

// The differential signal: a nonexistent plain value returns the "no results"
// page, the array control does the same, but wrapping the same value in a
// read-only selection operator returns the baseline result set. Two operators
// must agree before the engine confirms.
func TestNoSQLiConfirmsOperatorDifferentialWithControl(t *testing.T) {
	const full = `<html><body><ul>` +
		`<li>widget alpha</li><li>widget beta</li><li>widget gamma</li><li>widget delta</li>` +
		`<li>widget epsilon</li><li>widget zeta</li><li>widget eta</li><li>widget theta</li>` +
		`</ul></body></html>`
	const empty = `<html><body><p>No results.</p></body></html>`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if _, ok := q["q[$ne]"]; ok {
			fmt.Fprint(w, full)
			return
		}
		if _, ok := q["q[$gt]"]; ok {
			fmt.Fprint(w, full)
			return
		}
		if _, ok := q["q[]"]; ok {
			// Bracket shape with the SAME nonexistent value: no operator, no
			// match. This is the control that makes the operator result
			// attributable to the operator.
			fmt.Fprint(w, empty)
			return
		}
		if q.Get("q") == "widget" {
			fmt.Fprint(w, full)
			return
		}
		fmt.Fprint(w, empty)
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/search?q=widget", domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "widget")
	ip := env.injection(ep, focus)
	runNoSQLiJob(t, nosqliExecutorFor(t, env, ExecutorConfig{}), env, ep, focus, ip)

	findings := findingsByClass(t, env, domain.VulnNoSQLi)
	if len(findings) != 1 || findings[0].Verdict != domain.VerdictConfirmed {
		t.Fatalf("findings = %+v, want one confirmed operator differential", findings)
	}
	var detail nosqliDetail
	if err := json.Unmarshal(nosqliCase(t, env).Detail, &detail); err != nil {
		t.Fatalf("test case detail: %v", err)
	}
	if detail.DifferentialSignals != 2 || detail.ErrorSignals != 0 || detail.ConfirmMethod != "differential" {
		t.Fatalf("detail = %+v, want two operator differentials and no error signal", detail)
	}
	if !detail.ControlJudgeable {
		t.Fatalf("detail = %+v, control should be judgeable", detail)
	}
	var controls int
	for _, a := range detail.Attempts {
		if a.Role == "control" && a.DivergesBaseline {
			controls++
		}
	}
	if controls == 0 {
		t.Fatalf("attempts = %+v, want a recorded diverging benign control", detail.Attempts)
	}
	if detail.PoC == nil || !strings.Contains(detail.PoC.Key, "$") {
		t.Fatalf("PoC = %+v, want the operator request", detail.PoC)
	}
}

// A target that answers every unknown query value with the full page cannot be
// judged by a differential: an operator "match" would be indistinguishable
// from ordinary empty-result handling, so no finding may be invented.
func TestNoSQLiUnjudgeableControlProducesNoFinding(t *testing.T) {
	const page = `<html><body><ul><li>widget alpha</li><li>widget beta</li><li>widget gamma</li></ul></body></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Every request returns the same listing, including the controls.
		fmt.Fprint(w, page)
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/catalogue?q=widget", domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "widget")
	ip := env.injection(ep, focus)
	runNoSQLiJob(t, nosqliExecutorFor(t, env, ExecutorConfig{}), env, ep, focus, ip)

	if findings := findingsByClass(t, env, domain.VulnNoSQLi); len(findings) != 0 {
		t.Fatalf("an unjudgeable control must not produce a finding: %+v", findings)
	}
	var detail nosqliDetail
	if err := json.Unmarshal(nosqliCase(t, env).Detail, &detail); err != nil {
		t.Fatalf("test case detail: %v", err)
	}
	if detail.ControlJudgeable || detail.DifferentialSignals != 0 {
		t.Fatalf("detail = %+v, want an unjudgeable control and no differential", detail)
	}
}

// A plain value-validation bug is not operator injection: if the BENIGN
// control already produces the cast error, that signature is suppressed and
// the bracket probes cannot re-use it as evidence.
func TestNoSQLiPlainControlErrorIsNotEvidence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		if q != "" && q != "1" {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `CastError: Cast to ObjectId failed for value "`+q+`" at path "_id"`)
			return
		}
		fmt.Fprint(w, `<html><body><p>item 1</p></body></html>`)
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/item?id=1", domain.MethodGET)
	focus := env.param(ep, "id", domain.LocationQuery, "1")
	ip := env.injection(ep, focus)
	runNoSQLiJob(t, nosqliExecutorFor(t, env, ExecutorConfig{}), env, ep, focus, ip)

	if findings := findingsByClass(t, env, domain.VulnNoSQLi); len(findings) != 0 {
		t.Fatalf("a value-validation cast error must not be attributed to operator injection: %+v", findings)
	}
	var detail nosqliDetail
	if err := json.Unmarshal(nosqliCase(t, env).Detail, &detail); err != nil {
		t.Fatalf("test case detail: %v", err)
	}
	if detail.ErrorSignals != 0 {
		t.Fatalf("detail = %+v, want no error signal", detail)
	}
}

// Strictly read-only: a state-changing endpoint is skipped even when the scan
// explicitly allows state-changing requests, and the server must see ZERO
// requests — not even a baseline GET.
func TestNoSQLiSkipsStateChangingEndpoint(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		fmt.Fprint(w, `<html><body>ok</body></html>`)
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/api/items", domain.MethodPOST)
	focus := env.param(ep, "q", domain.LocationQuery, "widget")
	ip := env.injection(ep, focus)
	// AllowStateChanging is deliberately ON: this engine must ignore it.
	runNoSQLiJob(t, nosqliExecutorFor(t, env, ExecutorConfig{AllowStateChanging: true}), env, ep, focus, ip)

	if hits.Load() != 0 {
		t.Fatalf("a state-changing endpoint received %d request(s); the NoSQL engine is read-only", hits.Load())
	}
	tc := nosqliCase(t, env)
	if tc.Status != domain.TestCaseSkipped || !strings.Contains(tc.Note, "state-changing endpoint skipped by policy") {
		t.Fatalf("test case = %+v, want a state-changing skip", tc)
	}
	if findings := findingsByClass(t, env, domain.VulnNoSQLi); len(findings) != 0 {
		t.Fatalf("a skipped endpoint must not produce a finding: %+v", findings)
	}
}

// Header and body parameters are not GET query parameters and are skipped
// without a request.
func TestNoSQLiSkipsNonQueryLocations(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/api", domain.MethodGET)
	focus := env.param(ep, "X-Trace", domain.LocationHeader, "abc")
	ip := env.injection(ep, focus)
	runNoSQLiJob(t, nosqliExecutorFor(t, env, ExecutorConfig{}), env, ep, focus, ip)

	if hits.Load() != 0 {
		t.Fatalf("a non-query location received %d request(s)", hits.Load())
	}
	if tc := nosqliCase(t, env); tc.Status != domain.TestCaseSkipped {
		t.Fatalf("test case = %+v, want a skipped case", tc)
	}
}

// 429/503 is backpressure, not a judgement: the baseline itself is throttled,
// so exactly one request is sent and the result stays inconclusive.
func TestNoSQLiThrottledBaselineSendsNoProbes(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, "slow down")
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/search?q=widget", domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "widget")
	ip := env.injection(ep, focus)
	runNoSQLiJob(t, nosqliExecutorFor(t, env, ExecutorConfig{}), env, ep, focus, ip)

	if hits.Load() != 1 {
		t.Fatalf("server saw %d request(s), want exactly the baseline", hits.Load())
	}
	var detail nosqliDetail
	if err := json.Unmarshal(nosqliCase(t, env).Detail, &detail); err != nil {
		t.Fatalf("test case detail: %v", err)
	}
	if !detail.Throttled || detail.Verdict != domain.VerdictInconclusive {
		t.Fatalf("detail = %+v, want a throttled inconclusive result", detail)
	}
	if findings := findingsByClass(t, env, domain.VulnNoSQLi); len(findings) != 0 {
		t.Fatalf("a throttled baseline must not produce a finding: %+v", findings)
	}
}

// --- unit coverage ---------------------------------------------------------

func TestNoSQLiErrorSignaturesAreRecognized(t *testing.T) {
	for _, tc := range []struct {
		name    string
		body    string
		product string
	}{
		{"mongo server", `{"error":"MongoServerError: unknown top level operator: $ne"}`, "MongoDB"},
		{"mongo driver", `MongoError: bad query`, "MongoDB"},
		{"bson", `BSONTypeError: Argument must be a string`, "MongoDB"},
		{"mongo parse", `MongoParseError: Invalid query`, "MongoDB"},
		{"unknown operator", `unknown operator: $gt`, "MongoDB"},
		{"mongoose cast string", `Cast to string failed for value "[]" (type array) at path "q"`, "Mongoose"},
		{"mongoose objectid", `Cast to ObjectId failed for value "indago_absent" at path "_id"`, "Mongoose"},
		{"elasticsearch", `{"error":{"type":"search_phase_execution_exception"}}`, "Elasticsearch"},
		{"case-insensitive", `mongoservererror: boom`, "MongoDB"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sig, ok := nosqlNewErrorSignature([]byte(tc.body), nil)
			if !ok {
				t.Fatalf("%q was not recognized", tc.body)
			}
			if sig.product != tc.product {
				t.Fatalf("%q matched %s, want %s", tc.body, sig.product, tc.product)
			}
		})
	}
	if _, ok := nosqlNewErrorSignature([]byte("<html>ordinary page</html>"), nil); ok {
		t.Fatal("an ordinary page must not match a NoSQL error signature")
	}
}

// A signature already present in the baseline or the benign control is never
// returned as new.
func TestNoSQLiBaselineAndControlSignaturesAreSuppressed(t *testing.T) {
	suppressed := nosqlErrorSignaturesIn([]byte(`MongoServerError: no such collection`))
	suppressed["CastError"] = true
	if _, ok := nosqlNewErrorSignature([]byte(`MongoServerError: no such collection`), suppressed); ok {
		t.Fatal("the baseline's own signature must not count as new")
	}
	if _, ok := nosqlNewErrorSignature([]byte(`{"name":"CastError","message":"bad"}`), suppressed); ok {
		t.Fatal("the control's own signature must not count as new")
	}
	if sig, ok := nosqlNewErrorSignature([]byte(`BSONTypeError: bad value`), suppressed); !ok || sig.product != "MongoDB" {
		t.Fatalf("a different signature must still count: %+v %v", sig, ok)
	}
}

// The shape builder must replace ONLY the focused parameter and preserve every
// other observed query parameter byte-for-byte after decoding.
func TestNoSQLiShapeRequestKeepsOtherParameters(t *testing.T) {
	ep := &domain.Endpoint{URL: "http://example.test/search?q=widget&page=2&lang=en", Method: domain.MethodGET}
	q := &domain.Parameter{ID: "p1", Name: "q", Location: domain.LocationQuery, Example: "widget"}
	page := &domain.Parameter{ID: "p2", Name: "page", Location: domain.LocationQuery, Example: "2"}
	lang := &domain.Parameter{ID: "p3", Name: "lang", Location: domain.LocationQuery, Example: "en"}
	base, err := buildRequest(ep, []*domain.Parameter{q, page, lang}, nil)
	if err != nil {
		t.Fatal(err)
	}
	req, err := nosqliShapeRequest(base, "q", "q[$ne]", "indago_absent")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(req.URL, "q%5B%24ne%5D=indago_absent") {
		t.Fatalf("URL = %q, want the encoded operator shape", req.URL)
	}
	if strings.Contains(req.URL, "q=widget") {
		t.Fatalf("URL = %q, the plain value must be replaced", req.URL)
	}
	if !strings.Contains(req.URL, "page=2") || !strings.Contains(req.URL, "lang=en") {
		t.Fatalf("URL = %q, other parameters must be preserved", req.URL)
	}
}

// Two identical operator probes would make the "two independent signals" rule
// meaningless.
func TestNoSQLiOperatorProbesAreIndependent(t *testing.T) {
	seen := map[string]bool{}
	probes := append(nosqliArrayProbes("q", "absent"), nosqliOperatorProbes("q", "absent")...)
	if len(probes) < 4 {
		t.Fatalf("probes = %d, want at least 4", len(probes))
	}
	var operators int
	for _, p := range probes {
		if seen[p.Key+p.Value] {
			t.Fatalf("duplicate probe: %+v", p)
		}
		seen[p.Key+p.Value] = true
		if p.Operator {
			operators++
			if !strings.Contains(p.Key, "$") {
				t.Fatalf("operator probe key = %q, want a selection operator", p.Key)
			}
			// The engine must never send a write or JavaScript-execution
			// operator.
			for _, banned := range []string{"$set", "$unset", "$inc", "$push", "$rename", "$where", "$function", "$accumulator", "$merge", "$out"} {
				if strings.Contains(p.Key, banned) {
					t.Fatalf("probe %q uses a non-read-only operator", p.Key)
				}
			}
		}
	}
	if operators != 2 {
		t.Fatalf("operator probes = %d, want exactly 2", operators)
	}
}

// --- enqueue ---------------------------------------------------------------

func TestEnqueueNoSQLiProbesRespectsEnableNoSQLi(t *testing.T) {
	for _, tc := range []struct {
		name    string
		enabled bool
		want    int
	}{
		{name: "enabled", enabled: true, want: 1},
		{name: "disabled", enabled: false, want: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newScanEnv(t)
			env.setScanConfig(func(c *domain.ScanConfig) { c.EnableNoSQLi = tc.enabled })
			q := queue.NewMemory()
			c := &Controller{store: env.st, queue: q, log: execLog()}

			ep := env.endpoint("http://127.0.0.1:1/item?id=1", domain.MethodGET)
			focus := env.param(ep, "id", domain.LocationQuery, "1")
			ip := env.injection(ep, focus)
			// A POST endpoint and a header parameter are never eligible, even
			// when the engine is enabled.
			post := env.endpoint("http://127.0.0.1:1/api/items", domain.MethodPOST)
			env.injection(post, env.param(post, "q", domain.LocationQuery, "x"))
			hdr := env.endpoint("http://127.0.0.1:1/api", domain.MethodGET)
			env.injection(hdr, env.param(hdr, "X-Trace", domain.LocationHeader, "abc"))

			c.enqueueNoSQLiProbes(context.Background(), env.scanID)

			var jobs []*domain.TestJob
			for {
				j, err := q.Lease(context.Background(), "t", env.scanID, []domain.JobType{domain.JobNoSQLi}, time.Minute)
				if err != nil || j == nil {
					break
				}
				jobs = append(jobs, j)
			}
			if len(jobs) != tc.want {
				t.Fatalf("enqueued %d NoSQLi jobs, want %d", len(jobs), tc.want)
			}
			for _, j := range jobs {
				if j.Type != domain.JobNoSQLi || j.ScanID != env.scanID {
					t.Fatalf("bad job: %+v", j)
				}
				if j.Priority != nosqliPriority || j.Target.EndpointID != ep.ID || j.Target.InjectionPointID != ip.ID {
					t.Fatalf("job target/priority wrong: %+v", j)
				}
			}
		})
	}
}
