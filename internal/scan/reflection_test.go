package scan

// Reflection-step tests, driven through the executor against servers that echo a
// chosen parameter. They exercise query/form/JSON reflection, encoding, non-
// reflection, multiple locations, cancellation, baseline reuse, and persistence.

import (
	"context"
	"encoding/json"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
)

// reflector echoes one parameter back, in a configurable way, and records what it
// received so a test can tell baseline (observed value) from mutated (marker).
type reflector struct {
	param string // which parameter to echo
	mode  string // raw | html | none | double
	mu    sync.Mutex
	seen  []string // echoed values, in request order
}

func (rf *reflector) value(r *http.Request) string {
	switch {
	case strings.HasPrefix(r.Header.Get("Content-Type"), "application/json"):
		var m map[string]any
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &m)
		if v, ok := m[rf.param].(string); ok {
			return v
		}
		return ""
	case r.Method == http.MethodPost:
		_ = r.ParseForm()
		return r.PostFormValue(rf.param)
	default:
		return r.URL.Query().Get(rf.param)
	}
}

func (rf *reflector) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := rf.value(r)
		rf.mu.Lock()
		rf.seen = append(rf.seen, v)
		rf.mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		switch rf.mode {
		case "none":
			io.WriteString(w, "<html><body>nothing echoed</body></html>")
		case "html":
			io.WriteString(w, "<div>"+html.EscapeString(v)+"</div>")
		case "double":
			io.WriteString(w, "<title>"+v+"</title><body>"+v+"</body>")
		default: // raw
			io.WriteString(w, "<div>"+v+"</div>")
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func (rf *reflector) values() []string {
	rf.mu.Lock()
	defer rf.mu.Unlock()
	return append([]string(nil), rf.seen...)
}

// reflectReport runs a reflection job for one injection point and returns the
// persisted test case and its parsed reflection report.
func reflectReport(t *testing.T, env *execEnv, cfg ExecutorConfig, job *domain.TestJob) (*domain.TestCase, *detection.ReflectionReport) {
	t.Helper()
	if err := env.executor(scopedClient(t, openScope()), cfg).Handle(context.Background(), job); err != nil {
		t.Fatalf("handle: %v", err)
	}
	tc := env.only()
	rep, err := detection.ParseReflection(tc.Detail)
	if err != nil {
		t.Fatalf("parse reflection detail: %v", err)
	}
	return tc, rep
}

func TestReflectionQueryParameter(t *testing.T) {
	rf := &reflector{param: "q", mode: "raw"}
	srv := rf.server(t)
	env := newExecEnv(t)
	ep := env.endpoint(srv.URL+"/s?q=obs", domain.MethodGET)
	q := env.param(ep, "q", domain.LocationQuery, "obs")
	keep := env.param(ep, "other", domain.LocationQuery, "untouched")
	_ = keep
	ip := env.injection(ep, q)

	tc, rep := reflectReport(t, env, ExecutorConfig{}, env.job(domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID}))

	if tc.Outcome != domain.OutcomeSuccess || tc.VulnClass != domain.VulnReflectedXSS {
		t.Fatalf("outcome=%s class=%s", tc.Outcome, tc.VulnClass)
	}
	if !rep.Reflected || rep.Count != 1 || rep.Parameter != "q" || rep.Location != domain.LocationQuery {
		t.Fatalf("report: %+v", rep)
	}
	if rep.Locations[0].Encoding != detection.EncNone {
		t.Fatalf("raw echo should be encoding=none, got %q", rep.Locations[0].Encoding)
	}
	if rep.TokenInBaseline {
		t.Fatal("unique token must not be in the baseline")
	}
	// Baseline then mutated; the marker went ONLY into q, other kept its value.
	vals := rf.values()
	if len(vals) != 2 || vals[0] != "obs" || !strings.HasPrefix(vals[1], rep.Probe.Token) {
		t.Fatalf("server saw %q; want [obs, <marker>]", vals)
	}
}

func TestReflectionPreservesOtherParameters(t *testing.T) {
	// A server that records the full query so we can confirm only the focused
	// parameter changed between baseline and mutated.
	var mu sync.Mutex
	var queries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		queries = append(queries, r.URL.RawQuery)
		mu.Unlock()
		io.WriteString(w, "<div>"+r.URL.Query().Get("q")+"</div>")
	}))
	defer srv.Close()

	env := newExecEnv(t)
	ep := env.endpoint(srv.URL+"/s?q=obs&keep=fixed", domain.MethodGET)
	q := env.param(ep, "q", domain.LocationQuery, "obs")
	env.param(ep, "keep", domain.LocationQuery, "fixed")
	ip := env.injection(ep, q)

	reflectReport(t, env, ExecutorConfig{}, env.job(domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID}))

	mu.Lock()
	defer mu.Unlock()
	if len(queries) != 2 {
		t.Fatalf("expected baseline+mutated, got %q", queries)
	}
	for _, raw := range queries {
		if !strings.Contains(raw, "keep=fixed") {
			t.Fatalf("other parameter was not preserved: %q", raw)
		}
	}
	if !strings.Contains(queries[0], "q=obs") {
		t.Fatalf("baseline should keep q observed: %q", queries[0])
	}
	if strings.Contains(queries[1], "q=obs") {
		t.Fatalf("mutated should replace q with the marker: %q", queries[1])
	}
}

func TestReflectionFormParameter(t *testing.T) {
	rf := &reflector{param: "c", mode: "raw"}
	srv := rf.server(t)
	env := newExecEnv(t)
	ep := env.endpoint(srv.URL+"/submit", domain.MethodPOST)
	c := env.param(ep, "c", domain.LocationForm, "obs")
	ip := env.injection(ep, c)

	_, rep := reflectReport(t, env, ExecutorConfig{AllowStateChanging: true}, env.job(domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID}))
	if !rep.Reflected || rep.Count != 1 || rep.Location != domain.LocationForm {
		t.Fatalf("form reflection: %+v", rep)
	}
	if v := rf.values(); len(v) != 2 || v[0] != "obs" || !strings.HasPrefix(v[1], rep.Probe.Token) {
		t.Fatalf("server saw %q", v)
	}
}

func TestReflectionJSONParameter(t *testing.T) {
	rf := &reflector{param: "c", mode: "raw"}
	srv := rf.server(t)
	env := newExecEnv(t)
	ep := env.endpoint(srv.URL+"/api", domain.MethodPOST)
	c := env.param(ep, "c", domain.LocationJSON, "obs")
	ip := env.injection(ep, c)

	_, rep := reflectReport(t, env, ExecutorConfig{AllowStateChanging: true}, env.job(domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID}))
	if !rep.Reflected || rep.Location != domain.LocationJSON {
		t.Fatalf("json reflection: %+v", rep)
	}
}

func TestReflectionEncoded(t *testing.T) {
	rf := &reflector{param: "q", mode: "html"}
	srv := rf.server(t)
	env := newExecEnv(t)
	ep := env.endpoint(srv.URL+"/s?q=obs", domain.MethodGET)
	q := env.param(ep, "q", domain.LocationQuery, "obs")
	ip := env.injection(ep, q)

	_, rep := reflectReport(t, env, ExecutorConfig{}, env.job(domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID}))
	if !rep.Reflected || rep.Count != 1 {
		t.Fatalf("expected reflection: %+v", rep)
	}
	if rep.Locations[0].Encoding != detection.EncHTML {
		t.Fatalf("expected html encoding, got %q (segment %q)", rep.Locations[0].Encoding, rep.Locations[0].Segment)
	}
}

func TestReflectionNone(t *testing.T) {
	rf := &reflector{param: "q", mode: "none"}
	srv := rf.server(t)
	env := newExecEnv(t)
	ep := env.endpoint(srv.URL+"/s?q=obs", domain.MethodGET)
	q := env.param(ep, "q", domain.LocationQuery, "obs")
	ip := env.injection(ep, q)

	tc, rep := reflectReport(t, env, ExecutorConfig{}, env.job(domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID}))
	if tc.Outcome != domain.OutcomeSuccess {
		t.Fatalf("outcome = %s", tc.Outcome)
	}
	if rep.Reflected || rep.Count != 0 || len(rep.Locations) != 0 {
		t.Fatalf("expected no reflection: %+v", rep)
	}
	if !strings.Contains(tc.Note, "not reflected") {
		t.Fatalf("note = %q", tc.Note)
	}
}

func TestReflectionMultipleLocations(t *testing.T) {
	rf := &reflector{param: "q", mode: "double"}
	srv := rf.server(t)
	env := newExecEnv(t)
	ep := env.endpoint(srv.URL+"/s?q=obs", domain.MethodGET)
	q := env.param(ep, "q", domain.LocationQuery, "obs")
	ip := env.injection(ep, q)

	_, rep := reflectReport(t, env, ExecutorConfig{}, env.job(domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID}))
	if !rep.Reflected || rep.Count != 2 || len(rep.Locations) != 2 {
		t.Fatalf("expected 2 reflection sites: %+v", rep)
	}
	if rep.Locations[0].Offset >= rep.Locations[1].Offset {
		t.Fatal("locations should be in body order")
	}
}

func TestReflectionCancellation(t *testing.T) {
	started := make(chan struct{})
	var once sync.Once
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(started) })
		<-r.Context().Done() // hang until the client goes away
	}))
	defer srv.Close()
	env := newExecEnv(t)
	ep := env.endpoint(srv.URL+"/s?q=obs", domain.MethodGET)
	q := env.param(ep, "q", domain.LocationQuery, "obs")
	ip := env.injection(ep, q)

	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		errc <- env.executor(scopedClient(t, openScope()), ExecutorConfig{}).Handle(ctx, env.job(domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID}))
	}()
	<-started
	cancel()

	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("cancellation should return an error")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancellation did not interrupt the reflection request")
	}
	if tc := env.only(); tc.Outcome != domain.OutcomeCancelled || tc.Status != domain.TestCaseCancelled {
		t.Fatalf("expected cancelled test case, got %+v", env.only())
	}
}

func TestReflectionBaselineReusedAcrossInjectionPoints(t *testing.T) {
	var baselineHits atomic.Int64
	rf := &reflector{param: "a", mode: "raw"}
	// Count baseline requests: a baseline carries no marker in any parameter.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if !strings.HasPrefix(q.Get("a"), "ind") && !strings.HasPrefix(q.Get("b"), "ind") {
			baselineHits.Add(1)
		}
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, "<div>"+q.Get("a")+q.Get("b")+"</div>")
	}))
	defer srv.Close()
	_ = rf

	env := newExecEnv(t)
	ep := env.endpoint(srv.URL+"/s?a=1&b=2", domain.MethodGET)
	pa := env.param(ep, "a", domain.LocationQuery, "1")
	pb := env.param(ep, "b", domain.LocationQuery, "2")
	ipA := env.injection(ep, pa)
	ipB := env.injection(ep, pb)

	// One executor instance (one scan run): the baseline cache is shared.
	ex := env.executor(scopedClient(t, openScope()), ExecutorConfig{})
	for _, ipID := range []domain.ID{ipA.ID, ipB.ID} {
		if err := ex.Handle(context.Background(), env.job(domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ipID})); err != nil {
			t.Fatal(err)
		}
	}
	if n := baselineHits.Load(); n != 1 {
		t.Fatalf("baseline fetched %d times; it should be reused across injection points (want 1)", n)
	}
}

func TestReflectionPersistenceAndEvidence(t *testing.T) {
	rf := &reflector{param: "q", mode: "raw"}
	srv := rf.server(t)
	env := newExecEnv(t)
	ep := env.endpoint(srv.URL+"/s?q=obs", domain.MethodGET)
	q := env.param(ep, "q", domain.LocationQuery, "obs")
	ip := env.injection(ep, q)

	tc, rep := reflectReport(t, env, ExecutorConfig{}, env.job(domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID}))

	// Four evidence references: shared baseline (request, response) + mutated
	// (request, response).
	if len(tc.EvidenceIDs) != 4 {
		t.Fatalf("evidence refs = %d, want 4", len(tc.EvidenceIDs))
	}
	kinds := map[domain.EvidenceKind]int{}
	var mutatedResp, baselineResp string
	for i, id := range tc.EvidenceIDs {
		row, text := env.evidenceBlob(id)
		kinds[row.Kind]++
		if row.Kind == domain.EvidenceResponse {
			if i < 2 {
				baselineResp = text
			} else {
				mutatedResp = text
			}
		}
	}
	if kinds[domain.EvidenceRequest] != 2 || kinds[domain.EvidenceResponse] != 2 {
		t.Fatalf("evidence kinds: %v", kinds)
	}
	// The marker is in the mutated response, not the baseline response.
	if !strings.Contains(mutatedResp, rep.Probe.Token) {
		t.Fatal("mutated response evidence should contain the marker token")
	}
	if strings.Contains(baselineResp, rep.Probe.Token) {
		t.Fatal("baseline response evidence must not contain the marker token")
	}

	// The persisted report is self-describing and reproducible.
	if rep.Engine != "reflected-xss" || rep.Probe.Value() == "" || rep.Mutated.BodyLen == 0 {
		t.Fatalf("report incomplete: %+v", rep)
	}
	// The same injection point yields the same probe (determinism).
	if detection.NewProbe(env.scanID, ip.ID).Token != rep.Probe.Token {
		t.Fatal("probe is not reproducible for the injection point")
	}
}
