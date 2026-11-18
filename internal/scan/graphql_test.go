package scan

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/indago/indago/internal/domain"
)

// graphQLRecorder captures what the fake endpoint was actually sent, so the
// tests can assert the probe documents are the bounded, read-only ones this
// engine promises.
type graphQLRecorder struct {
	mu   sync.Mutex
	reqs []graphQLRecordedRequest
}

type graphQLRecordedRequest struct {
	method      string
	contentType string
	body        string
	queryParam  string
}

func (r *graphQLRecorder) add(req graphQLRecordedRequest) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reqs = append(r.reqs, req)
}

func (r *graphQLRecorder) all() []graphQLRecordedRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]graphQLRecordedRequest(nil), r.reqs...)
}

func (r *graphQLRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.reqs)
}

func recordGraphQLRequest(r *http.Request) graphQLRecordedRequest {
	body, _ := io.ReadAll(r.Body)
	return graphQLRecordedRequest{
		method:      r.Method,
		contentType: r.Header.Get("Content-Type"),
		body:        string(body),
		queryParam:  r.URL.Query().Get("query"),
	}
}

// A server exposing all four behaviours: introspection, alias/array batching,
// verbose validation errors and GET-based execution.
func exposedGraphQLHandler(rec *graphQLRecorder) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		record := recordGraphQLRequest(r)
		rec.add(record)
		w.Header().Set("Content-Type", "application/json")
		q := record.queryParam
		if q == "" {
			q = jsonQueryField(record.body)
		}
		bulk := strings.HasPrefix(strings.TrimSpace(record.body), "[")
		switch {
		case r.Method == http.MethodGet && strings.Contains(q, "__typename"):
			io.WriteString(w, `{"data":{"__typename":"Query"}}`)
		case strings.Contains(q, "__schema") && strings.Contains(q, "types"):
			io.WriteString(w, `{"data":{"__schema":{"types":[{"name":"Query"},{"name":"User"},{"name":"Mutation"}]}}}`)
		case strings.Contains(q, "a:__typename"):
			io.WriteString(w, `{"data":{"a":"Query","b":"Query","c":"Query"}}`)
		case bulk:
			io.WriteString(w, `[{"data":{"__typename":"Query"}},{"data":{"__typename":"Query"}}]`)
		case strings.Contains(q, "queryTypee"):
			io.WriteString(w, `{"errors":[{"message":"Cannot query field \"queryTypee\" on type \"__Schema\". Did you mean \"queryType\"?","stack":"Error: ...\n    at GraphQL.validate (/app/node_modules/graphql/validation/validate.js:1:2)"}]}`)
		case strings.Contains(q, "__typename"):
			io.WriteString(w, `{"data":{"__typename":"Query"}}`)
		default:
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, `{"errors":[{"message":"unknown operation"}]}`)
		}
	}
}

// jsonQueryField extracts the query string from a {"query": "..."} body; it is
// only a test convenience, never used by the engine.
func jsonQueryField(body string) string {
	var doc struct {
		Query string `json:"query"`
	}
	if json.Unmarshal([]byte(body), &doc) != nil {
		return ""
	}
	return doc.Query
}

func graphQLTestJob(env *scanEnv, ep *domain.Endpoint) *domain.TestJob {
	return &domain.TestJob{
		ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobType("graphql"),
		Target: domain.JobTarget{EndpointID: ep.ID, URL: ep.URL}, Attempts: 1, MaxAttempts: 3,
	}
}

func graphQLFindings(t *testing.T, env *scanEnv) []*domain.Finding {
	t.Helper()
	findings, err := env.st.Findings().ListByScan(context.Background(), env.scanID)
	if err != nil {
		t.Fatal(err)
	}
	return findings
}

func decodeGraphQLDetail(t *testing.T, tc *domain.TestCase) graphQLDetail {
	t.Helper()
	var d graphQLDetail
	if err := json.Unmarshal(tc.Detail, &d); err != nil {
		t.Fatalf("decode detail: %v (%s)", err, tc.Detail)
	}
	return d
}

func TestGraphQLDetectsIntrospectionBatchingVerboseErrorsAndGETQueries(t *testing.T) {
	rec := &graphQLRecorder{}
	srv := httptest.NewServer(exposedGraphQLHandler(rec))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/graphql", domain.MethodGET)
	ex := newGraphQLExecutor(env.st, scopedClient(t, openScope()), env.ev, ExecutorConfig{AllowStateChanging: true}, execLog(), nil)
	if err := ex.Handle(context.Background(), graphQLTestJob(env, ep)); err != nil {
		t.Fatalf("handle: %v", err)
	}

	findings := graphQLFindings(t, env)
	if len(findings) != 4 {
		t.Fatalf("findings = %d (%+v), want 4", len(findings), findings)
	}
	titles := map[string]bool{}
	for _, f := range findings {
		if f.Verdict != domain.VerdictConfirmed || f.VulnClass != domain.VulnGraphQL {
			t.Fatalf("finding %q = %s/%s, want confirmed/information_disclosure", f.Title, f.Verdict, f.VulnClass)
		}
		if f.EndpointID != ep.ID {
			t.Fatalf("finding %q has endpoint %q, want %q", f.Title, f.EndpointID, ep.ID)
		}
		if len(f.EvidenceIDs) == 0 {
			t.Fatalf("finding %q carries no evidence", f.Title)
		}
		titles[f.Title] = true
	}
	for _, want := range []string{
		"GraphQL introspection is enabled",
		"GraphQL endpoint accepts batched queries",
		"GraphQL endpoint discloses verbose validation errors",
		"GraphQL endpoint accepts GET-based queries",
	} {
		if !titles[want] {
			t.Fatalf("missing finding %q; got %v", want, titles)
		}
	}

	tc := env.only()
	if tc.Status != domain.TestCaseCompleted || tc.VulnClass != domain.VulnGraphQL {
		t.Fatalf("test case = %+v, want completed information_disclosure", tc)
	}
	d := decodeGraphQLDetail(t, tc)
	if !d.IsGraphQL || d.Verdict != domain.VerdictConfirmed {
		t.Fatalf("detail = %+v, want a confirmed GraphQL endpoint", d)
	}
	if len(d.ConfirmedChecks) != 4 {
		t.Fatalf("confirmed checks = %v, want all four", d.ConfirmedChecks)
	}
	if d.BaselineMethod != string(domain.MethodPOST) {
		t.Fatalf("baseline method = %q, want POST with AllowStateChanging", d.BaselineMethod)
	}
	if d.POSTChecksSkipped {
		t.Fatal("POST checks were marked skipped although AllowStateChanging is on")
	}
	if tc.Method != string(domain.MethodPOST) {
		t.Fatalf("test-case method = %q, want POST", tc.Method)
	}
	if len(tc.EvidenceIDs) != 2*rec.count() {
		t.Fatalf("evidence = %d ids for %d probes, want request+response each", len(tc.EvidenceIDs), rec.count())
	}

	// The probes themselves: bounded, read-only, and exactly the documented set.
	reqs := rec.all()
	if len(reqs) != 5 {
		t.Fatalf("probes = %d (%+v), want 5 (baseline, introspection, alias batch, verbose, get)", len(reqs), reqs)
	}
	for _, r := range reqs {
		if strings.Contains(strings.ToLower(r.body), "mutation") {
			t.Fatalf("engine sent a mutation document: %q", r.body)
		}
	}
	var aliases, gets int
	posts := 0
	for _, r := range reqs {
		switch r.method {
		case http.MethodPost:
			posts++
		case http.MethodGet:
			gets++
		}
		if n := strings.Count(r.body, ":__typename"); n > 0 {
			if n != 3 {
				t.Fatalf("alias batch carries %d aliases, want the bounded 3: %q", n, r.body)
			}
			aliases++
		}
		if r.method == http.MethodGet && r.queryParam != "{__typename}" {
			t.Fatalf("GET probe query = %q, want {__typename}", r.queryParam)
		}
	}
	if aliases != 1 || gets != 1 || posts != 4 {
		t.Fatalf("alias batches = %d, GET probes = %d, POST probes = %d; want 1/1/4", aliases, gets, posts)
	}
}

// Without AllowStateChanging, the engine must use GET for the baseline and keep
// the GET-based exposure check. This is the method-recording test for the
// default path: every request the fake endpoint sees is a GET.
func TestGraphQLDefaultSendsOnlyGETAndKeepsGETCheck(t *testing.T) {
	rec := &graphQLRecorder{}
	srv := httptest.NewServer(exposedGraphQLHandler(rec))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/graphql", domain.MethodGET)
	ex := newGraphQLExecutor(env.st, scopedClient(t, openScope()), env.ev, ExecutorConfig{}, execLog(), nil)
	if err := ex.Handle(context.Background(), graphQLTestJob(env, ep)); err != nil {
		t.Fatalf("handle: %v", err)
	}

	reqs := rec.all()
	if len(reqs) != 2 {
		t.Fatalf("probes = %d (%+v), want 2 GETs (baseline + GET check)", len(reqs), reqs)
	}
	for _, r := range reqs {
		if r.method != http.MethodGet {
			t.Fatalf("default GraphQL pass sent %s (%+v), want GET only", r.method, r)
		}
		if r.body != "" || r.contentType != "" {
			t.Fatalf("GET probe carried a body/content type: %+v", r)
		}
	}

	tc := env.only()
	if tc.Status != domain.TestCaseCompleted {
		t.Fatalf("test case = %+v, want completed", tc)
	}
	if tc.Method != string(domain.MethodGET) {
		t.Fatalf("test-case method = %q, want GET", tc.Method)
	}
	d := decodeGraphQLDetail(t, tc)
	if !d.IsGraphQL || d.Verdict != domain.VerdictConfirmed {
		t.Fatalf("detail = %+v, want a confirmed GraphQL endpoint", d)
	}
	if d.BaselineMethod != string(domain.MethodGET) {
		t.Fatalf("baseline method = %q, want GET", d.BaselineMethod)
	}
	if !d.POSTChecksSkipped {
		t.Fatal("POST checks were not marked skipped without AllowStateChanging")
	}
	if len(d.SkippedChecks) != 3 {
		t.Fatalf("skipped checks = %v, want introspection/batching/verbose_errors", d.SkippedChecks)
	}
	if len(d.ConfirmedChecks) != 1 || d.ConfirmedChecks[0] != graphQLCheckGETQueries {
		t.Fatalf("confirmed checks = %v, want only %s", d.ConfirmedChecks, graphQLCheckGETQueries)
	}
	if !strings.Contains(d.Reason, "AllowStateChanging") {
		t.Fatalf("detail reason does not explain the skipped POST checks: %q", d.Reason)
	}
	if !strings.Contains(tc.Note, "POST-only checks skipped") {
		t.Fatalf("test-case note does not explain the skipped POST checks: %q", tc.Note)
	}
	skipped := map[string]bool{}
	for _, c := range d.Checks {
		if c.Skipped {
			skipped[c.Name] = true
		}
	}
	for _, name := range []string{graphQLCheckIntrospection, graphQLCheckBatching, graphQLCheckVerboseErrors} {
		if !skipped[name] {
			t.Fatalf("check %q is not marked skipped: %+v", name, d.Checks)
		}
	}
	findings := graphQLFindings(t, env)
	if len(findings) != 1 || findings[0].Title != "GraphQL endpoint accepts GET-based queries" {
		t.Fatalf("findings = %+v, want only the GET-based-query finding", findings)
	}
}

// A POST-accepting server must not tempt the default path into a fallback: if
// GET is refused, the baseline is skipped rather than retried as POST.
func TestGraphQLDefaultDoesNotFallBackToPOST(t *testing.T) {
	var mu sync.Mutex
	var methods []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		methods = append(methods, r.Method)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			io.WriteString(w, `{"errors":[{"message":"GET is not allowed"}]}`)
			return
		}
		io.WriteString(w, `{"data":{"__typename":"Query"}}`)
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/graphql", domain.MethodGET)
	ex := newGraphQLExecutor(env.st, scopedClient(t, openScope()), env.ev, ExecutorConfig{}, execLog(), nil)
	if err := ex.Handle(context.Background(), graphQLTestJob(env, ep)); err != nil {
		t.Fatalf("handle: %v", err)
	}

	mu.Lock()
	got := append([]string(nil), methods...)
	mu.Unlock()
	for _, m := range got {
		if m != http.MethodGet {
			t.Fatalf("default path fell back to %s; methods=%v", m, got)
		}
	}
	if len(got) != 1 {
		t.Fatalf("methods = %v, want exactly one GET baseline", got)
	}
	tc := env.only()
	if tc.Status != domain.TestCaseSkipped {
		t.Fatalf("test case = %+v, want skipped (GET refused, no POST fallback)", tc)
	}
	if !strings.Contains(tc.Note, "AllowStateChanging") {
		t.Fatalf("skip note does not explain why POST was not tried: %q", tc.Note)
	}
	if findings := graphQLFindings(t, env); len(findings) != 0 {
		t.Fatalf("skipped baseline produced findings: %+v", findings)
	}
}

func TestGraphQLRejectsHardenedEndpoint(t *testing.T) {
	var hits int
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		body, _ := io.ReadAll(r.Body)
		q := r.URL.Query().Get("query")
		if q == "" {
			q = jsonQueryField(string(body))
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet:
			w.WriteHeader(http.StatusMethodNotAllowed)
			io.WriteString(w, `{"errors":[{"message":"GET is not allowed"}]}`)
		case strings.HasPrefix(strings.TrimSpace(string(body)), "["):
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, `{"errors":[{"message":"Batching is not supported"}]}`)
		case strings.Contains(q, "__schema"):
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, `{"errors":[{"message":"introspection is disabled"}]}`)
		case strings.Contains(q, "a:__typename"):
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, `{"errors":[{"message":"Too many fields in one operation"}]}`)
		case strings.Contains(q, "queryTypee"):
			w.WriteHeader(http.StatusBadRequest)
			// A bare validation error: no suggestion, no stack trace.
			io.WriteString(w, `{"errors":[{"message":"Cannot query field \"queryTypee\" on type \"__Schema\"."}]}`)
		case strings.Contains(q, "__typename"):
			// text/plain is rejected as a media type, JSON is answered.
			if strings.HasPrefix(r.Header.Get("Content-Type"), "text/plain") {
				w.WriteHeader(http.StatusUnsupportedMediaType)
				io.WriteString(w, `{"errors":[{"message":"unsupported media type"}]}`)
				return
			}
			io.WriteString(w, `{"data":{"__typename":"Query"}}`)
		default:
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, `{"errors":[{"message":"unknown operation"}]}`)
		}
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/graphql", domain.MethodGET)
	ex := newGraphQLExecutor(env.st, scopedClient(t, openScope()), env.ev, ExecutorConfig{AllowStateChanging: true}, execLog(), nil)
	if err := ex.Handle(context.Background(), graphQLTestJob(env, ep)); err != nil {
		t.Fatalf("handle: %v", err)
	}

	if findings := graphQLFindings(t, env); len(findings) != 0 {
		t.Fatalf("hardened endpoint produced findings: %+v", findings)
	}
	tc := env.only()
	if tc.Status != domain.TestCaseCompleted {
		t.Fatalf("test case = %+v, want completed", tc)
	}
	d := decodeGraphQLDetail(t, tc)
	if !d.IsGraphQL {
		t.Fatalf("endpoint was not recognised as GraphQL: %+v", d)
	}
	if d.Verdict != domain.VerdictRejected || len(d.ConfirmedChecks) != 0 {
		t.Fatalf("detail = %+v, want rejected with no confirmed checks", d)
	}
	mu.Lock()
	defer mu.Unlock()
	if hits != 7 {
		t.Fatalf("probes = %d, want 7 (baseline, introspection, alias, array, verbose, get, text/plain)", hits)
	}
}

// An endpoint that answers the baseline with something that is not a GraphQL
// response envelope must be skipped after ONE request: the exposure probes are
// not sprayed at a non-GraphQL endpoint.
func TestGraphQLSkipsNonGraphQLEndpointAfterOneProbe(t *testing.T) {
	rec := &graphQLRecorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.add(recordGraphQLRequest(r))
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, `<html><body>hello</body></html>`)
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/graphql", domain.MethodGET)
	ex := newGraphQLExecutor(env.st, scopedClient(t, openScope()), env.ev, ExecutorConfig{}, execLog(), nil)
	if err := ex.Handle(context.Background(), graphQLTestJob(env, ep)); err != nil {
		t.Fatalf("handle: %v", err)
	}

	if n := rec.count(); n != 1 {
		t.Fatalf("probes = %d (%+v), want the single baseline request", n, rec.all())
	}
	if reqs := rec.all(); len(reqs) != 1 || reqs[0].method != http.MethodGet {
		t.Fatalf("default baseline = %+v, want one GET", reqs)
	}
	if findings := graphQLFindings(t, env); len(findings) != 0 {
		t.Fatalf("non-GraphQL endpoint produced findings: %+v", findings)
	}
	tc := env.only()
	if tc.Status != domain.TestCaseSkipped {
		t.Fatalf("test case = %+v, want skipped", tc)
	}
	if !strings.Contains(tc.Note, "did not answer") {
		t.Fatalf("skip note = %q", tc.Note)
	}
}

// Re-running the same job must not duplicate findings: correlation keys on
// (endpoint, title).
func TestGraphQLDoesNotDuplicateFindingsOnRerun(t *testing.T) {
	srv := httptest.NewServer(exposedGraphQLHandler(&graphQLRecorder{}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/graphql", domain.MethodGET)
	ex := newGraphQLExecutor(env.st, scopedClient(t, openScope()), env.ev, ExecutorConfig{AllowStateChanging: true}, execLog(), nil)
	job := graphQLTestJob(env, ep)
	if err := ex.Handle(context.Background(), job); err != nil {
		t.Fatalf("first run: %v", err)
	}
	if err := ex.Handle(context.Background(), job); err != nil {
		t.Fatalf("second run: %v", err)
	}
	if findings := graphQLFindings(t, env); len(findings) != 4 {
		t.Fatalf("findings after two runs = %d, want the same 4", len(findings))
	}
}

// The response parsers are the false-positive guard: an echoed request body, a
// partial alias answer and a bare validation error must never confirm.
func TestGraphQLResponseParsersRejectEchoes(t *testing.T) {
	if _, ok := graphQLTypename([]byte(`{"query":"{__typename}"}`)); ok {
		t.Fatal("an echoed request body was read as a __typename answer")
	}
	if _, ok := graphQLTypename([]byte(`{"data":{"__typename":""}}`)); ok {
		t.Fatal("an empty __typename was accepted")
	}
	if _, ok := graphQLTypename([]byte(`{"data":{"__typename":"Query"}}`)); !ok {
		t.Fatal("a real __typename answer was rejected")
	}
	if _, ok := graphQLAliasValues([]byte(`{"data":{"a":"Query","b":"Query"}}`), "a", "b", "c"); ok {
		t.Fatal("a partial alias answer was accepted")
	}
	if _, ok := graphQLAliasValues([]byte(`{"data":{"a":"Query","b":"Query","c":"Query"}}`), "a", "b", "c"); !ok {
		t.Fatal("a complete alias answer was rejected")
	}
	if _, ok := graphQLBatchOperations([]byte(`{"data":{"__typename":"Query"}}`)); ok {
		t.Fatal("a single object was read as a two-operation batch")
	}
	if n, ok := graphQLBatchOperations([]byte(`[{"data":{"__typename":"Query"}},{"data":{"__typename":"Query"}}]`)); !ok || n != 2 {
		t.Fatalf("batch = %d/%v, want 2/true", n, ok)
	}
	if signal := graphQLVerboseErrorSignal([]byte(`{"errors":[{"message":"Cannot query field \"x\" on type \"Query\"."}]}`)); signal != "" {
		t.Fatalf("a bare validation error confirmed verbose errors: %q", signal)
	}
	if signal := graphQLVerboseErrorSignal([]byte(`{"errors":[{"message":"Cannot query field \"x\". Did you mean \"y\"?"}]}`)); signal == "" {
		t.Fatal("a field suggestion was not detected")
	}
	if signal := graphQLVerboseErrorSignal([]byte(`{"errors":[{"message":"boom","stack":"Error\n    at resolve (/srv/app.js:1:1)"}]}`)); signal == "" {
		t.Fatal("a stack trace was not detected")
	}
	if count, examples, ok := graphQLSchemaTypes([]byte(`{"data":{"__schema":{"types":[]}}}`)); ok || count != 0 || len(examples) != 0 {
		t.Fatalf("empty schema = %d/%v/%v, want no disclosure", count, examples, ok)
	}
}
