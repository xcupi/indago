package scan

// SQL injection engine tests: the deterministic signals it is allowed to use
// (a NEW database error signature, a stable TRUE/FALSE boolean divergence),
// the guards that keep a reflected payload or a permanently broken page from
// being promoted to a finding, and the opt-in enqueue contract.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/queue"
)

// --- helpers ---------------------------------------------------------------

func sqliExecutorFor(t *testing.T, env *scanEnv, cfg ExecutorConfig) *sqliExecutor {
	t.Helper()
	return newSQLiExecutor(env.st, scopedClient(t, openScope()), env.ev, cfg, execLog(), nil)
}

func runSQLiJob(t *testing.T, ex *sqliExecutor, env *scanEnv, ep *domain.Endpoint, focus *domain.Parameter, ip *domain.InjectionPoint) {
	t.Helper()
	job := &domain.TestJob{ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobSQLi,
		Target: domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID, URL: ep.URL}, Attempts: 1, MaxAttempts: 2}
	if err := ex.Handle(context.Background(), job); err != nil {
		t.Fatalf("handle: %v", err)
	}
}

func sqliFindings(t *testing.T, env *scanEnv) []*domain.Finding {
	t.Helper()
	findings, err := env.st.Findings().ListByScan(context.Background(), env.scanID)
	if err != nil {
		t.Fatal(err)
	}
	return findings
}

func sqliCase(t *testing.T, env *scanEnv) *domain.TestCase {
	t.Helper()
	cases, err := env.st.TestCases().ListByScan(context.Background(), env.scanID)
	if err != nil || len(cases) != 1 {
		t.Fatalf("expected exactly 1 test case, got %d (err %v)", len(cases), err)
	}
	return cases[0]
}

func sqliCaseDetail(t *testing.T, env *scanEnv) sqliDetail {
	t.Helper()
	var detail sqliDetail
	if err := json.Unmarshal(sqliCase(t, env).Detail, &detail); err != nil {
		t.Fatalf("test case detail: %v", err)
	}
	return detail
}

func sqliFindingDetail(t *testing.T, f *domain.Finding) sqliDetail {
	t.Helper()
	var detail sqliDetail
	if err := json.Unmarshal(f.Detail, &detail); err != nil {
		t.Fatalf("finding detail: %v", err)
	}
	return detail
}

// --- confirmation ----------------------------------------------------------

// A target that answers a quote-breaking probe with a database error, while
// the baseline page is clean, must be confirmed by two distinct probes.
func TestSQLiConfirmsErrorBasedInjection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		switch {
		case strings.Contains(q, "'"):
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `SQLITE_ERROR: near "'": syntax error`)
		case strings.Contains(q, `"`):
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `SQLITE_ERROR: unrecognized token: "hello""`)
		default:
			fmt.Fprintf(w, "<html><body>results for %s</body></html>", q)
		}
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/search?q=hello", domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "hello")
	ip := env.injection(ep, focus)
	runSQLiJob(t, sqliExecutorFor(t, env, ExecutorConfig{}), env, ep, focus, ip)

	findings := sqliFindings(t, env)
	if len(findings) != 1 || findings[0].VulnClass != domain.VulnSQLi || findings[0].Verdict != domain.VerdictConfirmed {
		t.Fatalf("findings = %+v, want one confirmed SQL injection", findings)
	}
	if !strings.Contains(findings[0].Title, "q") {
		t.Fatalf("finding title = %q, want the parameter name", findings[0].Title)
	}
	if len(findings[0].EvidenceIDs) == 0 {
		t.Fatal("a confirmed finding must carry request/response evidence")
	}

	detail := sqliCaseDetail(t, env)
	if detail.ErrorSignals != 2 || detail.ConfirmMethod != "error" || detail.IdentifiedDB != "SQLite" {
		t.Fatalf("detail = %+v, want two error signals attributed to SQLite", detail)
	}
	if detail.BaselineStatus != http.StatusOK || detail.BaselineLength == 0 {
		t.Fatalf("baseline not recorded: %+v", detail)
	}
	finding := sqliFindingDetail(t, findings[0])
	if finding.PoC == nil || !strings.Contains(finding.PoC.Payload, "'") {
		t.Fatalf("finding PoC = %+v, want the triggering payload", finding.PoC)
	}
	if finding.PoC.Method != "GET" || !strings.Contains(finding.PoC.URL, "q=") {
		t.Fatalf("PoC request = %+v, want the exact GET request", finding.PoC)
	}
}

// A page that answers every payload with the same content is not injectable:
// no new error signature appears and neither boolean side diverges.
func TestSQLiCleanEndpointProducesNoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><body><h1>Catalogue</h1><p>Static page.</p></body></html>")
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/catalogue?q=hello", domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "hello")
	ip := env.injection(ep, focus)
	runSQLiExecutor := sqliExecutorFor(t, env, ExecutorConfig{})
	runSQLiJob(t, runSQLiExecutor, env, ep, focus, ip)

	if findings := sqliFindings(t, env); len(findings) != 0 {
		t.Fatalf("a static page must not produce a finding: %+v", findings)
	}
	detail := sqliCaseDetail(t, env)
	if detail.Verdict != domain.VerdictRejected || detail.ErrorSignals != 0 || detail.BooleanSignals != 0 {
		t.Fatalf("detail = %+v, want a clean rejection", detail)
	}
	if cases := sqliCase(t, env); cases.Status != domain.TestCaseCompleted || cases.VulnClass != domain.VulnSQLi {
		t.Fatalf("test case = %+v, want one completed SQLi case", cases)
	}
}

// The boolean differential is the second signal: the TRUE condition reproduces
// the baseline and the FALSE condition loses the row. This fixture never
// renders a database error, so confirmation can only come from the two pairs.
func TestSQLiConfirmsBooleanDifferential(t *testing.T) {
	const page = `<html><body><table><tr><td>widget</td><td>42</td></tr></table></body></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("id") {
		case "1", "1 AND 1=1", "1 AND 2=2":
			fmt.Fprint(w, page)
		default:
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, "no such item")
		}
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/item?id=1", domain.MethodGET)
	focus := env.param(ep, "id", domain.LocationQuery, "1")
	ip := env.injection(ep, focus)
	runSQLiJob(t, sqliExecutorFor(t, env, ExecutorConfig{}), env, ep, focus, ip)

	findings := sqliFindings(t, env)
	if len(findings) != 1 || findings[0].VulnClass != domain.VulnSQLi || findings[0].Verdict != domain.VerdictConfirmed {
		t.Fatalf("findings = %+v, want one confirmed boolean SQL injection", findings)
	}
	detail := sqliCaseDetail(t, env)
	if detail.BooleanSignals != 2 || detail.ErrorSignals != 0 || detail.ConfirmMethod != "boolean" {
		t.Fatalf("detail = %+v, want two boolean pairs and no error signal", detail)
	}
	var pairs int
	for _, a := range detail.Attempts {
		if a.Kind == "boolean-true" && a.MatchesBaseline {
			pairs++
		}
	}
	if pairs < 2 {
		t.Fatalf("attempts = %+v, want two TRUE conditions matching the baseline", detail.Attempts)
	}
	if detail.PoC == nil || !strings.Contains(detail.PoC.Payload, "AND") {
		t.Fatalf("PoC = %+v, want a boolean payload", detail.PoC)
	}
}

// A page that always renders a database error is not evidence of injection:
// the signature is already in the baseline, so no probe can be "new".
func TestSQLiBaselineErrorMessageIsNotEvidence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `SQLITE_ERROR: no such table: products`)
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/broken?q=hello", domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "hello")
	ip := env.injection(ep, focus)
	runSQLiJob(t, sqliExecutorFor(t, env, ExecutorConfig{}), env, ep, focus, ip)

	if findings := sqliFindings(t, env); len(findings) != 0 {
		t.Fatalf("a baseline error must not be counted as a new signal: %+v", findings)
	}
	detail := sqliCaseDetail(t, env)
	if detail.ErrorSignals != 0 || detail.Verdict != domain.VerdictRejected {
		t.Fatalf("detail = %+v, want no error signal", detail)
	}
}

// Echoing the payload changes the body size, so the TRUE condition never
// matches the baseline: reflection alone can never confirm the boolean test.
func TestSQLiReflectionIsNotConfirmed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "<html><body>search: %s</body></html>", r.URL.Query().Get("q"))
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/search?q=hello", domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "hello")
	ip := env.injection(ep, focus)
	runSQLiJob(t, sqliExecutorFor(t, env, ExecutorConfig{}), env, ep, focus, ip)

	if findings := sqliFindings(t, env); len(findings) != 0 {
		t.Fatalf("a reflected payload must not be confirmed: %+v", findings)
	}
	detail := sqliCaseDetail(t, env)
	if detail.BooleanSignals != 0 {
		t.Fatalf("reflection produced %d boolean signals, want 0: %+v", detail.BooleanSignals, detail.Attempts)
	}
}

// One new error signature is not enough: the engine must stay inconclusive
// rather than promote a single probe to a finding.
func TestSQLiSingleErrorSignatureIsInconclusive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		// Only a trailing bare quote breaks this statement; the other probe
		// shapes and every boolean payload still return the normal page.
		if strings.HasSuffix(q, "'") && !strings.HasSuffix(q, "')") {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version")
			return
		}
		fmt.Fprint(w, "<html><body>static catalogue page</body></html>")
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/catalogue?q=hello", domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "hello")
	ip := env.injection(ep, focus)
	runSQLiJob(t, sqliExecutorFor(t, env, ExecutorConfig{}), env, ep, focus, ip)

	detail := sqliCaseDetail(t, env)
	if detail.ErrorSignals != 1 || detail.BooleanSignals != 0 {
		t.Fatalf("detail = %+v, want exactly one error signal", detail)
	}
	if detail.Verdict != domain.VerdictInconclusive {
		t.Fatalf("verdict = %s, want inconclusive", detail.Verdict)
	}
	if findings := sqliFindings(t, env); len(findings) != 0 {
		t.Fatalf("one signal must not create a finding: %+v", findings)
	}
	if !strings.Contains(sqliCase(t, env).Note, "second independent signal") {
		t.Fatalf("case note = %q, want the missing-signal explanation", sqliCase(t, env).Note)
	}
}

// --- unit coverage ---------------------------------------------------------

func TestSQLiErrorSignaturesAreRecognized(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		db   string
	}{
		{"sqlite", `SQLITE_ERROR: near "FROM": syntax error`, "SQLite"},
		{"mysql", "You have an error in your SQL syntax; check the manual", "MySQL"},
		{"mariadb", "MariaDB server version for the right syntax to use near", "MariaDB"},
		{"postgres", "ERROR:  syntax error at or near \"'\"", "PostgreSQL"},
		{"mssql", "Unclosed quotation mark after the character string", "MSSQL"},
		{"oracle", "ORA-00933: SQL command not properly ended", "Oracle"},
		{"pdo", "SQLSTATE[42000]: Syntax error or access violation", "generic"},
		{"case-insensitive", "unclosed QUOTATION mark", "MSSQL"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sig, ok := sqlNewErrorSignature([]byte(tc.body), nil)
			if !ok {
				t.Fatalf("%q was not recognized", tc.body)
			}
			if sig.db != tc.db {
				t.Fatalf("%q matched %s, want %s", tc.body, sig.db, tc.db)
			}
		})
	}
	if _, ok := sqlNewErrorSignature([]byte("<html>ordinary page</html>"), nil); ok {
		t.Fatal("an ordinary page must not match a SQL error signature")
	}
}

// A signature already present in the baseline is never returned as new.
func TestSQLiBaselineSignatureIsSuppressed(t *testing.T) {
	baseline := sqlErrorSignaturesIn([]byte(`SQLITE_ERROR: no such table: x`))
	if _, ok := sqlNewErrorSignature([]byte(`SQLITE_ERROR: no such table: x`), baseline); ok {
		t.Fatal("the baseline's own signature must not count as new")
	}
	if sig, ok := sqlNewErrorSignature([]byte("Unclosed quotation mark"), baseline); !ok || sig.db != "MSSQL" {
		t.Fatalf("a different signature must still count: %+v %v", sig, ok)
	}
}

// The boolean pairs must be distinct payloads: two identical pairs would make
// the "two independent signals" rule meaningless.
func TestSQLiBooleanPairsAreIndependent(t *testing.T) {
	seen := map[string]bool{}
	pairs := sqlBooleanPairs("1")
	if len(pairs) < 2 {
		t.Fatalf("pairs = %d, want at least 2", len(pairs))
	}
	for _, pair := range pairs {
		if pair.True == pair.False {
			t.Fatalf("%s: true and false payloads are identical", pair.Name)
		}
		if seen[pair.True] || seen[pair.False] {
			t.Fatalf("%s: duplicate payload", pair.Name)
		}
		seen[pair.True], seen[pair.False] = true, true
	}
}

// --- enqueue ---------------------------------------------------------------

func TestEnqueueSQLiProbesRespectsEnableSQLi(t *testing.T) {
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
			env.setScanConfig(func(c *domain.ScanConfig) { c.EnableSQLi = tc.enabled })
			q := queue.NewMemory()
			c := &Controller{store: env.st, queue: q, log: execLog()}

			ep := env.endpoint("http://127.0.0.1:1/item?id=1", domain.MethodGET)
			focus := env.param(ep, "id", domain.LocationQuery, "1")
			ip := env.injection(ep, focus)
			// A header parameter is not a SQL-injectable location and must
			// never be queued, even when the engine is enabled.
			hdr := env.endpoint("http://127.0.0.1:1/api", domain.MethodGET)
			env.injection(hdr, env.param(hdr, "X-Trace", domain.LocationHeader, "abc"))

			c.enqueueSQLiProbes(context.Background(), env.scanID)

			var jobs []*domain.TestJob
			for {
				j, err := q.Lease(context.Background(), "t", env.scanID, []domain.JobType{domain.JobSQLi}, time.Minute)
				if err != nil || j == nil {
					break
				}
				jobs = append(jobs, j)
			}
			if len(jobs) != tc.want {
				t.Fatalf("enqueued %d SQLi jobs, want %d", len(jobs), tc.want)
			}
			for _, j := range jobs {
				if j.Type != domain.JobSQLi || j.ScanID != env.scanID {
					t.Fatalf("bad job: %+v", j)
				}
				if j.Priority != 47 || j.Target.EndpointID != ep.ID || j.Target.InjectionPointID != ip.ID {
					t.Fatalf("job target/priority wrong: %+v", j)
				}
			}
		})
	}
}
