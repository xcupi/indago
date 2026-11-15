package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/indago/indago/internal/discovery"
	"github.com/indago/indago/internal/domain"
)

// --- helpers ---------------------------------------------------------------

// sstiArithmetic evaluates the "<int>*<int>" shape the engine sends. A real
// template engine is of course richer; every fixture only needs the arithmetic
// the probe actually carries.
func sstiArithmetic(expr string) (string, bool) {
	parts := strings.Split(strings.TrimSpace(expr), "*")
	if len(parts) != 2 {
		return "", false
	}
	a, errA := strconv.Atoi(strings.TrimSpace(parts[0]))
	b, errB := strconv.Atoi(strings.TrimSpace(parts[1]))
	if errA != nil || errB != nil {
		return "", false
	}
	return strconv.Itoa(a * b), true
}

// sstiEvalArithmetic replaces the first "<open><a>*<b><close>" expression in
// text with its product, keeping every other byte — including the per-probe
// marker that follows the closing delimiter.
func sstiEvalArithmetic(text, open, close string) (string, bool) {
	i := strings.Index(text, open)
	if i < 0 {
		return "", false
	}
	rest := text[i+len(open):]
	j := strings.Index(rest, close)
	if j < 0 {
		return "", false
	}
	value, ok := sstiArithmetic(rest[:j])
	if !ok {
		return "", false
	}
	return text[:i] + value + rest[j+len(close):], true
}

// sstiRenderJinja renders a Jinja-ish template: every {{…}} group is either an
// arithmetic expression (replaced by its product) or a bare variable reference
// (replaced by the empty string, like an undefined variable).
func sstiRenderJinja(tpl string) string {
	for {
		i := strings.Index(tpl, "{{")
		if i < 0 {
			return tpl
		}
		end := strings.Index(tpl[i+2:], "}}")
		if end < 0 {
			return tpl
		}
		repl := ""
		if value, ok := sstiArithmetic(tpl[i+2 : i+2+end]); ok {
			repl = value
		}
		tpl = tpl[:i] + repl + tpl[i+2+end+2:]
	}
}

func sstiExecutorFor(t *testing.T, env *scanEnv, cfg ExecutorConfig) *sstiExecutor {
	t.Helper()
	return newSSTIExecutor(env.st, scopedClient(t, openScope()), env.ev, cfg, execLog(), nil)
}

func runSSTIJob(t *testing.T, ex *sstiExecutor, env *scanEnv, ep *domain.Endpoint, focus *domain.Parameter, ip *domain.InjectionPoint) {
	t.Helper()
	job := &domain.TestJob{ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobSSTI,
		Target: domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID, URL: ep.URL}, Attempts: 1, MaxAttempts: 2}
	if err := ex.Handle(context.Background(), job); err != nil {
		t.Fatalf("handle: %v", err)
	}
}

func sstiFindings(t *testing.T, env *scanEnv) []*domain.Finding {
	t.Helper()
	findings, err := env.st.Findings().ListByScan(context.Background(), env.scanID)
	if err != nil {
		t.Fatal(err)
	}
	return findings
}

func sstiCaseDetail(t *testing.T, env *scanEnv) sstiDetail {
	t.Helper()
	cases, err := env.st.TestCases().ListByScan(context.Background(), env.scanID)
	if err != nil || len(cases) != 1 {
		t.Fatalf("expected exactly 1 test case, got %d (err %v)", len(cases), err)
	}
	var detail sstiDetail
	if err := json.Unmarshal(cases[0].Detail, &detail); err != nil {
		t.Fatalf("test case detail: %v", err)
	}
	return detail
}

func sstiEndpoint(t *testing.T, env *scanEnv, url string, method domain.HTTPMethod, contentType string) *domain.Endpoint {
	t.Helper()
	ep := &domain.Endpoint{ID: domain.NewID(), ScanID: env.scanID, URL: url, Method: method,
		ContentType: contentType, Source: domain.SourceCrawler, CreatedAt: time.Now()}
	if err := env.st.Endpoints().Create(context.Background(), ep); err != nil {
		t.Fatal(err)
	}
	return ep
}

// sstiJSONParam registers a body parameter the way browser-network discovery
// does: Example holds the serialized JSON literal.
func sstiJSONParam(t *testing.T, env *scanEnv, ep *domain.Endpoint, name, example string) *domain.Parameter {
	t.Helper()
	p := &domain.Parameter{ID: domain.NewID(), ScanID: env.scanID, EndpointID: ep.ID, Name: name,
		Location: domain.LocationJSON, Example: example, Source: domain.SourceBrowserNetwork, CreatedAt: time.Now()}
	if err := env.st.Parameters().Create(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	return p
}

// --- confirmation ----------------------------------------------------------

func TestSSTIConfirmsTwoIndependentTemplateExpressions(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/8.2")
		if out, ok := sstiEvalArithmetic(r.URL.Query().Get("q"), "{{", "}}"); ok {
			fmt.Fprintf(w, "rendered %s", out)
			return
		}
		fmt.Fprint(w, "template page")
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/page?q=hello", domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "hello")
	ip := env.injection(ep, focus)
	ex := sstiExecutorFor(t, env, ExecutorConfig{})
	runSSTIJob(t, ex, env, ep, focus, ip)

	findings := sstiFindings(t, env)
	if len(findings) != 1 || findings[0].VulnClass != domain.VulnSSTI || findings[0].Verdict != domain.VerdictConfirmed {
		t.Fatalf("findings = %+v, want one confirmed SSTI", findings)
	}
	if !strings.Contains(findings[0].Title, "q") {
		t.Fatalf("finding title = %q, want parameter name", findings[0].Title)
	}
	detail := sstiCaseDetail(t, env)
	if detail.Marker == "" || detail.ConfirmedCount != 2 {
		t.Fatalf("detail = %+v, want a marker and two confirmed expressions", detail)
	}
}

func TestSSTIConfirmsCodeContextBreakout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "Express")
		q := r.URL.Query().Get("q")
		// The application builds the template "Hello {{" + q + "}}".
		fmt.Fprint(w, sstiRenderJinja("Hello {{"+q+"}}"))
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/profile?q=user.name", domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "user.name")
	ip := env.injection(ep, focus)
	ex := sstiExecutorFor(t, env, ExecutorConfig{})
	runSSTIJob(t, ex, env, ep, focus, ip)

	findings := sstiFindings(t, env)
	if len(findings) != 1 || findings[0].VulnClass != domain.VulnSSTI || findings[0].Verdict != domain.VerdictConfirmed {
		t.Fatalf("findings = %+v, want one confirmed code-context SSTI", findings)
	}
	if detail := sstiCaseDetail(t, env); detail.ConfirmedCount != 2 {
		t.Fatalf("detail = %+v, want two confirmed expressions", detail)
	}
}

// A page that already renders the bare arithmetic result must not stop the
// engine from confirming: with the per-run marker the expected string is
// "<result><marker>", which no baseline number can contain.
func TestSSTIConfirmsWithNumericBaselineBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/8.2")
		if out, ok := sstiEvalArithmetic(r.URL.Query().Get("q"), "{{", "}}"); ok {
			fmt.Fprintf(w, `{"count":49,"total":143,"rendered":%q}`, out)
			return
		}
		fmt.Fprint(w, `{"count":49,"total":143,"rendered":""}`)
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/dashboard?q=hello", domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "hello")
	ip := env.injection(ep, focus)
	ex := sstiExecutorFor(t, env, ExecutorConfig{})
	runSSTIJob(t, ex, env, ep, focus, ip)

	findings := sstiFindings(t, env)
	if len(findings) != 1 || findings[0].Verdict != domain.VerdictConfirmed {
		t.Fatalf("findings = %+v, want a numeric baseline to no longer mask the evaluation", findings)
	}
}

// The mirror case: a numeric dashboard that echoes the payload (and therefore
// contains 49/143 everywhere) must never be promoted to a finding.
func TestSSTINumericDashboardReflectionIsNotConfirmed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/8.2")
		fmt.Fprintf(w, `{"count":49,"total":143,"echo":%q}`, r.URL.Query().Get("q"))
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/dashboard?q=hello", domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "hello")
	ip := env.injection(ep, focus)
	ex := sstiExecutorFor(t, env, ExecutorConfig{})
	runSSTIJob(t, ex, env, ep, focus, ip)

	if findings := sstiFindings(t, env); len(findings) != 0 {
		t.Fatalf("reflected payload on a numeric dashboard must not be confirmed: %+v", findings)
	}
	if detail := sstiCaseDetail(t, env); detail.Verdict != domain.VerdictRejected {
		t.Fatalf("verdict = %s, want rejected", detail.Verdict)
	}
}

// A POST form whose text inputs carry no observed value still has to reach the
// template sink: blank required fields must be filled with a harmless value,
// otherwise the baseline (and every probe) is rejected by the application.
func TestSSTIConfirmsPOSTFormWithEmptyExampleValues(t *testing.T) {
	var rejected atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/8.2")
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(r.PostForm.Get("name")) == "" || strings.TrimSpace(r.PostForm.Get("item")) == "" {
			rejected.Add(1)
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, "missing required field")
			return
		}
		if out, ok := sstiEvalArithmetic(r.PostForm.Get("comment"), "{{", "}}"); ok {
			fmt.Fprintf(w, "thanks %s", out)
			return
		}
		fmt.Fprint(w, "thanks")
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/feedback", domain.MethodPOST)
	env.param(ep, "name", domain.LocationForm, "")
	env.param(ep, "item", domain.LocationForm, "")
	focus := env.param(ep, "comment", domain.LocationForm, "")
	ip := env.injection(ep, focus)
	ex := sstiExecutorFor(t, env, ExecutorConfig{AllowStateChanging: true})
	runSSTIJob(t, ex, env, ep, focus, ip)

	if got := rejected.Load(); got != 0 {
		t.Fatalf("%d requests were rejected for a blank required field; empty examples must be filled", got)
	}
	findings := sstiFindings(t, env)
	if len(findings) != 1 || findings[0].Verdict != domain.VerdictConfirmed {
		t.Fatalf("findings = %+v, want one confirmed POST-form SSTI", findings)
	}
}

// A JSON endpoint whose baseline body already carries the bare results, with a
// numeric field that must keep its JSON type.
func TestSSTIConfirmsJSONParameterWithNumericBaseline(t *testing.T) {
	var wrongType atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "Express")
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		if err := json.Unmarshal(raw, &body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if _, ok := body["id"].(float64); !ok {
			wrongType.Add(1) // the non-focused numeric field changed type
		}
		message, _ := body["message"].(string)
		if out, ok := sstiEvalArithmetic(message, "{{", "}}"); ok {
			fmt.Fprintf(w, `{"status":200,"count":49,"rendered":%q}`, out)
			return
		}
		fmt.Fprintf(w, `{"status":200,"count":49,"rendered":%q}`, message)
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := sstiEndpoint(t, env, srv.URL+"/api/items", domain.MethodPOST, "application/json")
	id := sstiJSONParam(t, env, ep, "id", "42")
	focus := sstiJSONParam(t, env, ep, "message", `"hello 49 items"`)
	ip := env.injection(ep, focus)
	_ = id
	ex := sstiExecutorFor(t, env, ExecutorConfig{AllowStateChanging: true})
	runSSTIJob(t, ex, env, ep, focus, ip)

	if got := wrongType.Load(); got != 0 {
		t.Fatalf("%d requests changed the numeric field's JSON type", got)
	}
	findings := sstiFindings(t, env)
	if len(findings) != 1 || findings[0].Verdict != domain.VerdictConfirmed {
		t.Fatalf("findings = %+v, want one confirmed JSON SSTI", findings)
	}
}

// --- engine-family coverage ------------------------------------------------

// Pug uses "#{…}" and runs on Node, so a Node fingerprint must offer it. Before
// the family fix that syntax was Java-only and Pug targets were never probed.
func TestSSTICoversPugSyntaxOnNodeTarget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "Express")
		if out, ok := sstiEvalArithmetic(r.URL.Query().Get("q"), "#{", "}"); ok {
			fmt.Fprintf(w, "rendered %s", out)
			return
		}
		fmt.Fprint(w, "rendered")
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/pug?q=hello", domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "hello")
	ip := env.injection(ep, focus)
	ex := sstiExecutorFor(t, env, ExecutorConfig{})
	runSSTIJob(t, ex, env, ep, focus, ip)

	if findings := sstiFindings(t, env); len(findings) != 1 || findings[0].Verdict != domain.VerdictConfirmed {
		t.Fatalf("findings = %+v, want a confirmed Pug SSTI", findings)
	}
}

// Freemarker and JSP EL both use "${…}"; a Java servlet fingerprint must offer it.
func TestSSTICoversFreemarkerSyntaxOnJavaTarget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache-Coyote/1.1")
		w.Header().Set("Set-Cookie", "JSESSIONID=abc; Path=/")
		if out, ok := sstiEvalArithmetic(r.URL.Query().Get("q"), "${", "}"); ok {
			fmt.Fprintf(w, "rendered %s", out)
			return
		}
		fmt.Fprint(w, "rendered")
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/shop?q=hello", domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "hello")
	ip := env.injection(ep, focus)
	ex := sstiExecutorFor(t, env, ExecutorConfig{})
	runSSTIJob(t, ex, env, ep, focus, ip)

	if findings := sstiFindings(t, env); len(findings) != 1 || findings[0].Verdict != domain.VerdictConfirmed {
		t.Fatalf("findings = %+v, want a confirmed Freemarker/JSP-EL SSTI", findings)
	}
}

// ERB uses "<%= … %>"; a Ruby/Rails fingerprint must offer it.
func TestSSTICoversERBSyntaxOnRubyTarget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		w.Header().Set("Set-Cookie", "_session_id=abc; Path=/")
		if out, ok := sstiEvalArithmetic(r.URL.Query().Get("q"), "<%= ", " %>"); ok {
			fmt.Fprintf(w, "rendered %s", out)
			return
		}
		fmt.Fprint(w, "rendered")
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/rails?q=hello", domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "hello")
	ip := env.injection(ep, focus)
	ex := sstiExecutorFor(t, env, ExecutorConfig{})
	runSSTIJob(t, ex, env, ep, focus, ip)

	if findings := sstiFindings(t, env); len(findings) != 1 || findings[0].Verdict != domain.VerdictConfirmed {
		t.Fatalf("findings = %+v, want a confirmed ERB SSTI", findings)
	}
}

// Twig is identified by its framework cookie alone when the stack hides every
// header.
func TestSSTIConfirmsTwigByLaravelSessionCookie(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "laravel_session=abc; Path=/; HttpOnly")
		if out, ok := sstiEvalArithmetic(r.URL.Query().Get("q"), "{{", "}}"); ok {
			fmt.Fprintf(w, "rendered %s", out)
			return
		}
		fmt.Fprint(w, "rendered")
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/twig?q=hello", domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "hello")
	ip := env.injection(ep, focus)
	ex := sstiExecutorFor(t, env, ExecutorConfig{})
	runSSTIJob(t, ex, env, ep, focus, ip)

	if findings := sstiFindings(t, env); len(findings) != 1 || findings[0].Verdict != domain.VerdictConfirmed {
		t.Fatalf("findings = %+v, want a confirmed Twig SSTI", findings)
	}
}

// A path-segment injection point is a real template sink too: the payload must
// travel through URL encoding and still reach the engine intact.
func TestSSTIConfirmsPathSegmentLocation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/8.2")
		segs := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		value := ""
		if len(segs) >= 2 {
			value = segs[1]
		}
		if out, ok := sstiEvalArithmetic(value, "{{", "}}"); ok {
			fmt.Fprintf(w, "rendered %s", out)
			return
		}
		fmt.Fprint(w, "rendered")
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/item/42/detail", domain.MethodGET)
	focus := env.param(ep, discovery.PathSegmentParamName(1), domain.LocationPath, "42")
	ip := env.injection(ep, focus)
	ex := sstiExecutorFor(t, env, ExecutorConfig{})
	runSSTIJob(t, ex, env, ep, focus, ip)

	if findings := sstiFindings(t, env); len(findings) != 1 || findings[0].Verdict != domain.VerdictConfirmed {
		t.Fatalf("findings = %+v, want a confirmed path-segment SSTI", findings)
	}
}

// --- guards and unit coverage ---------------------------------------------

func TestSSTIUnknownStackIsSkippedWithoutPayloads(t *testing.T) {
	var templateRequests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		if strings.Contains(q, "{{") || strings.Contains(q, "${") || strings.Contains(q, "<%") {
			templateRequests.Add(1)
		}
		fmt.Fprint(w, "plain page")
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/page?q=hello", domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "hello")
	ip := env.injection(ep, focus)
	ex := sstiExecutorFor(t, env, ExecutorConfig{})
	runSSTIJob(t, ex, env, ep, focus, ip)

	if got := templateRequests.Load(); got != 0 {
		t.Fatalf("unknown stack received %d template payloads, want 0", got)
	}
	cases, err := env.st.TestCases().ListByScan(context.Background(), env.scanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) != 1 || cases[0].VulnClass != domain.VulnSSTI || cases[0].Status != domain.TestCaseSkipped {
		t.Fatalf("cases = %+v, want one skipped SSTI case", cases)
	}
	if !strings.Contains(cases[0].Note, "no supported template stack fingerprint") {
		t.Fatalf("skip note = %q", cases[0].Note)
	}
}

func TestSSTIReflectionIsNotConfirmed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/8.2")
		fmt.Fprintf(w, "echo %s", r.URL.Query().Get("q"))
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/page?q=hello", domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "hello")
	ip := env.injection(ep, focus)
	ex := sstiExecutorFor(t, env, ExecutorConfig{})
	runSSTIJob(t, ex, env, ep, focus, ip)

	if findings := sstiFindings(t, env); len(findings) != 0 {
		t.Fatalf("reflected template payload must not be confirmed: %+v", findings)
	}
}

// The marker makes the expected string impossible to obtain by reflection: the
// payload always carries the expression, never its own product.
func TestSSTIProbeMarkerCannotBeProducedByReflection(t *testing.T) {
	marker := "indagoMARKER"
	variants := append(sstiVariants(), sstiContextVariants("observed")...)
	for _, v := range variants {
		payload, expected := sstiProbe(v, marker)
		if strings.Contains(payload, expected) {
			t.Fatalf("payload %q already contains the expected string %q", payload, expected)
		}
		if !strings.HasSuffix(expected, marker) {
			t.Fatalf("expected %q does not end with the marker", expected)
		}
	}
}

func TestSSTIObservedValueUnquotesJSONLiteral(t *testing.T) {
	cases := []struct {
		name  string
		param *domain.Parameter
		want  string
	}{
		{name: "json string literal", param: &domain.Parameter{Location: domain.LocationJSON, Example: `"alice"`}, want: "alice"},
		{name: "json number literal", param: &domain.Parameter{Location: domain.LocationJSON, Example: "5"}, want: "5"},
		{name: "json null literal", param: &domain.Parameter{Location: domain.LocationJSON, Example: "null"}, want: "null"},
		{name: "query value untouched", param: &domain.Parameter{Location: domain.LocationQuery, Example: `"alice"`}, want: `"alice"`},
		{name: "empty", param: &domain.Parameter{Location: domain.LocationJSON, Example: ""}, want: ""},
	}
	for _, tc := range cases {
		if got := sstiObservedValue(tc.param); got != tc.want {
			t.Fatalf("%s: sstiObservedValue = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// A JSON example stored as `"alice"` must break out as `alice}}{{…}}`, not with
// the JSON quotes glued into the template syntax.
func TestSSTIContextVariantsUseTheUnquotedJSONValue(t *testing.T) {
	p := &domain.Parameter{Location: domain.LocationJSON, Example: `"alice"`}
	variants := sstiContextVariants(sstiObservedValue(p))
	if len(variants) == 0 {
		t.Fatal("no context variants for an observed JSON value")
	}
	payload, _ := sstiProbe(variants[0], "mk")
	if !strings.HasPrefix(payload, "alice}}{{") {
		t.Fatalf("payload = %q, want the unquoted observed value to close the expression", payload)
	}
}
