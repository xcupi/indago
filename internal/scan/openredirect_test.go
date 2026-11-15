package scan

// Open redirect engine tests: the pure payload/parameter/destination rules, plus
// the executor against real httptest servers (Location headers, meta refresh,
// script redirects, in-scope redirects that must NOT be followed, baseline
// attribution, payload shapes, skips, throttling and correlation).

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/httpengine"
)

func openRedirectJob(env *scanEnv, ep *domain.Endpoint) *domain.TestJob {
	env.t.Helper()
	return &domain.TestJob{
		ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobTest,
		Target: domain.JobTarget{EndpointID: ep.ID, URL: ep.URL}, Attempts: 1, MaxAttempts: 2,
	}
}

func runOpenRedirect(t *testing.T, env *scanEnv, ep *domain.Endpoint, cfg ExecutorConfig) *domain.TestCase {
	t.Helper()
	ex := newOpenRedirectExecutor(env.st, scopedClient(t, openScope()), env.ev, cfg, execLog(), nil)
	if err := ex.Handle(context.Background(), openRedirectJob(env, ep)); err != nil {
		t.Fatalf("handle: %v", err)
	}
	cases, err := env.st.TestCases().ListByScan(context.Background(), env.scanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) != 1 {
		t.Fatalf("test cases = %d, want 1", len(cases))
	}
	return cases[0]
}

func openRedirectDetailOf(t *testing.T, tc *domain.TestCase) openRedirectDetail {
	t.Helper()
	var d openRedirectDetail
	if err := json.Unmarshal(tc.Detail, &d); err != nil {
		t.Fatalf("unmarshal detail: %v (%s)", err, string(tc.Detail))
	}
	return d
}

// --- pure rules ---

func TestIsRedirectParamName(t *testing.T) {
	yes := []string{"next", "url", "returnUrl", "return_url", "returnTo", "redirect", "redirect_uri",
		"redirect_url", "goto", "dest", "destination", "redir", "callback", "callback_url", "continue",
		"next_page", "target", "forward", "RedirectURI"}
	no := []string{"q", "search", "image", "curl", "username", "password", "address", "birthday", "id", ""}
	for _, name := range yes {
		if !isRedirectParamName(name) {
			t.Errorf("isRedirectParamName(%q) = false, want true", name)
		}
	}
	for _, name := range no {
		if isRedirectParamName(name) {
			t.Errorf("isRedirectParamName(%q) = true, want false", name)
		}
	}
}

func TestOpenRedirectPayloadsAreBoundedAndHarmless(t *testing.T) {
	payloads := openRedirectPayloads("https://app.example.test/login?next=home")
	if len(payloads) != 4 {
		t.Fatalf("payloads = %d, want 4", len(payloads))
	}
	kinds := map[string]bool{}
	for _, p := range payloads {
		kinds[p.Kind] = true
		if !strings.Contains(p.Value, openRedirectCanaryHost) {
			t.Fatalf("payload %q does not target the canary host", p.Value)
		}
	}
	for _, kind := range []string{"absolute", "protocol_relative", "userinfo", "backslash"} {
		if !kinds[kind] {
			t.Fatalf("missing payload kind %q: %+v", kind, payloads)
		}
	}
	if got := payloads[2].Value; got != "https://app.example.test@canary.invalid/" {
		t.Fatalf("userinfo payload = %q", got)
	}
}

func TestOpenRedirectCanaryTarget(t *testing.T) {
	cases := []struct {
		name        string
		destination string
		wantHost    bool
		wantTarget  string
	}{
		{name: "absolute", destination: "https://canary.invalid/", wantHost: true, wantTarget: "https://canary.invalid/"},
		{name: "subdomain", destination: "https://x.canary.invalid/a", wantHost: true, wantTarget: "https://x.canary.invalid/a"},
		{name: "protocol relative", destination: "//canary.invalid/", wantHost: true, wantTarget: "https://canary.invalid/"},
		{name: "backslash", destination: `/\canary.invalid/`, wantHost: true},
		{name: "userinfo", destination: "https://127.0.0.1@canary.invalid/", wantHost: true, wantTarget: "https://127.0.0.1@canary.invalid/"},
		{name: "same site", destination: "/login", wantHost: false},
		{name: "canary only in a query", destination: "/login?next=https://canary.invalid/", wantHost: false},
		{name: "lookalike", destination: "https://canary.invalid.evil.test/", wantHost: false},
		{name: "empty", destination: "", wantHost: false},
	}
	base := "https://127.0.0.1/login?next=home"
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			target, ok := openRedirectCanaryTarget(base, tc.destination)
			if ok != tc.wantHost {
				t.Fatalf("ok = %v, want %v (target %q)", ok, tc.wantHost, target)
			}
			if tc.wantTarget != "" && target != tc.wantTarget {
				t.Fatalf("target = %q, want %q", target, tc.wantTarget)
			}
		})
	}
}

// redirectResponseStub builds the minimal httpengine.Response the pure detector
// needs: a status, headers and a body.
func redirectResponseStub(status int, headers map[string]string, body string) *httpengine.Response {
	h := http.Header{}
	for k, v := range headers {
		h.Set(k, v)
	}
	return &httpengine.Response{Status: status, Headers: h, Body: []byte(body)}
}

func TestDetectOpenRedirectSignals(t *testing.T) {
	base := "https://app.test/next"
	t.Run("location header", func(t *testing.T) {
		resp := redirectResponseStub(302, map[string]string{"Location": "https://canary.invalid/"}, "")
		sig, ok := detectOpenRedirect(resp, base)
		if !ok || sig.Kind != "location_header" || sig.Target != "https://canary.invalid/" {
			t.Fatalf("signal = %+v ok=%v", sig, ok)
		}
	})
	t.Run("meta refresh", func(t *testing.T) {
		body := `<html><head><meta http-equiv="refresh" content="0; url='https://canary.invalid/'"></head></html>`
		sig, ok := detectOpenRedirect(redirectResponseStub(200, nil, body), base)
		if !ok || sig.Kind != "meta_refresh" {
			t.Fatalf("signal = %+v ok=%v", sig, ok)
		}
	})
	t.Run("script redirect", func(t *testing.T) {
		body := `<script>window.location.href = "https://canary.invalid/";</script>`
		sig, ok := detectOpenRedirect(redirectResponseStub(200, nil, body), base)
		if !ok || sig.Kind != "script_redirect" {
			t.Fatalf("signal = %+v ok=%v", sig, ok)
		}
	})
	t.Run("same-origin redirect is not a signal", func(t *testing.T) {
		resp := redirectResponseStub(302, map[string]string{"Location": "/login"}, "")
		if sig, ok := detectOpenRedirect(resp, base); ok {
			t.Fatalf("signal = %+v, want none", sig)
		}
	})
	t.Run("comparison is not an assignment", func(t *testing.T) {
		body := `<script>if (location.href == "https://canary.invalid/") { }</script>`
		if sig, ok := detectOpenRedirect(redirectResponseStub(200, nil, body), base); ok {
			t.Fatalf("signal = %+v, want none", sig)
		}
	})
}

// --- executor against real servers ---

func TestOpenRedirectLocationHeaderIsConfirmed(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		next := r.URL.Query().Get("next")
		if strings.Contains(next, openRedirectCanaryHost) {
			w.Header().Set("Location", next)
			w.WriteHeader(http.StatusFound)
			return
		}
		fmt.Fprint(w, "home")
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/login?next=home", domain.MethodGET)
	env.param(ep, "next", domain.LocationQuery, "home")
	tc := runOpenRedirect(t, env, ep, ExecutorConfig{})

	if tc.Status != domain.TestCaseCompleted || tc.VulnClass != domain.VulnOpenRedirect {
		t.Fatalf("test case = %s/%s", tc.Status, tc.VulnClass)
	}
	d := openRedirectDetailOf(t, tc)
	if d.Verdict != domain.VerdictConfirmed || len(d.Confirmed) != 1 {
		t.Fatalf("detail = %+v, want one confirmation", d)
	}
	c := d.Confirmed[0]
	if c.Parameter != "next" || c.Signal != "location_header" || c.Target != openRedirectCanaryURL {
		t.Fatalf("confirmation = %+v", c)
	}
	if d.Baseline == nil || d.Baseline.Status != 200 {
		t.Fatalf("baseline = %+v, want the unmodified 200", d.Baseline)
	}
	if len(tc.EvidenceIDs) == 0 {
		t.Fatal("test case has no evidence")
	}

	findings := scanFindings(t, env)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	f := findings[0]
	if f.Verdict != domain.VerdictConfirmed || f.VulnClass != domain.VulnOpenRedirect {
		t.Fatalf("finding = %s/%s", f.Verdict, f.VulnClass)
	}
	if f.Severity != domain.SeverityMedium || f.Confidence != domain.ConfidenceHigh {
		t.Fatalf("severity/confidence = %s/%s", f.Severity, f.Confidence)
	}
	if !strings.Contains(f.Title, `"next"`) || !strings.Contains(f.Title, "127.0.0.1") {
		t.Fatalf("title = %q", f.Title)
	}
	if f.Location != domain.LocationQuery {
		t.Fatalf("finding location = %q", f.Location)
	}
	if len(f.EvidenceIDs) == 0 {
		t.Fatal("finding has no evidence")
	}
	var fd openRedirectDetail
	if err := json.Unmarshal(f.Detail, &fd); err != nil || fd.DedupKey == "" {
		t.Fatalf("finding detail = %s (err %v)", string(f.Detail), err)
	}
	// baseline + the first payload, which already confirmed: no further shapes are sent.
	if got := requests.Load(); got != 2 {
		t.Fatalf("requests = %d, want 2", got)
	}
}

func TestOpenRedirectRelativeRedirectIsNotAFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login", http.StatusFound)
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/login?next=home", domain.MethodGET)
	env.param(ep, "next", domain.LocationQuery, "home")
	tc := runOpenRedirect(t, env, ep, ExecutorConfig{})
	d := openRedirectDetailOf(t, tc)
	if d.Verdict != domain.VerdictRejected {
		t.Fatalf("verdict = %q, want rejected (%s)", d.Verdict, d.Reason)
	}
	if len(scanFindings(t, env)) != 0 {
		t.Fatal("a same-site redirect must not be reported")
	}
}

func TestOpenRedirectCanaryOnlyInQueryIsNotAFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The destination stays on this host; the canary is only echoed inside
		// the redirect's own query string.
		w.Header().Set("Location", "/login?next="+url.QueryEscape(r.URL.Query().Get("next")))
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/login?next=home", domain.MethodGET)
	env.param(ep, "next", domain.LocationQuery, "home")
	tc := runOpenRedirect(t, env, ep, ExecutorConfig{})
	if d := openRedirectDetailOf(t, tc); d.Verdict != domain.VerdictRejected {
		t.Fatalf("verdict = %q, want rejected (%s)", d.Verdict, d.Reason)
	}
	if len(scanFindings(t, env)) != 0 {
		t.Fatal("a Location that merely mentions the canary in its query is not an open redirect")
	}
}

func TestOpenRedirectInspectsInScopeRedirectWithoutFollowing(t *testing.T) {
	var landing atomic.Int32
	dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		landing.Add(1)
		fmt.Fprint(w, "landed")
	}))
	defer dest.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("next") != "home" {
			w.Header().Set("Location", dest.URL+"/land")
			w.WriteHeader(http.StatusFound)
			return
		}
		fmt.Fprint(w, "home")
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/go?next=home", domain.MethodGET)
	env.param(ep, "next", domain.LocationQuery, "home")
	tc := runOpenRedirect(t, env, ep, ExecutorConfig{})
	if landing.Load() != 0 {
		t.Fatalf("the in-scope redirect target received %d requests; payloads must be inspected, never followed", landing.Load())
	}
	d := openRedirectDetailOf(t, tc)
	if d.Verdict != domain.VerdictRejected {
		t.Fatalf("verdict = %q, want rejected", d.Verdict)
	}
	found := false
	for _, a := range d.Attempts {
		if a.RedirectTo == dest.URL+"/land" {
			found = true
		}
	}
	if !found {
		t.Fatalf("attempts = %+v, want the observed non-canary Location recorded", d.Attempts)
	}
}

func TestOpenRedirectPayloadShapes(t *testing.T) {
	shapes := []struct {
		kind  string
		index int
	}{
		{"absolute", 0},
		{"protocol_relative", 1},
		{"userinfo", 2},
		{"backslash", 3},
	}
	for _, shape := range shapes {
		t.Run(shape.kind, func(t *testing.T) {
			// The payload set is derived from the target URL, so the destination
			// this server must echo is only known once the server exists.
			var target atomic.Value
			target.Store("")
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				want, _ := target.Load().(string)
				if want != "" && r.URL.Query().Get("next") == want {
					w.Header().Set("Location", want)
					w.WriteHeader(http.StatusFound)
					return
				}
				fmt.Fprint(w, "home")
			}))
			defer srv.Close()
			target.Store(openRedirectPayloads(srv.URL + "/go?next=home")[shape.index].Value)

			env := newScanEnv(t)
			ep := env.endpoint(srv.URL+"/go?next=home", domain.MethodGET)
			env.param(ep, "next", domain.LocationQuery, "home")
			d := openRedirectDetailOf(t, runOpenRedirect(t, env, ep, ExecutorConfig{}))
			if d.Verdict != domain.VerdictConfirmed || len(d.Confirmed) != 1 {
				t.Fatalf("detail = %+v", d)
			}
			if d.Confirmed[0].PayloadKind != shape.kind {
				t.Fatalf("confirmed payload kind = %q, want %q", d.Confirmed[0].PayloadKind, shape.kind)
			}
			if !strings.Contains(d.Confirmed[0].Target, openRedirectCanaryHost) {
				t.Fatalf("target = %q, want the canary host", d.Confirmed[0].Target)
			}
		})
	}
}

// runOpenRedirectDetail is runOpenRedirect without the test-case plumbing.
func runOpenRedirectDetail(t *testing.T, env *scanEnv, ep *domain.Endpoint) openRedirectDetail {
	t.Helper()
	return openRedirectDetailOf(t, runOpenRedirect(t, env, ep, ExecutorConfig{}))
}

func TestOpenRedirectMetaRefreshIsConfirmed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next := r.URL.Query().Get("next")
		w.Header().Set("Content-Type", "text/html")
		if strings.Contains(next, openRedirectCanaryHost) {
			fmt.Fprintf(w, `<html><head><meta http-equiv="refresh" content="0;url=%s"></head><body>bye</body></html>`, next)
			return
		}
		fmt.Fprint(w, "<html><body>home</body></html>")
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/leave?next=home", domain.MethodGET)
	env.param(ep, "next", domain.LocationQuery, "home")
	d := openRedirectDetailOf(t, runOpenRedirect(t, env, ep, ExecutorConfig{}))
	if d.Verdict != domain.VerdictConfirmed || d.Confirmed[0].Signal != "meta_refresh" {
		t.Fatalf("detail = %+v", d)
	}
	findings := scanFindings(t, env)
	if len(findings) != 1 || !strings.Contains(findings[0].Summary, "meta refresh") {
		t.Fatalf("findings = %+v", findings)
	}
}

func TestOpenRedirectScriptRedirectIsConfirmed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next := r.URL.Query().Get("next")
		w.Header().Set("Content-Type", "text/html")
		if strings.Contains(next, openRedirectCanaryHost) {
			fmt.Fprintf(w, `<html><body><script>location.replace(%q)</script></body></html>`, next)
			return
		}
		fmt.Fprint(w, "<html><body>home</body></html>")
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/leave?next=home", domain.MethodGET)
	env.param(ep, "next", domain.LocationQuery, "home")
	d := openRedirectDetailOf(t, runOpenRedirect(t, env, ep, ExecutorConfig{}))
	if d.Verdict != domain.VerdictConfirmed || d.Confirmed[0].Signal != "script_redirect" {
		t.Fatalf("detail = %+v", d)
	}
}

func TestOpenRedirectBaselineRedirectIsNotAttributedToTheParameter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Every request, including the unmodified baseline, redirects here.
		w.Header().Set("Location", openRedirectCanaryURL)
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/go?next=home", domain.MethodGET)
	env.param(ep, "next", domain.LocationQuery, "home")
	tc := runOpenRedirect(t, env, ep, ExecutorConfig{})
	d := openRedirectDetailOf(t, tc)
	if d.Verdict != domain.VerdictRejected {
		t.Fatalf("verdict = %q, want rejected (%s)", d.Verdict, d.Reason)
	}
	if len(d.Confirmed) != 0 {
		t.Fatalf("confirmed = %+v, want none", d.Confirmed)
	}
	if len(scanFindings(t, env)) != 0 {
		t.Fatal("a redirect already present in the baseline must not be attributed to the parameter")
	}
}

func TestOpenRedirectSkipsEndpointWithoutRedirectParameters(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/search?q=hello", domain.MethodGET)
	env.param(ep, "q", domain.LocationQuery, "hello")
	tc := runOpenRedirect(t, env, ep, ExecutorConfig{})
	if tc.Status != domain.TestCaseSkipped {
		t.Fatalf("status = %s, want skipped", tc.Status)
	}
	if requests.Load() != 0 {
		t.Fatalf("requests = %d, want 0 (nothing to test)", requests.Load())
	}
}

func TestOpenRedirectSkipsStateChangingEndpointWithoutOptIn(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Location", openRedirectCanaryURL)
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/login", domain.MethodPOST)
	env.param(ep, "next", domain.LocationForm, "home")
	tc := runOpenRedirect(t, env, ep, ExecutorConfig{})
	if tc.Status != domain.TestCaseSkipped || !strings.Contains(tc.Note, "state-changing") {
		t.Fatalf("test case = %s (%s), want skipped for a state-changing method", tc.Status, tc.Note)
	}
	if requests.Load() != 0 {
		t.Fatalf("requests = %d, want 0", requests.Load())
	}
}

func TestOpenRedirectThrottledBaselineSendsNoPayloads(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/go?next=home", domain.MethodGET)
	env.param(ep, "next", domain.LocationQuery, "home")
	tc := runOpenRedirect(t, env, ep, ExecutorConfig{})
	d := openRedirectDetailOf(t, tc)
	if !d.Throttled || len(d.Attempts) != 0 {
		t.Fatalf("detail = %+v, want throttled with no payload attempts", d)
	}
	if requests.Load() != 1 {
		t.Fatalf("requests = %d, want only the baseline", requests.Load())
	}
}

func TestOpenRedirectCorrelatesRepeatedRunsIntoOneFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next := r.URL.Query().Get("next")
		if strings.Contains(next, openRedirectCanaryHost) {
			w.Header().Set("Location", next)
			w.WriteHeader(http.StatusFound)
			return
		}
		fmt.Fprint(w, "home")
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/login?next=home", domain.MethodGET)
	env.param(ep, "next", domain.LocationQuery, "home")
	ex := newOpenRedirectExecutor(env.st, scopedClient(t, openScope()), env.ev, ExecutorConfig{}, execLog(), nil)
	for i := 0; i < 2; i++ {
		if err := ex.Handle(context.Background(), openRedirectJob(env, ep)); err != nil {
			t.Fatalf("handle %d: %v", i, err)
		}
	}
	findings := scanFindings(t, env)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want exactly 1", len(findings))
	}
	var fd openRedirectDetail
	if err := json.Unmarshal(findings[0].Detail, &fd); err != nil {
		t.Fatal(err)
	}
	if fd.Occurrences != 2 {
		t.Fatalf("occurrences = %d, want 2", fd.Occurrences)
	}
}

func TestOpenRedirectURLEndpointWithoutDiscoveryRow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next := r.URL.Query().Get("next")
		if strings.Contains(next, openRedirectCanaryHost) {
			w.Header().Set("Location", next)
			w.WriteHeader(http.StatusFound)
			return
		}
		fmt.Fprint(w, "home")
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ex := newOpenRedirectExecutor(env.st, scopedClient(t, openScope()), env.ev, ExecutorConfig{}, execLog(), nil)
	job := &domain.TestJob{
		ID: domain.NewID(), ScanID: env.scanID,
		Target: domain.JobTarget{URL: srv.URL + "/go?next=home"}, Attempts: 1, MaxAttempts: 2,
	}
	if err := ex.Handle(context.Background(), job); err != nil {
		t.Fatalf("handle: %v", err)
	}
	findings := scanFindings(t, env)
	if len(findings) != 1 || findings[0].Verdict != domain.VerdictConfirmed {
		t.Fatalf("findings = %+v, want one confirmed finding for a URL-only job", findings)
	}
}

func TestOpenRedirectURLEndpointOverridesOnlyTheCandidateParameter(t *testing.T) {
	var other atomic.Value
	other.Store("")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if strings.Contains(q.Get("next"), openRedirectCanaryHost) {
			other.Store(q.Get("q"))
			w.Header().Set("Location", q.Get("next"))
			w.WriteHeader(http.StatusFound)
			return
		}
		fmt.Fprint(w, "home")
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ex := newOpenRedirectExecutor(env.st, scopedClient(t, openScope()), env.ev, ExecutorConfig{}, execLog(), nil)
	job := &domain.TestJob{
		ID: domain.NewID(), ScanID: env.scanID,
		Target: domain.JobTarget{URL: srv.URL + "/go?next=home&q=hello"}, Attempts: 1, MaxAttempts: 2,
	}
	if err := ex.Handle(context.Background(), job); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(scanFindings(t, env)) != 1 {
		t.Fatal("want one confirmed finding")
	}
	if got, _ := other.Load().(string); got != "hello" {
		t.Fatalf("unrelated parameter q = %q, want it left at its observed value", got)
	}
}

func TestOpenRedirectStateChangingEndpointIsProbedWithOptIn(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		next := r.FormValue("next")
		if strings.Contains(next, openRedirectCanaryHost) {
			w.Header().Set("Location", next)
			w.WriteHeader(http.StatusFound)
			return
		}
		fmt.Fprint(w, "home")
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/login", domain.MethodPOST)
	env.param(ep, "next", domain.LocationForm, "home")
	tc := runOpenRedirect(t, env, ep, ExecutorConfig{AllowStateChanging: true})
	d := openRedirectDetailOf(t, tc)
	if d.Verdict != domain.VerdictConfirmed || len(d.Confirmed) != 1 {
		t.Fatalf("detail = %+v (%s)", d, tc.Note)
	}
	if d.Confirmed[0].Location != domain.LocationForm {
		t.Fatalf("confirmation location = %q, want form", d.Confirmed[0].Location)
	}
}
