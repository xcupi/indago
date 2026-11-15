package scan

// SSRF engine tests: applicability, canary safety, response-differential
// confirmation, OAST collaborator confirmation, evidence persistence and the
// policy guards (state-changing opt-in, non-URL parameters, forbidden hosts).
//
// Everything is hermetic: targets are httptest servers and the "collaborator"
// is a local poll endpoint a simulating target reports a hit to. No test
// reaches a real network, an instance-metadata endpoint or a private address.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
)

const ssrfJobKind domain.JobType = "ssrf"

const (
	// ssrfModeError: a canary makes the target report the resolver failure a
	// server-side HTTP client would produce.
	ssrfModeError = "error"
	// ssrfModeOnce: only the FIRST canary produces that failure.
	ssrfModeOnce = "once"
	// ssrfModeCollab: a canary makes the target report a collaborator hit.
	ssrfModeCollab = "collab"
)

// ssrfTarget is a vulnerable-looking endpoint: it takes the value it was given,
// "fetches" it, and describes the outcome.
type ssrfTarget struct {
	srv      *httptest.Server
	requests atomic.Int32

	mu      sync.Mutex
	seen    []string
	pollURL string
	mode    string
	once    bool
}

func newSSRFTarget(t *testing.T, mode string) *ssrfTarget {
	t.Helper()
	tg := &ssrfTarget{mode: mode}
	tg.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tg.requests.Add(1)
		value := ssrfTargetValue(r)
		canary := strings.Contains(value, "indago-ssrf-")

		tg.mu.Lock()
		tg.seen = append(tg.seen, value)
		pollURL, first := tg.pollURL, !tg.once
		if canary {
			tg.once = true
		}
		tg.mu.Unlock()

		if canary && mode == ssrfModeCollab && pollURL != "" {
			// The vulnerable server's own outbound request, simulated by
			// reporting the token to the collaborator.
			if resp, err := http.Get(pollURL + "?hit=" + ssrfTokenFromValue(value)); err == nil {
				resp.Body.Close()
			}
			fmt.Fprint(w, "fetched")
			return
		}
		if canary && mode == ssrfModeOnce && !first {
			fmt.Fprint(w, "fetched")
			return
		}
		switch {
		case canary && (mode == ssrfModeError || mode == ssrfModeOnce):
			fmt.Fprintf(w, "failed to load image: Get %q: dial tcp: lookup %s: no such host",
				value, ssrfHostFromValue(value))
		case strings.Contains(strings.ToLower(value), "already-broken"):
			fmt.Fprint(w, "upstream error: dial tcp: lookup upstream.example: no such host")
		default:
			fmt.Fprint(w, "image loaded")
		}
	}))
	t.Cleanup(tg.srv.Close)
	return tg
}

// setPollURL points the target at a collaborator. Called before the job runs.
func (tg *ssrfTarget) setPollURL(u string) {
	tg.mu.Lock()
	tg.pollURL = u
	tg.mu.Unlock()
}

func (tg *ssrfTarget) received() []string {
	tg.mu.Lock()
	defer tg.mu.Unlock()
	return append([]string(nil), tg.seen...)
}

// ssrfTargetValue extracts the tested value from wherever the engine put it:
// query string, form/JSON body or the header used by the header-location test.
func ssrfTargetValue(r *http.Request) string {
	if v := r.URL.Query().Get("url"); v != "" {
		return v
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if len(body) > 0 {
		var asJSON map[string]any
		if json.Unmarshal(body, &asJSON) == nil {
			if s, ok := asJSON["url"].(string); ok {
				return s
			}
		}
		if v := parseFormValue(string(body), "url"); v != "" {
			return v
		}
	}
	if v := r.FormValue("url"); v != "" {
		return v
	}
	return r.Header.Get("X-Callback-Url")
}

func parseFormValue(body, key string) string {
	for _, pair := range strings.Split(body, "&") {
		name, value, ok := strings.Cut(pair, "=")
		if !ok || name != key {
			continue
		}
		if unescaped, err := url.QueryUnescape(value); err == nil {
			return unescaped
		}
		return value
	}
	return ""
}

func ssrfTokenFromValue(value string) string {
	for _, part := range strings.FieldsFunc(value, func(r rune) bool {
		return !(r == '-' || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'))
	}) {
		if strings.HasPrefix(part, "indago-ssrf-") {
			return part
		}
	}
	return value
}

func ssrfHostFromValue(value string) string {
	rest := value
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
	}
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}
	return rest
}

type ssrfRun struct {
	env      *scanEnv
	tc       *domain.TestCase
	findings []*domain.Finding
}

// ssrfExercise runs one SSRF job against tg for the given parameter.
func ssrfExercise(t *testing.T, tg *ssrfTarget, name string, loc domain.ParamLocation, method domain.HTTPMethod, example string, cfg ExecutorConfig, tune func(*ssrfExecutor)) ssrfRun {
	t.Helper()
	env := newScanEnv(t)
	ep := env.endpoint(tg.srv.URL+"/preview", method)
	focus := env.param(ep, name, loc, example)
	ip := env.injection(ep, focus)
	ex := newSSRFExecutor(env.st, scopedClient(t, openScope()), env.ev, cfg, execLog(), nil)
	ex.pollAttempts, ex.pollInterval = 5, 5*time.Millisecond
	if tune != nil {
		tune(ex)
	}
	job := &domain.TestJob{ID: domain.NewID(), ScanID: env.scanID, Type: ssrfJobKind,
		Target: domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID, URL: ep.URL}, Attempts: 1, MaxAttempts: 2}
	if err := ex.Handle(context.Background(), job); err != nil {
		t.Fatalf("handle: %v", err)
	}
	cases, err := env.st.TestCases().ListByScan(context.Background(), env.scanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) != 1 {
		t.Fatalf("test cases = %d, want 1", len(cases))
	}
	findings, err := env.st.Findings().ListByScan(context.Background(), env.scanID)
	if err != nil {
		t.Fatal(err)
	}
	return ssrfRun{env: env, tc: cases[0], findings: findings}
}

func ssrfDetailOf(t *testing.T, tc *domain.TestCase) ssrfDetail {
	t.Helper()
	var d ssrfDetail
	if err := json.Unmarshal(tc.Detail, &d); err != nil {
		t.Fatalf("decode detail: %v (raw %s)", err, string(tc.Detail))
	}
	return d
}

// --- applicability -------------------------------------------------------

func TestSSRFURLParameterNames(t *testing.T) {
	for _, name := range []string{
		"url", "URL", "uri", "redirect_uri", "callbackUrl", "callback_url",
		"webhook", "webhook_url", "feed", "rss", "proxy", "avatar_url",
		"image", "imageUrl", "targeturl", "next", "return_to", "dest",
		"host", "endpoint", "fetch", "remote_url", "src", "og:image",
	} {
		if !ssrfURLParamName(name) {
			t.Errorf("ssrfURLParamName(%q) = false, want true", name)
		}
	}
	for _, name := range []string{"page", "security", "username", "password", "q", "id", "csrf_token", "sort"} {
		if ssrfURLParamName(name) {
			t.Errorf("ssrfURLParamName(%q) = true, want false", name)
		}
	}
}

func TestSSRFURLLikeValueIsEnough(t *testing.T) {
	if !ssrfCandidateParameter(&domain.Parameter{Name: "q", Example: "https://example.com/a.png"}) {
		t.Fatal("a parameter whose observed value is an absolute URL must be eligible")
	}
	if !ssrfCandidateParameter(&domain.Parameter{Name: "langid", Examples: []string{"en", "https://cdn.example/x"}}) {
		t.Fatal("a URL among the observed examples must be eligible")
	}
	if ssrfCandidateParameter(&domain.Parameter{Name: "page", Example: "2"}) {
		t.Fatal("a plain numeric parameter must not be eligible")
	}
}

func TestSSRFSkipsNonURLParameter(t *testing.T) {
	tg := newSSRFTarget(t, ssrfModeError)
	run := ssrfExercise(t, tg, "page", domain.LocationQuery, domain.MethodGET, "2", ExecutorConfig{}, nil)
	if got := tg.requests.Load(); got != 0 {
		t.Fatalf("target received %d requests for a non-URL parameter, want 0", got)
	}
	if run.tc.Status != domain.TestCaseSkipped {
		t.Fatalf("status = %q, want skipped", run.tc.Status)
	}
	if !strings.Contains(run.tc.Note, "not URL-like") {
		t.Fatalf("note = %q, want a not-URL-like reason", run.tc.Note)
	}
}

func TestSSRFSkipsStateChangingEndpointWithoutOptIn(t *testing.T) {
	tg := newSSRFTarget(t, ssrfModeError)
	run := ssrfExercise(t, tg, "url", domain.LocationForm, domain.MethodPOST, "https://example.com/a.png", ExecutorConfig{}, nil)
	if got := tg.requests.Load(); got != 0 {
		t.Fatalf("POST endpoint received %d requests without the opt-in, want 0", got)
	}
	if run.tc.Status != domain.TestCaseSkipped {
		t.Fatalf("status = %q, want skipped", run.tc.Status)
	}
}

func TestSSRFSkipsStructuralHeader(t *testing.T) {
	tg := newSSRFTarget(t, ssrfModeError)
	run := ssrfExercise(t, tg, "Host", domain.LocationHeader, domain.MethodGET, "https://example.com/", ExecutorConfig{}, nil)
	if got := tg.requests.Load(); got != 0 {
		t.Fatalf("target received %d requests, want 0 for a structural header", got)
	}
	if run.tc.Status != domain.TestCaseSkipped {
		t.Fatalf("status = %q, want skipped", run.tc.Status)
	}
}

// --- canary safety -------------------------------------------------------

func TestSSRFCanaryTargetsAreSafe(t *testing.T) {
	c, err := ssrfDifferentialCanary()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(ssrfHostFromValue(c.URL), ".invalid") {
		t.Fatalf("canary = %q, want an RFC 2606 .invalid host", c.URL)
	}
	if !strings.Contains(c.URL, c.Token) {
		t.Fatalf("canary %q does not carry its token %q", c.URL, c.Token)
	}
	other, err := ssrfDifferentialCanary()
	if err != nil {
		t.Fatal(err)
	}
	if other.Token == c.Token {
		t.Fatal("two canaries share a correlation token")
	}
}

func TestSSRFForbiddenCanaryHosts(t *testing.T) {
	forbidden := []string{
		"169.254.169.254", // AWS/GCP/Azure/Oracle instance metadata
		"metadata.google.internal",
		"metadata",
		"127.0.0.1",
		"127.1.2.3",
		"::1",
		"[::1]",
		"0.0.0.0",
		"10.0.0.5",
		"172.16.4.9",
		"192.168.1.10",
		"100.100.100.200", // Alibaba metadata (CGNAT range)
		"fc00::1",
		"fe80::1",
		"localhost",
		"localhost.localdomain",
		"printer.local",
		"collab.internal",
		"anything.localhost",
	}
	for _, host := range forbidden {
		if reason, bad := ssrfForbiddenCanaryHost(host); !bad {
			t.Errorf("ssrfForbiddenCanaryHost(%q) allowed it, want refused (%s)", host, reason)
		}
	}
	for _, host := range []string{"oast.example.com", "8.8.8.8", "203.0.113.10", "collab.oast.pro"} {
		if reason, bad := ssrfForbiddenCanaryHost(host); bad {
			t.Errorf("ssrfForbiddenCanaryHost(%q) refused it (%s), want allowed", host, reason)
		}
	}
}

func TestSSRFOASTCanaryRefusesInternalCallback(t *testing.T) {
	for _, raw := range []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://metadata.google.internal/computeMetadata/v1/",
		"http://127.0.0.1:8080/cb",
		"http://[::1]/cb",
		"http://10.1.2.3/cb",
		"http://192.168.0.5/cb",
		"http://localhost/cb",
		"ftp://oast.example.com/cb",
		"",
	} {
		if _, err := ssrfOASTCanary(raw); err == nil {
			t.Errorf("ssrfOASTCanary(%q) returned a canary, want a refusal", raw)
		}
	}
	c, err := ssrfOASTCanary("https://oast.example.com/hook/abc?x=1#frag")
	if err != nil {
		t.Fatalf("public collaborator refused: %v", err)
	}
	if !strings.HasPrefix(c.URL, "https://oast.example.com/hook/abc/"+c.Token) {
		t.Fatalf("canary = %q, want collaborator path + token", c.URL)
	}
	if strings.Contains(c.URL, "?x=1") || strings.Contains(c.URL, "#frag") {
		t.Fatalf("canary = %q, want the operator's query/fragment stripped", c.URL)
	}
}

// TestSSRFNeverSendsForbiddenTargets is the core safety assertion: even with a
// callback misconfigured to an instance-metadata address, nothing the target
// receives names a metadata host, loopback or a private range.
func TestSSRFNeverSendsForbiddenTargets(t *testing.T) {
	tg := newSSRFTarget(t, ssrfModeError)
	run := ssrfExercise(t, tg, "url", domain.LocationQuery, domain.MethodGET, "https://example.com/a.png",
		ExecutorConfig{}, func(e *ssrfExecutor) {
			e.withCallback("http://169.254.169.254/latest/meta-data/", tg.srv.URL+"/poll")
		})

	d := ssrfDetailOf(t, run.tc)
	if d.CallbackNote == "" {
		t.Fatal("a metadata callback must be recorded as refused, not used silently")
	}
	if d.CallbackMode == ssrfConfirmOAST {
		t.Fatal("engine stayed in OAST mode with a forbidden callback")
	}
	seen := tg.received()
	if len(seen) == 0 {
		t.Fatal("no canary was sent at all")
	}
	for _, value := range seen {
		lower := strings.ToLower(value)
		for _, banned := range []string{"169.254.169.254", "metadata", "127.0.0.1", "localhost", "10.0.0", "192.168.", "172.16.", "100.100.100.200"} {
			if strings.Contains(lower, banned) {
				t.Fatalf("target received forbidden canary %q (contains %q)", value, banned)
			}
		}
	}
	if d.Verdict != domain.VerdictConfirmed || d.ConfirmMethod != ssrfConfirmDifferential {
		t.Fatalf("detail = %+v, want the safe differential to still confirm", d)
	}
}

func TestSSRFPollURLRefusesMetadata(t *testing.T) {
	for _, raw := range []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://metadata.google.internal/computeMetadata/v1/",
		"http://[fe80::1]/poll",
		"http://0.0.0.0/poll",
		"",
		"not a url at all",
		"ftp://oast.example.com/poll",
	} {
		if _, err := ssrfPollURL(raw); err == nil {
			t.Errorf("ssrfPollURL(%q) accepted it, want refused", raw)
		}
	}
	// A local/lab collaborator is the operator's own endpoint and stays usable.
	for _, raw := range []string{"http://127.0.0.1:9000/poll", "https://oast.example.com/api/requests", "http://192.168.1.9/poll"} {
		if _, err := ssrfPollURL(raw); err != nil {
			t.Errorf("ssrfPollURL(%q) refused a usable collaborator: %v", raw, err)
		}
	}
}

// TestSSRFRefusesMetadataReadCollaborator covers the scanner's own side of the
// safety rule: a collaborator poll endpoint pointed at instance metadata is
// refused, so this engine never reads one itself.
func TestSSRFRefusesMetadataReadCollaborator(t *testing.T) {
	tg := newSSRFTarget(t, ssrfModeError)
	run := ssrfExercise(t, tg, "url", domain.LocationQuery, domain.MethodGET, "https://example.com/a.png",
		ExecutorConfig{}, func(e *ssrfExecutor) {
			e.withCallback("https://oast.example.com/hook", "http://169.254.169.254/latest/meta-data/")
		})

	d := ssrfDetailOf(t, run.tc)
	if d.CallbackNote == "" {
		t.Fatal("a metadata poll endpoint must be recorded as refused")
	}
	if d.CallbackMode != ssrfModeDifferential {
		t.Fatalf("callback_mode = %q, want differential", d.CallbackMode)
	}
	if d.Verdict != domain.VerdictConfirmed || d.ConfirmMethod != ssrfConfirmDifferential {
		t.Fatalf("detail = %+v, want the safe differential to still confirm", d)
	}
	if got := tg.requests.Load(); got != 1+maxSSRFDifferentialProbes {
		t.Fatalf("target received %d requests, want baseline + differentials only", got)
	}
}

// --- response differential ----------------------------------------------

func TestSSRFDifferentialConfirmsTwoIndependentCanaries(t *testing.T) {
	tg := newSSRFTarget(t, ssrfModeError)
	run := ssrfExercise(t, tg, "url", domain.LocationQuery, domain.MethodGET, "https://example.com/a.png", ExecutorConfig{}, nil)

	d := ssrfDetailOf(t, run.tc)
	if d.Verdict != domain.VerdictConfirmed || d.ConfirmMethod != ssrfConfirmDifferential {
		t.Fatalf("detail = %+v, want confirmed via %s", d, ssrfConfirmDifferential)
	}
	if d.ConfirmedCount < maxSSRFDifferentialProbes {
		t.Fatalf("confirmed_count = %d, want >= %d", d.ConfirmedCount, maxSSRFDifferentialProbes)
	}
	if d.AttributedCount == 0 {
		t.Fatal("no attempt was attributed to its canary token")
	}
	if d.CallbackMode != ssrfModeDifferential {
		t.Fatalf("callback_mode = %q, want differential with no collaborator configured", d.CallbackMode)
	}
	tokens := map[string]bool{}
	for _, a := range d.Attempts {
		if a.Indicator == "" || !a.Attributed {
			t.Fatalf("attempt %+v is not attributed to its canary", a)
		}
		if tokens[a.Token] {
			t.Fatalf("token %q was reused across attempts", a.Token)
		}
		tokens[a.Token] = true
	}
	if len(tokens) != maxSSRFDifferentialProbes {
		t.Fatalf("distinct tokens = %d, want %d", len(tokens), maxSSRFDifferentialProbes)
	}

	if len(run.findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(run.findings))
	}
	f := run.findings[0]
	if f.VulnClass != ssrfVulnClass || f.Verdict != domain.VerdictConfirmed {
		t.Fatalf("finding = %+v, want a confirmed ssrf finding", f)
	}
	if f.Confidence != domain.ConfidenceMedium {
		t.Fatalf("confidence = %q, want medium for a response-differential confirmation", f.Confidence)
	}
	if !strings.Contains(f.Title, "url") {
		t.Fatalf("title = %q, want the parameter name", f.Title)
	}
	if len(f.EvidenceIDs) < 4 {
		t.Fatalf("evidence ids = %d, want baseline + two canaries (request+response each)", len(f.EvidenceIDs))
	}

	seen := tg.received()
	if len(seen) != 1+maxSSRFDifferentialProbes {
		t.Fatalf("target saw %d values (%v), want baseline + %d canaries", len(seen), seen, maxSSRFDifferentialProbes)
	}
	if !strings.Contains(seen[0], "example.com") {
		t.Fatalf("first request = %q, want the untouched baseline", seen[0])
	}
}

func TestSSRFSingleIndicatorIsInconclusive(t *testing.T) {
	tg := newSSRFTarget(t, ssrfModeOnce)
	run := ssrfExercise(t, tg, "url", domain.LocationQuery, domain.MethodGET, "https://example.com/a.png", ExecutorConfig{}, nil)

	d := ssrfDetailOf(t, run.tc)
	if d.Verdict != domain.VerdictInconclusive {
		t.Fatalf("verdict = %q, want inconclusive (%s)", d.Verdict, d.Reason)
	}
	if d.ConfirmedCount != 1 {
		t.Fatalf("confirmed_count = %d, want 1", d.ConfirmedCount)
	}
	if len(run.findings) != 0 {
		t.Fatalf("findings = %d, want none for an inconclusive result", len(run.findings))
	}
}

// TestSSRFBaselineIndicatorBlocksDifferential makes sure an application that
// always reports a fetch failure cannot be "confirmed" by that banner: no
// canary is attributed to us, and no differential probe is spent.
func TestSSRFBaselineIndicatorBlocksDifferential(t *testing.T) {
	tg := newSSRFTarget(t, ssrfModeError)
	run := ssrfExercise(t, tg, "url", domain.LocationQuery, domain.MethodGET, "https://example.com/already-broken", ExecutorConfig{}, nil)

	d := ssrfDetailOf(t, run.tc)
	if d.BaselineFailure == "" {
		t.Fatal("baseline failure indicator was not recorded")
	}
	if d.SentCount != 0 {
		t.Fatalf("sent %d canaries although the baseline already failed, want 0", d.SentCount)
	}
	if d.Verdict != domain.VerdictInconclusive {
		t.Fatalf("verdict = %q, want inconclusive", d.Verdict)
	}
	if got := tg.requests.Load(); got != 1 {
		t.Fatalf("target received %d requests, want only the baseline", got)
	}
	if len(run.findings) != 0 {
		t.Fatalf("findings = %d, want none", len(run.findings))
	}
}

func TestSSRFReflectedCanaryIsNotAFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "<img src=%q>", r.URL.Query().Get("url"))
	}))
	defer srv.Close()
	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/preview", domain.MethodGET)
	focus := env.param(ep, "url", domain.LocationQuery, "https://example.com/a.png")
	ip := env.injection(ep, focus)
	ex := newSSRFExecutor(env.st, scopedClient(t, openScope()), env.ev, ExecutorConfig{}, execLog(), nil)
	job := &domain.TestJob{ID: domain.NewID(), ScanID: env.scanID, Type: ssrfJobKind,
		Target: domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID, URL: ep.URL}, Attempts: 1, MaxAttempts: 2}
	if err := ex.Handle(context.Background(), job); err != nil {
		t.Fatalf("handle: %v", err)
	}
	findings, err := env.st.Findings().ListByScan(context.Background(), env.scanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("findings = %+v, want none for a reflected canary", findings)
	}
	cases, _ := env.st.TestCases().ListByScan(context.Background(), env.scanID)
	if d := ssrfDetailOf(t, cases[0]); d.Verdict != domain.VerdictRejected {
		t.Fatalf("verdict = %q, want rejected", d.Verdict)
	}
}

// --- OAST collaborator ---------------------------------------------------

// ssrfCollaborator is a minimal collaborator API: it records the tokens targets
// reported and returns them as received requests.
func ssrfCollaborator(t *testing.T) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	var hits []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if tok := r.URL.Query().Get("hit"); tok != "" {
			hits = append(hits, tok)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"requests": hits})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestSSRFOASTConfirmsCollaboratorHit(t *testing.T) {
	collab := ssrfCollaborator(t)
	tg := newSSRFTarget(t, ssrfModeCollab)
	tg.setPollURL(collab.URL)
	run := ssrfExercise(t, tg, "url", domain.LocationQuery, domain.MethodGET, "https://example.com/a.png",
		ExecutorConfig{}, func(e *ssrfExecutor) {
			e.withCallback("https://oast.example.com/hook", collab.URL)
		})

	d := ssrfDetailOf(t, run.tc)
	if d.Verdict != domain.VerdictConfirmed || d.ConfirmMethod != ssrfConfirmOAST {
		t.Fatalf("detail = %+v, want confirmed via oast", d)
	}
	if len(d.Attempts) != 1 || !d.Attempts[0].Callback {
		t.Fatalf("attempts = %+v, want exactly one callback-confirmed attempt", d.Attempts)
	}
	if d.Attempts[0].Kind != ssrfConfirmOAST {
		t.Fatalf("attempt kind = %q, want oast", d.Attempts[0].Kind)
	}

	if len(run.findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(run.findings))
	}
	if got := run.findings[0].Confidence; got != domain.ConfidenceHigh {
		t.Fatalf("confidence = %q, want high for an out-of-band confirmation", got)
	}
	// The differential pass is not spent once OAST confirmed.
	if got := tg.requests.Load(); got != 2 {
		t.Fatalf("target received %d requests, want baseline + one canary", got)
	}
}

func TestSSRFOASTMissFallsBackToDifferential(t *testing.T) {
	collab := ssrfCollaborator(t) // never receives a hit
	tg := newSSRFTarget(t, ssrfModeError)
	tg.setPollURL(collab.URL)
	run := ssrfExercise(t, tg, "url", domain.LocationQuery, domain.MethodGET, "https://example.com/a.png",
		ExecutorConfig{}, func(e *ssrfExecutor) {
			e.withCallback("https://oast.example.com/hook", collab.URL)
		})

	d := ssrfDetailOf(t, run.tc)
	if d.CallbackMode != ssrfConfirmOAST {
		t.Fatalf("callback_mode = %q, want oast", d.CallbackMode)
	}
	if d.ConfirmMethod != ssrfConfirmDifferential {
		t.Fatalf("confirm_method = %q, want the differential fallback (%s)", d.ConfirmMethod, d.Reason)
	}
	if len(d.Attempts) != 1+maxSSRFDifferentialProbes {
		t.Fatalf("attempts = %d, want %d", len(d.Attempts), 1+maxSSRFDifferentialProbes)
	}
	if d.Attempts[0].Kind != ssrfConfirmOAST || d.Attempts[0].Callback {
		t.Fatalf("first attempt = %+v, want an unconfirmed oast probe", d.Attempts[0])
	}
}

// --- other parameter locations ------------------------------------------

func TestSSRFHeaderParameter(t *testing.T) {
	var sawHeader atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if value := r.Header.Get("X-Callback-Url"); strings.Contains(value, "indago-ssrf-") {
			sawHeader.Store(true)
			fmt.Fprintf(w, "callback failed: Get %q: dial tcp: lookup %s: no such host",
				value, ssrfHostFromValue(value))
			return
		}
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/hook", domain.MethodGET)
	focus := env.param(ep, "X-Callback-Url", domain.LocationHeader, "https://example.com/cb")
	ip := env.injection(ep, focus)
	ex := newSSRFExecutor(env.st, scopedClient(t, openScope()), env.ev, ExecutorConfig{}, execLog(), nil)
	job := &domain.TestJob{ID: domain.NewID(), ScanID: env.scanID, Type: ssrfJobKind,
		Target: domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID, URL: ep.URL}, Attempts: 1, MaxAttempts: 2}
	if err := ex.Handle(context.Background(), job); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if !sawHeader.Load() {
		t.Fatal("the injected header never carried a canary")
	}
	cases, _ := env.st.TestCases().ListByScan(context.Background(), env.scanID)
	if d := ssrfDetailOf(t, cases[0]); d.Verdict != domain.VerdictConfirmed {
		t.Fatalf("verdict = %q (%s), want confirmed", d.Verdict, d.Reason)
	}
}

func TestSSRFJSONBodyParameter(t *testing.T) {
	var canaries atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		var asJSON map[string]any
		_ = json.Unmarshal(body, &asJSON)
		value, _ := asJSON["url"].(string)
		if strings.Contains(value, "indago-ssrf-") {
			canaries.Add(1)
			fmt.Fprintf(w, `{"error":"fetch %s: dial tcp: lookup %s: no such host"}`, value, ssrfHostFromValue(value))
			return
		}
		fmt.Fprint(w, `{"ok":true}`)
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/api/preview", domain.MethodPOST)
	focus := env.param(ep, "url", domain.LocationJSON, "https://example.com/a.png")
	ip := env.injection(ep, focus)
	ex := newSSRFExecutor(env.st, scopedClient(t, openScope()), env.ev,
		ExecutorConfig{AllowStateChanging: true}, execLog(), nil)
	job := &domain.TestJob{ID: domain.NewID(), ScanID: env.scanID, Type: ssrfJobKind,
		Target: domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID, URL: ep.URL}, Attempts: 1, MaxAttempts: 2}
	if err := ex.Handle(context.Background(), job); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if got := canaries.Load(); got != maxSSRFDifferentialProbes {
		t.Fatalf("JSON body carried %d canaries, want %d", got, maxSSRFDifferentialProbes)
	}
	cases, _ := env.st.TestCases().ListByScan(context.Background(), env.scanID)
	if d := ssrfDetailOf(t, cases[0]); d.Verdict != domain.VerdictConfirmed {
		t.Fatalf("verdict = %q (%s), want confirmed", d.Verdict, d.Reason)
	}
}

// --- misc ----------------------------------------------------------------

func TestSSRFIndicatorMatching(t *testing.T) {
	cases := map[string]string{
		"failed: dial tcp: lookup x.invalid: no such host": "no such host",
		"php_network_getaddresses: getaddrinfo failed":     "getaddrinfo",
		"cURL error 6: Could not resolve host: x.invalid":  "could not resolve host",
		"getaddrinfo ENOTFOUND x.invalid":                  "getaddrinfo",
		"Name or service not known":                        "name or service not known",
		"image loaded":                                     "",
	}
	for body, want := range cases {
		if got := ssrfFetchFailureIndicator(body); got != want {
			t.Errorf("ssrfFetchFailureIndicator(%q) = %q, want %q", body, got, want)
		}
	}
	if got := ssrfURLParsingIndicator(`{"error":"invalid url: http://x.invalid/"}`); got != "invalid url" {
		t.Errorf("ssrfURLParsingIndicator = %q, want invalid url", got)
	}
}

func TestSSRFCancelledContextSurfacesCancellation(t *testing.T) {
	tg := newSSRFTarget(t, ssrfModeError)
	env := newScanEnv(t)
	ep := env.endpoint(tg.srv.URL+"/preview", domain.MethodGET)
	focus := env.param(ep, "url", domain.LocationQuery, "https://example.com/a.png")
	ip := env.injection(ep, focus)
	ex := newSSRFExecutor(env.st, scopedClient(t, openScope()), env.ev, ExecutorConfig{}, execLog(), nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	job := &domain.TestJob{ID: domain.NewID(), ScanID: env.scanID, Type: ssrfJobKind,
		Target: domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID, URL: ep.URL}, Attempts: 1, MaxAttempts: 1}
	if err := ex.Handle(ctx, job); err == nil {
		t.Fatal("a cancelled scan must surface the cancellation to the queue")
	}
	cases, _ := env.st.TestCases().ListByScan(context.Background(), env.scanID)
	if len(cases) != 1 || cases[0].Status != domain.TestCaseFailed {
		t.Fatalf("cases = %+v, want one failed case", cases)
	}
	if cases[0].Outcome != domain.OutcomeCancelled {
		t.Fatalf("outcome = %q, want cancelled", cases[0].Outcome)
	}
}
