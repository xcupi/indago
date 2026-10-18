package scan

// PoC generation tests: one per carrier location (query/path/header/cookie/
// form/combined) plus the refuse-if-not-Confirmed guard (AGENTS.md evidence
// integrity — see poc.go). Findings are driven through the REAL
// enqueueVerification -> verifyExecutor.Handle -> correlateVerification path
// (fakeVerifier substitutes only the browser signal) so GeneratePoC is
// exercised against the exact Detail shape a live scan would produce, not a
// hand-built shortcut.

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/discovery"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/verification"
)

// confirmOne drives a single candidate to Confirmed through the real
// enqueueVerification -> verifyExecutor path and returns the resulting
// Finding ID.
func confirmOne(t *testing.T, env *scanEnv, ep *domain.Endpoint, ip *domain.InjectionPoint, cand detection.Candidate) domain.ID {
	t.Helper()
	q := queue.NewMemory()
	ex := env.executorQ(scopedClient(t, openScope()), q, ExecutorConfig{AllowStateChanging: true})
	target := domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID}
	job := env.candJob(target, cand)
	// enqueueVerification requires the marker; build it exactly like a real
	// candidate step would.
	ex.enqueueVerification(context.Background(), job, ep, cand, ipFocus(t, env, ip), domain.NewID())
	fs := env.findings()
	if len(fs) != 1 {
		t.Fatalf("expected exactly one pending finding, got %d", len(fs))
	}
	f := fs[0]

	fv := &fakeVerifier{result: confirmedResult(verification.SignalPageError)}
	vx := env.verifyExec(fv, openScope(), ExecutorConfig{AllowStateChanging: true})
	vjob := env.verifyJobFor(target, cand, f.ID)
	if err := vx.Handle(context.Background(), vjob); err != nil {
		t.Fatalf("verify handle: %v", err)
	}
	got, err := env.st.Findings().Get(context.Background(), f.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Verdict != domain.VerdictConfirmed {
		t.Fatalf("finding verdict = %s, want confirmed", got.Verdict)
	}
	return f.ID
}

// ipFocus resolves the injection point's own parameter — enqueueVerification
// needs the *domain.Parameter, not just the InjectionPoint.
func ipFocus(t *testing.T, env *scanEnv, ip *domain.InjectionPoint) *domain.Parameter {
	t.Helper()
	p, err := env.st.Parameters().Get(context.Background(), ip.ParameterID)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func echoServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		b, _ := io.ReadAll(r.Body)
		_, _ = io.WriteString(w, "<p>"+r.URL.Query().Get("q")+string(b)+"</p>")
	}))
	t.Cleanup(srv.Close)
	return srv
}

// --- refuse-if-not-confirmed guard ---

func TestGeneratePoCRefusesPending(t *testing.T) {
	srv := echoServer(t)
	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/s", domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "hi")
	ip := env.injection(ep, focus)
	f := env.pendingFinding(ep, ip)

	_, err := GeneratePoC(context.Background(), env.st, f.ID)
	if !errors.Is(err, ErrPoCNotConfirmed) {
		t.Fatalf("GeneratePoC on a Pending finding = %v, want ErrPoCNotConfirmed", err)
	}
}

func TestGeneratePoCRefusesRejected(t *testing.T) {
	srv := echoServer(t)
	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/s", domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "hi")
	ip := env.injection(ep, focus)
	f := env.pendingFinding(ep, ip)

	fv := &fakeVerifier{result: rejectedResult()}
	vx := env.verifyExec(fv, openScope(), ExecutorConfig{})
	job := env.verifyJobFor(domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID}, basicCandidate(), f.ID)
	if err := vx.Handle(context.Background(), job); err != nil {
		t.Fatal(err)
	}

	_, err := GeneratePoC(context.Background(), env.st, f.ID)
	if !errors.Is(err, ErrPoCNotConfirmed) {
		t.Fatalf("GeneratePoC on a Rejected finding = %v, want ErrPoCNotConfirmed", err)
	}
}

func TestGeneratePoCRefusesInconclusive(t *testing.T) {
	srv := echoServer(t)
	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/s", domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "hi")
	ip := env.injection(ep, focus)
	f := env.pendingFinding(ep, ip)

	fv := &fakeVerifier{result: inconclusiveResult()}
	vx := env.verifyExec(fv, openScope(), ExecutorConfig{})
	job := env.verifyJobFor(domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID}, basicCandidate(), f.ID)
	if err := vx.Handle(context.Background(), job); err != nil {
		t.Fatal(err)
	}

	_, err := GeneratePoC(context.Background(), env.st, f.ID)
	if !errors.Is(err, ErrPoCNotConfirmed) {
		t.Fatalf("GeneratePoC on an Inconclusive finding = %v, want ErrPoCNotConfirmed", err)
	}
}

// --- one-click locations: Query, Path, Form(POST) ---

func TestGeneratePoCQueryIsOneClickLink(t *testing.T) {
	srv := echoServer(t)
	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/s", domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "hi")
	ip := env.injection(ep, focus)
	m := marker(env.scanID, ip.ID)
	cand := detection.Candidate{Source: detection.SourceBuiltin, Category: detection.CatHTMLText, Context: detection.CtxHTMLText,
		Parameter: "q", Location: domain.LocationQuery, Value: "<svg onload=" + m + ">", DedupKey: "k", Priority: 90}

	fid := confirmOne(t, env, ep, ip, cand)
	poc, err := GeneratePoC(context.Background(), env.st, fid)
	if err != nil {
		t.Fatal(err)
	}
	if !poc.OneClick {
		t.Fatal("a Query-location finding must be a one-click PoC")
	}
	if !strings.Contains(poc.URL, "q=") || !strings.Contains(poc.URL, m) {
		t.Fatalf("poc.URL = %q, want it to carry the marker in q=", poc.URL)
	}
	html := string(poc.HTML)
	if !strings.Contains(html, `http-equiv="refresh"`) {
		t.Fatal("a one-click GET PoC must auto-navigate via a meta refresh")
	}
	if !strings.Contains(html, m) {
		t.Fatal("the generated HTML must carry the marker (as part of the URL)")
	}
	if !strings.Contains(html, "curl") {
		t.Fatal("the generated HTML must also include a curl command")
	}
}

func TestGeneratePoCPathIsOneClickLink(t *testing.T) {
	srv := echoServer(t)
	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/items/42/view", domain.MethodGET)
	focus := env.param(ep, discovery.PathSegmentParamName(1), domain.LocationPath, "42")
	ip := env.injection(ep, focus)
	m := marker(env.scanID, ip.ID)
	cand := detection.Candidate{Source: detection.SourceBuiltin, Category: detection.CatHTMLText, Context: detection.CtxHTMLText,
		Parameter: focus.Name, Location: domain.LocationPath, Value: m, DedupKey: "k", Priority: 90}

	fid := confirmOne(t, env, ep, ip, cand)
	poc, err := GeneratePoC(context.Background(), env.st, fid)
	if err != nil {
		t.Fatal(err)
	}
	if !poc.OneClick {
		t.Fatal("a Path-location finding must be a one-click PoC")
	}
	if !strings.Contains(poc.URL, "/items/"+m+"/view") {
		t.Fatalf("poc.URL = %q, want the rewritten path segment", poc.URL)
	}
}

func TestGeneratePoCFormPostIsOneClickAutoSubmit(t *testing.T) {
	srv := echoServer(t)
	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/submit", domain.MethodPOST)
	focus := env.param(ep, "q", domain.LocationForm, "hi")
	ip := env.injection(ep, focus)
	m := marker(env.scanID, ip.ID)
	cand := detection.Candidate{Source: detection.SourceBuiltin, Category: detection.CatHTMLText, Context: detection.CtxHTMLText,
		Parameter: "q", Location: domain.LocationForm, Value: "<svg onload=" + m + ">", DedupKey: "k", Priority: 90}

	fid := confirmOne(t, env, ep, ip, cand)
	poc, err := GeneratePoC(context.Background(), env.st, fid)
	if err != nil {
		t.Fatal(err)
	}
	if !poc.OneClick {
		t.Fatal("a POST+form-location finding must be a one-click PoC")
	}
	html := string(poc.HTML)
	if !strings.Contains(html, `id="indago-poc-form"`) || !strings.Contains(html, `method="post"`) {
		t.Fatal("expected an auto-submitting POST form, mirroring browser.Page.NavigateForm")
	}
	if !strings.Contains(html, "onload=\"document.getElementById('indago-poc-form').submit()\"") {
		t.Fatal("expected the form to auto-submit on load")
	}
	if !strings.Contains(html, m) {
		t.Fatal("the generated form must carry the marker as a hidden input value")
	}
}

// --- not-one-click locations: Header, Cookie ---

func TestGeneratePoCHeaderIsNotOneClickButHasCurl(t *testing.T) {
	srv := echoServer(t)
	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/s", domain.MethodGET)
	focus := env.param(ep, "X-Forwarded-For", domain.LocationHeader, "")
	ip := env.injection(ep, focus)
	m := marker(env.scanID, ip.ID)
	cand := detection.Candidate{Source: detection.SourceBuiltin, Category: detection.CatHTMLText, Context: detection.CtxHTMLText,
		Parameter: "X-Forwarded-For", Location: domain.LocationHeader, Value: "<svg onload=" + m + ">", DedupKey: "k", Priority: 90}

	fid := confirmOne(t, env, ep, ip, cand)
	poc, err := GeneratePoC(context.Background(), env.st, fid)
	if err != nil {
		t.Fatal(err)
	}
	if poc.OneClick {
		t.Fatal("a Header-location override cannot be a one-click PoC (no plain navigation can set it)")
	}
	html := string(poc.HTML)
	if strings.Contains(html, `http-equiv="refresh"`) {
		t.Fatal("a non-one-click PoC must never auto-navigate — that would silently fail to reproduce the header override")
	}
	if !strings.Contains(html, "No one-click PoC is possible") {
		t.Fatal("expected an explicit explanation of why no one-click PoC is possible")
	}
	if !strings.Contains(html, "-H") || !strings.Contains(html, "X-Forwarded-For") {
		t.Fatal("expected a curl command setting the header explicitly")
	}
}

func TestGeneratePoCCookieIsNotOneClickButHasCurl(t *testing.T) {
	srv := echoServer(t)
	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/s", domain.MethodGET)
	focus := env.param(ep, "pref", domain.LocationCookie, "orange")
	ip := env.injection(ep, focus)
	m := marker(env.scanID, ip.ID)
	cand := detection.Candidate{Source: detection.SourceBuiltin, Category: detection.CatHTMLText, Context: detection.CtxHTMLText,
		Parameter: "pref", Location: domain.LocationCookie, Value: "<svg onload=" + m + ">", DedupKey: "k", Priority: 90}

	fid := confirmOne(t, env, ep, ip, cand)
	poc, err := GeneratePoC(context.Background(), env.st, fid)
	if err != nil {
		t.Fatal(err)
	}
	if poc.OneClick {
		t.Fatal("a Cookie-location override cannot be a one-click PoC (same-origin policy)")
	}
	html := string(poc.HTML)
	if !strings.Contains(html, "same-origin policy") {
		t.Fatal("expected an explicit same-origin-policy explanation")
	}
	if !strings.Contains(html, "-b") || !strings.Contains(html, "pref=") {
		t.Fatal("expected a curl command setting the cookie explicitly")
	}
}

// --- combined (two-parameter) findings ---

// Both halves Query: still a true one-click link carrying BOTH overrides.
func TestGeneratePoCCombinedBothQueryIsOneClick(t *testing.T) {
	srv := echoServer(t)
	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/s", domain.MethodGET)
	a := env.param(ep, "a", domain.LocationQuery, "x")
	b := env.param(ep, "b", domain.LocationQuery, "y")
	ipA := env.injection(ep, a)
	_ = env.injection(ep, b)
	ma := marker(env.scanID, ipA.ID)
	cand := detection.Candidate{
		Source: detection.SourceBuiltin, Category: detection.CatHTMLAttr, Context: detection.CtxHTMLAttrValue,
		Parameter: "a", Location: domain.LocationQuery, Value: `">`, DedupKey: "combined-k", Priority: 90,
		Combined: true, ParameterB: "b", LocationB: domain.LocationQuery, ValueB: "<svg onload=" + ma + ">",
	}

	fid := confirmOne(t, env, ep, ipA, cand)
	poc, err := GeneratePoC(context.Background(), env.st, fid)
	if err != nil {
		t.Fatal(err)
	}
	if !poc.OneClick {
		t.Fatal("a combined Query+Query finding must be a one-click PoC")
	}
	if !poc.Combined || poc.ParameterB != "b" {
		t.Fatalf("poc = %+v, want Combined with ParameterB=b", poc)
	}
	if !strings.Contains(poc.URL, "a=") || !strings.Contains(poc.URL, "b=") {
		t.Fatalf("poc.URL = %q, want BOTH overrides present", poc.URL)
	}
}

// One half Query, one half Header: the artifact must carry both overrides
// in the curl command, but must NOT claim one-click (the header half can't
// be carried by a link).
func TestGeneratePoCCombinedQueryPlusHeaderIsNotOneClick(t *testing.T) {
	srv := echoServer(t)
	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/s", domain.MethodGET)
	a := env.param(ep, "a", domain.LocationQuery, "x")
	b := env.param(ep, "X-Trace", domain.LocationHeader, "")
	ipA := env.injection(ep, a)
	_ = env.injection(ep, b)
	ma := marker(env.scanID, ipA.ID)
	cand := detection.Candidate{
		Source: detection.SourceBuiltin, Category: detection.CatHTMLAttr, Context: detection.CtxHTMLAttrValue,
		Parameter: "a", Location: domain.LocationQuery, Value: `">`, DedupKey: "combined-k2", Priority: 90,
		Combined: true, ParameterB: "X-Trace", LocationB: domain.LocationHeader, ValueB: "<svg onload=" + ma + ">",
	}

	fid := confirmOne(t, env, ep, ipA, cand)
	poc, err := GeneratePoC(context.Background(), env.st, fid)
	if err != nil {
		t.Fatal(err)
	}
	if poc.OneClick {
		t.Fatal("a combined finding with a Header half must not claim one-click")
	}
	html := string(poc.HTML)
	if !strings.Contains(html, "X-Trace") {
		t.Fatal("expected the curl command to still set the header half explicitly")
	}
	if !strings.Contains(html, "combined") && !strings.Contains(html, "Combined") {
		t.Fatal("expected the artifact to flag this as a combined (multi-parameter) finding")
	}
}

// Authenticated and token-bearing requests are templates, not one-click
// reproductions. The saved session file is deliberately a dummy local fixture;
// GeneratePoC must inspect only session metadata and never read or render it.
func TestGeneratePoCAuthenticatedQueryUsesOperatorSessionWithoutSecrets(t *testing.T) {
	srv := echoServer(t)
	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/s", domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "hi")
	ip := env.injection(ep, focus)
	m := marker(env.scanID, ip.ID)
	candidate := detection.Candidate{Source: detection.SourceBuiltin, Category: detection.CatHTMLText, Context: detection.CtxHTMLText,
		Parameter: "q", Location: domain.LocationQuery, Value: "<svg onload=" + m + ">", DedupKey: "auth-query", Priority: 90}

	secret := "poc-test-session-cookie-not-real"
	statePath := filepath.Join(t.TempDir(), "storage-state.json")
	if err := os.WriteFile(statePath, []byte(`{"cookies":[{"name":"sid","value":"`+secret+`"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	sessionID := domain.NewID()
	env.sc.SessionID = sessionID
	if err := env.st.Scans().Update(context.Background(), env.sc); err != nil {
		t.Fatal(err)
	}
	if err := env.st.Sessions().Create(context.Background(), &domain.Session{
		ID: sessionID, ScanID: env.scanID, Mode: domain.AuthExisting,
		State: domain.SessionActive, StatePath: statePath, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	fid := confirmOne(t, env, ep, ip, candidate)
	poc, err := GeneratePoC(context.Background(), env.st, fid)
	if err != nil {
		t.Fatal(err)
	}
	if poc.OneClick {
		t.Fatal("an authenticated scan must not generate a one-click PoC")
	}
	html := string(poc.HTML)
	for _, want := range []string{"own authorized authenticated session", "session cookies are not embedded", "-b", "INDAGO_COOKIE_JAR", m} {
		if !strings.Contains(html, want) {
			t.Fatalf("authenticated PoC missing %q", want)
		}
	}
	if strings.Contains(html, `http-equiv="refresh"`) {
		t.Fatal("an authenticated PoC must not auto-navigate")
	}
	for _, forbidden := range []string{secret, statePath} {
		if strings.Contains(html, forbidden) || strings.Contains(poc.URL, forbidden) {
			t.Fatal("PoC leaked saved session material")
		}
	}
}

func TestGeneratePoCDynamicQueryTokenIsRedactedAndManual(t *testing.T) {
	srv := echoServer(t)
	env := newScanEnv(t)
	stale := "STALE_CSRF_VALUE_DO_NOT_RENDER"
	ep := env.endpoint(srv.URL+"/s?csrf_token="+stale, domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "hi")
	_ = env.param(ep, "csrf_token", domain.LocationQuery, stale)
	ip := env.injection(ep, focus)
	m := marker(env.scanID, ip.ID)
	candidate := detection.Candidate{Source: detection.SourceBuiltin, Category: detection.CatHTMLText, Context: detection.CtxHTMLText,
		Parameter: "q", Location: domain.LocationQuery, Value: "<svg onload=" + m + ">", DedupKey: "csrf-query", Priority: 90}

	fid := confirmOne(t, env, ep, ip, candidate)
	poc, err := GeneratePoC(context.Background(), env.st, fid)
	if err != nil {
		t.Fatal(err)
	}
	if poc.OneClick {
		t.Fatal("a dynamic non-focus token must disable one-click reproduction")
	}
	if strings.Contains(poc.URL, stale) || strings.Contains(string(poc.HTML), stale) {
		t.Fatal("PoC rendered the stale CSRF token")
	}
	for _, want := range []string{"FRESH_csrf_token_VALUE", "refresh current CSRF token", "token-issuing page", m, "request template"} {
		if !strings.Contains(poc.URL+string(poc.HTML), want) {
			t.Fatalf("dynamic-token PoC missing %q", want)
		}
	}
	if strings.Contains(string(poc.HTML), `http-equiv="refresh"`) {
		t.Fatal("a dynamic-token PoC must not auto-navigate")
	}
}

func TestGeneratePoCDynamicFormPostDoesNotAutoSubmit(t *testing.T) {
	srv := echoServer(t)
	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/submit", domain.MethodPOST)
	focus := env.param(ep, "q", domain.LocationForm, "hi")
	stale := "STALE_POST_CSRF_VALUE"
	_ = env.param(ep, "csrf_token", domain.LocationForm, stale)
	ip := env.injection(ep, focus)
	m := marker(env.scanID, ip.ID)
	candidate := detection.Candidate{Source: detection.SourceBuiltin, Category: detection.CatHTMLText, Context: detection.CtxHTMLText,
		Parameter: "q", Location: domain.LocationForm, Value: "<svg onload=" + m + ">", DedupKey: "csrf-post", Priority: 90}

	fid := confirmOne(t, env, ep, ip, candidate)
	poc, err := GeneratePoC(context.Background(), env.st, fid)
	if err != nil {
		t.Fatal(err)
	}
	html := string(poc.HTML)
	if poc.OneClick || strings.Contains(html, `onload="document.getElementById('indago-poc-form').submit()"`) {
		t.Fatal("a POST form with a dynamic token must not auto-submit")
	}
	if strings.Contains(html, stale) || !strings.Contains(html, "FRESH_csrf_token_VALUE") || !strings.Contains(html, m) {
		t.Fatal("POST template must redact the stale token while preserving the focused candidate payload")
	}
}

// --- wrong vuln class ---

func TestGeneratePoCRefusesNonFindingLookupError(t *testing.T) {
	env := newScanEnv(t)
	_, err := GeneratePoC(context.Background(), env.st, domain.NewID())
	if err == nil {
		t.Fatal("expected an error for a nonexistent finding")
	}
}
