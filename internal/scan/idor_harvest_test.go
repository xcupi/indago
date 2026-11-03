package scan

// Harvest integration tests. They use a fake httpengine.Engine (a table of
// canned responses) rather than an httptest server: harvesting must be provable
// as "no extra requests", and a fake engine makes the exact request list an
// assertion instead of an inference. No test here opens a socket.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/httpengine"
	"github.com/indago/indago/internal/idor"
)

type idorFakeEngine struct {
	mu      sync.Mutex
	calls   []string
	respond func(rawURL string) (int, string)
}

// idorHarvestEnv is the in-memory scan environment plus the IDOR helpers the
// harvest tests need. Unlike idorEnv it starts no server: the fake engine above
// is the only transport.
type idorHarvestEnv struct{ *scanEnv }

func newIDORHarvestEnv(t *testing.T) *idorHarvestEnv {
	t.Helper()
	return &idorHarvestEnv{scanEnv: newScanEnv(t)}
}

func (e *idorHarvestEnv) idorJobHelper(ep *domain.Endpoint, ip *domain.InjectionPoint) *domain.TestJob {
	return &domain.TestJob{ID: domain.NewID(), ScanID: e.scanID, Type: domain.JobIDOR,
		Target:   domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID, URL: ep.URL},
		Attempts: 1, MaxAttempts: 2}
}

func (e *idorHarvestEnv) cases() []*domain.TestCase {
	e.t.Helper()
	cases, err := e.st.TestCases().ListByScan(context.Background(), e.scanID)
	if err != nil {
		e.t.Fatal(err)
	}
	return cases
}

func (e *idorHarvestEnv) probeCase() *domain.TestCase {
	e.t.Helper()
	var out []*domain.TestCase
	for _, tc := range e.cases() {
		if tc.VulnClass == domain.VulnIDOR && !strings.HasPrefix(tc.Note, "idor identity") {
			out = append(out, tc)
		}
	}
	if len(out) != 1 {
		e.t.Fatalf("expected exactly 1 IDOR probe test case, got %d (%+v)", len(out), out)
	}
	return out[0]
}

func (f *idorFakeEngine) Do(_ context.Context, req *httpengine.Request) (*httpengine.Response, error) {
	f.mu.Lock()
	f.calls = append(f.calls, req.URL)
	f.mu.Unlock()
	status, body := http.StatusOK, ""
	if f.respond != nil {
		status, body = f.respond(req.URL)
	}
	return &httpengine.Response{
		Status: status, StatusText: http.StatusText(status), Proto: "HTTP/1.1",
		Headers:       http.Header{"Content-Type": []string{"text/html"}},
		Body:          []byte(body),
		ContentLength: int64(len(body)),
		FinalURL:      req.URL,
		ReceivedAt:    time.Now(),
		Request:       &httpengine.CapturedRequest{Method: req.Method, URL: req.URL, Headers: http.Header{}, Body: req.Body},
	}, nil
}

func (f *idorFakeEngine) seen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

// seedResponseEvidence stores one response body exactly the way the executors
// do (HTTP message dump + "test_case=" note) and attributes it to a TestCase
// URL, which is the provenance the harvest reports.
func seedResponseEvidence(t *testing.T, env *idorHarvestEnv, caseURL, body string) {
	t.Helper()
	now := time.Now()
	tc := &domain.TestCase{ID: domain.NewID(), ScanID: env.scanID, Status: domain.TestCaseCompleted,
		URL: caseURL, CreatedAt: now, UpdatedAt: now}
	if err := env.st.TestCases().Create(context.Background(), tc); err != nil {
		t.Fatal(err)
	}
	dump := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + body
	note := "test_case=" + string(tc.ID) + " candidate response"
	if _, err := putEvidenceBlob(context.Background(), env.st, env.ev, env.scanID,
		domain.EvidenceResponse, ".http", "message/http", []byte(dump), note); err != nil {
		t.Fatal(err)
	}
}

func TestIDORHarvestedCandidateConfirmsWithProvenance(t *testing.T) {
	env := newIDORHarvestEnv(t)
	const base = "http://app.test"
	ep := env.endpoint(base+"/my-account?id=wiener", domain.MethodGET)
	focus := env.param(ep, "id", domain.LocationQuery, "wiener")
	ip := env.injection(ep, focus)

	// A page the scan already fetched and stored lists a foreign user.
	seedResponseEvidence(t, env, base+"/admin/users", `{"shared":[{"username":"carlos"}]}`)

	eng := &idorFakeEngine{respond: func(raw string) (int, string) {
		switch {
		case strings.Contains(raw, "id=carlos"):
			return 200, `<p>Your username is <strong>carlos</strong></p>`
		case strings.Contains(raw, "id="):
			return 200, `<p>Your username is <strong>wiener</strong></p>`
		default:
			return 200, `<p>Your username is <strong>wiener</strong></p>`
		}
	}}
	ex := newIDORExecutor(env.st, eng, env.ev, ExecutorConfig{}, execLog(), nil, nil)
	if err := ex.Handle(context.Background(), env.idorJobHelper(ep, ip)); err != nil {
		t.Fatalf("handle: %v", err)
	}

	tc := env.probeCase()
	d := idorDecision(t, tc)
	if d.Verdict != domain.VerdictConfirmed {
		t.Fatalf("verdict = %q (%s), want confirmed", d.Verdict, d.Reason)
	}
	if d.HarvestedCount == 0 {
		t.Fatalf("detail must record that identifiers were harvested: %+v", d)
	}
	var confirmed idorAttempt
	for _, a := range d.Attempts {
		if a.Candidate == "carlos" && a.Outcome == string(idor.OutcomeConfirmed) {
			confirmed = a
		}
	}
	if confirmed.Candidate == "" {
		t.Fatalf("harvested carlos attempt not confirmed: %+v", d.Attempts)
	}
	if confirmed.Source != "harvested" {
		t.Fatalf("attempt source = %q, want harvested (no operator candidate was supplied)", confirmed.Source)
	}
	if confirmed.Origin == nil {
		t.Fatal("a harvested candidate must carry its provenance on the attempt")
	}
	if confirmed.Origin.Endpoint != base+"/admin/users" || confirmed.Origin.Via != idor.ViaJSON ||
		confirmed.Origin.Field != "shared.username" {
		t.Fatalf("provenance = %+v, want shared.username from /admin/users", confirmed.Origin)
	}
	if !strings.Contains(confirmed.Reason, "harvested from "+base+"/admin/users") {
		t.Fatalf("attempt reason must state where the identifier came from: %q", confirmed.Reason)
	}

	fs := env.findings()
	if len(fs) != 1 || fs[0].Verdict != domain.VerdictConfirmed {
		t.Fatalf("findings = %+v, want one confirmed", fs)
	}
	if !strings.Contains(fs[0].Summary, "harvested from "+base+"/admin/users") {
		t.Fatalf("finding summary must attribute the tested identifier: %q", fs[0].Summary)
	}

	// The harvest itself must not fetch anything: only the identity page, the
	// own-object baseline and the foreign candidate were requested.
	for _, call := range eng.seen() {
		if strings.Contains(call, "/admin/users") {
			t.Fatalf("harvesting fetched the source page instead of reusing stored data: %s", call)
		}
	}
	if len(eng.seen()) != 3 {
		t.Fatalf("requests = %v, want exactly identity + baseline + candidate", eng.seen())
	}
}

func TestIDORWithoutCandidatesOrHarvestSendsNoProbes(t *testing.T) {
	env := newIDORHarvestEnv(t)
	const base = "http://app.test"
	ep := env.endpoint(base+"/my-account?id=wiener", domain.MethodGET)
	focus := env.param(ep, "id", domain.LocationQuery, "wiener")
	ip := env.injection(ep, focus)

	// The only identifier anywhere in the scan's data is the caller's own.
	eng := &idorFakeEngine{respond: func(string) (int, string) {
		return 200, `<p>Your username is <strong>wiener</strong></p>`
	}}
	ex := newIDORExecutor(env.st, eng, env.ev, ExecutorConfig{}, execLog(), nil, nil)
	if err := ex.Handle(context.Background(), env.idorJobHelper(ep, ip)); err != nil {
		t.Fatalf("handle must not fail when there is nothing to test: %v", err)
	}

	tc := env.probeCase()
	if tc.Status != domain.TestCaseSkipped {
		t.Fatalf("status = %s, want skipped", tc.Status)
	}
	d := idorDecision(t, tc)
	if d.Verdict == domain.VerdictConfirmed {
		t.Fatal("nothing may be confirmed without a candidate")
	}
	if d.HarvestedCount != 0 || !strings.Contains(d.HarvestNote, "no foreign identifier") {
		t.Fatalf("detail must state that nothing was harvested: %+v", d)
	}
	if !strings.Contains(strings.ToLower(d.SkipReason), "unpredictable") {
		t.Fatalf("skip reason must explain the refusal: %q", d.SkipReason)
	}
	// Identity probe + own-object baseline only. No foreign object read.
	if len(eng.seen()) != 2 {
		t.Fatalf("requests = %v, want only identity + own baseline", eng.seen())
	}
	for _, call := range eng.seen() {
		if !strings.Contains(call, "id=wiener") && !strings.HasSuffix(call, "/my-account") {
			t.Fatalf("unexpected probe: %s", call)
		}
	}
}

func TestIDORExplicitCandidatesStillLead(t *testing.T) {
	env := newIDORHarvestEnv(t)
	const base = "http://app.test"
	ep := env.endpoint(base+"/my-account?id=wiener", domain.MethodGET)
	focus := env.param(ep, "id", domain.LocationQuery, "wiener")
	ip := env.injection(ep, focus)

	eng := &idorFakeEngine{respond: func(raw string) (int, string) {
		if strings.Contains(raw, "id=carlos") {
			return 200, `<p>Your username is <strong>carlos</strong></p>`
		}
		return 200, `<p>Your username is <strong>wiener</strong></p>`
	}}
	ex := newIDORExecutor(env.st, eng, env.ev, ExecutorConfig{}, execLog(), nil, []string{"carlos"})
	if err := ex.Handle(context.Background(), env.idorJobHelper(ep, ip)); err != nil {
		t.Fatalf("handle: %v", err)
	}

	d := idorDecision(t, env.probeCase())
	if d.Verdict != domain.VerdictConfirmed {
		t.Fatalf("verdict = %q (%s), want confirmed", d.Verdict, d.Reason)
	}
	if len(d.Attempts) != 1 {
		t.Fatalf("attempts = %+v, want the single explicit candidate (one positive mismatch stops the pass)", d.Attempts)
	}
	a := d.Attempts[0]
	if a.Candidate != "carlos" || a.Source != "supplied" {
		t.Fatalf("first attempt = %+v, want supplied carlos", a)
	}
	if a.Origin != nil {
		t.Fatalf("an explicit candidate must not carry harvest provenance: %+v", a.Origin)
	}
	for _, call := range eng.seen() {
		if strings.Contains(call, "?id=") && !strings.Contains(call, "id=wiener") && !strings.Contains(call, "id=carlos") {
			t.Fatalf("explicit-only pass sent an unreported candidate: %s", call)
		}
	}
}

func TestIDORExplicitCandidatesMergeAheadOfHarvested(t *testing.T) {
	env := newIDORHarvestEnv(t)
	const base = "http://app.test"
	ep := env.endpoint(base+"/my-account?id=wiener", domain.MethodGET)
	focus := env.param(ep, "id", domain.LocationQuery, "wiener")
	ip := env.injection(ep, focus)

	// Both names are harvested; carlos is ALSO supplied explicitly, so it must
	// be tried once, as supplied, before dave.
	seedResponseEvidence(t, env, base+"/admin/users", `{"users":[{"username":"carlos"},{"username":"dave"}]}`)
	eng := &idorFakeEngine{respond: func(raw string) (int, string) {
		switch {
		case strings.Contains(raw, "id=dave"):
			return 200, `<p>Your username is <strong>dave</strong></p>`
		case strings.Contains(raw, "id=carlos"):
			return 200, `<p>Your username is <strong>wiener</strong></p>` // same principal
		default:
			return 200, `<p>Your username is <strong>wiener</strong></p>`
		}
	}}
	ex := newIDORExecutor(env.st, eng, env.ev, ExecutorConfig{}, execLog(), nil, []string{"carlos"})
	if err := ex.Handle(context.Background(), env.idorJobHelper(ep, ip)); err != nil {
		t.Fatalf("handle: %v", err)
	}

	d := idorDecision(t, env.probeCase())
	if d.Verdict != domain.VerdictConfirmed {
		t.Fatalf("verdict = %q (%s), want confirmed on dave", d.Verdict, d.Reason)
	}
	if len(d.Attempts) != 2 {
		t.Fatalf("attempts = %+v, want [carlos(supplied) dave(harvested)]", d.Attempts)
	}
	if d.Attempts[0].Candidate != "carlos" || d.Attempts[0].Source != "supplied" {
		t.Fatalf("explicit candidate must come first: %+v", d.Attempts[0])
	}
	if d.Attempts[1].Candidate != "dave" || d.Attempts[1].Source != "harvested" || d.Attempts[1].Origin == nil {
		t.Fatalf("harvested candidate must follow with provenance: %+v", d.Attempts[1])
	}
	if d.Attempts[0].Origin != nil {
		t.Fatalf("supplied carlos must not be attributed to the harvest: %+v", d.Attempts[0].Origin)
	}
}

func TestIDORHarvestedCandidateMustMatchEndpointShape(t *testing.T) {
	env := newIDORHarvestEnv(t)
	const base = "http://app.test"
	const callerUUID = "11111111-1111-4111-8111-111111111111"
	const foreignUUID = "5f0c0f4e-1d2a-4c3b-9a11-8f6c2b7d4e10"

	ep := env.endpoint(base+"/documents?id="+callerUUID, domain.MethodGET)
	focus := env.param(ep, "id", domain.LocationQuery, callerUUID)
	ip := env.injection(ep, focus)

	// The scan's data contains a numeric id and a foreign UUID. Only the UUID
	// may be tried against a UUID endpoint.
	seedResponseEvidence(t, env, base+"/admin/documents",
		`{"documents":[{"id":17,"uuid":"`+foreignUUID+`"}]}`)

	eng := &idorFakeEngine{respond: func(raw string) (int, string) {
		if strings.Contains(raw, foreignUUID) {
			return 200, `<p>Your username is <strong>carlos</strong></p>`
		}
		return 200, `<p>Your username is <strong>wiener</strong></p>`
	}}
	ex := newIDORExecutor(env.st, eng, env.ev, ExecutorConfig{}, execLog(), nil, nil)
	if err := ex.Handle(context.Background(), env.idorJobHelper(ep, ip)); err != nil {
		t.Fatalf("handle: %v", err)
	}

	d := idorDecision(t, env.probeCase())
	if d.Verdict != domain.VerdictConfirmed {
		t.Fatalf("verdict = %q (%s), want confirmed on the foreign uuid", d.Verdict, d.Reason)
	}
	for _, call := range eng.seen() {
		if strings.Contains(call, "id=17") {
			t.Fatalf("a numeric id was sent to a UUID endpoint: %s", call)
		}
	}
	if len(d.Attempts) != 1 || d.Attempts[0].Candidate != foreignUUID {
		t.Fatalf("attempts = %+v, want only the uuid", d.Attempts)
	}
}

func TestIDORHarvestPersistsOnTheIdentityBaseline(t *testing.T) {
	env := newIDORHarvestEnv(t)
	const base = "http://app.test"
	ep := env.endpoint(base+"/my-account?id=wiener", domain.MethodGET)
	focus := env.param(ep, "id", domain.LocationQuery, "wiener")
	ip := env.injection(ep, focus)
	seedResponseEvidence(t, env, base+"/admin/users", `{"users":[{"username":"carlos"}]}`)

	eng := &idorFakeEngine{respond: func(string) (int, string) {
		return 200, `<p>Your username is <strong>wiener</strong></p>`
	}}
	ex := newIDORExecutor(env.st, eng, env.ev, ExecutorConfig{}, execLog(), nil, nil)
	if err := ex.Handle(context.Background(), env.idorJobHelper(ep, ip)); err != nil {
		t.Fatalf("handle: %v", err)
	}

	// The harvested set is a durable, read-only fact on the identity baseline,
	// which is what the read-only API surfaces.
	var identityCase *domain.TestCase
	for _, tc := range env.cases() {
		if strings.HasPrefix(tc.Note, "idor identity baseline") {
			identityCase = tc
		}
	}
	if identityCase == nil {
		t.Fatal("identity baseline TestCase missing")
	}
	var d idorDetail
	if err := json.Unmarshal(identityCase.Detail, &d); err != nil {
		t.Fatalf("decode identity detail: %v", err)
	}
	if len(d.Harvest) != 1 || d.Harvest[0].Value != "carlos" {
		t.Fatalf("persisted harvest = %+v, want carlos", d.Harvest)
	}
	if d.HarvestNote == "" {
		t.Fatal("persisted harvest must carry its note")
	}
}
