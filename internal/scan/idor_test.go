package scan

// IDOR engine tests: the object-identifier differential against real httptest
// servers, the identity baseline, verdict discipline (positive foreign data is
// Confirmed; same-principal data, no identity fields, login pages and opaque
// identifiers are never Confirmed), evidence retention and the bounded probe
// pass. These are the mandatory negative controls for the engine's central
// security claim.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/idor"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/ratelimit"
)

type idorEnv struct {
	*scanEnv
	mu       sync.Mutex
	requests []string // "METHOD path?query" of every request that reached the server
}

func newIDOREnv(t *testing.T, handler http.HandlerFunc) (*idorEnv, *httptest.Server) {
	t.Helper()
	env := &idorEnv{scanEnv: newScanEnv(t)}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		env.mu.Lock()
		env.requests = append(env.requests, r.Method+" "+r.URL.RequestURI())
		env.mu.Unlock()
		handler(w, r)
	}))
	t.Cleanup(srv.Close)
	authenticateIDOR(t, env.scanEnv)
	env.sc.SeedURLs = []string{srv.URL}
	if err := env.st.Scans().Update(context.Background(), env.sc); err != nil {
		t.Fatal(err)
	}
	return env, srv
}

// authenticateIDOR gives the scan a REAL caller identity: an active session
// with a non-anonymous auth mode. The IDOR engine is automatic — this, not a
// config flag, is the only thing that turns the pass on.
func authenticateIDOR(t *testing.T, env *scanEnv) {
	t.Helper()
	now := time.Now().UTC()
	sess := &domain.Session{
		ID:        domain.NewID(),
		ScanID:    env.scanID,
		Mode:      domain.AuthExisting,
		State:     domain.SessionActive,
		StatePath: filepath.Join(t.TempDir(), "session.json"),
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := env.st.Sessions().Create(context.Background(), sess); err != nil {
		t.Fatalf("seed authenticated session: %v", err)
	}
	env.sc.SessionID = sess.ID
}

func (e *idorEnv) saw() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.requests...)
}

func (e *idorEnv) idorJobHelper(ep *domain.Endpoint, ip *domain.InjectionPoint) *domain.TestJob {
	return &domain.TestJob{ID: domain.NewID(), ScanID: e.scanID, Type: domain.JobIDOR,
		Target:   domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID, URL: ep.URL},
		Attempts: 1, MaxAttempts: 2}
}

func (e *idorEnv) cases() []*domain.TestCase {
	e.t.Helper()
	cases, err := e.st.TestCases().ListByScan(context.Background(), e.scanID)
	if err != nil {
		e.t.Fatal(err)
	}
	return cases
}

func (e *idorEnv) findings() []*domain.Finding {
	e.t.Helper()
	fs, err := e.st.Findings().ListByScan(context.Background(), e.scanID)
	if err != nil {
		e.t.Fatal(err)
	}
	return fs
}

func (e *idorEnv) probeCase() *domain.TestCase {
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

func idorDecision(t *testing.T, tc *domain.TestCase) idorDetail {
	t.Helper()
	var d idorDetail
	if err := json.Unmarshal(tc.Detail, &d); err != nil {
		t.Fatalf("decode idor detail: %v (detail=%s)", err, tc.Detail)
	}
	return d
}

// accountServer serves an account page that identifies whoever the id selects.
func accountServer(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path != "/my-account" {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `<h1>Not found</h1>`)
			return
		}
		switch r.URL.Query().Get("id") {
		case "", "wiener":
			fmt.Fprint(w, `<h1>My Account</h1><p>Your username is <strong>wiener</strong></p><p>Email: wiener@example.com</p>`)
		case "carlos":
			fmt.Fprint(w, `<h1>My Account</h1><p>Your username is <strong>carlos</strong></p><p>Email: carlos@example.com</p>`)
		default:
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `<h1>Not found</h1>`)
		}
	}
}

func TestIDORConfirmsForeignObject(t *testing.T) {
	env, srv := newIDOREnv(t, accountServer(t))
	env.sc.Config.IDORCandidates = []string{"carlos"}

	ep := env.endpoint(srv.URL+"/my-account?id=wiener", domain.MethodGET)
	focus := env.param(ep, "id", domain.LocationQuery, "wiener")
	ip := env.injection(ep, focus)

	ex := newIDORExecutor(env.st, scopedClient(t, openScope()), env.ev, ExecutorConfig{}, execLog(), nil, env.sc.Config.IDORCandidates, idor.EnumerationOptions{})
	if err := ex.Handle(context.Background(), env.idorJobHelper(ep, ip)); err != nil {
		t.Fatalf("handle: %v", err)
	}

	d := idorDecision(t, env.probeCase())
	if d.Verdict != domain.VerdictConfirmed {
		t.Fatalf("verdict = %q (%s), want confirmed", d.Verdict, d.Reason)
	}
	if d.CallerIdentity.Empty() {
		t.Fatal("the established caller identity must be recorded in the detail")
	}
	if len(d.Attempts) == 0 {
		t.Fatal("no candidate attempts recorded")
	}
	var confirmed idorAttempt
	for _, a := range d.Attempts {
		if a.Candidate == "carlos" && a.Outcome == string(idor.OutcomeConfirmed) {
			confirmed = a
		}
	}
	if confirmed.Candidate == "" {
		t.Fatalf("carlos attempt not confirmed: %+v", d.Attempts)
	}
	if confirmed.Foreign == nil || confirmed.Foreign.Value != "carlos" {
		t.Fatalf("confirmed attempt must name the foreign identity it proved: %+v", confirmed.Foreign)
	}

	// Both request A (own object) and request B (foreign object) must be stored
	// as evidence, and the finding must reference them.
	if len(d.BaselineEvidence) == 0 {
		t.Fatal("baseline (own-object) request/response evidence missing")
	}
	if len(d.IdentityEvidence) == 0 {
		t.Fatal("identity-baseline request/response evidence missing")
	}
	if len(confirmed.EvidenceIDs) == 0 {
		t.Fatal("foreign-object request/response evidence missing")
	}
	var sawIdentity bool
	for _, id := range d.IdentityEvidence {
		_, body := env.evidenceBlob(id)
		if strings.Contains(body, "GET /my-account") && !strings.Contains(body, "?id=") {
			sawIdentity = true
		}
	}
	if !sawIdentity {
		t.Fatal("identity evidence must carry the account-page request that established the caller")
	}
	var sawOwn, sawForeign bool
	for _, id := range append(append([]domain.ID(nil), d.BaselineEvidence...), confirmed.EvidenceIDs...) {
		_, body := env.evidenceBlob(id)
		if strings.Contains(body, "GET /my-account?id=wiener") {
			sawOwn = true
		}
		if strings.Contains(body, "GET /my-account?id=carlos") {
			sawForeign = true
		}
	}
	if !sawOwn || !sawForeign {
		t.Fatalf("evidence must carry both requests (own=%v foreign=%v)", sawOwn, sawForeign)
	}

	fs := env.findings()
	if len(fs) != 1 {
		t.Fatalf("findings = %d, want 1: %+v", len(fs), fs)
	}
	f := fs[0]
	if f.VulnClass != domain.VulnIDOR || f.Verdict != domain.VerdictConfirmed {
		t.Fatalf("finding = %s/%s, want idor/confirmed", f.VulnClass, f.Verdict)
	}
	if len(f.EvidenceIDs) == 0 {
		t.Fatal("confirmed finding must reference evidence")
	}
	if !strings.Contains(f.Title, "id") {
		t.Fatalf("finding title should name the identifier parameter: %q", f.Title)
	}
}

// A target can name its account page /profile_user instead of the four
// conventional paths. The page is already in the scan's endpoint registry, so
// the identity baseline must use it rather than skipping every IDOR probe.
func TestIDORIdentityUsesDiscoveredProfilePage(t *testing.T) {
	env, srv := newIDOREnv(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path != "/profile_user" {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `<h1>Not found</h1>`)
			return
		}
		fmt.Fprint(w, `<h1>Profile</h1><p>Your username is <strong>wiener</strong></p><p>Email: wiener@example.com</p>`)
	})
	ep := env.endpoint(srv.URL+"/my-account?id=wiener", domain.MethodGET)
	env.endpoint(srv.URL+"/profile_user", domain.MethodGET)

	ex := newIDORExecutor(env.st, scopedClient(t, openScope()), env.ev, ExecutorConfig{}, execLog(), nil, nil, idor.EnumerationOptions{})
	ident, _ := ex.identity(context.Background(), env.scanID, ep)
	if ident == nil || ident.Identity.Empty() {
		t.Fatalf("identity was not established: %+v", ident)
	}
	if ident.Source != srv.URL+"/profile_user" {
		t.Fatalf("identity source = %q, want the discovered /profile_user page", ident.Source)
	}
}

func TestIDORIdentityUsesOverviewOnSeedOrigin(t *testing.T) {
	env, srv := newIDOREnv(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	authSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path != "/overview" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		fmt.Fprint(w, `<h1>Overview</h1><p>Your username is <strong>wiener</strong></p>`)
	}))
	defer authSrv.Close()
	env.sc.SeedURLs = []string{authSrv.URL + "/overview"}
	if err := env.st.Scans().Update(context.Background(), env.sc); err != nil {
		t.Fatal(err)
	}
	ep := env.endpoint(srv.URL+"/object?id=wiener", domain.MethodGET)
	ex := newIDORExecutor(env.st, scopedClient(t, openScope()), env.ev, ExecutorConfig{}, execLog(), nil, nil, idor.EnumerationOptions{})
	ident, _ := ex.identity(context.Background(), env.scanID, ep)
	if ident == nil || ident.Identity.Empty() {
		t.Fatalf("identity was not established from the seed origin: %+v", ident)
	}
	if ident.Source != authSrv.URL+"/overview" {
		t.Fatalf("identity source = %q, want seed-auth /overview", ident.Source)
	}
}

func TestIDORSamePrincipalIsNeverConfirmed(t *testing.T) {
	env, srv := newIDOREnv(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path != "/profile" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		// Every object id returns the CALLER's own identity: the server is
		// enforcing ownership correctly.
		if id := r.URL.Query().Get("id"); id != "" && id != "1" {
			fmt.Fprintf(w, `<p>Username: wiener</p><p>Object: %s</p>`, id)
			return
		}
		fmt.Fprint(w, `<p>Username: wiener</p>`)
	})

	ep := env.endpoint(srv.URL+"/profile?id=1", domain.MethodGET)
	focus := env.param(ep, "id", domain.LocationQuery, "1")
	ip := env.injection(ep, focus)

	ex := newIDORExecutor(env.st, scopedClient(t, openScope()), env.ev, ExecutorConfig{}, execLog(), nil, nil, idor.EnumerationOptions{})
	if err := ex.Handle(context.Background(), env.idorJobHelper(ep, ip)); err != nil {
		t.Fatalf("handle: %v", err)
	}
	d := idorDecision(t, env.probeCase())
	if d.Verdict == domain.VerdictConfirmed {
		t.Fatalf("same-principal responses must never be Confirmed: %s", d.Reason)
	}
	if d.Verdict != domain.VerdictRejected {
		t.Fatalf("verdict = %q (%s), want rejected for a positive same-identity observation", d.Verdict, d.Reason)
	}
	for _, f := range env.findings() {
		if f.Verdict == domain.VerdictConfirmed {
			t.Fatalf("a finding was Confirmed on a same-principal fixture: %+v", f)
		}
	}
}

func TestIDORNoIdentityFieldsIsNeverConfirmed(t *testing.T) {
	env, srv := newIDOREnv(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/my-account":
			w.Header().Set("Content-Type", "text/plain")
			if r.URL.Query().Get("id") == "" {
				fmt.Fprint(w, `Username: wiener`)
				return
			}
			w.WriteHeader(http.StatusNotFound)
		case "/download":
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprintf(w, "chat transcript %s: hello world", r.URL.Query().Get("file"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	// A supplied candidate gives the differential something to read; the point
	// of the test is what Decide makes of a body with no identity fields.
	env.sc.Config.IDORCandidates = []string{"2.txt"}

	ep := env.endpoint(srv.URL+"/download?file=1.txt", domain.MethodGET)
	focus := env.param(ep, "file", domain.LocationQuery, "1.txt")
	ip := env.injection(ep, focus)

	ex := newIDORExecutor(env.st, scopedClient(t, openScope()), env.ev, ExecutorConfig{}, execLog(), nil, []string{"2.txt"}, idor.EnumerationOptions{})
	if err := ex.Handle(context.Background(), env.idorJobHelper(ep, ip)); err != nil {
		t.Fatalf("handle: %v", err)
	}
	d := idorDecision(t, env.probeCase())
	if d.Verdict == domain.VerdictConfirmed {
		t.Fatalf("responses with no identity fields must never be Confirmed: %s", d.Reason)
	}
	if d.Verdict != domain.VerdictInconclusive {
		t.Fatalf("verdict = %q (%s), want inconclusive", d.Verdict, d.Reason)
	}
	if d.Reason == "" {
		t.Fatal("an unconfirmed result must state a reason")
	}
}

func TestIDORLoginRedirectIsInconclusive(t *testing.T) {
	env, srv := newIDOREnv(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch {
		case r.URL.Path == "/login":
			fmt.Fprint(w, `<form><input name="username"><input type="password" name="password"></form>`)
		case r.URL.Path == "/my-account" && (r.URL.Query().Get("id") == "" || r.URL.Query().Get("id") == "wiener"):
			fmt.Fprint(w, `<p>Username: wiener</p>`)
		default:
			http.Redirect(w, r, "/login", http.StatusFound)
		}
	})
	env.sc.Config.IDORCandidates = []string{"carlos"}
	ep := env.endpoint(srv.URL+"/my-account?id=wiener", domain.MethodGET)
	focus := env.param(ep, "id", domain.LocationQuery, "wiener")
	ip := env.injection(ep, focus)

	ex := newIDORExecutor(env.st, scopedClient(t, openScope()), env.ev, ExecutorConfig{}, execLog(), nil, env.sc.Config.IDORCandidates, idor.EnumerationOptions{})
	if err := ex.Handle(context.Background(), env.idorJobHelper(ep, ip)); err != nil {
		t.Fatalf("handle: %v", err)
	}
	d := idorDecision(t, env.probeCase())
	if d.Verdict == domain.VerdictConfirmed {
		t.Fatalf("a login redirect must never be Confirmed as IDOR: %s", d.Reason)
	}
}

// TestIDORRedirectBodyLeakConfirms is case 32: the object is disclosed in the
// BODY of the redirect that sends the caller away (302 -> /login, account page
// inside). Following that redirect used to make the response look like a login
// page and the case stayed Inconclusive; the engine now replays the request with
// redirects disabled and classifies the 3xx body.
func TestIDORRedirectBodyLeakConfirms(t *testing.T) {
	env, srv := newIDOREnv(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch {
		case r.URL.Path == "/login":
			fmt.Fprint(w, `<form><input name="username"><input type="password" name="password"></form>`)
		case r.URL.Path == "/my-account" && (r.URL.Query().Get("id") == "" || r.URL.Query().Get("id") == "wiener"):
			fmt.Fprint(w, `<h1>My Account</h1><p>Your username is <strong>wiener</strong></p><p>Email: wiener@example.com</p>`)
		case r.URL.Path == "/my-account" && r.URL.Query().Get("id") == "carlos":
			w.Header().Set("Location", "/login")
			w.WriteHeader(http.StatusFound)
			fmt.Fprint(w, `<h1>My Account</h1><p>Your username is <strong>carlos</strong></p><p>Email: carlos@example.com</p>`)
		default:
			http.NotFound(w, r)
		}
	})
	env.sc.Config.IDORCandidates = []string{"carlos"}
	ep := env.endpoint(srv.URL+"/my-account?id=wiener", domain.MethodGET)
	focus := env.param(ep, "id", domain.LocationQuery, "wiener")
	ip := env.injection(ep, focus)

	ex := newIDORExecutor(env.st, scopedClient(t, openScope()), env.ev, ExecutorConfig{}, execLog(), nil, env.sc.Config.IDORCandidates, idor.EnumerationOptions{})
	if err := ex.Handle(context.Background(), env.idorJobHelper(ep, ip)); err != nil {
		t.Fatalf("handle: %v", err)
	}

	d := idorDecision(t, env.probeCase())
	if d.Verdict != domain.VerdictConfirmed {
		t.Fatalf("verdict = %q (%s), want confirmed", d.Verdict, d.Reason)
	}
	if !d.RedirectBody {
		t.Fatal("the decision must record that the object was read from a redirect body")
	}
	if !strings.Contains(d.Reason, "redirect response") {
		t.Fatalf("reason should name the redirect-body leak: %q", d.Reason)
	}
	var foreign *idorAttempt
	for i := range d.Attempts {
		if d.Attempts[i].Candidate == "carlos" && d.Attempts[i].Outcome == string(idor.OutcomeConfirmed) {
			foreign = &d.Attempts[i]
		}
	}
	if foreign == nil || foreign.Foreign == nil || foreign.Foreign.Value != "carlos" {
		t.Fatalf("confirmed attempt must name carlos: %+v", d.Attempts)
	}
	fs := env.findings()
	if len(fs) != 1 || fs[0].VulnClass != domain.VulnIDOR {
		t.Fatalf("findings = %+v, want one idor finding", fs)
	}
}

func TestIDOROpaqueIdentifierSkipsWithoutGuessing(t *testing.T) {
	const own = "8f14e45f-ceea-467f-a8d5-1b3c4d5e6f70"
	env, srv := newIDOREnv(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path != "/my-account" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		fmt.Fprint(w, `<p>Username: wiener</p>`)
	})

	ep := env.endpoint(srv.URL+"/my-account?id="+own, domain.MethodGET)
	focus := env.param(ep, "id", domain.LocationQuery, own)
	ip := env.injection(ep, focus)

	ex := newIDORExecutor(env.st, scopedClient(t, openScope()), env.ev, ExecutorConfig{}, execLog(), nil, nil, idor.EnumerationOptions{})
	if err := ex.Handle(context.Background(), env.idorJobHelper(ep, ip)); err != nil {
		t.Fatalf("handle: %v", err)
	}
	tc := env.probeCase()
	if tc.Status != domain.TestCaseSkipped {
		t.Fatalf("status = %s, want skipped for an unpredictable identifier", tc.Status)
	}
	d := idorDecision(t, tc)
	if d.Verdict == domain.VerdictConfirmed {
		t.Fatal("an unpredictable identifier must never be Confirmed")
	}
	if !strings.Contains(strings.ToLower(d.Reason+d.SkipReason), "unpredictable") {
		t.Fatalf("skip reason must state why no candidates were tried: %+v", d)
	}
	// Nothing resembling guessing: only the identity probe and the own-value
	// baseline may have been requested.
	for _, req := range env.saw() {
		if strings.Contains(req, "/my-account?id=") && !strings.Contains(req, own) {
			t.Fatalf("engine guessed an opaque identifier: %s", req)
		}
	}
}

func TestIDORStateChangingParameterIsOutOfSlice(t *testing.T) {
	env, srv := newIDOREnv(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("state-changing request reached the server: %s %s", r.Method, r.URL)
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<p>Username: wiener</p>`)
	})

	ep := env.endpoint(srv.URL+"/transfer", domain.MethodPOST)
	focus := env.param(ep, "id", domain.LocationForm, "1")
	ip := env.injection(ep, focus)

	ex := newIDORExecutor(env.st, scopedClient(t, openScope()), env.ev, ExecutorConfig{}, execLog(), nil, nil, idor.EnumerationOptions{})
	if err := ex.Handle(context.Background(), env.idorJobHelper(ep, ip)); err != nil {
		t.Fatalf("handle: %v", err)
	}
	tc := env.probeCase()
	if tc.Status != domain.TestCaseSkipped {
		t.Fatalf("status = %s, want skipped for a body-carrying method", tc.Status)
	}
	d := idorDecision(t, tc)
	reason := strings.ToLower(d.Reason + d.SkipReason)
	if !strings.Contains(reason, "state-changing") && !strings.Contains(reason, "out of scope") {
		t.Fatalf("skip reason must say why: %+v", d)
	}
	for _, req := range env.saw() {
		if strings.HasPrefix(req, "POST ") {
			t.Fatalf("a POST was sent despite the read-only slice: %s", req)
		}
	}
}

func TestEnqueueIDORProbesSelectsOnlyObjectIdentifiers(t *testing.T) {
	env := newScanEnv(t)
	authenticateIDOR(t, env)
	if err := env.st.Scans().Update(context.Background(), env.sc); err != nil {
		t.Fatal(err)
	}
	q := queue.NewMemory()
	c := &Controller{store: env.st, queue: q, log: execLog()}

	getEP := env.endpoint("http://127.0.0.1:1/my-account?id=wiener", domain.MethodGET)
	env.param(getEP, "id", domain.LocationQuery, "wiener")
	env.param(getEP, "q", domain.LocationQuery, "hello") // not an object id
	postEP := env.endpoint("http://127.0.0.1:1/transfer", domain.MethodPOST)
	env.param(postEP, "id", domain.LocationForm, "1")
	headEP := env.endpoint("http://127.0.0.1:1/files/7", domain.MethodHEAD)
	env.param(headEP, "path[1]", domain.LocationPath, "7")

	c.enqueueIDORProbes(context.Background(), env.scanID)

	var jobs []*domain.TestJob
	for {
		j, err := q.Lease(context.Background(), "t", env.scanID, []domain.JobType{domain.JobIDOR}, time.Minute)
		if err != nil || j == nil {
			break
		}
		jobs = append(jobs, j)
	}
	if len(jobs) != 2 {
		t.Fatalf("enqueued %d IDOR jobs, want 2 (GET id param + HEAD path segment): %+v", len(jobs), jobs)
	}
	for _, j := range jobs {
		if j.Type != domain.JobIDOR || j.ScanID != env.scanID {
			t.Fatalf("bad job: %+v", j)
		}
	}
}

// TestEnqueueIDORProbesIsAutomaticOnlyWithACallerIdentity pins the new contract:
// there is no opt-in flag any more, so the scan's own session decides. An
// anonymous scan and an EXPIRED session plan nothing (there is no caller to
// compare against); an active authenticated session plans the pass with no
// configuration at all.
func TestEnqueueIDORProbesIsAutomaticOnlyWithACallerIdentity(t *testing.T) {
	for _, tc := range []struct {
		name  string
		mode  domain.AuthMode
		state domain.SessionState
		want  int
	}{
		{"no session", "", "", 0},
		{"anonymous session", domain.AuthAnonymous, domain.SessionActive, 0},
		{"expired session", domain.AuthExisting, domain.SessionExpired, 0},
		{"active session", domain.AuthExisting, domain.SessionActive, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newScanEnv(t)
			if tc.mode != "" {
				now := time.Now().UTC()
				sess := &domain.Session{
					ID: domain.NewID(), ScanID: env.scanID,
					Mode: tc.mode, State: tc.state,
					StatePath: filepath.Join(t.TempDir(), "session.json"),
					CreatedAt: now, UpdatedAt: now,
				}
				if err := env.st.Sessions().Create(context.Background(), sess); err != nil {
					t.Fatal(err)
				}
				env.sc.SessionID = sess.ID
				if err := env.st.Scans().Update(context.Background(), env.sc); err != nil {
					t.Fatal(err)
				}
			}
			q := queue.NewMemory()
			c := &Controller{store: env.st, queue: q, log: execLog()}
			ep := env.endpoint("http://127.0.0.1:1/my-account?id=wiener", domain.MethodGET)
			env.param(ep, "id", domain.LocationQuery, "wiener")

			c.enqueueIDORProbes(context.Background(), env.scanID)

			var jobs int
			for {
				j, err := q.Lease(context.Background(), "t", env.scanID, []domain.JobType{domain.JobIDOR}, time.Minute)
				if err != nil || j == nil {
					break
				}
				jobs++
			}
			if jobs != tc.want {
				t.Fatalf("enqueued %d IDOR jobs, want %d (mode=%q state=%q)", jobs, tc.want, tc.mode, tc.state)
			}
		})
	}
}

// TestJobIDORIsWiredToTheHTTPGroup is the "no special cases in the worker"
// gate: the new job type must be leased by the ordinary HTTP worker group and
// dispatched to the real handler, not a no-op.
func TestJobIDORIsWiredToTheHTTPGroup(t *testing.T) {
	env := newScanEnv(t)
	c := &Controller{store: env.st, log: execLog()}
	sc := &domain.Scan{Config: domain.ScanConfig{DiscoveryConcurrency: 1, HTTPConcurrency: 2, BrowserConcurrency: 1}}

	found := false
	for _, g := range c.poolConfig(sc).Groups {
		for _, ty := range g.Types {
			if ty != domain.JobIDOR {
				continue
			}
			found = true
			if g.Name != GroupHTTP {
				t.Fatalf("JobIDOR is routed to group %q, want %q", g.Name, GroupHTTP)
			}
		}
	}
	if !found {
		t.Fatal("JobIDOR is not in any worker group: queued IDOR jobs would never be leased")
	}
	h := c.defaultHandlers(nil, nil, openScope(), nil, ratelimit.New(0), []string{"carlos"})
	if _, ok := h[domain.JobIDOR].(*idorExecutor); !ok {
		t.Fatalf("JobIDOR handler = %T, want the real idorExecutor", h[domain.JobIDOR])
	}
}
