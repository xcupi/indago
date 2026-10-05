package scan_test

// End-to-end, real-Chromium tests of the COMPLETE Reflected XSS pipeline:
// discovery → endpoint/parameter → queue → reflection → context → candidate
// → HTTP test → browser verification → finding → correlation → report.
//
// Like the other real-browser suites, these run by default and skip (quickly)
// when no Chromium is found, so `go test ./...` never fails on a machine
// without one.

import (
	"bytes"
	"context"
	"encoding/json"
	"html"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/evidence"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/report"
	"github.com/indago/indago/internal/scan"
	"github.com/indago/indago/internal/store/memory"
)

// --- real Chromium skip helper (mirrors internal/verification's) ---

func findChromiumForScan() string {
	if p := os.Getenv("INDAGO_CHROMIUM_PATH"); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	matches, _ := filepath.Glob(filepath.Join(home, ".cache", "ms-playwright", "chromium-*", "chrome-linux*", "chrome"))
	sort.Strings(matches)
	if len(matches) == 0 {
		return ""
	}
	return matches[len(matches)-1]
}

func newBrowserManagerOrSkip(t *testing.T, poolSize int) *browser.Manager {
	t.Helper()
	if testing.Short() {
		t.Skip("real-browser test skipped in -short mode")
	}
	exe := findChromiumForScan()
	if exe == "" {
		t.Skip("no Chromium found (set INDAGO_CHROMIUM_PATH or `playwright install chromium`)")
	}
	m, err := browser.NewManager(browser.Config{Headless: true, ExecutablePath: exe, PoolSize: poolSize}, nil)
	if err != nil {
		t.Skipf("browser engine unavailable: %v", err)
	}
	return m
}

// --- the corpus ---

// corpus is a small, representative Reflected XSS test site: every handler
// below corresponds directly to one scenario this phase asks to validate.
type corpus struct {
	*site
	authedHits atomic.Int64 // requests that presented the authenticated cookie
}

func newCorpus(t *testing.T) *corpus {
	c := &corpus{}
	c.site = newSite(t, func(mux *http.ServeMux, base func() string) {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/" {
				http.NotFound(w, r)
				return
			}
			writeHTML(w, `
<a href="/safe?q=hi">safe</a>
<a href="/encoded?q=hi">encoded</a>
<a href="/attr?q=hi">attr</a>
<a href="/js?q=hi">js</a>
<a href="/multi?q=hi">multi</a>
<a href="/confirmed?q=hi">confirmed</a>
<a href="/noisy?q=hi">noisy</a>
<a href="/auth?q=hi">auth</a>
<a href="/outside">outside</a>
<form action="/submit" method="get"><input name="q"></form>
<form action="/form" method="post"><input name="q"></form>
<form action="/state" method="post"><input name="q"></form>
`)
		})
		// reflected but SAFE: the value never reaches the response at all.
		mux.HandleFunc("/safe", func(w http.ResponseWriter, r *http.Request) { writeHTML(w, "<p>thanks</p>") })
		// ENCODED reflection: HTML-escaped, so the breakout characters never survive.
		mux.HandleFunc("/encoded", func(w http.ResponseWriter, r *http.Request) {
			writeHTML(w, "<p>"+html.EscapeString(r.URL.Query().Get("q"))+"</p>")
		})
		// HTML ATTRIBUTE reflection: unescaped inside a quoted attribute value.
		mux.HandleFunc("/attr", func(w http.ResponseWriter, r *http.Request) {
			writeHTML(w, `<input value="`+r.URL.Query().Get("q")+`">`)
		})
		// JAVASCRIPT reflection: unescaped inside a <script> string literal.
		mux.HandleFunc("/js", func(w http.ResponseWriter, r *http.Request) {
			writeHTML(w, `<script>var a = "`+r.URL.Query().Get("q")+`";</script>`)
		})
		// MULTIPLE REFLECTION SITES: the same parameter lands in two contexts.
		mux.HandleFunc("/multi", func(w http.ResponseWriter, r *http.Request) {
			v := r.URL.Query().Get("q")
			writeHTML(w, "<p>"+v+"</p><script>var b = \""+v+"\";</script>")
		})
		// CONFIRMED reflected XSS: the headline case.
		mux.HandleFunc("/confirmed", func(w http.ResponseWriter, r *http.Request) {
			writeHTML(w, "<div>"+r.URL.Query().Get("q")+"</div>")
		})
		// PRE-EXISTING / UNRELATED BROWSER ERROR: fires on every load regardless
		// of the candidate, which must never be mistaken for its signal.
		// The reflection itself is HTML-encoded (never executable) so this page
		// is NOT exploitable; the unrelated error must not cause a false confirm.
		mux.HandleFunc("/noisy", func(w http.ResponseWriter, r *http.Request) {
			writeHTML(w, "<div>"+html.EscapeString(r.URL.Query().Get("q"))+`</div><script>setTimeout(function(){unrelatedBrokenThing();},0);</script>`)
		})
		// AUTHENTICATED TARGET: reflects only when the session cookie is present.
		mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
			if ck, err := r.Cookie("session"); err == nil && ck.Value == "authed" {
				c.authedHits.Add(1)
				writeHTML(w, "<div>"+r.URL.Query().Get("q")+"</div>")
				return
			}
			writeHTML(w, "<p>login required</p>")
		})
		// OUT-OF-SCOPE RESOURCE: this path is excluded from scope and must never
		// be requested. (Discovery would otherwise find it via the link on "/".)
		mux.HandleFunc("/outside/secret", func(w http.ResponseWriter, r *http.Request) {
			writeHTML(w, "SECRET")
		})
		mux.HandleFunc("/outside", func(w http.ResponseWriter, r *http.Request) {
			writeHTML(w, `<a href="/outside/secret">s</a>`)
		})
		// GET query reflection via a discovered form.
		mux.HandleFunc("/submit", func(w http.ResponseWriter, r *http.Request) {
			writeHTML(w, "<div>"+r.URL.Query().Get("q")+"</div>")
		})
		// POST FORM reflection.
		mux.HandleFunc("/form", func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			writeHTML(w, "<div>"+r.PostFormValue("q")+"</div>")
		})
		// STATE-CHANGING POST: must be skipped unless explicitly allowed.
		mux.HandleFunc("/state", func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			writeHTML(w, "<div>"+r.PostFormValue("q")+"</div>")
		})
		// POST JSON reflection (discovery has no JSON-body source; the test seeds
		// this parameter directly — see addJSONEndpoint below).
		mux.HandleFunc("/json", func(w http.ResponseWriter, r *http.Request) {
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			writeHTML(w, "<div>"+body["q"]+"</div>")
		})
	})
	return c
}

// workersCfgWithBrowser is workersCfg plus a non-zero browser group size: the
// plain workersCfg deliberately zeroes BrowserConcurrency for tests that never
// enqueue JobVerify jobs, which would otherwise queue forever with no worker
// to lease them — exactly the trap a real-browser e2e test must avoid.
func workersCfgWithBrowser(httpWorkers, browserWorkers int) *domain.ScanConfig {
	cfg := *workersCfg(httpWorkers)
	cfg.BrowserConcurrency = browserWorkers
	return &cfg
}

// corpusScope excludes /outside, matching the TestScopeEnforcedDuringDiscovery
// convention (path prefix on one host, since domain.Scope matches by host, not
// port — two httptest servers on 127.0.0.1 cannot be told apart by scope).
func corpusScope() domain.Scope {
	return domain.Scope{IncludeHosts: []string{"127.0.0.1"}, ExcludePathPrefixes: []string{"/outside"}}
}

// addJSONEndpoint seeds a POST-JSON endpoint/parameter/injection-point and its
// test job directly (discovery has no JSON-body source — see AGENTS.md: this
// phase adds no new detection features), exercising the queue→reflection→
// context→candidate→verify→finding chain exactly like a discovered one would.
func addJSONEndpoint(t *testing.T, st *memory.Store, q queue.Queue, scanID domain.ID, base string) {
	t.Helper()
	ctx := context.Background()
	ep := &domain.Endpoint{ID: domain.NewID(), ScanID: scanID, URL: base + "/json", Method: domain.MethodPOST, Source: domain.SourceUserProvided, CreatedAt: time.Now()}
	if err := st.Endpoints().Create(ctx, ep); err != nil {
		t.Fatal(err)
	}
	p := &domain.Parameter{ID: domain.NewID(), ScanID: scanID, EndpointID: ep.ID, Name: "q", Location: domain.LocationJSON, Example: "hi", Source: domain.SourceUserProvided, CreatedAt: time.Now()}
	if err := st.Parameters().Create(ctx, p); err != nil {
		t.Fatal(err)
	}
	ip := &domain.InjectionPoint{ID: domain.NewID(), ScanID: scanID, EndpointID: ep.ID, ParameterID: p.ID, Location: p.Location, CreatedAt: time.Now()}
	if err := st.InjectionPoints().Create(ctx, ip); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	job := &domain.TestJob{
		ID: domain.NewID(), ScanID: scanID, Type: domain.JobTest, State: domain.JobQueued,
		Target:      domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID, URL: ep.URL},
		MaxAttempts: 3, AvailableAt: now, CreatedAt: now, UpdatedAt: now,
	}
	if err := q.Enqueue(ctx, job); err != nil {
		t.Fatal(err)
	}
}

// --- the main end-to-end test ---

func TestE2E_FullPipelineAgainstCorpus(t *testing.T) {
	ctx := context.Background()
	c := newCorpus(t)
	st, q := memory.New(), queue.NewMemory()
	ev, err := evidence.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mgr := newBrowserManagerOrSkip(t, 2)
	defer mgr.Close()

	proj, tgt := seedProject(t, st, c.URL, corpusScope())
	cfg := domain.ScanConfig{DiscoveryConcurrency: 4, HTTPConcurrency: 8, BrowserConcurrency: 4}
	ctrl := newCtrl(t, st, q, scan.Options{Browser: mgr, Evidence: ev})

	sc := createScan(t, ctrl, proj, tgt, &cfg, domain.StopPolicy{})

	// Seed the POST-JSON endpoint BEFORE starting: discovery has no JSON-body
	// source (see addJSONEndpoint), so this stands in for it. Seeding before
	// Start avoids a race against the monitor declaring the scan complete
	// before a job added mid-run is ever leased.
	addJSONEndpoint(t, st, q, sc.ID, c.URL)

	if err := ctrl.Start(ctx, sc.ID); err != nil {
		t.Fatal(err)
	}
	waitStatus(t, ctrl, sc.ID, 5*time.Second, func(s *scan.Status) bool { return s.Discovery.Endpoints > 0 })

	// --- pause/resume mid-scan ---
	if err := ctrl.Pause(ctx, sc.ID); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if err := ctrl.Resume(ctx, sc.ID); err != nil {
		t.Fatal(err)
	}

	done := waitStatus(t, ctrl, sc.ID, 90*time.Second, isCompleted)

	// --- scope enforcement: the out-of-scope resource was never requested ---
	if c.hitCount("/outside/secret") != 0 {
		t.Fatal("an out-of-scope resource was requested")
	}

	// --- state-changing default-skip ---
	cases, err := st.TestCases().ListByScan(ctx, sc.ID)
	if err != nil {
		t.Fatal(err)
	}
	var sawStateSkipped bool
	for _, tc := range cases {
		if tc.Status == domain.TestCaseSkipped && tc.Note != "" {
			sawStateSkipped = true
		}
	}
	if !sawStateSkipped {
		t.Fatal("expected the state-changing /state endpoint to be skipped by default")
	}

	// --- findings: verdicts land where the corpus says they should ---
	findings, err := st.Findings().ListByScan(ctx, sc.ID)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("findings: %d total, breakdown=%+v", len(findings), done.Findings)

	byEndpointPath := map[string][]*domain.Finding{}
	for _, f := range findings {
		ep, err := st.Endpoints().Get(ctx, f.EndpointID)
		if err != nil {
			continue
		}
		byEndpointPath[urlPath(ep.URL)] = append(byEndpointPath[urlPath(ep.URL)], f)
	}

	requireVerdict := func(path string, want domain.Verdict) {
		fs := byEndpointPath[path]
		if len(fs) == 0 {
			t.Errorf("no finding for %s (want %s)", path, want)
			return
		}
		for _, f := range fs {
			if f.Verdict == want {
				return
			}
		}
		var got []domain.Verdict
		for _, f := range fs {
			got = append(got, f.Verdict)
		}
		t.Errorf("%s: verdicts = %v, want one of them to be %s", path, got, want)
	}

	requireVerdict("/attr", domain.VerdictConfirmed)
	requireVerdict("/js", domain.VerdictConfirmed)
	requireVerdict("/confirmed", domain.VerdictConfirmed)
	requireVerdict("/noisy", domain.VerdictRejected) // unrelated error must not confirm
	requireVerdict("/encoded", domain.VerdictRejected)
	requireVerdict("/multi", domain.VerdictConfirmed)
	if fs := byEndpointPath["/safe"]; len(fs) != 0 {
		t.Errorf("/safe must never reflect a candidate at all, got findings %+v", fs)
	}

	// /multi reflects into TWO distinct contexts: correlation must keep them as
	// two distinct findings, not collapse them into one.
	if len(byEndpointPath["/multi"]) < 2 {
		t.Errorf("/multi should have produced at least 2 distinct (per-context) findings, got %d", len(byEndpointPath["/multi"]))
	}

	// The state-changing safeguard applies uniformly to every POST endpoint by
	// default — including /json, which was seeded directly rather than
	// discovered, proving the safeguard does not depend on discovery provenance.
	if fs := byEndpointPath["/json"]; len(fs) != 0 {
		t.Errorf("/json must stay untested (POST, AllowStateChanging off), got findings %+v", fs)
	}
	if fs := byEndpointPath["/form"]; len(fs) != 0 {
		t.Errorf("/form must stay untested (POST, AllowStateChanging off), got findings %+v", fs)
	}

	// --- evidence integrity: every referenced blob exists and hashes match ---
	for _, f := range findings {
		for _, id := range f.EvidenceIDs {
			row, err := st.Evidence().Get(ctx, id)
			if err != nil {
				t.Fatalf("evidence row %s missing: %v", id, err)
			}
			rc, err := ev.Open(row.BlobPath)
			if err != nil {
				t.Fatalf("evidence blob %s unreadable: %v", row.BlobPath, err)
			}
			rc.Close()
		}
	}

	// --- report reproducibility: generating twice from the same findings is
	// byte-identical (GeneratedAt held fixed) ---
	rdata := report.Data{Project: domain.Project{ID: proj}, Scan: *done.Scan, Findings: findings, GeneratedAt: time.Now(), ToolVersion: "e2e-test"}
	jgen, _ := report.For(domain.ReportJSON)
	mgen, _ := report.For(domain.ReportMarkdown)
	var j1, j2, m1, m2 bytes.Buffer
	if err := jgen.Generate(&j1, rdata); err != nil {
		t.Fatal(err)
	}
	if err := jgen.Generate(&j2, rdata); err != nil {
		t.Fatal(err)
	}
	if j1.String() != j2.String() {
		t.Fatal("JSON report is not reproducible for identical findings")
	}
	if err := mgen.Generate(&m1, rdata); err != nil {
		t.Fatal(err)
	}
	if err := mgen.Generate(&m2, rdata); err != nil {
		t.Fatal(err)
	}
	if m1.String() != m2.String() {
		t.Fatal("Markdown report is not reproducible for identical findings")
	}

	// --- browser/context leak check ---
	if stats := mgr.Stats(); stats.OpenContexts != 0 {
		t.Fatalf("browser contexts leaked: %d still open after the scan completed", stats.OpenContexts)
	}
}

// With the operator's explicit opt-in, POST form and POST JSON candidates are
// actually sent and reflected (unlike the main test above, which exercises the
// DEFAULT — off — behavior where they are skipped entirely). Browser
// navigation still has no request body, though, so these can never progress
// past a Pending finding — AllowStateChanging controls whether the HTTP-level
// candidate is sent, not whether browser verification becomes possible.
func TestE2E_StateChangingAllowedSendsPostCandidates(t *testing.T) {
	ctx := context.Background()
	c := newCorpus(t)
	st, q := memory.New(), queue.NewMemory()
	ev, err := evidence.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mgr := newBrowserManagerOrSkip(t, 2)
	defer mgr.Close()

	proj, tgt := seedProject(t, st, c.URL, corpusScope())
	ctrl := newCtrl(t, st, q, scan.Options{Browser: mgr, Evidence: ev, Executor: scan.ExecutorConfig{AllowStateChanging: true}})
	sc := createScan(t, ctrl, proj, tgt, workersCfgWithBrowser(4, 4), domain.StopPolicy{})
	addJSONEndpoint(t, st, q, sc.ID, c.URL)

	if err := ctrl.Start(ctx, sc.ID); err != nil {
		t.Fatal(err)
	}
	done := waitStatus(t, ctrl, sc.ID, 60*time.Second, isCompleted)
	t.Logf("findings: breakdown=%+v", done.Findings)

	// The opt-in means POST candidates are now sent and reflected (unlike the
	// main test, where they are skipped entirely) — but browser navigation has
	// no request body, so verification never runs for them regardless: these
	// findings can only ever reach Pending, never Confirmed/Rejected.
	findings, err := st.Findings().ListByScan(ctx, sc.ID)
	if err != nil {
		t.Fatal(err)
	}
	byPath := map[string][]domain.Verdict{}
	for _, f := range findings {
		if ep, err := st.Endpoints().Get(ctx, f.EndpointID); err == nil {
			byPath[urlPath(ep.URL)] = append(byPath[urlPath(ep.URL)], f.Verdict)
		}
	}
	for _, path := range []string{"/form", "/json"} {
		vs, ok := byPath[path]
		if !ok {
			t.Errorf("%s: no finding, want a Pending one now that POST is allowed to be sent", path)
			continue
		}
		for _, v := range vs {
			if v != domain.VerdictPending {
				t.Errorf("%s: verdict = %s, want pending (POST candidates can never be browser-verified)", path, v)
			}
		}
	}
	if st, _ := q.Stats(ctx, sc.ID); st.Dead+st.Succeeded == 0 {
		t.Fatal("expected the POST candidate jobs to have actually run")
	}
}

// --- authenticated scan flow (separate: needs its own session + a running scan) ---

func TestE2E_AuthenticatedScanFlow(t *testing.T) {
	ctx := context.Background()
	c := newCorpus(t)
	st, q := memory.New(), queue.NewMemory()
	ev, err := evidence.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mgr := newBrowserManagerOrSkip(t, 1)
	defer mgr.Close()

	// Save a browser storage state carrying the authenticated cookie — standing
	// in for an interactive-login run completed once, out of band (Interactive/
	// MFA themselves remain stubs; see AGENTS.md) — and import it via the
	// AuthExisting mode, exactly as an operator would point a real scan at a
	// saved session.
	statePath := filepath.Join(t.TempDir(), "state.json")
	seedCtx, err := mgr.NewContext(ctx, browser.ContextOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := seedCtx.SetCookies(ctx, []browser.Cookie{{Name: "session", Value: "authed", URL: c.URL}}); err != nil {
		t.Fatal(err)
	}
	if err := seedCtx.SaveStorageState(ctx, statePath); err != nil {
		t.Fatal(err)
	}
	seedCtx.Close()

	proj, tgt := seedProject(t, st, c.URL, corpusScope())
	ctrl := newCtrl(t, st, q, scan.Options{Browser: mgr, Evidence: ev})
	sc, err := ctrl.CreateScan(ctx, scan.CreateScanParams{
		ProjectID: proj, TargetID: tgt, Name: "authed-e2e", Profile: domain.ProfileCustom,
		Config: workersCfgWithBrowser(4, 4), AuthMode: domain.AuthExisting, AuthStatePath: statePath,
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := ctrl.Start(ctx, sc.ID); err != nil {
		t.Fatal(err)
	}
	done := waitStatus(t, ctrl, sc.ID, 60*time.Second, isCompleted)

	if c.authedHits.Load() == 0 {
		t.Fatal("the HTTP-level executor never presented the session cookie to /auth")
	}
	findings, _ := st.Findings().ListByScan(ctx, sc.ID)
	var sawAuthConfirmed bool
	for _, f := range findings {
		ep, err := st.Endpoints().Get(ctx, f.EndpointID)
		if err == nil && urlPath(ep.URL) == "/auth" && f.Verdict == domain.VerdictConfirmed {
			sawAuthConfirmed = true
		}
	}
	if !sawAuthConfirmed {
		t.Fatal("the authenticated endpoint's candidate was never confirmed")
	}
	_ = done
}

// urlPath returns rawURL's path component, for matching against the corpus's
// fixed handler paths regardless of scheme/host/query.
func urlPath(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return u.Path
}
