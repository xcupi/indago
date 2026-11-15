package scan

// Built-in OAST collaborator wiring tests.
//
// The property under test is the one the feature promises: when the server was
// started with a local OAST manager, an engine that confirms a vulnerability by
// callback gets a collaborator without any operator configuration, and a real
// callback through that manager turns into a confirmed finding. Every test is
// hermetic: the "target" is an httptest server, the collaborator is an
// oast.Manager bound to loopback, and the only network traffic is between them.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/oast"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/ratelimit"
	"github.com/indago/indago/internal/worker"
)

// oastTestManager starts a loopback OAST manager for the duration of the test.
func oastTestManager(t *testing.T, mutate func(*oast.Config)) *oast.Manager {
	t.Helper()
	cfg := oast.Config{}
	if mutate != nil {
		mutate(&cfg)
	}
	mgr, err := oast.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("oast.New: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Close() })
	return mgr
}

// oastTestHandlers builds the real handler set for a scan whose controller has
// the given collaborator — the same path scan.Start takes.
func oastTestHandlers(t *testing.T, env *scanEnv, mgr OASTCollaborator, cfg domain.ScanConfig, exec ExecutorConfig) map[domain.JobType]worker.Handler {
	t.Helper()
	c := &Controller{store: env.st, log: execLog(), opts: Options{OAST: mgr, Executor: exec, Evidence: env.ev}}
	sc := &domain.Scan{ID: env.scanID, Config: cfg, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	return c.defaultHandlers(sc, scopedClient(t, openScope()), openScope(), nil, ratelimit.New(0), nil)
}

// oastDecodeDetail decodes a TestCase detail blob into the engine's own detail
// struct, so an assertion reads the verdict the engine actually recorded.
func oastDecodeDetail(t *testing.T, raw []byte, into any) {
	t.Helper()
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatalf("decode detail: %v (raw %s)", err, string(raw))
	}
}

func oastPollBody(t *testing.T, pollURL string) string {
	t.Helper()
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(pollURL)
	if err != nil {
		t.Fatalf("poll %s: %v", pollURL, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("poll body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("poll status = %d, want 200 (body %s)", resp.StatusCode, body)
	}
	return string(body)
}

func oastFinding(t *testing.T, env *scanEnv, class domain.VulnClass) *domain.Finding {
	t.Helper()
	findings, err := env.st.Findings().ListByScan(context.Background(), env.scanID)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.VulnClass == class {
			return f
		}
	}
	t.Fatalf("no %s finding among %+v", class, findings)
	return nil
}

// --- no collaborator: nothing changes -------------------------------------

// TestOASTWiringDisabledByDefault is the zero-breaking-change guarantee: with
// no manager configured, every out-of-band engine still receives exactly the
// callback configuration the operator supplied (here: none), which is the
// "engine skips itself" path it has always had.
func TestOASTWiringDisabledByDefault(t *testing.T) {
	env := newScanEnv(t)
	// The state-changing opt-in is on so the XXE engine reaches its collaborator
	// gate — the branch this test is about — instead of stopping earlier.
	h := oastTestHandlers(t, env, nil, domain.ScanConfig{}, ExecutorConfig{AllowStateChanging: true})

	if got := h[domain.JobXXE].(*xxeExecutor); got.callback != "" || got.poll != "" {
		t.Fatalf("xxe callbacks = (%q, %q), want both empty without a collaborator", got.callback, got.poll)
	}
	if got := h[domain.JobCommandInjection].(*commandInjectionExecutor); got.callbackURL != "" || got.callbackPollURL != "" {
		t.Fatalf("command-injection callbacks = (%q, %q), want both empty without a collaborator", got.callbackURL, got.callbackPollURL)
	}
	if got := h[domain.JobSSRF].(*ssrfExecutor); got.callbackURL != "" || got.callbackPollURL != "" {
		t.Fatalf("ssrf callbacks = (%q, %q), want both empty without a collaborator", got.callbackURL, got.callbackPollURL)
	}

	// And the engine still behaves as before: XXE with no collaborator is
	// skipped, not run against a half-built callback.
	ep := &domain.Endpoint{ID: domain.NewID(), ScanID: env.scanID, URL: "http://127.0.0.1:1/x",
		Method: domain.MethodPOST, Source: domain.SourceBrowserNetwork, ContentType: "application/xml",
		RequestBody: `<a><b>1</b></a>`, CreatedAt: time.Now()}
	if err := env.st.Endpoints().Create(context.Background(), ep); err != nil {
		t.Fatal(err)
	}
	job := &domain.TestJob{ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobXXE,
		Target: domain.JobTarget{EndpointID: ep.ID, URL: ep.URL}, Attempts: 1, MaxAttempts: 1}
	if err := h[domain.JobXXE].Handle(context.Background(), job); err != nil {
		t.Fatalf("handle: %v", err)
	}
	tc := env.only()
	if tc.Status != domain.TestCaseSkipped || !strings.Contains(tc.Note, "no XXE callback configured") {
		t.Fatalf("test case = %+v, want the unchanged 'no XXE callback configured' skip", tc)
	}
}

// --- loopback collaborator: XXE + command injection -----------------------

// TestOASTWiringLoopbackWiresXXEAndCommandInjection checks the URLs the engines
// actually receive: one listener base URL for the target, one loopback poll URL
// for the scanner, and — deliberately — no SSRF canary from a loopback host.
func TestOASTWiringLoopbackWiresXXEAndCommandInjection(t *testing.T) {
	mgr := oastTestManager(t, nil)
	env := newScanEnv(t)
	c := &Controller{store: env.st, log: execLog(), opts: Options{OAST: mgr}}
	if c.oastCollaborator() != c.oastCollaborator() {
		t.Fatal("collaborator wiring is not cached per controller")
	}

	h := oastTestHandlers(t, env, mgr, domain.ScanConfig{}, ExecutorConfig{})

	pollURL := ""
	xxe := h[domain.JobXXE].(*xxeExecutor)
	if xxe.callback != mgr.BaseURL() {
		t.Fatalf("xxe callback = %q, want the collaborator base URL %q", xxe.callback, mgr.BaseURL())
	}
	if xxe.poll == "" {
		t.Fatal("xxe poll URL is empty, want the collaborator's poll API")
	}
	pollURL = xxe.poll

	cmdi := h[domain.JobCommandInjection].(*commandInjectionExecutor)
	if cmdi.callbackURL != mgr.BaseURL() || cmdi.callbackPollURL != pollURL {
		t.Fatalf("command-injection callbacks = (%q, %q), want (%q, %q)",
			cmdi.callbackURL, cmdi.callbackPollURL, mgr.BaseURL(), pollURL)
	}

	// The poll API is the scanner's own read path: loopback only, never the
	// callback base URL a target is given.
	u, err := url.Parse(pollURL)
	if err != nil {
		t.Fatalf("parse poll URL: %v", err)
	}
	if host, _, _ := net.SplitHostPort(u.Host); host != "127.0.0.1" {
		t.Fatalf("poll host = %q, want the loopback listener", u.Host)
	}
	if strings.HasPrefix(pollURL, mgr.BaseURL()) {
		t.Fatalf("poll URL %q is derived from the target-visible base URL %q", pollURL, mgr.BaseURL())
	}

	// SSRF refuses a loopback canary by design (ssrfOASTCanary), so a
	// loopback-only listener must leave it unwired rather than hand it a URL it
	// would reject on every probe.
	ssrf := h[domain.JobSSRF].(*ssrfExecutor)
	if ssrf.callbackURL != "" || ssrf.callbackPollURL != "" {
		t.Fatalf("ssrf callbacks = (%q, %q), want none for a loopback collaborator", ssrf.callbackURL, ssrf.callbackPollURL)
	}
	if note := c.oastCollaborator().SSRFNote; !strings.Contains(note, "loopback") {
		t.Fatalf("ssrf note = %q, want it to name the loopback refusal", note)
	}
}

// --- operator configuration wins ------------------------------------------

func TestOASTWiringOperatorOverrideWins(t *testing.T) {
	mgr := oastTestManager(t, nil)
	env := newScanEnv(t)
	cfg := domain.ScanConfig{
		XXECallbackURL:                  "https://operator.example/xxe",
		XXECallbackPollURL:              "https://operator.example/xxe/poll",
		CommandInjectionCallbackURL:     "https://operator.example/cmdi",
		CommandInjectionCallbackPollURL: "https://operator.example/cmdi/poll",
		SSRFCallbackURL:                 "https://operator.example/ssrf",
		SSRFCallbackPollURL:             "https://operator.example/ssrf/poll",
	}
	h := oastTestHandlers(t, env, mgr, cfg, ExecutorConfig{})

	xxe := h[domain.JobXXE].(*xxeExecutor)
	if xxe.callback != cfg.XXECallbackURL || xxe.poll != cfg.XXECallbackPollURL {
		t.Fatalf("xxe callbacks = (%q, %q), want the operator's own", xxe.callback, xxe.poll)
	}
	cmdi := h[domain.JobCommandInjection].(*commandInjectionExecutor)
	if cmdi.callbackURL != cfg.CommandInjectionCallbackURL || cmdi.callbackPollURL != cfg.CommandInjectionCallbackPollURL {
		t.Fatalf("command-injection callbacks = (%q, %q), want the operator's own", cmdi.callbackURL, cmdi.callbackPollURL)
	}
	ssrf := h[domain.JobSSRF].(*ssrfExecutor)
	if ssrf.callbackURL != cfg.SSRFCallbackURL || ssrf.callbackPollURL != cfg.SSRFCallbackPollURL {
		t.Fatalf("ssrf callbacks = (%q, %q), want the operator's own", ssrf.callbackURL, ssrf.callbackPollURL)
	}
}

// TestOASTWiringHalfConfiguredPairIsNotMixed covers the subtle case: an operator
// who set only one half of a pair gets it passed through untouched. Mixing the
// operator's callback with the built-in poll API would point the engine at a
// listener that never receives that service's hits.
func TestOASTWiringHalfConfiguredPairIsNotMixed(t *testing.T) {
	mgr := oastTestManager(t, nil)
	env := newScanEnv(t)
	cfg := domain.ScanConfig{XXECallbackURL: "https://operator.example/xxe"}
	h := oastTestHandlers(t, env, mgr, cfg, ExecutorConfig{})

	xxe := h[domain.JobXXE].(*xxeExecutor)
	if xxe.callback != cfg.XXECallbackURL {
		t.Fatalf("xxe callback = %q, want the operator's", xxe.callback)
	}
	if xxe.poll != "" {
		t.Fatalf("xxe poll = %q, want it left empty rather than mixed with the built-in poll API", xxe.poll)
	}
}

// --- a published collaborator makes SSRF eligible -------------------------

// TestOASTWiringPublicBaseURLWiresSSRF covers the deployment the feature is
// really for: a loopback listener published through a tunnel. The callback URL
// must then be both what a target can reach and what the SSRF engine's own
// canary rules accept.
func TestOASTWiringPublicBaseURLWiresSSRF(t *testing.T) {
	const publicURL = "https://oast.example.test"
	mgr := oastTestManager(t, func(c *oast.Config) { c.PublicBaseURL = publicURL })
	env := newScanEnv(t)
	h := oastTestHandlers(t, env, mgr, domain.ScanConfig{}, ExecutorConfig{})

	if got := mgr.BaseURL(); got != publicURL {
		t.Fatalf("base URL = %q, want the published URL %q", got, publicURL)
	}
	ssrf := h[domain.JobSSRF].(*ssrfExecutor)
	if ssrf.callbackURL != publicURL {
		t.Fatalf("ssrf callback = %q, want %q", ssrf.callbackURL, publicURL)
	}
	if ssrf.callbackPollURL == "" {
		t.Fatal("ssrf poll URL is empty")
	}
	// Both halves must survive the engine's own validation, or the wiring is
	// cosmetic: the canary would be refused and the poll never fetched.
	canary, err := ssrfOASTCanary(ssrf.callbackURL)
	if err != nil {
		t.Fatalf("the wired canary is refused by the engine: %v", err)
	}
	if u, perr := url.Parse(canary.URL); perr != nil || u.Hostname() != "oast.example.test" {
		t.Fatalf("canary URL = %q, want it under %s", canary.URL, publicURL)
	}
	if _, err := ssrfPollURL(ssrf.callbackPollURL); err != nil {
		t.Fatalf("the wired poll URL is refused by the engine: %v", err)
	}
}

// --- end to end: a real callback confirms through the manager -------------

// TestOASTWiringXXEEndToEnd runs the real XXE handler over the real wiring: the
// vulnerable target resolves the external entity by calling the collaborator,
// the manager records the hit, the engine finds its marker in the poll API's
// body, and the result is a Confirmed finding.
func TestOASTWiringXXEEndToEnd(t *testing.T) {
	mgr := oastTestManager(t, nil)
	systemURL := regexp.MustCompile(`SYSTEM "([^"]+)"`)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if m := systemURL.FindStringSubmatch(string(body)); m != nil {
			// The target's "XML parser" resolving the external entity.
			if resp, err := http.Get(m[1]); err == nil {
				resp.Body.Close()
			}
		}
		fmt.Fprint(w, "<result>ok</result>")
	}))
	defer target.Close()

	env := newScanEnv(t)
	ep := &domain.Endpoint{ID: domain.NewID(), ScanID: env.scanID, URL: target.URL + "/stock",
		Method: domain.MethodPOST, Source: domain.SourceBrowserNetwork, ContentType: "application/xml",
		RequestBody: `<stockCheck><productId>1</productId></stockCheck>`, CreatedAt: time.Now()}
	if err := env.st.Endpoints().Create(context.Background(), ep); err != nil {
		t.Fatal(err)
	}
	// XXE is a body-carrying method, so the state-changing opt-in is required —
	// the same policy every scan is subject to.
	h := oastTestHandlers(t, env, mgr, domain.ScanConfig{}, ExecutorConfig{AllowStateChanging: true})
	job := &domain.TestJob{ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobXXE,
		Target: domain.JobTarget{EndpointID: ep.ID, URL: ep.URL}, Attempts: 1, MaxAttempts: 1}
	if err := h[domain.JobXXE].Handle(context.Background(), job); err != nil {
		t.Fatalf("handle: %v", err)
	}

	tc := env.only()
	var d xxeDetail
	oastDecodeDetail(t, tc.Detail, &d)
	if d.Verdict != domain.VerdictConfirmed {
		t.Fatalf("xxe detail = %+v, want a callback-confirmed verdict", d)
	}
	confirmed := false
	for _, a := range d.Attempts {
		if a.Callback {
			confirmed = true
		}
	}
	if !confirmed {
		t.Fatalf("xxe attempts = %+v, want one carrying the callback", d.Attempts)
	}
	// The hit is the manager's, not a test stub's.
	hits := mgr.Interactions()
	if len(hits) != 1 {
		t.Fatalf("collaborator interactions = %d (%+v), want the one callback", len(hits), hits)
	}
	if !strings.Contains(hits[0].Path, "indago-xxe-") || hits[0].Source != string(oast.ModeLocal) {
		t.Fatalf("interaction = %+v, want the XXE marker recorded by the local listener", hits[0])
	}
	poll, err := mgr.PollURL()
	if err != nil {
		t.Fatalf("poll URL: %v", err)
	}
	if body := oastPollBody(t, poll); !strings.Contains(body, strings.TrimPrefix(hits[0].Path, "/")) {
		t.Fatalf("poll body does not report the hit:\n%s", body)
	}
	if f := oastFinding(t, env, domain.VulnXXE); f.Verdict != domain.VerdictConfirmed {
		t.Fatalf("finding verdict = %q, want confirmed", f.Verdict)
	}
}

// TestOASTWiringCommandInjectionEndToEnd does the same for blind command
// injection: the target "executes" the injected curl by calling the
// collaborator with the engine's marker in the query string.
func TestOASTWiringCommandInjectionEndToEnd(t *testing.T) {
	mgr := oastTestManager(t, nil)
	anyURL := regexp.MustCompile(`https?://[^\s"]+`)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m := anyURL.FindString(r.URL.Query().Get("cmd")); m != "" {
			// The target's "shell" running the injected curl.
			if resp, err := http.Get(m); err == nil {
				resp.Body.Close()
			}
		}
		fmt.Fprint(w, "ok")
	}))
	defer target.Close()

	env := newScanEnv(t)
	ep := env.endpoint(target.URL+"/run", domain.MethodGET)
	focus := env.param(ep, "cmd", domain.LocationQuery, "1")
	ip := env.injection(ep, focus)
	h := oastTestHandlers(t, env, mgr, domain.ScanConfig{}, ExecutorConfig{})
	job := &domain.TestJob{ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobCommandInjection,
		Target: domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID, URL: ep.URL}, Attempts: 1, MaxAttempts: 1}
	if err := h[domain.JobCommandInjection].Handle(context.Background(), job); err != nil {
		t.Fatalf("handle: %v", err)
	}

	tc := env.only()
	var d commandInjectionDetail
	oastDecodeDetail(t, tc.Detail, &d)
	if d.Verdict != domain.VerdictConfirmed || d.ConfirmMethod != "oob" {
		t.Fatalf("command-injection detail = %+v, want confirmed via oob", d)
	}
	hits := mgr.Interactions()
	if len(hits) != 1 {
		t.Fatalf("collaborator interactions = %d (%+v), want the one callback", len(hits), hits)
	}
	if !strings.Contains(hits[0].Query, "marker=indago-oob-") {
		t.Fatalf("interaction query = %q, want the engine's OOB marker", hits[0].Query)
	}
	if f := oastFinding(t, env, domain.VulnCommandInjection); f.Verdict != domain.VerdictConfirmed {
		t.Fatalf("finding verdict = %q, want confirmed", f.Verdict)
	}
}

// TestOASTWiringSSRFEndToEnd covers the published-collaborator path end to end:
// the target fetches the canary the engine built from the manager's base URL
// (the test resolves that name to the listener, exactly as DNS would), and the
// engine confirms from the poll API.
func TestOASTWiringSSRFEndToEnd(t *testing.T) {
	const publicHost = "oast.example.test"
	mgr := oastTestManager(t, func(c *oast.Config) { c.PublicBaseURL = "https://" + publicHost })
	listenAddr := mgr.ListenAddr()
	if listenAddr == "" {
		t.Fatal("manager reported no listener address")
	}

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := r.URL.Query().Get("url")
		if u, err := url.Parse(raw); err == nil && u.Hostname() == publicHost {
			// "Resolve" the published name to the local listener.
			u.Scheme, u.Host = "http", listenAddr
			if resp, err := http.Get(u.String()); err == nil {
				resp.Body.Close()
			}
		}
		fmt.Fprint(w, "image loaded")
	}))
	defer target.Close()

	env := newScanEnv(t)
	ep := env.endpoint(target.URL+"/fetch", domain.MethodGET)
	focus := env.param(ep, "url", domain.LocationQuery, "https://example.com/a.png")
	ip := env.injection(ep, focus)
	h := oastTestHandlers(t, env, mgr, domain.ScanConfig{}, ExecutorConfig{})
	job := &domain.TestJob{ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobSSRF,
		Target: domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID, URL: ep.URL}, Attempts: 1, MaxAttempts: 1}
	if err := h[domain.JobSSRF].Handle(context.Background(), job); err != nil {
		t.Fatalf("handle: %v", err)
	}

	tc := env.only()
	var d ssrfDetail
	oastDecodeDetail(t, tc.Detail, &d)
	if d.Verdict != domain.VerdictConfirmed || d.ConfirmMethod != ssrfConfirmOAST {
		t.Fatalf("ssrf detail = %+v, want confirmed via oast (%s)", d, d.Reason)
	}
	hits := mgr.Interactions()
	if len(hits) != 1 || !strings.Contains(hits[0].Path, "indago-ssrf-") {
		t.Fatalf("collaborator interactions = %+v, want the one SSRF canary", hits)
	}
	if f := oastFinding(t, env, domain.VulnSSRF); f.Verdict != domain.VerdictConfirmed {
		t.Fatalf("finding verdict = %q, want confirmed", f.Verdict)
	}
}

// TestOASTWiringXXEOperatorBodyIsRegistered covers the one place where the
// enqueue step itself depended on a collaborator being configured: an operator
// XML body (the only way to reach an XML endpoint discovery cannot see) is
// registered as an endpoint only when something can confirm the callback. A
// built-in OAST listener is exactly such a collaborator, so it must count.
func TestOASTWiringXXEOperatorBodyIsRegistered(t *testing.T) {
	const xmlURL = "http://127.0.0.1:9/stock"
	xmlBody := `<stockCheck><productId>1</productId></stockCheck>`

	newScan := func(t *testing.T, env *scanEnv, cfg domain.ScanConfig) *domain.Scan {
		t.Helper()
		now := time.Now()
		sc := &domain.Scan{ID: domain.NewID(), ProjectID: env.sc.ProjectID, Name: "xxe-body",
			State: domain.ScanRunning, Config: cfg, CreatedAt: now, UpdatedAt: now}
		if err := env.st.Scans().Create(context.Background(), sc); err != nil {
			t.Fatal(err)
		}
		return sc
	}
	cfg := domain.ScanConfig{EnableXXE: true, XXEBodyURL: xmlURL, XXEBody: xmlBody}
	lease := func(t *testing.T, c *Controller, q *queue.Memory, sc *domain.Scan) *domain.TestJob {
		t.Helper()
		job, err := q.Lease(context.Background(), "worker", sc.ID, []domain.JobType{domain.JobXXE}, time.Minute)
		if err != nil {
			t.Fatalf("lease queued XXE job: %v", err)
		}
		return job
	}
	registered := func(t *testing.T, env *scanEnv, sc *domain.Scan) *domain.Endpoint {
		t.Helper()
		eps, err := env.st.Endpoints().ListByScan(context.Background(), sc.ID)
		if err != nil {
			t.Fatal(err)
		}
		for _, ep := range eps {
			if ep.URL == xmlURL && ep.Method == domain.MethodPOST && isXMLBodyEndpoint(ep) {
				return ep
			}
		}
		return nil
	}

	t.Run("with a built-in collaborator", func(t *testing.T) {
		env := newScanEnv(t)
		q := queue.NewMemory()
		c := NewController(env.st, q, execLog(), "test", Options{OAST: oastTestManager(t, nil)})
		t.Cleanup(c.Shutdown)
		sc := newScan(t, env, cfg)

		c.enqueueXXEProbes(context.Background(), sc.ID)
		if registered(t, env, sc) == nil {
			t.Fatal("the operator XML body was not registered: the built-in collaborator was not counted as a way to confirm")
		}
		if job := lease(t, c, q, sc); job.Target.URL != xmlURL {
			t.Fatalf("queued job target = %q, want %q", job.Target.URL, xmlURL)
		}
	})

	t.Run("without a collaborator", func(t *testing.T) {
		env := newScanEnv(t)
		q := queue.NewMemory()
		c := NewController(env.st, q, execLog(), "test", Options{})
		t.Cleanup(c.Shutdown)
		sc := newScan(t, env, cfg)

		c.enqueueXXEProbes(context.Background(), sc.ID)
		if registered(t, env, sc) != nil {
			t.Fatal("the operator XML body was registered with no collaborator to confirm it")
		}
		if _, err := q.Lease(context.Background(), "worker", sc.ID, []domain.JobType{domain.JobXXE}, time.Minute); err == nil {
			t.Fatal("an XXE job was queued with no collaborator, want none")
		}
	})
}
