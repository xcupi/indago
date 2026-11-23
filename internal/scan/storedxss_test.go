package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/httpengine"
	"github.com/indago/indago/internal/queue"
)

type storedXSSCountingEngine struct {
	calls atomic.Int32
}

func (e *storedXSSCountingEngine) Do(_ context.Context, _ *httpengine.Request) (*httpengine.Response, error) {
	e.calls.Add(1)
	return &httpengine.Response{Status: http.StatusOK}, nil
}

func TestStoredXSSGatedWhenAllowStateChangingFalse(t *testing.T) {
	ctx := context.Background()
	env := newScanEnv(t)
	env.sc.Config.EnableStoredXSS = true
	if err := env.st.Scans().Update(ctx, env.sc); err != nil {
		t.Fatal(err)
	}

	ep := env.endpoint("http://target.example/comment", domain.MethodPOST)
	_ = env.st.Endpoints().Create(ctx, ep)
	env.param(ep, "comment", domain.LocationForm, "hello")

	payload, _ := json.Marshal(storedXSSJob{EndpointID: ep.ID})
	job := &domain.TestJob{
		ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobStoredXSS,
		Target: domain.JobTarget{EndpointID: ep.ID, URL: ep.URL}, Payload: payload, Attempts: 1,
	}

	eng := &storedXSSCountingEngine{}
	h := newStoredXSSExecutor(env.st, eng, nil, env.ev, ExecutorConfig{AllowStateChanging: false}, execLog(), &sync.Mutex{})
	if err := h.Handle(ctx, job); err != nil {
		t.Fatalf("Handle returned error: %v", err)
	}
	if got := eng.calls.Load(); got != 0 {
		t.Fatalf("expected 0 HTTP requests when AllowStateChanging=false, got %d", got)
	}
	tc := env.only()
	if tc.Status != domain.TestCaseSkipped {
		t.Fatalf("status = %s, want skipped", tc.Status)
	}
	if !strings.Contains(tc.Note, "AllowStateChanging is off") {
		t.Fatalf("note = %q, want AllowStateChanging is off", tc.Note)
	}
}

func TestStoredXSSNoBrowserSkipsCleanly(t *testing.T) {
	ctx := context.Background()
	env := newScanEnv(t)
	env.sc.Config.EnableStoredXSS = true
	if err := env.st.Scans().Update(ctx, env.sc); err != nil {
		t.Fatal(err)
	}

	ep := env.endpoint("http://target.example/comment", domain.MethodPOST)
	_ = env.st.Endpoints().Create(ctx, ep)
	env.param(ep, "comment", domain.LocationForm, "hello")

	payload, _ := json.Marshal(storedXSSJob{EndpointID: ep.ID})
	job := &domain.TestJob{
		ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobStoredXSS,
		Target: domain.JobTarget{EndpointID: ep.ID, URL: ep.URL}, Payload: payload, Attempts: 1,
	}

	eng := &storedXSSCountingEngine{}
	h := newStoredXSSExecutor(env.st, eng, nil, env.ev, ExecutorConfig{AllowStateChanging: true}, execLog(), &sync.Mutex{})
	if err := h.Handle(ctx, job); err != nil {
		t.Fatalf("Handle with nil browser returned error: %v", err)
	}
	if got := eng.calls.Load(); got != 0 {
		t.Fatalf("expected 0 HTTP requests when browser is nil, got %d", got)
	}
	tc := env.only()
	if tc.Status != domain.TestCaseSkipped {
		t.Fatalf("status = %s, want skipped", tc.Status)
	}
	if !strings.Contains(tc.Note, "stored_xss skipped: no browser configured") {
		t.Fatalf("note = %q, want no browser configured", tc.Note)
	}
}

func TestEnqueueStoredXSSProbesCapFilterAndOptIn(t *testing.T) {
	ctx := context.Background()

	t.Run("respects EnableStoredXSS=false", func(t *testing.T) {
		env := newScanEnv(t)
		env.sc.Config.EnableStoredXSS = false
		if err := env.st.Scans().Update(ctx, env.sc); err != nil {
			t.Fatal(err)
		}
		ep := env.endpoint("http://target.example/comment", domain.MethodPOST)
		_ = env.st.Endpoints().Create(ctx, ep)
		env.param(ep, "comment", domain.LocationForm, "hello")

		q := queue.NewMemory()
		ctrl := NewController(env.st, q, execLog(), "test", Options{})
		ctrl.enqueueStoredXSSProbes(ctx, env.scanID)

		job, err := q.Lease(ctx, "test-worker", env.scanID, []domain.JobType{domain.JobStoredXSS}, time.Minute)
		if err == nil && job != nil {
			t.Fatalf("expected 0 jobs when EnableStoredXSS=false, got %+v", job)
		}
	})

	t.Run("filters ineligible endpoints and caps at maxStoredXSSEndpoints", func(t *testing.T) {
		env := newScanEnv(t)
		env.sc.Config.EnableStoredXSS = true
		if err := env.st.Scans().Update(ctx, env.sc); err != nil {
			t.Fatal(err)
		}

		// Ineligible: GET, DELETE, login, logout, download, query-only POST.
		ineligible := []struct {
			method domain.HTTPMethod
			url    string
			loc    domain.ParamLocation
		}{
			{domain.MethodGET, "http://target.example/comments", domain.LocationQuery},
			{domain.MethodDELETE, "http://target.example/comments/1", domain.LocationForm},
			{domain.MethodPOST, "http://target.example/login", domain.LocationForm},
			{domain.MethodPOST, "http://target.example/auth/logout", domain.LocationForm},
			{domain.MethodPOST, "http://target.example/users/delete", domain.LocationForm},
			{domain.MethodPOST, "http://target.example/export/report.csv", domain.LocationForm},
			{domain.MethodPOST, "http://target.example/search", domain.LocationQuery},
		}
		for _, tc := range ineligible {
			ep := env.endpoint(tc.url, tc.method)
			_ = env.st.Endpoints().Create(ctx, ep)
			env.param(ep, "q", tc.loc, "val")
		}

		// 15 eligible POST/PUT/PATCH endpoints -> should cap at maxStoredXSSEndpoints (10).
		methods := []domain.HTTPMethod{domain.MethodPOST, domain.MethodPUT, domain.MethodPATCH}
		for i := 0; i < 15; i++ {
			m := methods[i%len(methods)]
			loc := domain.LocationForm
			if i%2 == 1 {
				loc = domain.LocationJSON
			}
			ep := env.endpoint(fmt.Sprintf("http://target.example/items/%02d", i), m)
			_ = env.st.Endpoints().Create(ctx, ep)
			env.param(ep, "comment", loc, `"hello"`)
		}

		q := queue.NewMemory()
		ctrl := NewController(env.st, q, execLog(), "test", Options{})
		ctrl.enqueueStoredXSSProbes(ctx, env.scanID)

		var count int
		for {
			job, err := q.Lease(ctx, "test-worker", env.scanID, []domain.JobType{domain.JobStoredXSS}, time.Minute)
			if err != nil || job == nil {
				break
			}
			count++
		}
		if count != maxStoredXSSEndpoints {
			t.Fatalf("enqueued %d jobs, want %d", count, maxStoredXSSEndpoints)
		}
	})
}

func TestStoredXSSFindingDeduplication(t *testing.T) {
	ctx := context.Background()
	env := newScanEnv(t)
	ep := env.endpoint("http://target.example/comment", domain.MethodPOST)
	exec := newStoredXSSExecutor(env.st, nil, nil, env.ev, ExecutorConfig{AllowStateChanging: true}, execLog(), &sync.Mutex{}).(*storedXSSExecutor)
	job := &domain.TestJob{ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobStoredXSS, Attempts: 1}
	tc1 := exec.newTestCase(ctx, job, ep.Method, ep.URL)
	tc2 := exec.newTestCase(ctx, job, ep.Method, ep.URL)

	exec.correlateFinding(ctx, env.sc, job, ep, tc1, "comment", storedXSSTrigger{
		ConfirmMethod: storedXSSConfirmBrowser, SinkPageURL: "http://target.example/comments", Token: "tok1",
	})
	exec.correlateFinding(ctx, env.sc, job, ep, tc2, "comment", storedXSSTrigger{
		ConfirmMethod: storedXSSConfirmBrowser, SinkPageURL: "http://target.example/comments", Token: "tok2",
	})

	findings, err := env.st.Findings().ListByScan(ctx, env.scanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1 deduplicated finding", len(findings))
	}
	if findings[0].VulnClass != domain.VulnStoredXSS || findings[0].Verdict != domain.VerdictConfirmed {
		t.Fatalf("unexpected finding: %+v", findings[0])
	}
	var detail storedXSSDetail
	if err := json.Unmarshal(findings[0].Detail, &detail); err != nil {
		t.Fatal(err)
	}
	if detail.Occurrences != 2 {
		t.Fatalf("occurrences = %d, want 2", detail.Occurrences)
	}
}

func TestStoredXSSBrowserIntegration(t *testing.T) {
	exe := os.Getenv("INDAGO_CHROMIUM_PATH")
	if exe == "" {
		exe = "/usr/bin/google-chrome"
	}
	if _, err := os.Stat(exe); err != nil {
		t.Skipf("Chromium not available at %s: %v", exe, err)
	}

	mgr, err := browser.NewManager(browser.Config{
		Headless:          true,
		ExecutablePath:    exe,
		PoolSize:          1,
		NavigationTimeout: 15 * time.Second,
	}, nil)
	if err != nil {
		t.Skipf("start Chromium: %v", err)
	}
	defer mgr.Close()

	runScenario := func(t *testing.T, escaped bool) []*domain.Finding {
		t.Helper()
		var mu sync.Mutex
		var comments []string

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == http.MethodPost && r.URL.Path == "/comment":
				if err := r.ParseForm(); err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				c := r.FormValue("comment")
				mu.Lock()
				comments = append(comments, c)
				mu.Unlock()
				w.Header().Set("Content-Type", "text/html")
				_, _ = w.Write([]byte("<!doctype html><html><body>ok</body></html>"))
			case r.Method == http.MethodGet && r.URL.Path == "/comments":
				w.Header().Set("Content-Type", "text/html")
				mu.Lock()
				snapshot := append([]string(nil), comments...)
				mu.Unlock()
				var sb strings.Builder
				sb.WriteString("<!doctype html><html><body><h1>Comments</h1><ul>")
				for _, c := range snapshot {
					if escaped {
						sb.WriteString("<li>" + html.EscapeString(c) + "</li>")
					} else {
						sb.WriteString("<li>" + c + "</li>")
					}
				}
				sb.WriteString("</ul></body></html>")
				_, _ = w.Write([]byte(sb.String()))
			default:
				w.Header().Set("Content-Type", "text/html")
				_, _ = w.Write([]byte("<!doctype html><html><body>home</body></html>"))
			}
		}))
		defer srv.Close()

		u, err := url.Parse(srv.URL)
		if err != nil {
			t.Fatal(err)
		}

		ctx := context.Background()
		env := newScanEnv(t)
		env.sc.Config.EnableStoredXSS = true
		if err := env.st.Scans().Update(ctx, env.sc); err != nil {
			t.Fatal(err)
		}

		scope := &domain.Scope{
			ID:           domain.NewID(),
			ProjectID:    env.sc.ProjectID,
			IncludeHosts: []string{u.Hostname()},
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
		}
		if err := env.st.Scopes().Create(ctx, scope); err != nil {
			t.Fatal(err)
		}

		postEP := &domain.Endpoint{
			ID: domain.NewID(), ScanID: env.scanID, Method: domain.MethodPOST, URL: srv.URL + "/comment",
		}
		getEP := &domain.Endpoint{
			ID: domain.NewID(), ScanID: env.scanID, Method: domain.MethodGET, URL: srv.URL + "/comments", ContentType: "text/html",
		}
		if err := env.st.Endpoints().Create(ctx, postEP); err != nil {
			t.Fatal(err)
		}
		if err := env.st.Endpoints().Create(ctx, getEP); err != nil {
			t.Fatal(err)
		}
		env.param(postEP, "comment", domain.LocationForm, "nice post")

		payload, _ := json.Marshal(storedXSSJob{EndpointID: postEP.ID})
		job := &domain.TestJob{
			ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobStoredXSS,
			Target: domain.JobTarget{EndpointID: postEP.ID, URL: postEP.URL}, Payload: payload, Attempts: 1,
		}

		h := newStoredXSSExecutor(env.st, scopedClient(t, *scope), mgr, env.ev, ExecutorConfig{AllowStateChanging: true}, execLog(), &sync.Mutex{})
		if err := h.Handle(ctx, job); err != nil {
			t.Fatalf("Handle: %v", err)
		}

		findings, err := env.st.Findings().ListByScan(ctx, env.scanID)
		if err != nil {
			t.Fatal(err)
		}
		return findings
	}

	t.Run("unescaped stored comment confirms VulnStoredXSS", func(t *testing.T) {
		findings := runScenario(t, false)
		if len(findings) != 1 {
			t.Fatalf("expected 1 confirmed VulnStoredXSS finding, got %d", len(findings))
		}
		f := findings[0]
		if f.VulnClass != domain.VulnStoredXSS || f.Verdict != domain.VerdictConfirmed ||
			f.Severity != domain.SeverityHigh || f.Confidence != domain.ConfidenceHigh {
			t.Fatalf("unexpected finding attributes: %+v", f)
		}
		if len(f.EvidenceIDs) == 0 {
			t.Fatalf("expected recorded evidence on finding %s", f.ID)
		}
	})

	t.Run("html-escaped stored comment produces 0 findings", func(t *testing.T) {
		findings := runScenario(t, true)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings on escaped output, got %d: %+v", len(findings), findings)
		}
	})
}

// ---------------------------------------------------------------------------
// blind OAST callback arm
// ---------------------------------------------------------------------------

// storedXSSFakeCollaborator is the collaborator seam from oast_wiring.go
// without a listener: it only reports where callbacks and polls would go, which
// is all the enqueue step needs.
type storedXSSFakeCollaborator struct {
	base string
	poll string
}

func (f storedXSSFakeCollaborator) BaseURL() string          { return f.base }
func (f storedXSSFakeCollaborator) PollURL() (string, error) { return f.poll, nil }
func (f storedXSSFakeCollaborator) ListenAddr() string       { return "" }

// TestStoredXSSEnqueueArmsConfiguredCollaborator covers the production wiring:
// the pair the controller derived from its built-in collaborator is what
// travels with each job, and the default (no collaborator) leaves it empty.
func TestStoredXSSEnqueueArmsConfiguredCollaborator(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name         string
		collab       OASTCollaborator
		wantCallback string
		wantPoll     string
	}{
		{name: "no collaborator configured", collab: nil, wantCallback: "", wantPoll: ""},
		{
			name:         "configured collaborator is carried",
			collab:       storedXSSFakeCollaborator{base: "https://collab.example.test", poll: "http://127.0.0.1:1/poll/secret"},
			wantCallback: "https://collab.example.test",
			wantPoll:     "http://127.0.0.1:1/poll/secret",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newScanEnv(t)
			env.sc.Config.EnableStoredXSS = true
			if err := env.st.Scans().Update(ctx, env.sc); err != nil {
				t.Fatal(err)
			}
			ep := env.endpoint("http://target.example/comment", domain.MethodPOST)
			env.param(ep, "comment", domain.LocationForm, "hello")

			q := queue.NewMemory()
			ctrl := NewController(env.st, q, execLog(), "test", Options{OAST: tc.collab})
			ctrl.enqueueStoredXSSProbes(ctx, env.scanID)

			job, err := q.Lease(ctx, "test-worker", env.scanID, []domain.JobType{domain.JobStoredXSS}, time.Minute)
			if err != nil || job == nil {
				t.Fatalf("no stored_xss job enqueued (err %v)", err)
			}
			sj, err := parseStoredXSSJob(job)
			if err != nil {
				t.Fatal(err)
			}
			if sj.CallbackURL != tc.wantCallback || sj.PollURL != tc.wantPoll {
				t.Fatalf("job collaborator = (%q, %q), want (%q, %q)", sj.CallbackURL, sj.PollURL, tc.wantCallback, tc.wantPoll)
			}
		})
	}
}

// TestStoredXSSMarkerPayloadStaysBenign pins the marker's shape: byte-identical
// to the pre-OAST payload when no collaborator is armed, and still a bare token
// (plus one beacon request) when one is.
func TestStoredXSSMarkerPayloadStaysBenign(t *testing.T) {
	const token = "sxss_abc123"
	legacy := `<img src=x onerror="window.__indago_sxss=window.__indago_sxss||{};window.__indago_sxss['` + token + `']=1">`
	if got := storedXSSMarkerPayload(token, ""); got != legacy {
		t.Fatalf("unarmed marker changed shape:\n got %q\nwant %q", got, legacy)
	}

	beacon := "https://collab.example.test/p/" + token
	armed := storedXSSMarkerPayload(token, beacon)
	if !strings.Contains(armed, beacon) || !strings.Contains(armed, token) {
		t.Fatalf("armed marker does not carry the beacon and token: %q", armed)
	}
	if strings.Count(armed, "<img") != 1 {
		t.Fatalf("armed marker should still be one element: %q", armed)
	}
	for _, banned := range []string{"alert(", "document.cookie", "localStorage", "sessionStorage", "fetch(", "XMLHttpRequest", "eval(", "<script"} {
		if strings.Contains(armed, banned) {
			t.Fatalf("armed marker carries %q; it must stay a benign marker", banned)
		}
	}
}

// TestStoredXSSOASTCallbackValidation pins which collaborator pairs may arm the
// blind arm. A refused pair is never substituted: the probe keeps its in-band
// behavior and records the reason.
func TestStoredXSSOASTCallbackValidation(t *testing.T) {
	const token = "sxss_token"

	t.Run("no pair leaves the probe unchanged", func(t *testing.T) {
		cfg := storedXSSOASTFor("", "", token)
		if cfg.armed() || cfg.Note != "" {
			t.Fatalf("empty pair = %+v, want unarmed with no note", cfg)
		}
	})

	t.Run("half a pair is refused with a reason", func(t *testing.T) {
		cfg := storedXSSOASTFor("https://collab.example.test", "", token)
		if cfg.armed() || !strings.Contains(cfg.Note, "incomplete") {
			t.Fatalf("half pair = %+v, want an incomplete-pair note", cfg)
		}
	})

	t.Run("instance metadata is never a callback", func(t *testing.T) {
		cfg := storedXSSOASTFor("http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:1/poll/x", token)
		if cfg.armed() || !strings.Contains(cfg.Note, "link-local") {
			t.Fatalf("metadata callback = %+v, want a link-local refusal", cfg)
		}
	})

	t.Run("a metadata poll URL is refused too", func(t *testing.T) {
		cfg := storedXSSOASTFor("https://collab.example.test", "http://169.254.169.254/latest/meta-data/", token)
		if cfg.armed() || !strings.Contains(cfg.Note, "poll URL") {
			t.Fatalf("metadata poll = %+v, want a poll refusal", cfg)
		}
	})

	t.Run("a quote in the path cannot break out of the marker", func(t *testing.T) {
		cfg := storedXSSOASTFor(`https://collab.example.test/a'b`, "http://127.0.0.1:1/poll/x", token)
		if bad := storedXSSUnsafeBeaconChar(cfg.BeaconURL); bad != "" {
			t.Fatalf("beacon %q still carries %q, which would break out of the marker", cfg.BeaconURL, bad)
		}
		if !strings.Contains(cfg.BeaconURL, "%27") {
			t.Fatalf("beacon %q lost the quoting character instead of escaping it", cfg.BeaconURL)
		}
		marker := storedXSSMarkerPayload(token, cfg.BeaconURL)
		if n := strings.Count(marker, `"`); n != 2 {
			t.Fatalf("marker %q has %d attribute delimiters, want exactly 2", marker, n)
		}
	})

	t.Run("a loopback collaborator is usable", func(t *testing.T) {
		cfg := storedXSSOASTFor("http://127.0.0.1:8751/cb", "http://127.0.0.1:8751/poll/x", token)
		if !cfg.armed() {
			t.Fatalf("loopback collaborator = %+v, want it armed", cfg)
		}
		if !strings.HasSuffix(cfg.BeaconURL, "/cb/"+token) {
			t.Fatalf("beacon URL = %q, want the token appended to the callback path", cfg.BeaconURL)
		}
	})
}

// storedXSSCollaborator is the collaborator double the blind tests poll: it
// records every beacon path and serves the read API format internal/oast uses
// (one interaction per line).
type storedXSSCollaborator struct {
	srv  *httptest.Server
	mu   sync.Mutex
	hits []string
}

func newStoredXSSCollaborator(t *testing.T) *storedXSSCollaborator {
	t.Helper()
	c := &storedXSSCollaborator{}
	c.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/poll/") {
			c.mu.Lock()
			lines := append([]string(nil), c.hits...)
			c.mu.Unlock()
			var b strings.Builder
			fmt.Fprintf(&b, "indago-oast poll: %d interaction(s), 0 correlated\n", len(lines))
			for _, line := range lines {
				b.WriteString(line)
				b.WriteByte('\n')
			}
			_, _ = io.WriteString(w, b.String())
			return
		}
		c.mu.Lock()
		c.hits = append(c.hits, fmt.Sprintf("2026-01-01T00:00:00Z http GET %s%s source=local", r.Host, r.URL.Path))
		c.mu.Unlock()
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(c.srv.Close)
	return c
}

func (c *storedXSSCollaborator) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.hits)
}

func (c *storedXSSCollaborator) pollURL() string { return c.srv.URL + "/poll/secret" }

// storedXSSBeaconPattern pulls the beacon out of the submitted marker, the way
// a renderer picks the URL out of the attribute.
var storedXSSBeaconPattern = regexp.MustCompile(`src='([^']+)'`)

// storedXSSRendererEngine stands in for the target endpoint: it accepts the ONE
// submission and, when render is set, plays the downstream renderer by
// requesting the beacon URL it found in the submitted body.
type storedXSSRendererEngine struct {
	calls  atomic.Int32
	render bool
	mu     sync.Mutex
	last   string
}

// storedXSSSubmittedValue returns the parameter value the engine submitted,
// decoded the way the target would read it: the form body carries the marker
// percent-encoded, so the beacon only appears after decoding.
func storedXSSSubmittedValue(req *httpengine.Request) string {
	raw := string(req.Body)
	if strings.Contains(req.ContentType, "x-www-form-urlencoded") {
		if vals, err := url.ParseQuery(raw); err == nil {
			for _, vs := range vals {
				for _, v := range vs {
					if strings.Contains(v, "src='") {
						return v
					}
				}
			}
		}
	}
	return raw
}

func (e *storedXSSRendererEngine) Do(ctx context.Context, req *httpengine.Request) (*httpengine.Response, error) {
	e.calls.Add(1)
	body := storedXSSSubmittedValue(req)
	e.mu.Lock()
	e.last = body
	e.mu.Unlock()
	if e.render {
		if m := storedXSSBeaconPattern.FindStringSubmatch(body); len(m) == 2 {
			if breq, err := http.NewRequestWithContext(ctx, http.MethodGet, m[1], nil); err == nil {
				if bresp, err := http.DefaultClient.Do(breq); err == nil {
					_ = bresp.Body.Close()
				}
			}
		}
	}
	return &httpengine.Response{Status: http.StatusOK}, nil
}

func (e *storedXSSRendererEngine) submitted() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.last
}

func storedXSSJobWithCollaborator(env *scanEnv, ep *domain.Endpoint, callback, poll string) *domain.TestJob {
	payload, _ := json.Marshal(storedXSSJob{EndpointID: ep.ID, CallbackURL: callback, PollURL: poll})
	return &domain.TestJob{
		ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobStoredXSS,
		Target: domain.JobTarget{EndpointID: ep.ID, URL: ep.URL}, Payload: payload, Attempts: 1, MaxAttempts: 1,
	}
}

// TestStoredXSSOASTBlindCallbackConfirms is the blind path end to end: one
// submission, a renderer the scan cannot visit calls back with this probe's
// token, and the engine records a confirmed finding — with no browser at all.
func TestStoredXSSOASTBlindCallbackConfirms(t *testing.T) {
	ctx := context.Background()
	env := newScanEnv(t)
	env.sc.Config.EnableStoredXSS = true
	if err := env.st.Scans().Update(ctx, env.sc); err != nil {
		t.Fatal(err)
	}
	ep := env.endpoint("http://target.example/comment", domain.MethodPOST)
	env.param(ep, "comment", domain.LocationForm, "hello")

	collab := newStoredXSSCollaborator(t)
	eng := &storedXSSRendererEngine{render: true}
	ex := newStoredXSSExecutor(env.st, eng, nil, env.ev, ExecutorConfig{AllowStateChanging: true}, execLog(), &sync.Mutex{}).(*storedXSSExecutor)
	ex.pollAttempts, ex.pollInterval = 2, time.Millisecond

	if err := ex.Handle(ctx, storedXSSJobWithCollaborator(env, ep, collab.srv.URL, collab.pollURL())); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if got := eng.calls.Load(); got != 1 {
		t.Fatalf("target submissions = %d, want exactly 1 (the blind arm must not add a target request)", got)
	}
	if !strings.Contains(eng.submitted(), collab.srv.URL) {
		t.Fatal("the submitted marker did not carry the beacon")
	}
	if got := collab.count(); got != 1 {
		t.Fatalf("collaborator hits = %d, want 1", got)
	}

	tc := env.only()
	if tc.Status != domain.TestCaseCompleted || !strings.Contains(tc.Note, "confirmed blind") {
		t.Fatalf("test case = %+v, want a completed blind confirmation", tc)
	}
	if len(tc.EvidenceIDs) < 2 {
		t.Fatalf("evidence ids = %v, want the submission plus the callback record", tc.EvidenceIDs)
	}

	findings, err := env.st.Findings().ListByScan(ctx, env.scanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want exactly 1", len(findings))
	}
	f := findings[0]
	if f.VulnClass != domain.VulnStoredXSS || f.Verdict != domain.VerdictConfirmed {
		t.Fatalf("finding = %+v, want a confirmed stored_xss", f)
	}
	var detail storedXSSDetail
	if err := json.Unmarshal(f.Detail, &detail); err != nil {
		t.Fatal(err)
	}
	if detail.ConfirmMethod != storedXSSConfirmOAST || !detail.Blind || detail.JSEvalResult {
		t.Fatalf("detail = %+v, want an OAST-blind confirmation without a JS eval result", detail)
	}
	if detail.Token == "" || !strings.Contains(string(f.Detail), detail.Token) {
		t.Fatalf("detail token = %q, want the probe's token recorded", detail.Token)
	}
	if len(f.EvidenceIDs) == 0 {
		t.Fatal("finding has no evidence")
	}
}

// TestStoredXSSOASTSilentCollaboratorRecordsNoFinding is the negative control:
// the beacon is planted but never requested, so nothing is confirmed and the
// test case says so.
func TestStoredXSSOASTSilentCollaboratorRecordsNoFinding(t *testing.T) {
	ctx := context.Background()
	env := newScanEnv(t)
	env.sc.Config.EnableStoredXSS = true
	if err := env.st.Scans().Update(ctx, env.sc); err != nil {
		t.Fatal(err)
	}
	ep := env.endpoint("http://target.example/comment", domain.MethodPOST)
	env.param(ep, "comment", domain.LocationForm, "hello")

	collab := newStoredXSSCollaborator(t)
	eng := &storedXSSRendererEngine{render: false}
	ex := newStoredXSSExecutor(env.st, eng, nil, env.ev, ExecutorConfig{AllowStateChanging: true}, execLog(), &sync.Mutex{}).(*storedXSSExecutor)
	ex.pollAttempts, ex.pollInterval = 2, time.Millisecond

	if err := ex.Handle(ctx, storedXSSJobWithCollaborator(env, ep, collab.srv.URL, collab.pollURL())); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if got := eng.calls.Load(); got != 1 {
		t.Fatalf("target submissions = %d, want exactly 1", got)
	}
	if got := collab.count(); got != 0 {
		t.Fatalf("collaborator hits = %d, want 0", got)
	}
	tc := env.only()
	if !strings.Contains(tc.Note, "did not reach the OAST collaborator") {
		t.Fatalf("note = %q, want the missing-callback note", tc.Note)
	}
	findings, err := env.st.Findings().ListByScan(ctx, env.scanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("findings = %d, want none without a callback", len(findings))
	}
}

// TestStoredXSSOASTRefusedCollaboratorSendsNothing: a collaborator pointing at
// instance metadata is refused before any request exists, so the probe records
// the refusal and mutates nothing.
func TestStoredXSSOASTRefusedCollaboratorSendsNothing(t *testing.T) {
	ctx := context.Background()
	env := newScanEnv(t)
	env.sc.Config.EnableStoredXSS = true
	if err := env.st.Scans().Update(ctx, env.sc); err != nil {
		t.Fatal(err)
	}
	ep := env.endpoint("http://target.example/comment", domain.MethodPOST)
	env.param(ep, "comment", domain.LocationForm, "hello")

	eng := &storedXSSCountingEngine{}
	ex := newStoredXSSExecutor(env.st, eng, nil, env.ev, ExecutorConfig{AllowStateChanging: true}, execLog(), &sync.Mutex{}).(*storedXSSExecutor)
	job := storedXSSJobWithCollaborator(env, ep, "http://169.254.169.254/latest/meta-data/", "http://169.254.169.254/latest/meta-data/")

	if err := ex.Handle(ctx, job); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if got := eng.calls.Load(); got != 0 {
		t.Fatalf("requests = %d, want 0 for a refused collaborator", got)
	}
	tc := env.only()
	if tc.Status != domain.TestCaseSkipped || !strings.Contains(tc.Note, "not armed") {
		t.Fatalf("test case = %+v, want a skip explaining the refusal", tc)
	}
}
