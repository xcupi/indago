package web_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/evidence"
	"github.com/indago/indago/internal/httpengine"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/scan"
	"github.com/indago/indago/internal/store"
	"github.com/indago/indago/internal/store/memory"
	"github.com/indago/indago/internal/web"
	"github.com/indago/indago/internal/worker"
)

// api drives the real handler over httptest, adding the client header that
// state-changing requests require.
type api struct {
	t  *testing.T
	h  http.Handler
	st store.Store
	ev evidence.Store
}

func (a api) do(method, path string, body any) *httptest.ResponseRecorder {
	a.t.Helper()
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rdr)
	if method != http.MethodGet {
		req.Header.Set(web.ClientHeader, "test")
	}
	rec := httptest.NewRecorder()
	a.h.ServeHTTP(rec, req)
	return rec
}

func (a api) mustJSON(rec *httptest.ResponseRecorder, wantStatus int, out any) {
	a.t.Helper()
	if rec.Code != wantStatus {
		a.t.Fatalf("status %d (want %d): %s", rec.Code, wantStatus, rec.Body.String())
	}
	if out != nil {
		if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
			a.t.Fatalf("decode: %v: %s", err, rec.Body.String())
		}
	}
}

// newAPI builds a handler over a real controller. A nil handlers map uses the
// no-op Phase 0 handlers.
func newAPI(t *testing.T, handlers map[domain.JobType]worker.Handler) api {
	t.Helper()
	cfg := httpengine.DefaultConfig()
	cfg.FollowRedirects = false
	eng, err := httpengine.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(eng.Close)

	st := memory.New()
	q := queue.NewMemory()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctrl := scan.NewController(st, q, log, "test", scan.Options{
		HTTP: eng, Handlers: handlers,
		IdlePoll: 10 * time.Millisecond, PollInterval: 20 * time.Millisecond,
	})
	t.Cleanup(ctrl.Shutdown)
	evStore, err := evidence.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return api{t: t, h: web.NewServer(st, ctrl, "test", log, evStore, t.TempDir()).Handler(), st: st, ev: evStore}
}

func testSite(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, `<a href="/page?x=1">p</a><form action="/post" method="post"><input name="msg"></form>`)
	})
	mux.HandleFunc("/page", func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") })
	mux.HandleFunc("/post", func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// setupScan creates a project, target, and scope over the API and returns the
// project and target IDs.
func setupScan(a api, baseURL string) (projectID, targetID string) {
	a.t.Helper()
	var p, tg map[string]any
	a.mustJSON(a.do("POST", "/api/projects", map[string]string{"name": "p"}), 201, &p)
	projectID = p["id"].(string)
	a.mustJSON(a.do("PUT", "/api/projects/"+projectID+"/scope", map[string]any{"include_hosts": []string{"127.0.0.1"}}), 201, nil)
	a.mustJSON(a.do("POST", "/api/projects/"+projectID+"/targets", map[string]string{"name": "t", "base_url": baseURL}), 201, &tg)
	return projectID, tg["id"].(string)
}

func pollStatus(a api, id string, d time.Duration, cond func(scan.Status) bool) scan.Status {
	a.t.Helper()
	deadline := time.Now().Add(d)
	var last scan.Status
	for time.Now().Before(deadline) {
		rec := a.do("GET", "/api/scans/"+id+"/status", nil)
		if rec.Code == 200 {
			var st scan.Status
			if json.Unmarshal(rec.Body.Bytes(), &st) == nil {
				last = st
				if cond(st) {
					return st
				}
			}
		}
		time.Sleep(15 * time.Millisecond)
	}
	a.t.Fatalf("condition not met within %s; last state=%v discovery=%v", d, last.Scan, last.Discovery)
	return last
}

// The whole workflow over HTTP: scope → target → scan → start → status → done.
func TestScanWorkflowOverHTTP(t *testing.T) {
	a := newAPI(t, nil)
	site := testSite(t)
	projectID, targetID := setupScan(a, site.URL)

	var sc domain.Scan
	a.mustJSON(a.do("POST", "/api/scans", map[string]any{
		"project_id": projectID, "target_id": targetID, "name": "web scan",
		"profile": "custom", "config": map[string]any{"discovery_concurrency": 2, "http_concurrency": 4, "browser_concurrency": 0},
	}), 201, &sc)
	if sc.State != domain.ScanCreated || sc.Discovery != domain.DiscoveryPending {
		t.Fatalf("new scan: state=%s discovery=%s", sc.State, sc.Discovery)
	}

	var started scan.Status
	a.mustJSON(a.do("POST", "/api/scans/"+string(sc.ID)+"/start", nil), 200, &started)
	if started.Scan.State != domain.ScanRunning && started.Scan.State != domain.ScanCompleted {
		t.Fatalf("after start: %s", started.Scan.State)
	}

	done := pollStatus(a, string(sc.ID), 8*time.Second, func(s scan.Status) bool {
		return s.Scan.State == domain.ScanCompleted
	})
	if done.Discovery.State != domain.DiscoveryComplete || done.Discovery.Endpoints < 3 {
		t.Fatalf("discovery status: %+v", done.Discovery)
	}
	if done.Discovery.EndpointsBySource[domain.SourceUserProvided] == 0 || done.Discovery.EndpointsBySource[domain.SourceForm] == 0 {
		t.Fatalf("provenance missing from status: %v", done.Discovery.EndpointsBySource)
	}
	if done.Discovery.Parameters < 2 || done.Jobs.Succeeded != done.Jobs.Total() {
		t.Fatalf("status: params=%d jobs=%+v", done.Discovery.Parameters, done.Jobs)
	}

	// The scan list reflects the terminal state too.
	var list []domain.Scan
	a.mustJSON(a.do("GET", "/api/scans", nil), 200, &list)
	if len(list) != 1 || list[0].State != domain.ScanCompleted {
		t.Fatalf("scan list: %+v", list)
	}
}

func TestScanControlRoutes(t *testing.T) {
	hold := make(chan struct{})
	handlers := map[domain.JobType]worker.Handler{
		domain.JobTest: worker.HandlerFunc(func(ctx context.Context, _ *domain.TestJob) error {
			select {
			case <-hold:
			case <-ctx.Done():
			}
			return nil
		}),
	}
	defer close(hold)
	a := newAPI(t, handlers)
	site := testSite(t)
	projectID, targetID := setupScan(a, site.URL)

	var sc domain.Scan
	a.mustJSON(a.do("POST", "/api/scans", map[string]any{"project_id": projectID, "target_id": targetID}), 201, &sc)
	id := string(sc.ID)

	// Lifecycle violations map to 409.
	if rec := a.do("POST", "/api/scans/"+id+"/pause", nil); rec.Code != 409 {
		t.Fatalf("pause before start: %d", rec.Code)
	}
	a.mustJSON(a.do("POST", "/api/scans/"+id+"/start", nil), 200, nil)
	if rec := a.do("POST", "/api/scans/"+id+"/start", nil); rec.Code != 409 {
		t.Fatalf("second start: %d", rec.Code)
	}

	var st scan.Status
	a.mustJSON(a.do("POST", "/api/scans/"+id+"/pause", nil), 200, &st)
	if st.Scan.State != domain.ScanPaused {
		t.Fatalf("after pause: %s", st.Scan.State)
	}
	a.mustJSON(a.do("POST", "/api/scans/"+id+"/resume", nil), 200, &st)
	if st.Scan.State != domain.ScanRunning {
		t.Fatalf("after resume: %s", st.Scan.State)
	}
	a.mustJSON(a.do("POST", "/api/scans/"+id+"/cancel", nil), 200, &st)
	if st.Scan.State != domain.ScanCanceled || st.Running {
		t.Fatalf("after cancel: state=%s running=%v", st.Scan.State, st.Running)
	}

	if rec := a.do("POST", "/api/scans/"+id+"/explode", nil); rec.Code != 404 {
		t.Fatalf("unknown action: %d", rec.Code)
	}
	if rec := a.do("POST", "/api/scans/nope/start", nil); rec.Code != 404 {
		t.Fatalf("unknown scan: %d", rec.Code)
	}
	if rec := a.do("GET", "/api/scans/nope/status", nil); rec.Code != 404 {
		t.Fatalf("unknown scan status: %d", rec.Code)
	}
}

func TestCreateScanValidation(t *testing.T) {
	a := newAPI(t, nil)
	site := testSite(t)
	projectID, targetID := setupScan(a, site.URL)

	// A project with no scope at all.
	var noScope map[string]any
	a.mustJSON(a.do("POST", "/api/projects", map[string]string{"name": "noscope"}), 201, &noScope)
	var noScopeTarget map[string]any
	a.mustJSON(a.do("POST", "/api/projects/"+noScope["id"].(string)+"/targets", map[string]string{"name": "t", "base_url": site.URL}), 201, &noScopeTarget)

	over := map[string]any{"discovery_concurrency": 1, "http_concurrency": 9999}
	cases := []struct {
		name string
		body map[string]any
	}{
		{"missing ids", map[string]any{}},
		{"no scope", map[string]any{"project_id": noScope["id"], "target_id": noScopeTarget["id"]}},
		{"out of scope seed", map[string]any{"project_id": projectID, "target_id": targetID, "seed_urls": []string{"http://evil.example/"}}},
		{"invalid seed", map[string]any{"project_id": projectID, "target_id": targetID, "seed_urls": []string{"ftp://127.0.0.1/"}}},
		{"unknown profile", map[string]any{"project_id": projectID, "target_id": targetID, "profile": "ludicrous"}},
		{"unknown auth mode", map[string]any{"project_id": projectID, "target_id": targetID, "auth_mode": "telepathy"}},
		{"unknown stop mode", map[string]any{"project_id": projectID, "target_id": targetID, "stop": map[string]any{"mode": "whenever"}}},
		{"stop N without limit", map[string]any{"project_id": projectID, "target_id": targetID, "stop": map[string]any{"mode": "after_n_confirmed"}}},
		{"config without custom profile", map[string]any{"project_id": projectID, "target_id": targetID, "config": over}},
		{"config over cap", map[string]any{"project_id": projectID, "target_id": targetID, "profile": "custom", "config": over}},
	}
	for _, c := range cases {
		if rec := a.do("POST", "/api/scans", c.body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400: %s", c.name, rec.Code, rec.Body.String())
		}
	}
	if rec := a.do("POST", "/api/scans", map[string]any{"project_id": "nope", "target_id": targetID}); rec.Code != 404 {
		t.Errorf("unknown project: status %d, want 404", rec.Code)
	}
}

func TestScopeAndTargetValidation(t *testing.T) {
	a := newAPI(t, nil)
	var p map[string]any
	a.mustJSON(a.do("POST", "/api/projects", map[string]string{"name": "p"}), 201, &p)
	pid := p["id"].(string)

	// Empty include list is refused; scope is the safety boundary.
	if rec := a.do("PUT", "/api/projects/"+pid+"/scope", map[string]any{"include_hosts": []string{"  ", ""}}); rec.Code != 400 {
		t.Fatalf("empty include_hosts: %d", rec.Code)
	}
	// Upsert: first PUT creates, second replaces.
	a.mustJSON(a.do("PUT", "/api/projects/"+pid+"/scope", map[string]any{"include_hosts": []string{"a.example"}}), 201, nil)
	var sc domain.Scope
	a.mustJSON(a.do("PUT", "/api/projects/"+pid+"/scope", map[string]any{
		"include_hosts": []string{"b.example"}, "exclude_path_prefixes": []string{"/admin"}, "allow_subdomains": true,
	}), 200, &sc)
	if len(sc.IncludeHosts) != 1 || sc.IncludeHosts[0] != "b.example" || !sc.AllowSubdomains {
		t.Fatalf("scope not replaced: %+v", sc)
	}
	a.mustJSON(a.do("GET", "/api/projects/"+pid+"/scope", nil), 200, &sc)
	if sc.IncludeHosts[0] != "b.example" {
		t.Fatalf("scope not persisted: %+v", sc)
	}
	if rec := a.do("PUT", "/api/projects/nope/scope", map[string]any{"include_hosts": []string{"x"}}); rec.Code != 404 {
		t.Fatalf("scope on unknown project: %d", rec.Code)
	}

	for name, body := range map[string]map[string]string{
		"no name":      {"base_url": "http://x.example/"},
		"relative url": {"name": "t", "base_url": "/just/a/path"},
		"non-http":     {"name": "t", "base_url": "ftp://x.example/"},
		"hostless url": {"name": "t", "base_url": "http:///path"},
	} {
		if rec := a.do("POST", "/api/projects/"+pid+"/targets", body); rec.Code != 400 {
			t.Errorf("target %s: %d", name, rec.Code)
		}
	}
	var list []domain.Target
	a.mustJSON(a.do("GET", "/api/projects/"+pid+"/targets", nil), 200, &list)
	if len(list) != 0 {
		t.Fatalf("invalid targets were persisted: %+v", list)
	}
}

// State-changing requests need the client header and a same-origin Origin.
func TestMutationGuard(t *testing.T) {
	a := newAPI(t, nil)
	body := func() io.Reader { return bytes.NewReader([]byte(`{"name":"x"}`)) }

	// No client header → refused, and nothing was created.
	req := httptest.NewRequest("POST", "/api/projects", body())
	rec := httptest.NewRecorder()
	a.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("missing header: %d", rec.Code)
	}
	var list []domain.Project
	a.mustJSON(a.do("GET", "/api/projects", nil), 200, &list)
	if len(list) != 0 {
		t.Fatal("a refused request still created a project")
	}

	// Cross-origin (even with the header, e.g. via a permissive proxy) → refused.
	req = httptest.NewRequest("POST", "/api/projects", body())
	req.Header.Set(web.ClientHeader, "1")
	req.Header.Set("Origin", "http://evil.example")
	rec = httptest.NewRecorder()
	a.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-origin: %d", rec.Code)
	}

	// Same-origin with the header → allowed.
	req = httptest.NewRequest("POST", "/api/projects", body())
	req.Header.Set(web.ClientHeader, "1")
	req.Header.Set("Origin", "http://"+req.Host)
	rec = httptest.NewRecorder()
	a.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("same-origin: %d %s", rec.Code, rec.Body.String())
	}

	// Reads never need the header.
	if rec := a.do("GET", "/api/scans", nil); rec.Code != 200 {
		t.Fatalf("GET: %d", rec.Code)
	}
}
