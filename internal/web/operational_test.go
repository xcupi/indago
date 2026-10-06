package web_test

// Tests for the operational-UI additions: target detail, per-scan crawl
// controls, runtime reconfigure, redacted session/worker monitoring fields, and
// the interactive-login endpoint. They go through the real handler + controller
// over httptest, so the UI and CLI exercise exactly this behavior.

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/evidence"
	"github.com/indago/indago/internal/httpengine"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/scan"
	"github.com/indago/indago/internal/store/memory"
	"github.com/indago/indago/internal/web"
	"github.com/indago/indago/internal/worker"
)

// newAPIWith builds an api like newAPI, but lets the caller customize the
// controller handlers and the Server (e.g. install a login function).
func newAPIWith(t *testing.T, handlers map[domain.JobType]worker.Handler, configure func(*web.Server)) api {
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
	srv := web.NewServer(st, ctrl, "test", log, evStore, t.TempDir())
	if configure != nil {
		configure(srv)
	}
	return api{t: t, h: srv.Handler(), st: st, ev: evStore}
}

func TestTargetDetailEndpoint(t *testing.T) {
	a := newAPI(t, nil)
	site := testSite(t)
	projectID, targetID := setupScan(a, site.URL)

	var tgt domain.Target
	a.mustJSON(a.do("GET", "/api/projects/"+projectID+"/targets/"+targetID, nil), 200, &tgt)
	if tgt.ID != domain.ID(targetID) || tgt.BaseURL == "" {
		t.Fatalf("unexpected target detail: %+v", tgt)
	}

	// Unknown target → 404.
	if rec := a.do("GET", "/api/projects/"+projectID+"/targets/nope", nil); rec.Code != 404 {
		t.Fatalf("unknown target: status %d", rec.Code)
	}
	// Target that belongs to another project → 404 (no cross-project leakage).
	var p2 map[string]any
	a.mustJSON(a.do("POST", "/api/projects", map[string]string{"name": "other"}), 201, &p2)
	if rec := a.do("GET", "/api/projects/"+p2["id"].(string)+"/targets/"+targetID, nil); rec.Code != 404 {
		t.Fatalf("cross-project target: status %d", rec.Code)
	}
}

func TestCreateScanCrawlControls(t *testing.T) {
	a := newAPI(t, nil)
	site := testSite(t)
	projectID, targetID := setupScan(a, site.URL)

	// Quick scan + explicit limits are persisted on the scan's config.
	var sc domain.Scan
	a.mustJSON(a.do("POST", "/api/scans", map[string]any{
		"project_id": projectID, "target_id": targetID, "name": "quick",
		"quick_scan": true, "max_pages": 50, "max_endpoints": 123,
	}), 201, &sc)
	if !sc.Config.QuickScan || sc.Config.MaxPages != 50 || sc.Config.MaxEndpoints != 123 {
		t.Fatalf("crawl controls not stored: %+v", sc.Config)
	}

	// Crawl depth works with a named profile (orthogonal to the concurrency preset).
	a.mustJSON(a.do("POST", "/api/scans", map[string]any{
		"project_id": projectID, "target_id": targetID, "name": "deep",
		"profile": "fast", "max_depth": 5,
	}), 201, &sc)
	if sc.Config.MaxDepth != 5 || sc.Profile != domain.ProfileFast {
		t.Fatalf("depth+profile not stored: profile=%s cfg=%+v", sc.Profile, sc.Config)
	}

	// Out-of-range depth is rejected with a clear 400.
	if rec := a.do("POST", "/api/scans", map[string]any{
		"project_id": projectID, "target_id": targetID, "max_depth": 999,
	}); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad depth: status %d, want 400", rec.Code)
	}
}

func TestReconfigurePreservesCrawlExtent(t *testing.T) {
	a := newAPI(t, nil)
	site := testSite(t)
	projectID, targetID := setupScan(a, site.URL)

	var sc domain.Scan
	a.mustJSON(a.do("POST", "/api/scans", map[string]any{
		"project_id": projectID, "target_id": targetID, "name": "r",
		"quick_scan": true, "max_pages": 77,
	}), 201, &sc)

	var st scan.Status
	a.mustJSON(a.do("POST", "/api/scans/"+string(sc.ID)+"/config", map[string]any{
		"discovery_concurrency": 3, "http_concurrency": 7, "browser_concurrency": 1, "requests_per_second": 5,
	}), 200, &st)
	cfg := st.Scan.Config
	if cfg.HTTPConcurrency != 7 || cfg.DiscoveryConcurrency != 3 || cfg.RequestsPerSecond != 5 {
		t.Fatalf("runtime fields not applied: %+v", cfg)
	}
	// Crawl extent set at creation must survive the reconfigure untouched.
	if !cfg.QuickScan || cfg.MaxPages != 77 {
		t.Fatalf("crawl extent clobbered by reconfigure: %+v", cfg)
	}

	// Over-cap value is rejected; unknown scan → 404.
	if rec := a.do("POST", "/api/scans/"+string(sc.ID)+"/config", map[string]any{"http_concurrency": 9999}); rec.Code != 400 {
		t.Fatalf("over-cap reconfigure: status %d, want 400", rec.Code)
	}
	if rec := a.do("POST", "/api/scans/nope/config", map[string]any{"http_concurrency": 1}); rec.Code != 404 {
		t.Fatalf("reconfigure unknown scan: status %d, want 404", rec.Code)
	}
}

func TestStatusSessionIsRedacted(t *testing.T) {
	a := newAPI(t, nil)
	site := testSite(t)
	projectID, targetID := setupScan(a, site.URL)

	var sc domain.Scan
	a.mustJSON(a.do("POST", "/api/scans", map[string]any{
		"project_id": projectID, "target_id": targetID, "name": "s",
	}), 201, &sc)

	var st scan.Status
	a.mustJSON(a.do("GET", "/api/scans/"+string(sc.ID)+"/status", nil), 200, &st)
	if st.Session == nil || st.Session.Mode != domain.AuthAnonymous {
		t.Fatalf("unexpected session info: %+v", st.Session)
	}
	// The redacted view must carry no session material: neither a state path nor
	// any cookies/storage-state field in the raw JSON.
	raw := a.do("GET", "/api/scans/"+string(sc.ID)+"/status", nil).Body.String()
	for _, banned := range []string{"state_path", "StatePath", "cookies", "storage_state", "storageState"} {
		if strings.Contains(raw, banned) {
			t.Fatalf("status JSON leaked %q: %s", banned, raw)
		}
	}
}

func TestInteractiveLoginEndpoint(t *testing.T) {
	// Default (no login function): reports unavailable.
	a := newAPI(t, nil)
	if rec := a.do("POST", "/api/auth/login", map[string]string{"login_url": "https://app.example.com/login"}); rec.Code != http.StatusNotImplemented {
		t.Fatalf("login without browser: status %d, want 501", rec.Code)
	}

	// With a login function wired: forwards params, returns path + final URL
	// only (no session material).
	var gotURL, gotSuccess string
	b := newAPIWith(t, nil, func(srv *web.Server) {
		srv.SetLoginFunc(func(_ context.Context, p web.LoginParams) (string, string, error) {
			gotURL, gotSuccess = p.LoginURL, p.SuccessURL
			return "/data/sessions/login-abc.json", "https://app.example.com/dashboard", nil
		})
	})
	var out map[string]string
	b.mustJSON(b.do("POST", "/api/auth/login", map[string]string{
		"login_url": "https://app.example.com/login", "success_url": "**/dashboard",
	}), 200, &out)
	if gotURL != "https://app.example.com/login" || gotSuccess != "**/dashboard" {
		t.Fatalf("login params not forwarded: url=%q success=%q", gotURL, gotSuccess)
	}
	if out["state_path"] != "/data/sessions/login-abc.json" || !strings.Contains(out["final_url"], "dashboard") {
		t.Fatalf("unexpected login response: %+v", out)
	}
	// Invalid login URL → 400.
	if rec := b.do("POST", "/api/auth/login", map[string]string{"login_url": "notaurl"}); rec.Code != 400 {
		t.Fatalf("bad login_url: status %d, want 400", rec.Code)
	}
}

// Session-expired → re-auth over HTTP: an existing-session scan whose session
// expires mid-run moves to awaiting_auth (surfaced in status), and resuming
// without the material is refused 400, leaving it awaiting auth. This is the
// state the UI shows. Blocking handlers keep the scan running deterministically.
func TestSessionExpiredStateOverHTTP(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	var once sync.Once
	handlers := map[domain.JobType]worker.Handler{
		domain.JobTest: worker.HandlerFunc(func(ctx context.Context, _ *domain.TestJob) error {
			once.Do(func() {}) // nothing; just block below
			select {
			case <-release:
			case <-ctx.Done():
			}
			return ctx.Err()
		}),
	}
	a := newAPIWith(t, handlers, nil)
	site := testSite(t)
	projectID, targetID := setupScan(a, site.URL)

	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")
	if err := os.WriteFile(statePath, []byte(`{"cookies":[],"origins":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	var sc domain.Scan
	a.mustJSON(a.do("POST", "/api/scans", map[string]any{
		"project_id": projectID, "target_id": targetID, "name": "auth",
		"auth_mode": "existing", "auth_state_path": statePath,
	}), 201, &sc)
	a.mustJSON(a.do("POST", "/api/scans/"+string(sc.ID)+"/start", nil), 200, nil)
	pollStatus(a, string(sc.ID), 5*time.Second, func(st scan.Status) bool {
		return st.Scan.State == domain.ScanRunning
	})

	// Force the session to expire (deterministic), the way an operator's
	// session timing out would, and let the monitor observe it.
	sess, err := a.st.Sessions().GetByScan(context.Background(), sc.ID)
	if err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-time.Hour)
	sess.ExpiresAt = &past
	if err := a.st.Sessions().Update(context.Background(), sess); err != nil {
		t.Fatal(err)
	}
	st := pollStatus(a, string(sc.ID), 5*time.Second, func(st scan.Status) bool {
		return st.Scan.State == domain.ScanAwaitingAuth
	})
	if st.Session == nil || st.Session.State != domain.SessionExpired {
		t.Fatalf("expected an expired session in status, got %+v", st.Session)
	}

	// Resume without the material present → 400 (the file is gone now), still
	// awaiting auth.
	if err := os.Remove(statePath); err != nil {
		t.Fatal(err)
	}
	if rec := a.do("POST", "/api/scans/"+string(sc.ID)+"/resume", nil); rec.Code != 400 {
		t.Fatalf("resume without session: status %d, want 400", rec.Code)
	}
	a.mustJSON(a.do("GET", "/api/scans/"+string(sc.ID)+"/status", nil), 200, &st)
	if st.Scan.State != domain.ScanAwaitingAuth {
		t.Fatalf("scan state = %s, want awaiting_auth", st.Scan.State)
	}
}
