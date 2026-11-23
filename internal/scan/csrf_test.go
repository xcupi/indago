package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/store/memory"
)

func csrfJob(env *scanEnv, ep *domain.Endpoint) *domain.TestJob {
	env.t.Helper()
	return &domain.TestJob{
		ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobCSRF,
		Target: domain.JobTarget{EndpointID: ep.ID, URL: ep.URL}, Attempts: 1, MaxAttempts: 2,
	}
}

func runCSRF(t *testing.T, env *scanEnv, ep *domain.Endpoint, cfg ExecutorConfig) *domain.TestCase {
	t.Helper()
	ex := newCSRFExecutor(env.st, scopedClient(t, openScope()), env.ev, cfg, execLog(), nil)
	if err := ex.Handle(context.Background(), csrfJob(env, ep)); err != nil {
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

func csrfDetailOf(t *testing.T, tc *domain.TestCase) csrfDetail {
	t.Helper()
	var d csrfDetail
	if err := json.Unmarshal(tc.Detail, &d); err != nil {
		t.Fatalf("unmarshal detail: %v (%s)", err, string(tc.Detail))
	}
	return d
}

func writeCSRFStorageState(t *testing.T, rawURL, name, value, sameSite string) string {
	t.Helper()
	host := strings.TrimPrefix(rawURL, "http://")
	host = strings.TrimPrefix(host, "https://")
	if i := strings.IndexByte(host, '/'); i >= 0 {
		host = host[:i]
	}
	if i := strings.LastIndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	state := map[string]any{
		"cookies": []map[string]any{
			{
				"name":     name,
				"value":    value,
				"domain":   host,
				"path":     "/",
				"httpOnly": true,
				"sameSite": sameSite,
			},
		},
	}
	b, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCSRFGatedWithoutAllowStateChanging(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/profile/update", domain.MethodPOST)
	tc := runCSRF(t, env, ep, ExecutorConfig{AllowStateChanging: false})

	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Fatalf("target hits = %d, want 0 when AllowStateChanging is false", got)
	}
	if tc.Status != domain.TestCaseSkipped {
		t.Fatalf("status = %q, want skipped", tc.Status)
	}
	if !strings.Contains(tc.Note, "AllowStateChanging") {
		t.Fatalf("skip note = %q, want AllowStateChanging", tc.Note)
	}
	if d := csrfDetailOf(t, tc); !d.Skipped {
		t.Fatalf("detail = %+v, want Skipped=true", d)
	}
	if got := scanFindings(t, env); len(got) != 0 {
		t.Fatalf("findings = %d, want 0", len(got))
	}
}

func TestCSRFHTTPAcceptanceRemainsInconclusive(t *testing.T) {
	const secret = "supersecret-csrf-session-token"
	var gotOrigin, gotReferer, gotCookie string
	var gotFormAction, gotFormCSRF string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotOrigin = r.Header.Get("Origin")
		gotReferer = r.Header.Get("Referer")
		gotCookie = r.Header.Get("Cookie")
		_ = r.ParseForm()
		gotFormAction = r.FormValue("action")
		gotFormCSRF = r.FormValue("csrf_token")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	env := newScanEnv(t)
	statePath := writeCSRFStorageState(t, srv.URL, "sid", secret, "None")
	now := time.Now()
	if err := env.st.Sessions().Create(context.Background(), &domain.Session{
		ID: domain.NewID(), ScanID: env.scanID, Mode: domain.AuthExisting,
		State: domain.SessionActive, StatePath: statePath, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	ep := env.endpoint(srv.URL+"/account/email", domain.MethodPOST)
	env.param(ep, "action", domain.LocationForm, "change")
	env.param(ep, "csrf_token", domain.LocationForm, "tok123")

	tc := runCSRF(t, env, ep, ExecutorConfig{AllowStateChanging: true})

	if gotOrigin != csrfEvilOrigin {
		t.Fatalf("Origin = %q, want %q", gotOrigin, csrfEvilOrigin)
	}
	if gotReferer != csrfEvilReferer {
		t.Fatalf("Referer = %q, want %q", gotReferer, csrfEvilReferer)
	}
	if !strings.Contains(gotCookie, secret) {
		t.Fatalf("Cookie = %q, want session cookie to be sent", gotCookie)
	}
	if gotFormAction != "change" {
		t.Fatalf("form action = %q, want change", gotFormAction)
	}
	if gotFormCSRF != "" {
		t.Fatalf("form csrf_token = %q, want omitted", gotFormCSRF)
	}

	d := csrfDetailOf(t, tc)
	if d.Verdict != domain.VerdictInconclusive {
		t.Fatalf("verdict = %q, want inconclusive", d.Verdict)
	}
	if !d.HasTokenParam || len(d.TokenParamNames) != 1 || d.TokenParamNames[0] != "csrf_token" {
		t.Fatalf("token params = %v (HasTokenParam=%v), want [csrf_token]", d.TokenParamNames, d.HasTokenParam)
	}
	if !d.LacksSameSiteProtection || len(d.WeakSameSiteCookies) != 1 || d.WeakSameSiteCookies[0] != "sid" {
		t.Fatalf("SameSite tracking = %v (lacks=%v), want [sid]", d.WeakSameSiteCookies, d.LacksSameSiteProtection)
	}

	findings := scanFindings(t, env)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if findings[0].VulnClass != domain.VulnCSRF {
		t.Fatalf("VulnClass = %q, want %q", findings[0].VulnClass, domain.VulnCSRF)
	}
	if findings[0].Verdict != domain.VerdictInconclusive {
		t.Fatalf("finding Verdict = %q, want inconclusive", findings[0].Verdict)
	}

	if len(tc.EvidenceIDs) == 0 {
		t.Fatal("expected request/response evidence to be persisted")
	}
	for _, evID := range tc.EvidenceIDs {
		evMeta, err := env.st.Evidence().Get(context.Background(), evID)
		if err != nil {
			t.Fatal(err)
		}
		rc, err := env.ev.Open(evMeta.BlobPath)
		if err != nil {
			t.Fatal(err)
		}
		blob, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(blob), secret) {
			t.Fatalf("evidence blob %s leaked raw cookie value:\n%s", evID, string(blob))
		}
	}
}

func TestCSRFProtectedEndpointRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") != srvURLHostOrigin(r) || r.FormValue("csrf_token") == "" {
			http.Error(w, "invalid csrf token", http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/account/password", domain.MethodPOST)
	tc := runCSRF(t, env, ep, ExecutorConfig{AllowStateChanging: true})

	d := csrfDetailOf(t, tc)
	if d.Verdict != domain.VerdictRejected {
		t.Fatalf("verdict = %q, want rejected", d.Verdict)
	}
	if tc.HTTPStatus != http.StatusForbidden {
		t.Fatalf("HTTPStatus = %d, want 403", tc.HTTPStatus)
	}
	if got := scanFindings(t, env); len(got) != 0 {
		t.Fatalf("findings = %d, want 0", len(got))
	}
}

func srvURLHostOrigin(r *http.Request) string {
	return "http://" + r.Host
}

func TestCSRFThrottledInconclusive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/orders", domain.MethodPOST)
	tc := runCSRF(t, env, ep, ExecutorConfig{AllowStateChanging: true})

	d := csrfDetailOf(t, tc)
	if !d.Throttled {
		t.Fatalf("detail = %+v, want Throttled=true", d)
	}
	if d.Verdict != domain.VerdictInconclusive {
		t.Fatalf("verdict = %q, want inconclusive", d.Verdict)
	}
	if got := scanFindings(t, env); len(got) != 0 {
		t.Fatalf("findings = %d, want 0", len(got))
	}
}

func TestEnqueueCSRFProbes(t *testing.T) {
	for _, tc := range []struct {
		name       string
		skipCSRF   bool
		hasSession bool
		want       int
	}{
		{name: "enabled with session caps at maxCSRFEndpoints", skipCSRF: false, hasSession: true, want: maxCSRFEndpoints},
		{name: "respects SkipCSRF", skipCSRF: true, hasSession: true, want: 0},
		{name: "requires authenticated session", skipCSRF: false, hasSession: false, want: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			st, q := memory.New(), queue.NewMemory()
			now := time.Now()
			sc := &domain.Scan{
				ID: domain.NewID(), ProjectID: domain.NewID(), State: domain.ScanCreated,
				Config: domain.ScanConfig{SkipCSRF: tc.skipCSRF}, CreatedAt: now, UpdatedAt: now,
			}
			if err := st.Scans().Create(ctx, sc); err != nil {
				t.Fatal(err)
			}
			if tc.hasSession {
				if err := st.Sessions().Create(ctx, &domain.Session{
					ID: domain.NewID(), ScanID: sc.ID, Mode: domain.AuthExisting,
					State: domain.SessionActive, CreatedAt: now, UpdatedAt: now,
				}); err != nil {
					t.Fatal(err)
				}
			}
			// Non-state-changing, logout, and download endpoints must be skipped.
			for _, ep := range []*domain.Endpoint{
				{ID: domain.NewID(), ScanID: sc.ID, URL: "https://app.example.test/profile", Method: domain.MethodGET, Source: domain.SourceCrawler, CreatedAt: now},
				{ID: domain.NewID(), ScanID: sc.ID, URL: "https://app.example.test/logout", Method: domain.MethodPOST, Source: domain.SourceCrawler, CreatedAt: now},
				{ID: domain.NewID(), ScanID: sc.ID, URL: "https://app.example.test/export", Method: domain.MethodPOST, Source: domain.SourceCrawler, CreatedAt: now},
			} {
				if err := st.Endpoints().Create(ctx, ep); err != nil {
					t.Fatal(err)
				}
			}
			// Create 25 unique state-changing endpoints to verify the 20-endpoint cap.
			for i := 0; i < 25; i++ {
				ep := &domain.Endpoint{
					ID: domain.NewID(), ScanID: sc.ID,
					URL:    fmt.Sprintf("https://app.example.test/api/item/%d", i),
					Method: domain.MethodPOST, Source: domain.SourceCrawler, CreatedAt: now,
				}
				if err := st.Endpoints().Create(ctx, ep); err != nil {
					t.Fatal(err)
				}
			}

			ctrl := NewController(st, q, execLog(), "test", Options{})
			t.Cleanup(ctrl.Shutdown)
			ctrl.enqueueCSRFProbes(ctx, sc.ID)

			jobs, err := q.Jobs(ctx, sc.ID)
			if err != nil {
				t.Fatal(err)
			}
			if len(jobs) != tc.want {
				t.Fatalf("jobs = %d, want %d", len(jobs), tc.want)
			}
			for _, job := range jobs {
				if job.Type != domain.JobCSRF || job.Priority != csrfPriority {
					t.Fatalf("unexpected job type/priority: %+v", job)
				}
			}
		})
	}
}
