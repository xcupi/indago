package scan

// Cases 28 and 29: the access-control bypass probes, against real servers.
//
//   - /hdr:  GET /admin is denied (403), but GET / with X-Original-URL: /admin
//            answers the administrative surface — the header-override bypass.
//   - /meth: POST /admin-roles is denied (401), but GET /admin-roles answers with
//            the application's own validation error ("Missing parameter") — the
//            method-based bypass.
//   - /none: denies both and answers the header probe with a denial page, so the
//            pass must record Rejected and create no finding.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
)

func runBypassJob(t *testing.T, target string, cfg ExecutorConfig) (*scanEnv, accessControlDetail, []*domain.Finding) {
	t.Helper()
	env := newScanEnv(t)
	ep := acEndpoint(t, env, target, domain.SourceCrawler, domain.MethodGET)
	ex := newAccessControlExecutor(env.st, newScopedEngine(noFollowClient(t), openScope()), env.ev,
		cfg, execLog(), &sync.Mutex{}, true)
	job := &domain.TestJob{ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobAccessControl,
		Target: domain.JobTarget{EndpointID: ep.ID, URL: target}, MaxAttempts: 1,
		Payload:   accessControlModePayload(accessModeBypass),
		CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := ex.Handle(context.Background(), job); err != nil {
		t.Fatalf("handle: %v", err)
	}
	cases := acCases(t, env)
	if len(cases) != 1 {
		t.Fatalf("expected 1 access-control test case, got %d", len(cases))
	}
	return env, acDetail(t, cases[0]), acFindings(t, env)
}

func TestAccessBypassHeaderOverrideConfirms(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/admin":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("Forbidden"))
		case r.URL.Path == "/" && r.Header.Get("X-Original-URL") == "/admin":
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `<h1>Admin panel</h1><form action="/admin/delete"><input name="username"></form>`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	_, d, findings := runBypassJob(t, srv.URL+"/admin", ExecutorConfig{})
	if d.Verdict != domain.VerdictConfirmed || d.Bypass != "header_url_override" {
		t.Fatalf("verdict=%q bypass=%q reason=%q, want confirmed/header_url_override", d.Verdict, d.Bypass, d.Reason)
	}
	if len(d.HeaderProbes) == 0 || !d.HeaderProbes[0].Reached {
		t.Fatalf("header probes = %+v, want the X-Original-URL probe to have reached", d.HeaderProbes)
	}
	if len(findings) != 1 || findings[0].VulnClass != domain.VulnAccessControl {
		t.Fatalf("findings = %+v, want exactly one access_control finding", findings)
	}
}

func TestAccessBypassMethodConfirms(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin-roles" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("Unauthorized"))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("Missing parameter 'username'"))
	}))
	defer srv.Close()

	_, d, findings := runBypassJob(t, srv.URL+"/admin-roles", ExecutorConfig{AllowStateChanging: true})
	if d.Verdict != domain.VerdictConfirmed || d.Bypass != "method_bypass" {
		t.Fatalf("verdict=%q bypass=%q reason=%q, want confirmed/method_bypass", d.Verdict, d.Bypass, d.Reason)
	}
	if len(findings) != 1 || findings[0].VulnClass != domain.VulnAccessControl {
		t.Fatalf("findings = %+v, want exactly one access_control finding", findings)
	}
}

func TestAccessBypassDenialStaysRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("Access denied"))
	}))
	defer srv.Close()

	_, d, findings := runBypassJob(t, srv.URL+"/admin", ExecutorConfig{})
	if d.Verdict != domain.VerdictRejected {
		t.Fatalf("verdict=%q reason=%q, want rejected", d.Verdict, d.Reason)
	}
	if len(findings) != 0 {
		t.Fatalf("findings = %+v, want none for a surface that stays denied", findings)
	}
}

// The default path must not send POST or TRACE. GET checks stay: the direct
// baseline and the two header-override GETs are still recorded.
func TestAccessBypassDefaultSendsNoPOSTOrTRACE(t *testing.T) {
	var mu sync.Mutex
	var methods []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		methods = append(methods, r.Method)
		mu.Unlock()
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("denied"))
	}))
	defer srv.Close()

	_, d, _ := runBypassJob(t, srv.URL+"/admin", ExecutorConfig{})

	mu.Lock()
	got := append([]string(nil), methods...)
	mu.Unlock()
	sawGET := false
	for _, m := range got {
		switch m {
		case http.MethodGet:
			sawGET = true
		case http.MethodPost, http.MethodTrace:
			t.Fatalf("default bypass pass sent %s; methods=%v", m, got)
		}
	}
	if !sawGET {
		t.Fatalf("default bypass pass sent no GET; methods=%v", got)
	}
	if len(d.SkippedProbes) != 2 {
		t.Fatalf("skipped probes = %v, want POST and TRACE named", d.SkippedProbes)
	}
	if !strings.Contains(d.Reason, "AllowStateChanging") {
		t.Fatalf("reason does not explain the skipped probes: %q", d.Reason)
	}
}

// With the explicit opt-in, both method probes run again; this test records
// them at the endpoint, not just in the detail JSON.
func TestAccessBypassOptInSendsPOSTAndTRACE(t *testing.T) {
	var mu sync.Mutex
	var methods []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		methods = append(methods, r.Method)
		mu.Unlock()
		switch r.Method {
		case http.MethodTrace:
			w.WriteHeader(http.StatusMethodNotAllowed)
		case http.MethodPost:
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("Unauthorized"))
		default:
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("Access denied"))
		}
	}))
	defer srv.Close()

	_, d, _ := runBypassJob(t, srv.URL+"/admin-roles", ExecutorConfig{AllowStateChanging: true})

	mu.Lock()
	got := append([]string(nil), methods...)
	mu.Unlock()
	seen := map[string]bool{}
	for _, m := range got {
		seen[m] = true
	}
	if !seen[http.MethodPost] || !seen[http.MethodTrace] {
		t.Fatalf("opt-in bypass methods = %v, want POST and TRACE", got)
	}
	if d.PostStatus != http.StatusUnauthorized {
		t.Fatalf("post status = %d, want 401", d.PostStatus)
	}
	if len(d.SkippedProbes) != 0 {
		t.Fatalf("opt-in path still reports skipped probes: %v", d.SkippedProbes)
	}
}

// skip_write_endpoints suppresses the non-GET bypass probes even when the
// server opt-in is on.
func TestAccessBypassSkipWriteEndpointsSuppressesNonGET(t *testing.T) {
	var mu sync.Mutex
	var methods []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		methods = append(methods, r.Method)
		mu.Unlock()
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	_, d, _ := runBypassJob(t, srv.URL+"/admin", ExecutorConfig{
		AllowStateChanging: true,
		SkipWriteEndpoints: true,
	})

	mu.Lock()
	got := append([]string(nil), methods...)
	mu.Unlock()
	for _, m := range got {
		if m == http.MethodPost || m == http.MethodTrace {
			t.Fatalf("skip_write_endpoints still allowed %s; methods=%v", m, got)
		}
	}
	if len(d.SkippedProbes) == 0 || !strings.Contains(strings.Join(d.SkippedProbes, "; "), "skip_write_endpoints") {
		t.Fatalf("skipped probes = %v, want skip_write_endpoints named", d.SkippedProbes)
	}
}
