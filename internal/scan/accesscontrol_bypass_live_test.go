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
	"sync"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
)

func runBypassJob(t *testing.T, target string) (*scanEnv, accessControlDetail, []*domain.Finding) {
	t.Helper()
	env := newScanEnv(t)
	ep := acEndpoint(t, env, target, domain.SourceCrawler, domain.MethodGET)
	ex := newAccessControlExecutor(env.st, newScopedEngine(noFollowClient(t), openScope()), env.ev,
		ExecutorConfig{}, execLog(), &sync.Mutex{}, true)
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

	_, d, findings := runBypassJob(t, srv.URL+"/admin")
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

	_, d, findings := runBypassJob(t, srv.URL+"/admin-roles")
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

	_, d, findings := runBypassJob(t, srv.URL+"/admin")
	if d.Verdict != domain.VerdictRejected {
		t.Fatalf("verdict=%q reason=%q, want rejected", d.Verdict, d.Reason)
	}
	if len(findings) != 0 {
		t.Fatalf("findings = %+v, want none for a surface that stays denied", findings)
	}
}
