package scan

// Cases 35 and 36: the admin ACTION step, probed with a username that does not
// exist so no role can change whatever the answer is.
//
//   - confirmation-step fixture: the ordinary request is refused (401) but the
//     same request with confirmed=true reaches the handler (400 "Could not
//     change user role"), and the anonymous control is refused.
//   - referer fixture: the same shape, but the variant carries Referer: /admin.
//   - public fixture: the variant reaches the handler for an ANONYMOUS caller
//     too, so there is no authorization gap and nothing may be confirmed.
//   - deny-all fixture: no variant reaches the handler.

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

func runMutationJob(t *testing.T, target string) (*scanEnv, accessControlDetail, []*domain.Finding) {
	t.Helper()
	env := newScanEnv(t)
	ep := acEndpoint(t, env, target, domain.SourceCrawler, domain.MethodPOST)
	ex := newAccessControlExecutor(env.st, acSessionEngine(t), env.ev, ExecutorConfig{}, execLog(), &sync.Mutex{}, true)
	job := &domain.TestJob{ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobAccessControl,
		Target: domain.JobTarget{EndpointID: ep.ID, URL: target}, MaxAttempts: 1,
		Payload:   accessControlModePayload(accessModeMutation),
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

func hasCallerSession(r *http.Request) bool {
	c, err := r.Cookie("sid")
	return err == nil && c.Value == "nonadmin"
}

func TestAccessMutationConfirmationStepConfirms(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin-roles" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = r.ParseForm()
		if r.Form.Get("confirmed") == "true" && hasCallerSession(r) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprint(w, `Could not change user role`)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprint(w, `"Unauthorized"`)
	}))
	defer srv.Close()

	_, d, findings := runMutationJob(t, srv.URL+"/admin-roles")
	if d.Verdict != domain.VerdictConfirmed || d.Bypass != "confirmation" {
		t.Fatalf("verdict=%q bypass=%q reason=%q, want confirmed/confirmation", d.Verdict, d.Bypass, d.Reason)
	}
	if d.StepBaseline != 401 || d.StepConfirm != 400 || d.StepAnonymous != 401 {
		t.Fatalf("statuses baseline=%d confirm=%d anon=%d, want 401/400/401", d.StepBaseline, d.StepConfirm, d.StepAnonymous)
	}
	if len(findings) != 1 || findings[0].VulnClass != domain.VulnAccessControl {
		t.Fatalf("findings = %+v, want one access_control finding", findings)
	}
	if !strings.Contains(d.Reason, "confirmation-step") {
		t.Fatalf("reason should name the technique: %q", d.Reason)
	}
}

func TestAccessMutationRefererConfirms(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin-roles" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if strings.Contains(r.Header.Get("Referer"), "/admin") && hasCallerSession(r) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprint(w, `Could not change user role`)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprint(w, `"Unauthorized"`)
	}))
	defer srv.Close()

	_, d, findings := runMutationJob(t, srv.URL+"/admin-roles")
	if d.Verdict != domain.VerdictConfirmed || d.Bypass != "referer" {
		t.Fatalf("verdict=%q bypass=%q reason=%q, want confirmed/referer", d.Verdict, d.Bypass, d.Reason)
	}
	if d.StepReferer != 400 {
		t.Fatalf("referer variant status = %d, want 400", d.StepReferer)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want one finding", findings)
	}
}

func TestAccessMutationPublicHandlerIsNeverConfirmed(t *testing.T) {
	// The handler answers the confirmed request for anybody, anonymous included:
	// there is no authorization gap to report.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin-roles" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = r.ParseForm()
		if r.Form.Get("confirmed") == "true" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprint(w, `Could not change user role`)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprint(w, `"Unauthorized"`)
	}))
	defer srv.Close()

	_, d, findings := runMutationJob(t, srv.URL+"/admin-roles")
	if d.Verdict == domain.VerdictConfirmed {
		t.Fatalf("a handler that answers anonymous callers must never be Confirmed: %s", d.Reason)
	}
	if len(findings) != 0 {
		t.Fatalf("findings = %+v, want none", findings)
	}
}

func TestAccessMutationDeniedEverywhereStaysRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprint(w, `"Unauthorized"`)
	}))
	defer srv.Close()

	_, d, findings := runMutationJob(t, srv.URL+"/admin-roles")
	if d.Verdict != domain.VerdictRejected {
		t.Fatalf("verdict=%q reason=%q, want rejected", d.Verdict, d.Reason)
	}
	if len(findings) != 0 {
		t.Fatalf("findings = %+v, want none", findings)
	}
}
