package scan

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/indago/indago/internal/domain"
)

func TestSSTIConfirmsTwoIndependentTemplateExpressions(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/8.2")
		value := r.URL.Query().Get("q")
		switch {
		case strings.Contains(value, "<%= 7*7 %>"):
			fmt.Fprint(w, "rendered 49")
		case strings.Contains(value, "<%= 11*13 %>"):
			fmt.Fprint(w, "rendered 143")
		case strings.Contains(value, "{{7*7}}"):
			fmt.Fprint(w, "rendered 49")
		case strings.Contains(value, "{{11*13}}"):
			fmt.Fprint(w, "rendered 143")
		case strings.Contains(value, "${11*13}"):
			fmt.Fprint(w, "rendered 143")
		default:
			fmt.Fprint(w, "template page")
		}
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/page?q=hello", domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "hello")
	ip := env.injection(ep, focus)
	ex := newSSTIExecutor(env.st, scopedClient(t, openScope()), env.ev, ExecutorConfig{}, execLog(), nil)
	job := &domain.TestJob{ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobSSTI,
		Target: domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID, URL: ep.URL}, Attempts: 1, MaxAttempts: 2}
	if err := ex.Handle(context.Background(), job); err != nil {
		t.Fatalf("handle: %v", err)
	}
	findings, err := env.st.Findings().ListByScan(context.Background(), env.scanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].VulnClass != domain.VulnSSTI || findings[0].Verdict != domain.VerdictConfirmed {
		t.Fatalf("findings = %+v, want one confirmed SSTI", findings)
	}
	if !strings.Contains(findings[0].Title, "q") {
		t.Fatalf("finding title = %q, want parameter name", findings[0].Title)
	}
}

func TestSSTIConfirmsCodeContextBreakout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "Express")
		value := r.URL.Query().Get("q")
		switch {
		case strings.Contains(value, "}}{{7*7}}"):
			fmt.Fprint(w, "Hello Carlos49")
		case strings.Contains(value, "}}{{11*13}}"):
			fmt.Fprint(w, "Hello Carlos143")
		default:
			fmt.Fprint(w, "Hello Carlos")
		}
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/profile?q=user.name", domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "user.name")
	ip := env.injection(ep, focus)
	ex := newSSTIExecutor(env.st, scopedClient(t, openScope()), env.ev, ExecutorConfig{}, execLog(), nil)
	job := &domain.TestJob{ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobSSTI,
		Target: domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID, URL: ep.URL}, Attempts: 1, MaxAttempts: 2}
	if err := ex.Handle(context.Background(), job); err != nil {
		t.Fatalf("handle: %v", err)
	}
	findings, err := env.st.Findings().ListByScan(context.Background(), env.scanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].VulnClass != domain.VulnSSTI || findings[0].Verdict != domain.VerdictConfirmed {
		t.Fatalf("findings = %+v, want one confirmed code-context SSTI", findings)
	}
}

func TestSSTIUnknownStackIsSkippedWithoutPayloads(t *testing.T) {
	var templateRequests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		if strings.Contains(q, "{{") || strings.Contains(q, "${") || strings.Contains(q, "<%") {
			templateRequests.Add(1)
		}
		fmt.Fprint(w, "plain page")
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/page?q=hello", domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "hello")
	ip := env.injection(ep, focus)
	ex := newSSTIExecutor(env.st, scopedClient(t, openScope()), env.ev, ExecutorConfig{}, execLog(), nil)
	job := &domain.TestJob{ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobSSTI,
		Target: domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID, URL: ep.URL}, Attempts: 1, MaxAttempts: 2}
	if err := ex.Handle(context.Background(), job); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if got := templateRequests.Load(); got != 0 {
		t.Fatalf("unknown stack received %d template payloads, want 0", got)
	}
	cases, err := env.st.TestCases().ListByScan(context.Background(), env.scanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) != 1 || cases[0].VulnClass != domain.VulnSSTI || cases[0].Status != domain.TestCaseSkipped {
		t.Fatalf("cases = %+v, want one skipped SSTI case", cases)
	}
	if !strings.Contains(cases[0].Note, "no supported template stack fingerprint") {
		t.Fatalf("skip note = %q", cases[0].Note)
	}
}

func TestSSTIReflectionIsNotConfirmed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/8.2")
		fmt.Fprintf(w, "echo %s", r.URL.Query().Get("q"))
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/page?q=hello", domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "hello")
	ip := env.injection(ep, focus)
	ex := newSSTIExecutor(env.st, scopedClient(t, openScope()), env.ev, ExecutorConfig{}, execLog(), nil)
	job := &domain.TestJob{ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobSSTI,
		Target: domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID, URL: ep.URL}, Attempts: 1, MaxAttempts: 2}
	if err := ex.Handle(context.Background(), job); err != nil {
		t.Fatalf("handle: %v", err)
	}
	findings, err := env.st.Findings().ListByScan(context.Background(), env.scanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("reflected template payload must not be confirmed: %+v", findings)
	}
}
