package scan

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/indago/indago/internal/domain"
)

var commandExpr = regexp.MustCompile(`indago([0-9]+)\$\(\((\d+)\*(\d+)\)\)`)

func TestCommandInjectionConfirmsTwoIndependentMarkers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := r.URL.Query().Get("cmd")
		if m := commandExpr.FindStringSubmatch(value); m != nil {
			a, _ := strconv.Atoi(m[2])
			b, _ := strconv.Atoi(m[3])
			fmt.Fprintf(w, "result indago%s%d", m[1], a*b)
			return
		}
		fmt.Fprint(w, "stock available")
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/stock?cmd=1", domain.MethodGET)
	focus := env.param(ep, "cmd", domain.LocationQuery, "1")
	ip := env.injection(ep, focus)
	ex := newCommandInjectionExecutor(env.st, scopedClient(t, openScope()), env.ev, ExecutorConfig{}, execLog(), nil)
	job := &domain.TestJob{ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobCommandInjection,
		Target: domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID, URL: ep.URL}, Attempts: 1, MaxAttempts: 2}
	if err := ex.Handle(context.Background(), job); err != nil {
		t.Fatalf("handle: %v", err)
	}
	findings, err := env.st.Findings().ListByScan(context.Background(), env.scanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].VulnClass != domain.VulnCommandInjection || findings[0].Verdict != domain.VerdictConfirmed {
		t.Fatalf("findings = %+v, want one confirmed command injection", findings)
	}
	if !strings.Contains(findings[0].Title, "cmd") {
		t.Fatalf("finding title = %q, want parameter name", findings[0].Title)
	}
}

func TestCommandInjectionRefreshParamsFromParentForm(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/feedback" {
			fmt.Fprint(w, `<form action="/feedback/submit" method="POST"><input name="csrf" value="fresh-token"><input name="email"></form>`)
			return
		}
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()
	env := newScanEnv(t)
	action := env.endpoint(srv.URL+"/feedback/submit", domain.MethodPOST)
	page := env.endpoint(srv.URL+"/feedback", domain.MethodGET)
	csrf := env.param(action, "csrf", domain.LocationForm, "stale-token")
	focus := env.param(action, "email", domain.LocationForm, "x@example.com")
	ex := newCommandInjectionExecutor(env.st, scopedClient(t, openScope()), env.ev, ExecutorConfig{}, execLog(), nil)
	got := ex.refreshParams(context.Background(), action, []*domain.Parameter{csrf, focus}, focus)
	var fresh string
	for _, p := range got {
		if p.ID == csrf.ID {
			fresh = p.Example
		}
	}
	_ = page
	if fresh != "fresh-token" {
		t.Fatalf("csrf = %q, want fresh token", fresh)
	}
}
