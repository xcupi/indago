package scan

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

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

func TestCommandInjectionRefreshParamsCachesParentForm(t *testing.T) {
	var otherHits, formHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/other":
			otherHits.Add(1)
			fmt.Fprint(w, `<p>unrelated</p>`)
		case "/feedback":
			n := formHits.Add(1)
			fmt.Fprintf(w, `<form action="/feedback/submit" method="POST"><input name="csrf" value="token-%d"><input name="email"></form>`, n)
		default:
			fmt.Fprint(w, "ok")
		}
	}))
	defer srv.Close()

	env := newScanEnv(t)
	_ = env.endpoint(srv.URL+"/other", domain.MethodGET)
	_ = env.endpoint(srv.URL+"/feedback", domain.MethodGET)
	action := env.endpoint(srv.URL+"/feedback/submit", domain.MethodPOST)
	csrf := env.param(action, "csrf", domain.LocationForm, "stale")
	focus := env.param(action, "email", domain.LocationForm, "x@example.com")

	ex := newCommandInjectionExecutor(env.st, scopedClient(t, openScope()), env.ev, ExecutorConfig{}, execLog(), nil)
	got1 := ex.refreshParams(context.Background(), action, []*domain.Parameter{csrf, focus}, focus)
	otherAfterFirst := otherHits.Load()
	got2 := ex.refreshParams(context.Background(), action, []*domain.Parameter{csrf, focus}, focus)

	if otherAfterFirst > 1 || otherHits.Load() != otherAfterFirst {
		t.Fatalf("otherHits = (%d -> %d), want <= 1 and unchanged on second call", otherAfterFirst, otherHits.Load())
	}
	if formHits.Load() != 2 {
		t.Fatalf("formHits = %d, want 2 (parent form should still rotate)", formHits.Load())
	}
	if got1[0].Example != "token-1" || got2[0].Example != "token-2" {
		t.Fatalf("tokens = (%q, %q), want (token-1, token-2)", got1[0].Example, got2[0].Example)
	}
}

func TestCommandInjectionRefreshParamsSkipsTimedOutAndMissingSources(t *testing.T) {
	var slowHits, unrelatedHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/slow":
			slowHits.Add(1)
			time.Sleep(150 * time.Millisecond)
			fmt.Fprint(w, "slow")
		case "/unrelated":
			unrelatedHits.Add(1)
			fmt.Fprint(w, "plain")
		default:
			fmt.Fprint(w, "ok")
		}
	}))
	defer srv.Close()

	env := newScanEnv(t)
	_ = env.endpoint(srv.URL+"/slow", domain.MethodGET)
	_ = env.endpoint(srv.URL+"/unrelated", domain.MethodGET)
	ep1 := env.endpoint(srv.URL+"/api/task1", domain.MethodPOST)
	ep2 := env.endpoint(srv.URL+"/api/task2", domain.MethodPOST)
	tok1 := env.param(ep1, "token", domain.LocationForm, "abc")
	focus1 := env.param(ep1, "target", domain.LocationForm, "1")
	tok2 := env.param(ep2, "token", domain.LocationForm, "abc")
	focus2 := env.param(ep2, "target", domain.LocationForm, "1")

	ex := newCommandInjectionExecutor(env.st, scopedClient(t, openScope()), env.ev, ExecutorConfig{RequestTimeout: 40 * time.Millisecond}, execLog(), nil)
	_ = ex.refreshParams(context.Background(), ep1, []*domain.Parameter{tok1, focus1}, focus1)
	_ = ex.refreshParams(context.Background(), ep1, []*domain.Parameter{tok1, focus1}, focus1)
	_ = ex.refreshParams(context.Background(), ep2, []*domain.Parameter{tok2, focus2}, focus2)

	if slowHits.Load() != 1 {
		t.Fatalf("slowHits = %d, want 1 (timed-out page must not be retried)", slowHits.Load())
	}
	if unrelatedHits.Load() != 2 {
		t.Fatalf("unrelatedHits = %d, want 2 (once for ep1, once for ep2; ep1 second call negatively cached)", unrelatedHits.Load())
	}
}
