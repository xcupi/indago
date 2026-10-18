//go:build browser_integration

package scan

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/ratelimit"
	"github.com/indago/indago/internal/worker"
)

func TestDOMStringTimerControlPlane(t *testing.T) {
	mgr := newSourceSelectionBrowser(t)
	defer mgr.Close()
	for _, sink := range []string{"setTimeout", "setInterval"} {
		t.Run(sink, func(t *testing.T) {
			var mu sync.Mutex
			var requests []string
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodConnect {
					http.Error(w, "no tunnels", 502)
					return
				}
				mu.Lock()
				requests = append(requests, r.URL.Path)
				mu.Unlock()
				if r.URL.Path != "/allowed" || r.Header.Get("Cookie") != "dummy=timer-policy" {
					http.Error(w, "missing dummy session or unexpected path", 403)
					return
				}
				w.Header().Set("Content-Type", "text/html")
				page := stringTimerMatrixPage(sink, "document.referrer", "positive")
				fmt.Fprint(w, strings.Replace(page, "</script>", "fetch('/denied');</script>", 1))
			}))
			defer proxy.Close()
			env := newScanEnv(t)
			ctx := context.Background()
			state := filepath.Join(t.TempDir(), "dummy-state.json")
			if err := os.WriteFile(state, []byte(`{"cookies":[{"name":"dummy","value":"timer-policy","domain":"timer-policy.invalid","path":"/allowed","expires":-1,"httpOnly":true,"secure":false,"sameSite":"Lax"}],"origins":[]}`), 0600); err != nil {
				t.Fatal(err)
			}
			if err := env.st.Sessions().Create(ctx, &domain.Session{ID: domain.NewID(), ScanID: env.scanID, StatePath: state}); err != nil {
				t.Fatal(err)
			}
			scope := domain.Scope{IncludeHosts: []string{"timer-policy.invalid"}, IncludePathPrefixes: []string{"/allowed"}}
			c := &Controller{store: env.st, opts: Options{Browser: mgr, Evidence: env.ev}, log: execLog()}
			lim := ratelimit.New(1)
			ex := c.defaultHandlers(nil, scope, []string{proxy.URL}, lim)[domain.JobDOMXSS]
			ep := env.endpoint("http://timer-policy.invalid/allowed", domain.MethodGET)
			if err := lim.Wait(ctx); err != nil {
				t.Fatal(err)
			}
			short, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
			err := ex.Handle(short, sourceSelectionJob(t, env.scanID, ep, "document.referrer"))
			cancel()
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("limiter cancellation not propagated: %v", err)
			}
			mu.Lock()
			n := len(requests)
			mu.Unlock()
			if n != 0 {
				t.Fatalf("request before permit: %d", n)
			}
			outside := env.endpoint("http://timer-policy.invalid/denied", domain.MethodGET)
			if err := ex.Handle(ctx, sourceSelectionJob(t, env.scanID, outside, "document.referrer")); !errors.Is(err, worker.ErrPermanent) {
				t.Fatalf("scope refusal must fail closed: %v", err)
			}
			mu.Lock()
			n = len(requests)
			mu.Unlock()
			if n != 0 {
				t.Fatal("refused endpoint sent network request")
			}
			lim.SetRate(0)
			if err := ex.Handle(ctx, sourceSelectionJob(t, env.scanID, ep, "document.referrer")); err != nil {
				t.Fatal(err)
			}
			fs := sourceSelectionFindings(t, env.st, env.scanID, ep.ID)
			if len(fs) != 1 || fs[0].Verdict != domain.VerdictConfirmed {
				t.Fatalf("proxy/session timer execution missing: %+v", fs)
			}
			d := decodeFindingDetail(fs[0].Detail)
			if len(d.Candidates) != 1 || string(d.Candidates[0].Context) != sink {
				t.Fatalf("wrong timer provenance: %+v", d)
			}
			htmlSourceMatrixEvidence(t, env, fs[0], d.Attempts[1].VerifyTestCaseID)
			mu.Lock()
			defer mu.Unlock()
			if len(requests) != 2 {
				t.Fatalf("both phases must use configured proxy/session: %v", requests)
			}
			for _, path := range requests {
				if path != "/allowed" {
					t.Fatalf("out-of-scope subrequest reached proxy: %s", path)
				}
			}
		})
	}
}
