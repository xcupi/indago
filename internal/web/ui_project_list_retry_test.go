package web_test

import (
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/indago/indago/internal/web"
)

// TestUINewScanActionsStayReachableOnShortViewport failed on a hosted run with
// "UI condition never held: project selected": the test calls loadProjects()
// and indexes ctx.projects[0], so one failed /api/projects read threw and the
// selector stayed empty. That is the same product weakness the capability read
// had — a bootstrap fetch with no retry — so it gets the same bounded retry.
//
// The failure is injected AFTER startup and after the project exists, so this
// exercises the retry itself rather than an empty-but-valid list.
func TestUIProjectListRecoversFromOneFailedRead(t *testing.T) {
	var failNext atomic.Bool
	var count atomic.Int64
	u := newUIHarnessWithHandler(t, "", web.Capabilities{}, func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/projects" {
				count.Add(1)
				if failNext.CompareAndSwap(true, false) {
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
			}
			h.ServeHTTP(w, r)
		})
	})
	_ = uiFindingsScan(t, u)

	before := count.Load()
	failNext.Store(true)
	u.eval(`(async () => { await loadProjects(); })(); true`)
	u.waitUI("project list recovered after a failed read", `ctx.projects.length === 1`)
	if got := count.Load() - before; got < 2 {
		t.Fatalf("project list was read %d time(s) after the injected failure; the retry never happened", got)
	}
}
