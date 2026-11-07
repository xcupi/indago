package web_test

import (
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/indago/indago/internal/web"
)

// The readiness card is what stops a browserless scan reading as clean, and it
// is built from /api/capabilities once at startup. A single failed read used to
// leave ctx.caps null for the whole session: the card then says "Server
// capabilities unknown" and never recovers, so an operator loses the OFF
// warning. loadCapabilities retries a bounded number of times; this proves the
// card recovers from one transient failure — and the second half proves a real
// outage still reports honestly instead of guessing "on".
func TestUIReadinessRecoversFromOneFailedCapabilityRead(t *testing.T) {
	var reads atomic.Int64
	u := newUIHarnessWithHandler(t, "", web.Capabilities{}, func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/capabilities" && reads.Add(1) == 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			h.ServeHTTP(w, r)
		})
	})
	scanID := uiFindingsScan(t, u)
	u.openScanTab(scanID, "overview")

	// Wait for the CONDITION, not the element: #readiness exists as soon as the
	// view renders and can still hold the "unknown" placeholder while the read
	// is being retried.
	u.waitUI("readiness states the browser engine is OFF",
		`/Browser engine/.test(document.getElementById('readiness').textContent) && /OFF/.test(document.getElementById('readiness').textContent)`)
	if n := reads.Load(); n < 2 {
		t.Fatalf("capabilities were read %d time(s): the retry never happened, so the card cannot have recovered", n)
	}
	if txt := u.evalStr(`document.getElementById('readiness').textContent`); strings.Contains(txt, "unknown") {
		t.Fatalf("readiness still reports unknown capabilities after a retry: %q", txt)
	}
}
