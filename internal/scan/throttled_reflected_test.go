package scan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/indago/indago/internal/domain"
)

// A throttle/maintenance page can still echo the request (an error page showing
// the URL), so reflection alone must not hide a 429/503. The escalation gate
// reads findingDetail.Throttled per injection point; if a reflected throttle
// response records no block finding, the gate happily points the bypass pass at
// a target that just asked for less traffic.
func TestThrottledReflectedResponseStillRecordsBackpressure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		if v != "obs" { // the mutated (probe-carrying) request
			w.WriteHeader(http.StatusTooManyRequests)
		}
		// Echoes the value even on the 429, like a rate-limit page that shows
		// the blocked request.
		_, _ = w.Write([]byte("<div>" + v + "</div>"))
	}))
	t.Cleanup(srv.Close)

	env := newScanEnv(t) // the block diagnostic needs a scan row to attach to
	ep := env.endpoint(srv.URL+"/s?q=obs", domain.MethodGET)
	q := env.param(ep, "q", domain.LocationQuery, "obs")
	ip := env.injection(ep, q)

	_, rep := reflectReport(t, env.execEnv, ExecutorConfig{}, env.job(domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID}))
	if !rep.Reflected {
		t.Fatalf("setup: the 429 body was expected to reflect the marker, report=%+v", rep)
	}

	findings, err := env.st.Findings().ListByScan(context.Background(), env.scanID)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if decodeFindingDetail(f.Detail).Throttled {
			return
		}
	}
	t.Fatalf("a reflected 429 recorded no backpressure signal, so the escalation gate cannot skip this point; findings=%d", len(findings))
}
