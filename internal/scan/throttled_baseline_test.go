package scan

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/queue"
)

// AGENTS.md §2.2 requires the automatic fallback to be suppressed at "any point
// where the target answered 429 (rate limit) or 503 (unavailable/maintenance)".
//
// The mutated-probe path is covered (possibleBlockNote runs whatever reflection
// reported). The BASELINE request is not: possibleBlockNote only fires for a
// healthy baseline, and upsertBlockFinding keys Throttled off the mutated
// status — so a point whose own baseline answered 429 recorded nothing at all
// and the automatic pass still targeted it. A 429 baseline also hides a
// throttled mutation (404 baseline -> 429 probe), which is the same gap seen
// from the other side.
func TestBaselineThrottledPointRecordsBackpressure(t *testing.T) {
	cases := []struct {
		name                          string
		baselineStatus, mutatedStatus int
		echo                          bool
	}{
		{"baseline 429, clean mutation", 429, 200, false},
		{"baseline 429, reflected mutation", 429, 200, true},
		{"baseline 503, clean mutation", 503, 200, false},
		{"baseline 404, throttled mutation", 404, 429, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				v := r.URL.Query().Get("q")
				w.Header().Set("Content-Type", "text/html")
				if v == "obs" {
					w.WriteHeader(tc.baselineStatus)
				} else {
					w.WriteHeader(tc.mutatedStatus)
				}
				if tc.echo {
					_, _ = fmt.Fprintf(w, "<div>%s</div>", v)
				} else {
					_, _ = fmt.Fprint(w, "<div>no marker here</div>")
				}
			}))
			t.Cleanup(srv.Close)

			env := newScanEnv(t)
			ep := env.endpoint(srv.URL+"/s?q=obs", domain.MethodGET)
			q := env.param(ep, "q", domain.LocationQuery, "obs")
			ip := env.injection(ep, q)

			reflectReport(t, env.execEnv, ExecutorConfig{}, env.job(domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID}))

			findings, err := env.st.Findings().ListByScan(context.Background(), env.scanID)
			if err != nil {
				t.Fatal(err)
			}
			for _, f := range findings {
				if decodeFindingDetail(f.Detail).Throttled {
					return
				}
			}
			t.Fatalf("a point that answered %d -> %d recorded no backpressure signal (%d findings), so the automatic pass can still target it",
				tc.baselineStatus, tc.mutatedStatus, len(findings))
		})
	}
}

// The recording test above proves the flag is written; this one proves the real
// gate reads it and refuses to enqueue. The healthy-baseline control keeps the
// assertion honest: without it, a gate that always returns zero would pass.
func TestBaselineThrottledPointSkipsAutomaticEscalation(t *testing.T) {
	cases := []struct {
		name              string
		baseline, mutated int
		wantCandidates    int
	}{
		{"throttled baseline", 429, 200, 0},
		{"healthy baseline control", 200, 200, -1}, // -1 = any non-zero count
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				v := r.URL.Query().Get("q")
				w.Header().Set("Content-Type", "text/html")
				if v == "obs" {
					w.WriteHeader(tc.baseline)
				} else {
					w.WriteHeader(tc.mutated)
				}
				_, _ = fmt.Fprint(w, "<div>no marker here</div>")
			}))
			t.Cleanup(srv.Close)

			env := newScanEnv(t)
			q := queue.NewMemory()
			ep := env.endpoint(srv.URL+"/s?q=obs", domain.MethodGET)
			p := env.param(ep, "q", domain.LocationQuery, "obs")
			ip := env.injection(ep, p)

			reflectReport(t, env.execEnv, ExecutorConfig{}, env.job(domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID}))

			_, rep := escalationParent(t, env, q, ep, ip)
			for _, cand := range rep.Plan.Candidates {
				completedCanonicalEscalationJob(t, env, q, ep, ip, cand)
			}

			evasionController(env, q).enqueueEvasionEscalationCandidates(ctx, env.scanID)
			got := automaticTechniqueCandidates(t, q, env.scanID)
			switch {
			case tc.wantCandidates == 0 && len(got) != 0:
				t.Fatalf("baseline %d / probe %d is backpressure, yet the automatic gate enqueued %d technique candidates",
					tc.baseline, tc.mutated, len(got))
			case tc.wantCandidates < 0 && len(got) == 0:
				t.Fatalf("control: a healthy point must still be escalated, got 0 candidates — the test would pass vacuously")
			}
		})
	}
}
