package scan

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/discovery"
	"github.com/indago/indago/internal/domain"
)

// A raw-query APPEND probe costs one request per endpoint. In AUTO mode it is
// registered on endpoints that already have query parameters, so the probe only
// earns its request when the canonical parameter probe did not reflect: once a
// named parameter reflects, the blob shape cannot add a finding.
//
// The mode gate matters as much as the skip: an explicit -raw-query=always scan
// must keep sending it, because the operator asked for the blob probe.
func TestRawQueryAppendProbeGate(t *testing.T) {
	cases := []struct {
		name           string
		mode           string
		canonical      bool // did the canonical parameter reflect?
		wantSkipped    bool
		wantAtLeastOne bool
	}{
		{"auto, canonical already reflected", "auto", true, true, false},
		{"auto, canonical did not reflect", "auto", false, false, true},
		{"always, canonical already reflected", "always", true, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			var hits atomic.Int64
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				w.Header().Set("Content-Type", "text/html")
				_, _ = w.Write([]byte(`<!doctype html><html><body><p>` + r.URL.Query().Get("q") + `</p></body></html>`))
			}))
			t.Cleanup(srv.Close)

			env := newScanEnv(t)
			env.sc.Config.RawQueryInjection = tc.mode
			if err := env.st.Scans().Update(ctx, env.sc); err != nil {
				t.Fatal(err)
			}

			ep := env.endpoint(srv.URL+"/search?q=hi", domain.MethodGET)
			q := env.param(ep, "q", domain.LocationQuery, "hi")
			qIP := env.injection(ep, q)
			if tc.canonical {
				seedReflectionCase(t, env, qIP, "q", true)
			} else {
				seedReflectionCase(t, env, qIP, "q", false)
			}

			raw := rawQueryParamFor(t, ep, discovery.RawQueryAppendName)
			if err := env.st.Parameters().Create(ctx, raw); err != nil {
				t.Fatal(err)
			}
			rawIP := env.injection(ep, raw)
			job := env.job(domain.JobTarget{EndpointID: ep.ID, InjectionPointID: rawIP.ID})

			if err := env.executor(scopedClient(t, openScope()), ExecutorConfig{}).Handle(ctx, job); err != nil {
				t.Fatalf("handle: %v", err)
			}

			out := testCaseForJob(t, env, job.ID)
			if tc.wantSkipped {
				if out.Status != domain.TestCaseSkipped || !strings.Contains(out.Note, "already reflected") {
					t.Fatalf("status=%s note=%q, want an explicit skip naming the reflected parameter", out.Status, out.Note)
				}
				if hits.Load() != 0 {
					t.Fatalf("the append probe sent %d request(s) although a canonical parameter already reflected", hits.Load())
				}
				return
			}
			if out.Status == domain.TestCaseSkipped {
				t.Fatalf("the probe was skipped (%q) but this mode/state must send it", out.Note)
			}
			if tc.wantAtLeastOne && hits.Load() == 0 {
				t.Fatal("the append probe never reached the target")
			}
		})
	}
}

// seedReflectionCase records the canonical parameter's reflection outcome the
// way the executor does, so the gate reads the same evidence it would in a scan.
func seedReflectionCase(t *testing.T, env *scanEnv, ip *domain.InjectionPoint, param string, reflected bool) {
	t.Helper()
	detail, err := json.Marshal(detection.ReflectionReport{Reflected: reflected, Parameter: param, Location: domain.LocationQuery})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := env.st.TestCases().Create(context.Background(), &domain.TestCase{
		ID: domain.NewID(), ScanID: env.scanID, JobID: domain.NewID(), InjectionPointID: ip.ID,
		VulnClass: domain.VulnReflectedXSS, Status: domain.TestCaseCompleted, Outcome: domain.OutcomeSuccess,
		Detail: detail, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
}

func testCaseForJob(t *testing.T, env *scanEnv, jobID domain.ID) *domain.TestCase {
	t.Helper()
	cases, err := env.st.TestCases().ListByScan(context.Background(), env.scanID)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		if c.JobID == jobID {
			return c
		}
	}
	t.Fatalf("no test case recorded for job %s", jobID)
	return nil
}
