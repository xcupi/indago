package scan

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/indago/indago/internal/domain"
)

func TestWritePolicyBlocksStateChangingChecks(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := ExecutorConfig{AllowStateChanging: true, SkipWriteEndpoints: true}
	for name, run := range map[string]func(*testing.T, *scanEnv, *domain.Endpoint, ExecutorConfig) *domain.TestCase{
		"CSRF":        runCSRF,
		"file upload": runFileUpload,
		"stored XSS": func(t *testing.T, env *scanEnv, ep *domain.Endpoint, cfg ExecutorConfig) *domain.TestCase {
			ctx := t.Context()
			env.sc.Config.EnableStoredXSS = true
			env.sc.Config.SkipWriteEndpoints = true
			if err := env.st.Scans().Update(ctx, env.sc); err != nil {
				t.Fatal(err)
			}
			env.param(ep, "comment", domain.LocationForm, "example")
			body, err := json.Marshal(storedXSSJob{EndpointID: ep.ID})
			if err != nil {
				t.Fatal(err)
			}
			eng := &storedXSSCountingEngine{}
			h := newStoredXSSExecutor(env.st, eng, nil, env.ev, cfg, execLog(), &sync.Mutex{})
			job := &domain.TestJob{ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobStoredXSS,
				Target: domain.JobTarget{EndpointID: ep.ID, URL: ep.URL}, Payload: body}
			if err := h.Handle(ctx, job); err != nil {
				t.Fatal(err)
			}
			if got := eng.calls.Load(); got != 0 {
				t.Fatalf("sent %d requests despite the write policy", got)
			}
			return env.only()
		},
	} {
		t.Run(name, func(t *testing.T) {
			env := newScanEnv(t)
			ep := env.endpoint(srv.URL+"/profile/update", domain.MethodPOST)
			tc := run(t, env, ep, cfg)
			if tc.Status != domain.TestCaseSkipped || !strings.Contains(tc.Note, "skip_write_endpoints") {
				t.Fatalf("status = %s, note = %q, want the write policy skip", tc.Status, tc.Note)
			}
		})
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("target received %d requests despite the write policy", got)
	}
}
