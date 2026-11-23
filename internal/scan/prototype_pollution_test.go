package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/queue"
)

func TestPrototypePollutionNoBrowserSkipsCleanly(t *testing.T) {
	env := newScanEnv(t)
	ep := env.endpoint("http://target.example/app", domain.MethodGET)
	ep.ContentType = "text/html"
	_ = env.st.Endpoints().Create(context.Background(), ep)

	payload, err := json.Marshal(prototypePollutionJob{EndpointID: ep.ID})
	if err != nil {
		t.Fatal(err)
	}
	job := &domain.TestJob{
		ID:       domain.NewID(),
		ScanID:   env.scanID,
		Type:     domain.JobPrototypePollution,
		Target:   domain.JobTarget{EndpointID: ep.ID, URL: ep.URL},
		Payload:  payload,
		Attempts: 1,
	}

	h := newPrototypePollutionExecutor(env.st, nil, env.ev, 0, execLog(), &sync.Mutex{})
	if err := h.Handle(context.Background(), job); err != nil {
		t.Fatalf("Handle with nil browser returned error: %v", err)
	}

	tc := env.only()
	if tc.Status != domain.TestCaseSkipped {
		t.Fatalf("status = %s, want skipped", tc.Status)
	}
	if !strings.Contains(tc.Note, "prototype_pollution skipped: no browser configured") {
		t.Fatalf("note = %q, want no browser configured", tc.Note)
	}
}

func TestBuildPrototypePollutionURL(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		vec  prototypePollutionVector
		want string
	}{
		{
			name: "query proto no existing params",
			raw:  "https://example.com/page",
			vec:  prototypePollutionVectors[0],
			want: "https://example.com/page?__proto__[indago_pp]=1",
		},
		{
			name: "query proto preserves existing params",
			raw:  "https://example.com/page?foo=bar&baz=1#old",
			vec:  prototypePollutionVectors[0],
			want: "https://example.com/page?foo=bar&baz=1&__proto__[indago_pp]=1",
		},
		{
			name: "query constructor preserves existing params",
			raw:  "https://example.com/page?a=1",
			vec:  prototypePollutionVectors[1],
			want: "https://example.com/page?a=1&constructor[prototype][indago_pp]=1",
		},
		{
			name: "fragment proto",
			raw:  "https://example.com/page?a=1",
			vec:  prototypePollutionVectors[2],
			want: "https://example.com/page?a=1#__proto__%5Bindago_pp%5D=1",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := buildPrototypePollutionURL(tc.raw, tc.vec)
			if err != nil {
				t.Fatalf("buildPrototypePollutionURL: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestEnqueuePrototypePollutionProbesCapFilterAndSkip(t *testing.T) {
	ctx := context.Background()

	t.Run("cap dedup and filtering", func(t *testing.T) {
		env := newScanEnv(t)
		q := queue.NewMemory()
		ctrl := NewController(env.st, q, execLog(), "test", Options{})

		// Non-eligible endpoints: POST, JSON, static JS, download PDF.
		_ = env.st.Endpoints().Create(ctx, &domain.Endpoint{
			ID: domain.NewID(), ScanID: env.scanID, Method: domain.MethodPOST, URL: "http://target.example/submit", ContentType: "text/html",
		})
		_ = env.st.Endpoints().Create(ctx, &domain.Endpoint{
			ID: domain.NewID(), ScanID: env.scanID, Method: domain.MethodGET, URL: "http://target.example/api/data", ContentType: "application/json",
		})
		_ = env.st.Endpoints().Create(ctx, &domain.Endpoint{
			ID: domain.NewID(), ScanID: env.scanID, Method: domain.MethodGET, URL: "http://target.example/static/app.js",
		})
		_ = env.st.Endpoints().Create(ctx, &domain.Endpoint{
			ID: domain.NewID(), ScanID: env.scanID, Method: domain.MethodGET, URL: "http://target.example/report.pdf",
		})

		// Duplicate URL should only be counted once; 20 unique HTML GET URLs should cap at 15.
		for i := 0; i < 20; i++ {
			u := fmt.Sprintf("http://target.example/page-%02d", i)
			_ = env.st.Endpoints().Create(ctx, &domain.Endpoint{
				ID: domain.NewID(), ScanID: env.scanID, Method: domain.MethodGET, URL: u, ContentType: "text/html; charset=utf-8",
			})
			if i == 0 {
				_ = env.st.Endpoints().Create(ctx, &domain.Endpoint{
					ID: domain.NewID(), ScanID: env.scanID, Method: domain.MethodGET, URL: u, ContentType: "text/html",
				})
			}
		}

		ctrl.enqueuePrototypePollutionProbes(ctx, env.scanID)

		var count int
		seenURLs := map[string]bool{}
		for {
			job, err := q.Lease(ctx, "test-worker", env.scanID, []domain.JobType{domain.JobPrototypePollution}, time.Minute)
			if err != nil || job == nil {
				break
			}
			count++
			if seenURLs[job.Target.URL] {
				t.Fatalf("duplicate job enqueued for %s", job.Target.URL)
			}
			seenURLs[job.Target.URL] = true
		}
		if count != maxPrototypePollutionEndpoints {
			t.Fatalf("enqueued %d jobs, want %d", count, maxPrototypePollutionEndpoints)
		}
	})

	t.Run("respects SkipPrototypePollution", func(t *testing.T) {
		env := newScanEnv(t)
		env.sc.Config.SkipPrototypePollution = true
		if err := env.st.Scans().Update(ctx, env.sc); err != nil {
			t.Fatal(err)
		}
		_ = env.st.Endpoints().Create(ctx, &domain.Endpoint{
			ID: domain.NewID(), ScanID: env.scanID, Method: domain.MethodGET, URL: "http://target.example/page", ContentType: "text/html",
		})

		q := queue.NewMemory()
		ctrl := NewController(env.st, q, execLog(), "test", Options{})
		ctrl.enqueuePrototypePollutionProbes(ctx, env.scanID)

		job, err := q.Lease(ctx, "test-worker", env.scanID, []domain.JobType{domain.JobPrototypePollution}, time.Minute)
		if err == nil && job != nil {
			t.Fatalf("expected 0 jobs when SkipPrototypePollution=true, got %+v", job)
		}
	})
}

func TestPrototypePollutionFindingDeduplication(t *testing.T) {
	ctx := context.Background()
	env := newScanEnv(t)
	ep := env.endpoint("http://target.example/app", domain.MethodGET)
	exec := newPrototypePollutionExecutor(env.st, nil, env.ev, 0, execLog(), &sync.Mutex{}).(*prototypePollutionExecutor)
	job := &domain.TestJob{ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobPrototypePollution, Attempts: 1}
	tc1 := exec.newTestCase(ctx, job, "http://target.example/app?__proto__[indago_pp]=1")
	tc2 := exec.newTestCase(ctx, job, "http://target.example/app?__proto__[indago_pp]=1")

	vec := prototypePollutionVectors[0]
	exec.correlateFinding(ctx, env.sc, job, ep, tc1, vec, tc1.URL)
	exec.correlateFinding(ctx, env.sc, job, ep, tc2, vec, tc2.URL)

	findings, err := env.st.Findings().ListByScan(ctx, env.scanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1 deduplicated finding", len(findings))
	}
	if findings[0].VulnClass != domain.VulnPrototypePollution || findings[0].Verdict != domain.VerdictConfirmed {
		t.Fatalf("unexpected finding: %+v", findings[0])
	}
	var detail prototypePollutionDetail
	if err := json.Unmarshal(findings[0].Detail, &detail); err != nil {
		t.Fatal(err)
	}
	if detail.Occurrences != 2 {
		t.Fatalf("occurrences = %d, want 2", detail.Occurrences)
	}
}

func TestPrototypePollutionBrowserIntegration(t *testing.T) {
	exe := os.Getenv("INDAGO_CHROMIUM_PATH")
	if exe == "" {
		exe = "/usr/bin/google-chrome"
	}
	if _, err := os.Stat(exe); err != nil {
		t.Skipf("Chromium not available at %s: %v", exe, err)
	}

	mgr, err := browser.NewManager(browser.Config{
		Headless:          true,
		ExecutablePath:    exe,
		PoolSize:          1,
		NavigationTimeout: 15 * time.Second,
	}, nil)
	if err != nil {
		t.Skipf("start Chromium: %v", err)
	}
	defer mgr.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/vuln":
			_, _ = w.Write([]byte(`<!doctype html><html><body><script>
function merge(target, key, val) {
  var parts = key.replace(/\]/g, '').split('[');
  var cur = target;
  for (var i = 0; i < parts.length - 1; i++) {
    if (!cur[parts[i]]) cur[parts[i]] = {};
    cur = cur[parts[i]];
  }
  cur[parts[parts.length - 1]] = val;
}
var q = location.search.slice(1).split('&');
var obj = {};
for (var i = 0; i < q.length; i++) {
  if (!q[i]) continue;
  var kv = q[i].split('=');
  merge(obj, decodeURIComponent(kv[0]), decodeURIComponent(kv[1] || ''));
}
</script></body></html>`))
		case "/safe":
			_, _ = w.Write([]byte(`<!doctype html><html><body><script>
var params = new URLSearchParams(location.search);
var obj = Object.create(null);
params.forEach(function(v, k) {
  if (k.indexOf('__proto__') !== -1 || k.indexOf('constructor') !== -1 || k.indexOf('prototype') !== -1) return;
  obj[k] = v;
});
</script></body></html>`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("vulnerable page confirms prototype pollution", func(t *testing.T) {
		ctx := context.Background()
		env := newScanEnv(t)
		if err := env.st.Scopes().Create(ctx, &domain.Scope{
			ID:           domain.NewID(),
			ProjectID:    env.sc.ProjectID,
			IncludeHosts: []string{u.Hostname()},
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
		}); err != nil {
			t.Fatal(err)
		}
		ep := &domain.Endpoint{
			ID:          domain.NewID(),
			ScanID:      env.scanID,
			Method:      domain.MethodGET,
			URL:         srv.URL + "/vuln",
			ContentType: "text/html",
		}
		if err := env.st.Endpoints().Create(ctx, ep); err != nil {
			t.Fatal(err)
		}
		payload, _ := json.Marshal(prototypePollutionJob{EndpointID: ep.ID})
		job := &domain.TestJob{
			ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobPrototypePollution,
			Target: domain.JobTarget{EndpointID: ep.ID, URL: ep.URL}, Payload: payload, Attempts: 1,
		}

		h := newPrototypePollutionExecutor(env.st, mgr, env.ev, 50*time.Millisecond, execLog(), &sync.Mutex{})
		if err := h.Handle(ctx, job); err != nil {
			t.Fatalf("Handle(vuln): %v", err)
		}

		findings, err := env.st.Findings().ListByScan(ctx, env.scanID)
		if err != nil {
			t.Fatal(err)
		}
		if len(findings) == 0 {
			t.Fatal("expected confirmed VulnPrototypePollution finding on /vuln, got 0")
		}
		for _, f := range findings {
			if f.VulnClass != domain.VulnPrototypePollution || f.Verdict != domain.VerdictConfirmed {
				t.Fatalf("unexpected finding: %+v", f)
			}
			if len(f.EvidenceIDs) == 0 {
				t.Fatalf("expected recorded evidence on finding %s", f.ID)
			}
		}
	})

	t.Run("safe page produces no findings", func(t *testing.T) {
		ctx := context.Background()
		env := newScanEnv(t)
		if err := env.st.Scopes().Create(ctx, &domain.Scope{
			ID:           domain.NewID(),
			ProjectID:    env.sc.ProjectID,
			IncludeHosts: []string{u.Hostname()},
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
		}); err != nil {
			t.Fatal(err)
		}
		ep := &domain.Endpoint{
			ID:          domain.NewID(),
			ScanID:      env.scanID,
			Method:      domain.MethodGET,
			URL:         srv.URL + "/safe",
			ContentType: "text/html",
		}
		if err := env.st.Endpoints().Create(ctx, ep); err != nil {
			t.Fatal(err)
		}
		payload, _ := json.Marshal(prototypePollutionJob{EndpointID: ep.ID})
		job := &domain.TestJob{
			ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobPrototypePollution,
			Target: domain.JobTarget{EndpointID: ep.ID, URL: ep.URL}, Payload: payload, Attempts: 1,
		}

		h := newPrototypePollutionExecutor(env.st, mgr, env.ev, 50*time.Millisecond, execLog(), &sync.Mutex{})
		if err := h.Handle(ctx, job); err != nil {
			t.Fatalf("Handle(safe): %v", err)
		}

		findings, err := env.st.Findings().ListByScan(ctx, env.scanID)
		if err != nil {
			t.Fatal(err)
		}
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings on /safe, got %d: %+v", len(findings), findings)
		}
	})
}
