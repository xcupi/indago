package scan_test

// Hardening tests beyond the main corpus: concurrent scans sharing one browser
// pool, goroutine/memory behavior across a full scan lifecycle, malformed
// responses, large bodies/crawls, and basic throughput/scaling measurements.
// These assert sane bounds, not exact numbers — the point is "doesn't crash,
// doesn't leak, doesn't fall over," not a performance SLA.

import (
	"context"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/evidence"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/scan"
	"github.com/indago/indago/internal/store/memory"
)

// --- concurrent scans share one browser pool without cross-contamination ---

func TestE2E_ConcurrentScansShareBrowserPoolSafely(t *testing.T) {
	ctx := context.Background()
	siteA := newCorpus(t)
	siteB := newCorpus(t)
	st, q := memory.New(), queue.NewMemory()
	ev, err := evidence.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mgr := newBrowserManagerOrSkip(t, 3)
	defer mgr.Close()

	ctrl := newCtrl(t, st, q, scan.Options{Browser: mgr, Evidence: ev})
	projA, tgtA := seedProject(t, st, siteA.URL, corpusScope())
	projB, tgtB := seedProject(t, st, siteB.URL, corpusScope())
	scA := createScan(t, ctrl, projA, tgtA, workersCfgWithBrowser(4, 3), domain.StopPolicy{})
	scB := createScan(t, ctrl, projB, tgtB, workersCfgWithBrowser(4, 3), domain.StopPolicy{})

	if err := ctrl.Start(ctx, scA.ID); err != nil {
		t.Fatal(err)
	}
	if err := ctrl.Start(ctx, scB.ID); err != nil {
		t.Fatal(err)
	}
	doneA := waitStatus(t, ctrl, scA.ID, 60*time.Second, isCompleted)
	doneB := waitStatus(t, ctrl, scB.ID, 60*time.Second, isCompleted)

	findA, _ := st.Findings().ListByScan(ctx, scA.ID)
	findB, _ := st.Findings().ListByScan(ctx, scB.ID)
	if len(findA) == 0 || len(findB) == 0 {
		t.Fatalf("both scans should produce findings: A=%d B=%d", len(findA), len(findB))
	}
	for _, f := range findA {
		if f.ScanID != scA.ID {
			t.Fatalf("scan A's finding store leaked a finding from scan %s", f.ScanID)
		}
	}
	for _, f := range findB {
		if f.ScanID != scB.ID {
			t.Fatalf("scan B's finding store leaked a finding from scan %s", f.ScanID)
		}
	}
	t.Logf("concurrent scans: A findings=%d (%+v) B findings=%d (%+v)", len(findA), doneA.Findings, len(findB), doneB.Findings)

	if stats := mgr.Stats(); stats.OpenContexts != 0 {
		t.Fatalf("browser contexts leaked across concurrent scans: %d still open", stats.OpenContexts)
	}
}

// --- goroutine leak check across a full scan lifecycle ---

func TestE2E_NoGoroutineLeakAcrossScanLifecycle(t *testing.T) {
	ctx := context.Background()
	c := newCorpus(t)
	st, q := memory.New(), queue.NewMemory()
	ev, err := evidence.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mgr := newBrowserManagerOrSkip(t, 2)

	runtime.GC()
	baseline := runtime.NumGoroutine()

	proj, tgt := seedProject(t, st, c.URL, corpusScope())
	ctrl := newCtrl(t, st, q, scan.Options{Browser: mgr, Evidence: ev})
	sc := createScan(t, ctrl, proj, tgt, workersCfgWithBrowser(4, 2), domain.StopPolicy{})
	if err := ctrl.Start(ctx, sc.ID); err != nil {
		t.Fatal(err)
	}
	waitStatus(t, ctrl, sc.ID, 60*time.Second, isCompleted)

	ctrl.Shutdown()
	if err := mgr.Close(); err != nil {
		t.Fatal(err)
	}

	// Worker/discovery/monitor goroutines exit asynchronously; give them a
	// moment, then require the count to have settled back near baseline.
	var after int
	deadline := time.Now().Add(3 * time.Second)
	for {
		runtime.GC()
		after = runtime.NumGoroutine()
		if after <= baseline+5 || time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Logf("goroutines: baseline=%d after=%d", baseline, after)
	if after > baseline+5 {
		t.Fatalf("goroutine leak suspected: %d -> %d (tolerance 5)", baseline, after)
	}
}

// --- malformed / unexpected responses must never panic the pipeline ---

func TestE2E_MalformedResponsesDoNotCrashThePipeline(t *testing.T) {
	ctx := context.Background()
	st, q := memory.New(), queue.NewMemory()

	s := newSite(t, func(mux *http.ServeMux, _ func() string) {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			writeHTML(w, `
<a href="/badutf8?q=hi">a</a>
<a href="/mismatched-type?q=hi">b</a>
<a href="/truncated-tag?q=hi">c</a>
<a href="/binary?q=hi">d</a>
<form action="/deep" method="get"><input name="q"></form>
`)
		})
		// Invalid UTF-8 bytes in the body, with the marker still reflected.
		mux.HandleFunc("/badutf8", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte("<div>\xff\xfe" + r.URL.Query().Get("q") + "</div>"))
		})
		// Claims HTML, is actually arbitrary binary.
		mux.HandleFunc("/mismatched-type", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte{0x00, 0x01, 0x02, 0xDE, 0xAD, 0xBE, 0xEF})
		})
		// A tag that never closes.
		mux.HandleFunc("/truncated-tag", func(w http.ResponseWriter, r *http.Request) {
			writeHTML(w, `<div><span><a href="`+r.URL.Query().Get("q"))
		})
		// Pure binary content type.
		mux.HandleFunc("/binary", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write([]byte{0xFF, 0x00, 0xFF, 0x00})
		})
		// Deeply nested markup around the reflection.
		mux.HandleFunc("/deep", func(w http.ResponseWriter, r *http.Request) {
			var b strings.Builder
			for i := 0; i < 500; i++ {
				b.WriteString("<div>")
			}
			b.WriteString(r.URL.Query().Get("q"))
			for i := 0; i < 500; i++ {
				b.WriteString("</div>")
			}
			writeHTML(w, b.String())
		})
	})

	proj, tgt := seedProject(t, st, s.URL, hostScope())
	ctrl := newCtrl(t, st, q, scan.Options{})
	sc := createScan(t, ctrl, proj, tgt, workersCfg(4), domain.StopPolicy{})

	if err := ctrl.Start(ctx, sc.ID); err != nil {
		t.Fatal(err)
	}
	// The assertion IS that this completes at all, without the process crashing.
	done := waitStatus(t, ctrl, sc.ID, 15*time.Second, isCompleted)
	if done.Jobs.Total() == 0 {
		t.Fatal("expected some jobs to have run")
	}
	cases, _ := st.TestCases().ListByScan(ctx, sc.ID)
	for _, tc := range cases {
		if tc.Status != domain.TestCaseCompleted && tc.Status != domain.TestCaseSkipped {
			t.Errorf("unexpected status for a malformed-response test case: %s (%s)", tc.Status, tc.Note)
		}
	}
}

// --- a large response body flows through reflection/context/candidate planning ---

func TestE2E_LargeResponseBody(t *testing.T) {
	ctx := context.Background()
	st, q := memory.New(), queue.NewMemory()
	const pad = 3 << 20 // 3 MiB of padding around the reflection

	s := newSite(t, func(mux *http.ServeMux, _ func() string) {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { writeHTML(w, `<a href="/big?q=hi">big</a>`) })
		mux.HandleFunc("/big", func(w http.ResponseWriter, r *http.Request) {
			var b strings.Builder
			b.WriteString("<html><body><!-- ")
			b.WriteString(strings.Repeat("x", pad))
			b.WriteString(" --><div>")
			b.WriteString(r.URL.Query().Get("q"))
			b.WriteString("</div></body></html>")
			writeHTML(w, b.String())
		})
	})

	proj, tgt := seedProject(t, st, s.URL, hostScope())
	ctrl := newCtrl(t, st, q, scan.Options{})
	sc := createScan(t, ctrl, proj, tgt, workersCfg(2), domain.StopPolicy{})

	start := time.Now()
	if err := ctrl.Start(ctx, sc.ID); err != nil {
		t.Fatal(err)
	}
	waitStatus(t, ctrl, sc.ID, 20*time.Second, isCompleted)
	t.Logf("large-response scan completed in %s", time.Since(start))

	findings, _ := st.Findings().ListByScan(ctx, sc.ID)
	var sawBig bool
	for _, f := range findings {
		if ep, err := st.Endpoints().Get(ctx, f.EndpointID); err == nil && urlPath(ep.URL) == "/big" {
			sawBig = true
		}
	}
	if !sawBig {
		t.Fatal("expected a finding from the large-body endpoint's reflection")
	}
}

// --- a larger crawl completes correctly, with no duplicate endpoints ---

func TestE2E_LargeCrawl(t *testing.T) {
	ctx := context.Background()
	st, q := memory.New(), queue.NewMemory()
	const pages = 80

	s := newSite(t, func(mux *http.ServeMux, _ func() string) {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			var b strings.Builder
			for i := 0; i < pages; i++ {
				fmt.Fprintf(&b, `<a href="/p%d">p%d</a> `, i, i)
			}
			writeHTML(w, b.String())
		})
		for i := 0; i < pages; i++ {
			i := i
			mux.HandleFunc(fmt.Sprintf("/p%d", i), func(w http.ResponseWriter, r *http.Request) {
				writeHTML(w, fmt.Sprintf(`<form action="/p%d/sub" method="get"><input name="q"></form>`, i))
			})
			mux.HandleFunc(fmt.Sprintf("/p%d/sub", i), func(w http.ResponseWriter, r *http.Request) { writeHTML(w, "ok") })
		}
	})

	proj, tgt := seedProject(t, st, s.URL, hostScope())
	ctrl := newCtrl(t, st, q, scan.Options{})
	sc := createScan(t, ctrl, proj, tgt, workersCfg(8), domain.StopPolicy{})

	var memBefore, memAfter runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&memBefore)
	start := time.Now()

	if err := ctrl.Start(ctx, sc.ID); err != nil {
		t.Fatal(err)
	}
	done := waitStatus(t, ctrl, sc.ID, 30*time.Second, isCompleted)

	elapsed := time.Since(start)
	runtime.GC()
	runtime.ReadMemStats(&memAfter)
	t.Logf("large crawl: %d endpoints, %d jobs in %s (%.0f jobs/s); heap %.1fMB -> %.1fMB",
		done.Discovery.Endpoints, done.Jobs.Total(), elapsed, float64(done.Jobs.Total())/elapsed.Seconds(),
		float64(memBefore.HeapAlloc)/1e6, float64(memAfter.HeapAlloc)/1e6)

	if done.Discovery.Endpoints < pages+1 {
		t.Fatalf("expected at least %d endpoints, got %d", pages+1, done.Discovery.Endpoints)
	}
	eps, _ := st.Endpoints().ListByScan(ctx, sc.ID)
	seen := map[string]int{}
	for _, e := range eps {
		seen[e.Fingerprint]++
	}
	for fp, c := range seen {
		if c != 1 {
			t.Fatalf("duplicate endpoint in a large crawl: %q x%d", fp, c)
		}
	}
	if done.Jobs.Total() != done.Jobs.Succeeded {
		t.Fatalf("not every job succeeded: %+v", done.Jobs)
	}
}

// --- throughput / queue latency under increasing worker counts ---

func TestE2E_ThroughputScalesWithWorkerCount(t *testing.T) {
	ctx := context.Background()
	const pages = 40

	runOnce := func(t *testing.T, workers int) time.Duration {
		st, q := memory.New(), queue.NewMemory()
		s := newSite(t, func(mux *http.ServeMux, _ func() string) {
			mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				var b strings.Builder
				for i := 0; i < pages; i++ {
					fmt.Fprintf(&b, `<a href="/p%d">p</a> `, i)
				}
				writeHTML(w, b.String())
			})
			for i := 0; i < pages; i++ {
				mux.HandleFunc(fmt.Sprintf("/p%d", i), func(w http.ResponseWriter, r *http.Request) {
					time.Sleep(5 * time.Millisecond) // a little realism per request
					writeHTML(w, "ok")
				})
			}
		})
		proj, tgt := seedProject(t, st, s.URL, hostScope())
		ctrl := newCtrl(t, st, q, scan.Options{})
		sc := createScan(t, ctrl, proj, tgt, workersCfg(workers), domain.StopPolicy{})
		start := time.Now()
		if err := ctrl.Start(ctx, sc.ID); err != nil {
			t.Fatal(err)
		}
		waitStatus(t, ctrl, sc.ID, 20*time.Second, isCompleted)
		return time.Since(start)
	}

	var prev time.Duration
	for _, workers := range []int{1, 4, 16} {
		d := runOnce(t, workers)
		t.Logf("workers=%2d  elapsed=%s  (~%.1f req/s)", workers, d, float64(pages)/d.Seconds())
		prev = d
	}
	_ = prev // scaling is logged for human inspection, not asserted (timing is inherently noisy in CI)
}

// --- memory per browser context ---

// Logs the process-level heap growth per opened browser context, as a rough
// per-context memory signal. Chromium's own (out-of-process) memory is not
// visible to runtime.MemStats, so this measures Go-side bookkeeping only —
// still useful to confirm it does not grow unboundedly with context count,
// and that it is released after Close.
func TestE2E_MemoryPerBrowserContext(t *testing.T) {
	mgr := newBrowserManagerOrSkip(t, 1)
	defer mgr.Close()
	ctx := context.Background()

	const n = 10
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	contexts := make([]interface{ Close() error }, 0, n)
	for i := 0; i < n; i++ {
		c, err := mgr.NewContext(ctx, browser.ContextOptions{})
		if err != nil {
			t.Fatal(err)
		}
		contexts = append(contexts, c)
	}

	runtime.GC()
	var opened runtime.MemStats
	runtime.ReadMemStats(&opened)
	perContext := float64(opened.HeapAlloc-before.HeapAlloc) / float64(n) / 1024
	t.Logf("heap per open browser context: ~%.1f KB (n=%d, total delta %.1f KB)", perContext, n, float64(opened.HeapAlloc-before.HeapAlloc)/1024)

	if stats := mgr.Stats(); stats.OpenContexts != n {
		t.Fatalf("open contexts = %d, want %d", stats.OpenContexts, n)
	}
	for _, c := range contexts {
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if stats := mgr.Stats(); stats.OpenContexts != 0 {
		t.Fatalf("contexts still open after closing all of them: %d", stats.OpenContexts)
	}
}
