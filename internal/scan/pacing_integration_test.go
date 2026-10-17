package scan_test

// Pacing integration tests: a real Controller, real discovery and the real HTTP
// engine against a live httptest site. They prove the scan's RequestsPerSecond
// paces the discovery crawl (which is controller-run, not an HTTP test job) and
// that a runtime Reconfigure reaches that crawl.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/scan"
	"github.com/indago/indago/internal/store/memory"
)

// crawlSite serves a small linked graph and records the arrival time of every
// request. When gate is non-nil, /p0 blocks until gate is closed (after its
// arrival is recorded), so a test can change the rate while the crawl is held.
type crawlSite struct {
	*httptest.Server
	mu sync.Mutex
	at []arrival
}

type arrival struct {
	path string
	at   time.Time
}

func (s *crawlSite) record(path string) {
	s.mu.Lock()
	s.at = append(s.at, arrival{path: path, at: time.Now()})
	s.mu.Unlock()
}

func (s *crawlSite) snapshot() []arrival {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]arrival(nil), s.at...)
}

func newCrawlSite(t *testing.T, gate <-chan struct{}) *crawlSite {
	t.Helper()
	s := &crawlSite{}
	links := map[string][]string{
		"/p0": {"/p1", "/p2", "/p3", "/p4"},
		"/p1": {"/p5"},
		"/p2": {"/p6"},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/p", func(w http.ResponseWriter, r *http.Request) {})
	for _, p := range []string{"/p0", "/p1", "/p2", "/p3", "/p4", "/p5", "/p6"} {
		path := p
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			s.record(path)
			if path == "/p0" && gate != nil {
				<-gate
			}
			w.Header().Set("Content-Type", "text/html")
			body := ""
			for _, l := range links[path] {
				body += fmt.Sprintf(`<a href="%s">x</a>`, l)
			}
			_, _ = io.WriteString(w, body)
		})
	}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" || r.URL.Path == "/sitemap.xml" {
			s.record(r.URL.Path)
		}
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(s.Close)
	return s
}

// gapsOf returns the sorted-by-arrival gaps between consecutive arrivals whose
// time is at or after from.
func gapsOf(arr []arrival, from time.Time) []time.Duration {
	var ts []time.Time
	for _, a := range arr {
		if !a.at.Before(from) {
			ts = append(ts, a.at)
		}
	}
	sort.Slice(ts, func(i, j int) bool { return ts[i].Before(ts[j]) })
	var out []time.Duration
	for i := 1; i < len(ts); i++ {
		out = append(out, ts[i].Sub(ts[i-1]))
	}
	return out
}

func minOf(ds []time.Duration) time.Duration {
	m := time.Duration(1<<63 - 1)
	for _, d := range ds {
		if d < m {
			m = d
		}
	}
	return m
}

// The discovery crawl alone (no HTTP test jobs) must respect RequestsPerSecond.
func TestDiscoveryCrawlIsPacedByRequestsPerSecond(t *testing.T) {
	ctx := context.Background()
	site := newCrawlSite(t, nil)
	st, q := memory.New(), queue.NewMemory()
	proj, tgt := seedProject(t, st, site.URL+"/p0", hostScope())
	handlers, _ := recordingHandlers()
	ctrl := newCtrl(t, st, q, scan.Options{Handlers: handlers})

	cfg := &domain.ScanConfig{DiscoveryConcurrency: 4, HTTPConcurrency: 1, RequestsPerSecond: 10, MaxDepth: 5}
	sc := createScan(t, ctrl, proj, tgt, cfg, domain.StopPolicy{})
	if err := ctrl.Start(ctx, sc.ID); err != nil {
		t.Fatal(err)
	}
	waitStatus(t, ctrl, sc.ID, 20*time.Second, isCompleted)

	arr := site.snapshot()
	if len(arr) < 7 {
		t.Fatalf("crawl reached only %d requests; want the whole graph", len(arr))
	}
	gaps := gapsOf(arr, time.Time{})
	if g := minOf(gaps); g < 90*time.Millisecond {
		t.Fatalf("min gap between target requests = %v, want >= 90ms at 10 rps (gaps %v)", g, gaps)
	}
}

// A runtime Reconfigure must reach the discovery crawl that is already running.
func TestReconfigureRateReachesRunningDiscovery(t *testing.T) {
	ctx := context.Background()
	gate := make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(gate) }) }
	defer release()

	site := newCrawlSite(t, gate)
	st, q := memory.New(), queue.NewMemory()
	proj, tgt := seedProject(t, st, site.URL+"/p0", hostScope())
	handlers, _ := recordingHandlers()
	ctrl := newCtrl(t, st, q, scan.Options{Handlers: handlers})

	// Start unlimited; the crawl then blocks on /p0.
	cfg := &domain.ScanConfig{DiscoveryConcurrency: 4, HTTPConcurrency: 1, RequestsPerSecond: 0, MaxDepth: 5}
	sc := createScan(t, ctrl, proj, tgt, cfg, domain.StopPolicy{})
	if err := ctrl.Start(ctx, sc.ID); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, func() bool {
		for _, a := range site.snapshot() {
			if a.path == "/p0" {
				return true
			}
		}
		return false
	})

	// Raise the rate while the crawl is held, then let it continue.
	if err := ctrl.Reconfigure(ctx, sc.ID, domain.ScanConfig{
		DiscoveryConcurrency: 4, HTTPConcurrency: 1, RequestsPerSecond: 10, MaxDepth: 5,
	}); err != nil {
		t.Fatal(err)
	}
	reconfiguredAt := time.Now()
	release()
	waitStatus(t, ctrl, sc.ID, 20*time.Second, isCompleted)

	gaps := gapsOf(site.snapshot(), reconfiguredAt)
	if len(gaps) < 3 {
		t.Fatalf("only %d post-reconfigure gaps; crawl did not continue", len(gaps))
	}
	if g := minOf(gaps); g < 90*time.Millisecond {
		t.Fatalf("after Reconfigure to 10 rps, min gap = %v, want >= 90ms (gaps %v)", g, gaps)
	}
}
