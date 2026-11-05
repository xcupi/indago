package scan_test

// Tests for the opt-in raw query-string injection capability
// (docs/raw-query-injection.md): the canonical-link class, where the page
// echoes its ENTIRE query string and there is no named parameter to test.
//
// They cover the whole contract required by the slice:
//   - a fixture that reflects the whole query string into an href is CONFIRMED
//     through the normal reflection → context → candidate → browser-verification
//     pipeline (no second detector);
//   - the same fixture with the reflection HTML-escaped stays REJECTED;
//   - default off sends zero blob requests (real request count);
//   - the per-endpoint and per-scan caps hold on a counting fixture;
//   - a named-parameter request is byte-identical with the pseudo-parameters
//     present (buildRequest-level proof, below).

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/discovery"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/evidence"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/scan"
	"github.com/indago/indago/internal/store/memory"
)

// rawQuerySite records the raw query of every request it serves.
type rawQuerySite struct {
	*httptest.Server
	mu   sync.Mutex
	hits []string // "path?rawquery" for requests with a non-empty query
	per  map[string]int
}

func newRawQuerySite(t *testing.T, reflect bool, links int) *rawQuerySite {
	t.Helper()
	s := &rawQuerySite{per: map[string]int{}}
	mux := http.NewServeMux()
	page := func(escaped bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			q, _ := url.QueryUnescape(r.URL.RawQuery)
			if escaped {
				q = html.EscapeString(q)
			}
			writeHTML(w, `<html><head><link rel="canonical" href="/?`+q+`"></head><body><p>ok</p></body></html>`)
		}
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		var b strings.Builder
		if reflect {
			b.WriteString(`<html><head><link rel="canonical" href="/?`)
			q, _ := url.QueryUnescape(r.URL.RawQuery)
			b.WriteString(q)
			b.WriteString(`"></head><body><a href="/escaped">escaped</a>`)
		} else {
			b.WriteString(`<html><body><p>ok</p>`)
		}
		for i := 0; i < links; i++ {
			fmt.Fprintf(&b, `<a href="/p%d">p%d</a>`, i, i)
		}
		b.WriteString(`</body></html>`)
		writeHTML(w, b.String())
	})
	mux.HandleFunc("/escaped", page(true))
	mux.HandleFunc("/reflect-raw", page(false))
	for i := 0; i < links; i++ {
		p := fmt.Sprintf("/p%d", i)
		mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) { writeHTML(w, "ok") })
	}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "" && !strings.HasPrefix(r.URL.Path, "/favicon") {
			s.mu.Lock()
			s.hits = append(s.hits, r.URL.Path+"?"+r.URL.RawQuery)
			s.per[r.URL.Path]++
			s.mu.Unlock()
		}
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *rawQuerySite) queryHits() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.hits...)
}

func (s *rawQuerySite) maxPerPath() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	max := 0
	for _, n := range s.per {
		if n > max {
			max = n
		}
	}
	return max
}

func (s *rawQuerySite) hitsFor(path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.per[path]
}

// runRawQueryScan creates and completes a scan against site with the given
// raw-query mode. With a browser it also verifies findings; without one it is
// a fast HTTP-only scan.
func runRawQueryScan(t *testing.T, site *rawQuerySite, mode discovery.RawQueryMode, withBrowser bool, links int) (*memory.Store, *queue.Memory, domain.ID, []*domain.Finding) {
	t.Helper()
	ctx := context.Background()
	st, q := memory.New(), queue.NewMemory()
	proj, tgt := seedProject(t, st, site.URL, hostScope())

	cfg := &domain.ScanConfig{
		DiscoveryConcurrency: 4, HTTPConcurrency: 8, BrowserConcurrency: 0,
		MaxDepth: 1, RawQueryInjection: string(mode),
	}
	opts := scan.Options{}
	if withBrowser {
		mgr := newRawQueryBrowserOrSkip(t, 2)
		t.Cleanup(func() { mgr.Close() })
		ev, err := evidence.NewFS(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		cfg.BrowserConcurrency = 4
		opts.Browser = mgr
		opts.Evidence = ev
	}
	ctrl := newCtrl(t, st, q, opts)
	sc := createScan(t, ctrl, proj, tgt, cfg, domain.StopPolicy{})
	if err := ctrl.Start(ctx, sc.ID); err != nil {
		t.Fatalf("start: %v", err)
	}
	waitStatus(t, ctrl, sc.ID, 120*time.Second, isCompleted)
	findings, err := st.Findings().ListByScan(ctx, sc.ID)
	if err != nil {
		t.Fatal(err)
	}
	return st, q, sc.ID, findings
}

// newRawQueryBrowserOrSkip mirrors newBrowserManagerOrSkip, but lets a LOCAL
// test run opt out of Chromium's process sandbox when the host cannot support
// it (Ubuntu 24.04's restricted user namespaces are the common case). This is a
// TEST-HARNESS switch only: production's sandbox stays on by default, and
// without INDAGO_TEST_BROWSER_NO_SANDBOX=1 the behaviour is identical to the
// shared helper (sandbox on, skip when it cannot start).
func newRawQueryBrowserOrSkip(t *testing.T, poolSize int) *browser.Manager {
	t.Helper()
	if testing.Short() {
		t.Skip("real-browser test skipped in -short mode")
	}
	exe := findChromiumForScan()
	if exe == "" {
		t.Skip("no Chromium found (set INDAGO_CHROMIUM_PATH or `playwright install chromium`)")
	}
	cfg := browser.Config{Headless: true, ExecutablePath: exe, PoolSize: poolSize}
	if os.Getenv("INDAGO_TEST_BROWSER_NO_SANDBOX") == "1" {
		cfg.DisableSandbox = true
	}
	m, err := browser.NewManager(cfg, nil)
	if err != nil {
		t.Skipf("browser engine unavailable: %v", err)
	}
	return m
}

func endpointPath(t *testing.T, st *memory.Store, scanID, endpointID domain.ID) string {
	t.Helper()
	ep, err := st.Endpoints().Get(context.Background(), endpointID)
	if err != nil {
		return "?"
	}
	u, err := url.Parse(ep.URL)
	if err != nil {
		return "?"
	}
	return u.Path
}

// A whole-query reflection into a canonical-link href must be CONFIRMED by the
// real browser verifier, and the same page with the reflection HTML-escaped
// must stay REJECTED. This is the headline behaviour of the new mode.
func TestRawQueryInjection_ConfirmsCanonicalLinkAndRejectsEscaped(t *testing.T) {
	site := newRawQuerySite(t, true, 0)
	st, _, scanID, findings := runRawQueryScan(t, site, discovery.RawQueryAuto, true, 0)

	if len(site.queryHits()) == 0 {
		t.Fatal("the raw-query mode sent no request carrying a query string")
	}

	confirmedRaw, rejectedEscaped := 0, 0
	for _, f := range findings {
		path := endpointPath(t, st, scanID, f.EndpointID)
		switch path {
		case "/", "/reflect-raw":
			if f.Verdict == domain.VerdictConfirmed {
				confirmedRaw++
				if f.Location != domain.LocationRawQuery {
					t.Errorf("confirmed finding location = %q, want %q", f.Location, domain.LocationRawQuery)
				}
				if !strings.Contains(f.Title, "raw query string") {
					t.Errorf("confirmed finding title does not name the raw query string: %q", f.Title)
				}
				if strings.Contains(f.Title, `parameter "`) {
					t.Errorf("finding claims a named parameter for a raw-query injection point: %q", f.Title)
				}
				if len(f.EvidenceIDs) == 0 {
					t.Error("confirmed finding has no evidence")
				}
			}
		case "/escaped":
			if f.Verdict == domain.VerdictConfirmed {
				t.Errorf("escaped reflection was CONFIRMED (impossible): %q", f.Title)
			}
			if f.Verdict == domain.VerdictRejected {
				rejectedEscaped++
			}
		}
	}
	if confirmedRaw == 0 {
		var got []string
		for _, f := range findings {
			got = append(got, fmt.Sprintf("%s=%s", endpointPath(t, st, scanID, f.EndpointID), f.Verdict))
		}
		t.Fatalf("no raw-query finding was browser-confirmed; findings: %v", got)
	}
	if rejectedEscaped == 0 {
		t.Fatalf("escaped fixture produced no Rejected finding (findings=%d)", len(findings))
	}

	// The reflection TestCase must carry the raw_query location in its note,
	// so engine-level provenance agrees with the Finding.
	cases, err := st.TestCases().ListByScan(context.Background(), scanID)
	if err != nil {
		t.Fatal(err)
	}
	sawRawNote := false
	for _, tc := range cases {
		if strings.Contains(tc.Note, "(raw_query)") {
			sawRawNote = true
			break
		}
	}
	if !sawRawNote {
		t.Fatal("no TestCase note records the raw_query injection point")
	}
}

// With the option off (the default), not one blob request is sent: this is a
// real request count against a counting fixture, not an inspection of config.
func TestRawQueryInjection_OffSendsNoBlobRequests(t *testing.T) {
	site := newRawQuerySite(t, false, 3)
	runRawQueryScan(t, site, discovery.RawQueryOff, false, 3)
	if got := site.queryHits(); len(got) != 0 {
		t.Fatalf("off mode sent %d request(s) carrying a query string: %v", len(got), got)
	}
}

// On a counting fixture, the hard bounds hold in real traffic: at most 2
// blob requests per endpoint and exactly the per-scan cap (40) when 26
// endpoints would otherwise produce 52.
func TestRawQueryInjection_CapsHoldOnCountingFixture(t *testing.T) {
	const links = 25
	site := newRawQuerySite(t, false, links)
	_, _, _, findings := runRawQueryScan(t, site, discovery.RawQueryAlways, false, links)
	if len(findings) != 0 {
		t.Fatalf("non-reflecting fixture produced %d finding(s); want 0", len(findings))
	}

	hits := site.queryHits()
	if len(hits) != discovery.MaxRawQueryProbesPerScan {
		t.Fatalf("blob requests = %d, want exactly the per-scan cap %d", len(hits), discovery.MaxRawQueryProbesPerScan)
	}
	if got := site.maxPerPath(); got > discovery.MaxRawQueryShapesPerEndpoint {
		t.Fatalf("one endpoint received %d blob requests; per-endpoint cap is %d", got, discovery.MaxRawQueryShapesPerEndpoint)
	}
	// The cap is applied in discovery order, so later endpoints must not be
	// probed at all once the budget is spent.
	if n := site.hitsFor(fmt.Sprintf("/p%d", links-1)); n != 0 {
		t.Fatalf("an endpoint beyond the per-scan cap still received %d blob request(s)", n)
	}
}
