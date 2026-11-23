package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/httpengine"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/store/memory"
)

func runCachePoisoning(t *testing.T, env *scanEnv, eng httpengine.Engine, ep *domain.Endpoint, cfg ExecutorConfig) *domain.TestCase {
	t.Helper()
	job := &domain.TestJob{
		ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobCachePoisoning,
		Target: domain.JobTarget{EndpointID: ep.ID, URL: ep.URL}, Attempts: 1, MaxAttempts: 2,
	}
	ex := newCachePoisoningExecutor(env.st, eng, env.ev, cfg, execLog(), nil)
	if err := ex.Handle(context.Background(), job); err != nil {
		t.Fatalf("handle: %v", err)
	}
	cases, err := env.st.TestCases().ListByScan(context.Background(), env.scanID)
	if err != nil {
		t.Fatalf("list test cases: %v", err)
	}
	for _, tc := range cases {
		if tc.JobID == job.ID {
			return tc
		}
	}
	t.Fatalf("no test case recorded for job %s", job.ID)
	return nil
}

func cpDetailOf(t *testing.T, tc *domain.TestCase) cachePoisoningDetail {
	t.Helper()
	var d cachePoisoningDetail
	if err := json.Unmarshal(tc.Detail, &d); err != nil {
		t.Fatalf("unmarshal detail: %v (%s)", err, string(tc.Detail))
	}
	return d
}

// TestCachePoisoningConfirmedWhenCached verifies that when an unkeyed
// X-Forwarded-Host header is reflected and cached under the cache-busted URL,
// the clean follow-up GET receives the canary and VulnCachePoisoning is confirmed.
func TestCachePoisoningConfirmedWhenCached(t *testing.T) {
	var mu sync.Mutex
	cache := make(map[string]string)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("unexpected method %s, want GET", r.Method)
		}
		cb := r.URL.Query().Get(cpCacheBusterParam)
		if cb == "" {
			t.Fatalf("missing %s cache-buster on %s", cpCacheBusterParam, r.URL.String())
		}

		mu.Lock()
		defer mu.Unlock()
		if cached, ok := cache[r.URL.RequestURI()]; ok {
			w.Header().Set("X-Cache", "HIT")
			_, _ = w.Write([]byte(cached))
			return
		}
		body := "<html><body>ok</body></html>"
		if xfh := r.Header.Get("X-Forwarded-Host"); xfh != "" {
			body = fmt.Sprintf(`<html><body><script src="https://%s/app.js"></script></body></html>`, xfh)
		}
		cache[r.URL.RequestURI()] = body
		w.Header().Set("X-Cache", "MISS")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/page", domain.MethodGET)
	tc := runCachePoisoning(t, env, shEngineFor(t, false), ep, ExecutorConfig{})

	if tc.Status != domain.TestCaseCompleted {
		t.Fatalf("status = %q, want completed (note: %s)", tc.Status, tc.Note)
	}
	d := cpDetailOf(t, tc)
	if d.Verdict != domain.VerdictConfirmed {
		t.Fatalf("verdict = %q, want confirmed (reason: %s)", d.Verdict, d.Reason)
	}
	if len(d.Signals) == 0 || d.Signals[0].Header != "X-Forwarded-Host" {
		t.Fatalf("signals = %+v, want X-Forwarded-Host signal", d.Signals)
	}

	var foundXFH bool
	for _, p := range d.Probes {
		if p.Header == "X-Forwarded-Host" {
			foundXFH = true
			if !p.Reflected || !p.Cached {
				t.Fatalf("X-Forwarded-Host probe = %+v, want Reflected=true and Cached=true", p)
			}
		}
	}
	if !foundXFH {
		t.Fatalf("expected X-Forwarded-Host probe in %+v", d.Probes)
	}

	findings, err := env.st.Findings().ListByScan(context.Background(), env.scanID)
	if err != nil {
		t.Fatalf("list findings: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	f := findings[0]
	if f.VulnClass != domain.VulnCachePoisoning {
		t.Fatalf("vuln_class = %q, want %q", f.VulnClass, domain.VulnCachePoisoning)
	}
	if f.Verdict != domain.VerdictConfirmed || f.Severity != domain.SeverityMedium || f.Confidence != domain.ConfidenceHigh {
		t.Fatalf("finding verdict/sev/conf = %q/%q/%q, want confirmed/medium/high", f.Verdict, f.Severity, f.Confidence)
	}
	if len(f.EvidenceIDs) == 0 {
		t.Fatalf("expected finding to carry evidence IDs")
	}
}

// TestCachePoisoningUnkeyedReflectionWithoutCachingProducesNoFinding verifies
// that reflection on the probe request alone (when the clean follow-up does NOT
// receive the canary) does not confirm VulnCachePoisoning.
func TestCachePoisoningUnkeyedReflectionWithoutCachingProducesNoFinding(t *testing.T) {
	var followUpSeen atomic.Bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if xfh := r.Header.Get("X-Forwarded-Host"); xfh != "" {
			_, _ = fmt.Fprintf(w, `<a href="https://%s/home">home</a>`, xfh)
			return
		}
		followUpSeen.Store(true)
		_, _ = w.Write([]byte(`<a href="https://origin.example/home">home</a>`))
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/dynamic", domain.MethodGET)
	tc := runCachePoisoning(t, env, shEngineFor(t, false), ep, ExecutorConfig{})

	if !followUpSeen.Load() {
		t.Fatalf("expected clean follow-up GET to be sent after reflection")
	}
	d := cpDetailOf(t, tc)
	if d.Verdict != domain.VerdictRejected {
		t.Fatalf("verdict = %q, want rejected (reason: %s)", d.Verdict, d.Reason)
	}
	for _, p := range d.Probes {
		if p.Header == "X-Forwarded-Host" {
			if !p.Reflected || p.Cached {
				t.Fatalf("X-Forwarded-Host probe = %+v, want Reflected=true and Cached=false", p)
			}
		}
	}

	findings, err := env.st.Findings().ListByScan(context.Background(), env.scanID)
	if err != nil {
		t.Fatalf("list findings: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("findings = %d, want 0", len(findings))
	}
}

// TestCachePoisoningThrottled429IsInconclusive verifies that HTTP 429
// responses yield VerdictInconclusive and 0 findings.
func TestCachePoisoningThrottled429IsInconclusive(t *testing.T) {
	for _, tcCase := range []struct {
		name     string
		onSecond bool
	}{
		{"baseline_429", false},
		{"probe_429", true},
	} {
		t.Run(tcCase.name, func(t *testing.T) {
			var hits atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n := hits.Add(1)
				if !tcCase.onSecond || n >= 2 {
					w.WriteHeader(http.StatusTooManyRequests)
					return
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer srv.Close()

			env := newScanEnv(t)
			ep := env.endpoint(srv.URL+"/rate-limited", domain.MethodGET)
			tc := runCachePoisoning(t, env, shEngineFor(t, false), ep, ExecutorConfig{})

			d := cpDetailOf(t, tc)
			if !d.Throttled {
				t.Fatalf("expected Throttled=true")
			}
			if d.Verdict != domain.VerdictInconclusive {
				t.Fatalf("verdict = %q, want inconclusive", d.Verdict)
			}

			findings, err := env.st.Findings().ListByScan(context.Background(), env.scanID)
			if err != nil {
				t.Fatalf("list findings: %v", err)
			}
			if len(findings) != 0 {
				t.Fatalf("findings = %d, want 0", len(findings))
			}
		})
	}
}

// TestCachePoisoningSkipsNonGET verifies that non-GET endpoints are skipped
// without sending any HTTP request.
func TestCachePoisoningSkipsNonGET(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/submit", domain.MethodPOST)
	tc := runCachePoisoning(t, env, shEngineFor(t, false), ep, ExecutorConfig{})

	if tc.Status != domain.TestCaseSkipped {
		t.Fatalf("status = %q, want skipped", tc.Status)
	}
	if !strings.Contains(tc.Note, "not GET") {
		t.Fatalf("note = %q, want explanation of GET-only guard", tc.Note)
	}
	if hits.Load() != 0 {
		t.Fatalf("target hits = %d, want 0", hits.Load())
	}
}

// cpFindingDetail decodes a finding's cache-poisoning detail.
func cpFindingDetail(t *testing.T, f *domain.Finding) cachePoisoningDetail {
	t.Helper()
	var d cachePoisoningDetail
	if err := json.Unmarshal(f.Detail, &d); err != nil {
		t.Fatalf("unmarshal finding detail: %v", err)
	}
	return d
}

// TestCachePoisoningUnkeyedQueryParameterConfirmed verifies that a parameter
// stripped from the cache key is caught by the value/revert differential: the
// probe request reflects the canary and the clean follow-up — same unique
// cache-busted URL with the original value restored — is served that canary
// from the cache.
func TestCachePoisoningUnkeyedQueryParameterConfirmed(t *testing.T) {
	var mu sync.Mutex
	cache := make(map[string]string)
	var hits atomic.Int32
	var badMethod, missingBuster atomic.Bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Method != http.MethodGet {
			badMethod.Store(true)
		}
		q := r.URL.Query()
		if q.Get(cpCacheBusterParam) == "" {
			missingBuster.Store(true)
		}
		// Simulated intermediary cache: utm_source is stripped from the key,
		// so two URLs differing only by that parameter share one entry.
		reflected := q.Get(cpQueryFallbackParameter)
		keyQuery := r.URL.Query()
		keyQuery.Del(cpQueryFallbackParameter)
		key := r.URL.Path + "?" + keyQuery.Encode()

		mu.Lock()
		body, ok := cache[key]
		if !ok {
			body = "<html><body><h1>Landing</h1><p>" + html.EscapeString(reflected) + "</p></body></html>"
			cache[key] = body
		}
		mu.Unlock()

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if ok {
			w.Header().Set("X-Cache", "HIT")
		} else {
			w.Header().Set("X-Cache", "MISS")
		}
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/landing", domain.MethodGET)
	tc := runCachePoisoning(t, env, shEngineFor(t, false), ep, ExecutorConfig{})

	if tc.Status != domain.TestCaseCompleted {
		t.Fatalf("status = %q, want completed (note: %s)", tc.Status, tc.Note)
	}
	d := cpDetailOf(t, tc)
	if d.Verdict != domain.VerdictConfirmed {
		t.Fatalf("verdict = %q, want confirmed (reason: %s)", d.Verdict, d.Reason)
	}
	var querySignal *cachePoisoningSignal
	for i := range d.Signals {
		if d.Signals[i].Technique == cpTechniqueUnkeyedQuery {
			querySignal = &d.Signals[i]
		}
	}
	if querySignal == nil {
		t.Fatalf("signals = %+v, want an unkeyed query-parameter signal", d.Signals)
	}
	if querySignal.Parameter != cpQueryFallbackParameter {
		t.Fatalf("signal parameter = %q, want %q", querySignal.Parameter, cpQueryFallbackParameter)
	}
	if querySignal.Kind != cpKindBody {
		t.Fatalf("signal kind = %q, want %q", querySignal.Kind, cpKindBody)
	}
	if len(d.QueryProbes) != 1 || !d.QueryProbes[0].Reflected || !d.QueryProbes[0].Unkeyed {
		t.Fatalf("query probes = %+v, want one reflected+unkeyed probe", d.QueryProbes)
	}
	if len(d.QueryProbes) > maxCachePoisoningQueryParams {
		t.Fatalf("query probes = %d, want <= %d", len(d.QueryProbes), maxCachePoisoningQueryParams)
	}
	if len(d.DeceptionProbes) > maxCacheDeceptionSuffixes {
		t.Fatalf("deception probes = %d, want <= %d", len(d.DeceptionProbes), maxCacheDeceptionSuffixes)
	}
	if badMethod.Load() {
		t.Fatalf("observed a non-GET request; cache checks must stay read-only")
	}
	if missingBuster.Load() {
		t.Fatalf("observed a request without the %s cache-buster", cpCacheBusterParam)
	}
	if got := hits.Load(); got > int32(maxCachePoisoningRequestsPerOrigin) {
		t.Fatalf("requests = %d, want <= %d", got, maxCachePoisoningRequestsPerOrigin)
	}

	findings := scanFindings(t, env)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if findings[0].VulnClass != domain.VulnCachePoisoning {
		t.Fatalf("vuln_class = %q, want %q", findings[0].VulnClass, domain.VulnCachePoisoning)
	}
	if fd := cpFindingDetail(t, findings[0]); len(fd.QueryProbes) == 0 {
		t.Fatalf("finding detail has no query probes")
	}
}

// TestCachePoisoningUnkeyedQueryParameterKeyedProducesNoFinding verifies that
// a parameter the cache DOES key on cannot be turned into a finding: the probe
// reflects the canary, but the clean follow-up is a fresh cache entry and
// carries no canary.
func TestCachePoisoningUnkeyedQueryParameterKeyedProducesNoFinding(t *testing.T) {
	var mu sync.Mutex
	cache := make(map[string]string)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("unexpected method %s, want GET", r.Method)
			return
		}
		if r.URL.Query().Get(cpCacheBusterParam) == "" {
			t.Errorf("missing cache-buster on %s", r.URL.Path)
		}
		key := r.URL.RequestURI() // full query string is part of the key
		mu.Lock()
		body, ok := cache[key]
		if !ok {
			body = "<html><body><h1>Search</h1><p>" +
				html.EscapeString(r.URL.Query().Get(cpQueryFallbackParameter)) + "</p></body></html>"
			cache[key] = body
		}
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if ok {
			w.Header().Set("X-Cache", "HIT")
		} else {
			w.Header().Set("X-Cache", "MISS")
		}
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/search", domain.MethodGET)
	tc := runCachePoisoning(t, env, shEngineFor(t, false), ep, ExecutorConfig{})

	d := cpDetailOf(t, tc)
	if d.Verdict != domain.VerdictRejected {
		t.Fatalf("verdict = %q, want rejected (reason: %s)", d.Verdict, d.Reason)
	}
	if len(d.QueryProbes) != 1 {
		t.Fatalf("query probes = %+v, want one probe", d.QueryProbes)
	}
	if !d.QueryProbes[0].Reflected || d.QueryProbes[0].Unkeyed {
		t.Fatalf("query probe = %+v, want Reflected=true and Unkeyed=false", d.QueryProbes[0])
	}
	for _, s := range d.Signals {
		if s.Technique == cpTechniqueUnkeyedQuery {
			t.Fatalf("unexpected unkeyed query signal: %+v", s)
		}
	}
	if findings := scanFindings(t, env); len(findings) != 0 {
		t.Fatalf("findings = %d, want 0", len(findings))
	}
}

// TestCacheDeceptionConfirmedWhenStaticSuffixIsCached verifies the web cache
// deception differential: a dynamic HTML document reproduced at a unique
// static-suffixed URL, explicitly cacheable, and reported as a HIT on the
// repeat request to that exact URL.
func TestCacheDeceptionConfirmedWhenStaticSuffixIsCached(t *testing.T) {
	var mu sync.Mutex
	counts := make(map[string]int)
	var badMethod, missingBuster atomic.Bool

	page := `<html><body><h1>Account</h1><p>This profile page belongs to the signed-in user and ` +
		`contains private account details, saved addresses and order history for this session.</p></body></html>`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			badMethod.Store(true)
		}
		if r.URL.Query().Get(cpCacheBusterParam) == "" {
			missingBuster.Store(true)
		}
		mu.Lock()
		n := counts[r.URL.RequestURI()]
		counts[r.URL.RequestURI()] = n + 1
		mu.Unlock()

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=60")
		if n == 0 {
			w.Header().Set("X-Cache", "MISS")
		} else {
			w.Header().Set("X-Cache", "HIT")
		}
		_, _ = w.Write([]byte(page))
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/account", domain.MethodGET)
	tc := runCachePoisoning(t, env, shEngineFor(t, false), ep, ExecutorConfig{})

	d := cpDetailOf(t, tc)
	if d.Verdict != domain.VerdictConfirmed {
		t.Fatalf("verdict = %q, want confirmed (reason: %s)", d.Verdict, d.Reason)
	}
	var deceptionSignal *cachePoisoningSignal
	for i := range d.Signals {
		if d.Signals[i].Technique == cpTechniqueCacheDeception && d.Signals[i].Suffix == ".css" {
			deceptionSignal = &d.Signals[i]
		}
	}
	if deceptionSignal == nil {
		t.Fatalf("signals = %+v, want a cache-deception signal for .css", d.Signals)
	}
	if deceptionSignal.Suffix != ".css" {
		t.Fatalf("signal suffix = %q, want .css", deceptionSignal.Suffix)
	}
	var cssProbe *cachePoisoningDeceptionProbe
	for i := range d.DeceptionProbes {
		if d.DeceptionProbes[i].Suffix == ".css" {
			cssProbe = &d.DeceptionProbes[i]
		}
	}
	if cssProbe == nil {
		t.Fatalf("deception probes = %+v, want a .css probe", d.DeceptionProbes)
	}
	if !cssProbe.BodyMatched || !cssProbe.Cacheable || !cssProbe.CacheHit {
		t.Fatalf("css probe = %+v, want BodyMatched/Cacheable/CacheHit all true", cssProbe)
	}
	if badMethod.Load() {
		t.Fatalf("observed a non-GET request; deception probes must stay read-only")
	}
	if missingBuster.Load() {
		t.Fatalf("observed a request without the %s cache-buster", cpCacheBusterParam)
	}
	if findings := scanFindings(t, env); len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
}

// TestCacheDeceptionNotConfirmedWhenResponseIsNotCacheable verifies that a
// dynamic document served at a static suffix without an explicit cacheability
// signal is never reported: the pass does not guess that a cache stored it.
func TestCacheDeceptionNotConfirmedWhenResponseIsNotCacheable(t *testing.T) {
	var mu sync.Mutex
	counts := make(map[string]int)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("unexpected method %s, want GET", r.Method)
			return
		}
		if r.URL.Query().Get(cpCacheBusterParam) == "" {
			t.Errorf("missing cache-buster on %s", r.URL.Path)
		}
		mu.Lock()
		counts[r.URL.RequestURI()]++
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store, private")
		w.Header().Set("X-Cache", "MISS")
		_, _ = w.Write([]byte(`<html><body><h1>Account</h1><p>Private page that must never be stored.</p></body></html>`))
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/account", domain.MethodGET)
	tc := runCachePoisoning(t, env, shEngineFor(t, false), ep, ExecutorConfig{})

	d := cpDetailOf(t, tc)
	if d.Verdict != domain.VerdictRejected {
		t.Fatalf("verdict = %q, want rejected (reason: %s)", d.Verdict, d.Reason)
	}
	if len(d.DeceptionProbes) == 0 {
		t.Fatalf("deception probes = 0, want the probes to have run and stayed negative")
	}
	for _, p := range d.DeceptionProbes {
		if p.CacheHit {
			t.Fatalf("deception probe = %+v, want no cache hit", p)
		}
	}
	for _, s := range d.Signals {
		if s.Technique == cpTechniqueCacheDeception {
			t.Fatalf("unexpected cache-deception signal: %+v", s)
		}
	}
	if findings := scanFindings(t, env); len(findings) != 0 {
		t.Fatalf("findings = %d, want 0", len(findings))
	}
}

// TestCachePoisoningOnlySendsSafeMethods verifies the hard read-only boundary:
// GET and HEAD endpoints are checked (using their own method), every mutating
// method is skipped without a single request.
func TestCachePoisoningOnlySendsSafeMethods(t *testing.T) {
	for _, tc := range []struct {
		name   string
		method domain.HTTPMethod
		allow  bool
	}{
		{"get", domain.MethodGET, true},
		{"head", domain.MethodHEAD, true},
		{"post", domain.MethodPOST, false},
		{"put", domain.MethodPUT, false},
		{"patch", domain.MethodPATCH, false},
		{"delete", domain.MethodDELETE, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var methods []string
			var missingBuster atomic.Bool

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				methods = append(methods, r.Method)
				mu.Unlock()
				if r.URL.Query().Get(cpCacheBusterParam) == "" {
					missingBuster.Store(true)
				}
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(http.StatusOK)
			}))
			defer srv.Close()

			env := newScanEnv(t)
			ep := env.endpoint(srv.URL+"/page", tc.method)
			got := runCachePoisoning(t, env, shEngineFor(t, false), ep, ExecutorConfig{})

			mu.Lock()
			seen := append([]string(nil), methods...)
			mu.Unlock()

			if !tc.allow {
				if len(seen) != 0 {
					t.Fatalf("requests = %d, want 0 for %s (seen %v)", len(seen), tc.method, seen)
				}
				if got.Status != domain.TestCaseSkipped {
					t.Fatalf("status = %q, want skipped", got.Status)
				}
				return
			}
			if len(seen) == 0 {
				t.Fatalf("no request sent for allowed %s endpoint", tc.method)
			}
			for _, m := range seen {
				if m != string(tc.method) {
					t.Fatalf("request method = %q, want %q", m, tc.method)
				}
			}
			if missingBuster.Load() {
				t.Fatalf("observed a request without the %s cache-buster", cpCacheBusterParam)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// pure helpers
// ---------------------------------------------------------------------------

// TestCachePoisoningQueryDifferentialURLs verifies the pair isolates exactly
// one parameter value: everything else, including the cache-buster, is
// identical, and the follow-up restores the original value (or omits the
// parameter when it did not exist).
func TestCachePoisoningQueryDifferentialURLs(t *testing.T) {
	base := "https://app.example.test/search?q=hello&lang=en&indago_cb=cb1#frag"

	probe, follow, ok := cpQueryDifferentialURLs(base, "q", "indago-cpq-canary")
	if !ok {
		t.Fatal("cpQueryDifferentialURLs returned !ok")
	}
	pu, err := url.Parse(probe)
	if err != nil {
		t.Fatalf("parse probe: %v", err)
	}
	fu, err := url.Parse(follow)
	if err != nil {
		t.Fatalf("parse follow: %v", err)
	}
	if pu.Query().Get("q") != "indago-cpq-canary" {
		t.Fatalf("probe q = %q, want the canary", pu.Query().Get("q"))
	}
	if fu.Query().Get("q") != "hello" {
		t.Fatalf("follow-up q = %q, want the original value", fu.Query().Get("q"))
	}
	if pu.Query().Get("indago_cb") != "cb1" || fu.Query().Get("indago_cb") != "cb1" {
		t.Fatalf("cache-buster changed between probe and follow-up")
	}
	if pu.Query().Get("lang") != fu.Query().Get("lang") {
		t.Fatalf("unrelated parameter changed between probe and follow-up")
	}
	if pu.Fragment != fu.Fragment || pu.Path != fu.Path || pu.Host != fu.Host {
		t.Fatalf("path/host/fragment differ between probe and follow-up")
	}

	probe, follow, ok = cpQueryDifferentialURLs(base, "utm_source", "indago-cpq-canary")
	if !ok {
		t.Fatal("cpQueryDifferentialURLs returned !ok for an absent parameter")
	}
	pu, _ = url.Parse(probe)
	fu, _ = url.Parse(follow)
	if pu.Query().Get("utm_source") != "indago-cpq-canary" {
		t.Fatalf("probe utm_source = %q, want the canary", pu.Query().Get("utm_source"))
	}
	if _, present := fu.Query()["utm_source"]; present {
		t.Fatalf("follow-up still carries utm_source, want it omitted")
	}
}

// TestCachePoisoningQueryCandidateNames verifies candidate selection is
// bounded, deterministic, and refuses state-shaped names.
func TestCachePoisoningQueryCandidateNames(t *testing.T) {
	ep := &domain.Endpoint{URL: "https://app.example.test/search?a=1&b=2&indago_cb=x&csrf=y"}
	params := []*domain.Parameter{
		{Name: "z", Location: domain.LocationQuery},
		{Name: "c", Location: domain.LocationQuery},
		{Name: "body", Location: domain.LocationForm},
		{Name: "action", Location: domain.LocationQuery},
		{Name: "a", Location: domain.LocationQuery},
	}
	got := cpQueryCandidateNames(ep, params)
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("candidates = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("candidates = %v, want %v", got, want)
		}
	}
	if len(got) > maxCachePoisoningQueryParams {
		t.Fatalf("candidates = %d, want <= %d", len(got), maxCachePoisoningQueryParams)
	}

	fallback := cpQueryCandidateNames(&domain.Endpoint{URL: "https://app.example.test/plain"}, nil)
	if len(fallback) != 1 || fallback[0] != cpQueryFallbackParameter {
		t.Fatalf("fallback = %v, want [%s]", fallback, cpQueryFallbackParameter)
	}
}

// TestCachePoisoningCacheObservation verifies cacheability/HIT parsing is
// driven by explicit response signals only.
func TestCachePoisoningCacheObservation(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	public := http.Header{}
	public.Set("Cache-Control", "public, max-age=60")
	public.Set("X-Cache", "MISS")
	if obs := cpCacheObservationOf(public, now); !obs.Cacheable || obs.Hit {
		t.Fatalf("public max-age observation = %+v, want cacheable and not a hit", obs)
	}

	hit := http.Header{}
	hit.Set("Cache-Control", "public, max-age=60")
	hit.Set("X-Cache", "HIT")
	if obs := cpCacheObservationOf(hit, now); !obs.Hit || !obs.Cacheable {
		t.Fatalf("HIT observation = %+v, want hit and cacheable", obs)
	}

	age := http.Header{}
	age.Set("Age", "12")
	if obs := cpCacheObservationOf(age, now); !obs.Hit {
		t.Fatalf("Age observation = %+v, want a hit", obs)
	}

	private := http.Header{}
	private.Set("Cache-Control", "no-store, private")
	if obs := cpCacheObservationOf(private, now); obs.Cacheable {
		t.Fatalf("no-store observation = %+v, want not cacheable", obs)
	}
}

// TestCachePoisoningBodySimilarity verifies the deception body comparison:
// identical documents match, short bodies must match exactly, and a materially
// different document does not match.
func TestCachePoisoningBodySimilarity(t *testing.T) {
	doc := "<html><body><h1>Account</h1><p>This profile page belongs to the signed-in user and " +
		"contains private account details, saved addresses and order history for this session.</p></body></html>"
	if got := cpBodySimilarity(doc, doc); got != 1 {
		t.Fatalf("identical similarity = %v, want 1", got)
	}
	if got := cpBodySimilarity("<html>a</html>", "<html>b</html>"); got != 0 {
		t.Fatalf("short different similarity = %v, want 0", got)
	}
	other := "<html><body><h1>Sign in</h1><p>Enter your credentials to continue to the site.</p></body></html>"
	if got := cpBodySimilarity(doc, other); got >= 0.9 {
		t.Fatalf("different document similarity = %v, want < 0.9", got)
	}
}

// TestEnqueueCachePoisoningProbesRespectsSkipAndDeduplicatesPerOrigin verifies
// SkipCachePoisoning, GET/HEAD filtering, per-origin deduplication, and the
// maxCachePoisoningOrigins cap.
func TestEnqueueCachePoisoningProbesRespectsSkipAndDeduplicatesPerOrigin(t *testing.T) {
	for _, tc := range []struct {
		name string
		skip bool
		want int
	}{
		{"enabled", false, 3},
		{"skipped", true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			st, q := memory.New(), queue.NewMemory()
			now := time.Now()
			sc := &domain.Scan{
				ID: domain.NewID(), ProjectID: domain.NewID(), State: domain.ScanCreated,
				Config: domain.ScanConfig{SkipCachePoisoning: tc.skip}, CreatedAt: now, UpdatedAt: now,
			}
			if err := st.Scans().Create(ctx, sc); err != nil {
				t.Fatal(err)
			}
			endpoints := []struct {
				method domain.HTTPMethod
				url    string
			}{
				{domain.MethodPOST, "https://post-only.example.test/submit"},
				{domain.MethodGET, "https://app.example.test/"},
				{domain.MethodGET, "https://app.example.test/about"},
				{domain.MethodGET, "https://app.example.test/pricing?plan=pro"},
				{domain.MethodGET, "https://other.example.test/"},
				{domain.MethodHEAD, "https://head.example.test/"},
			}
			for _, item := range endpoints {
				ep := &domain.Endpoint{
					ID: domain.NewID(), ScanID: sc.ID, URL: item.url,
					Method: item.method, Source: domain.SourceCrawler, CreatedAt: now,
				}
				if err := st.Endpoints().Create(ctx, ep); err != nil {
					t.Fatal(err)
				}
			}

			ctrl := NewController(st, q, execLog(), "test", Options{})
			t.Cleanup(ctrl.Shutdown)
			ctrl.enqueueCachePoisoningProbes(ctx, sc.ID)

			jobs, err := q.Jobs(ctx, sc.ID)
			if err != nil {
				t.Fatal(err)
			}
			if len(jobs) != tc.want {
				t.Fatalf("jobs = %d, want %d", len(jobs), tc.want)
			}
			if tc.want == 0 {
				return
			}
			origins := make(map[string]bool)
			for _, job := range jobs {
				if job.Type != domain.JobCachePoisoning || job.Priority != cachePoisoningPriority {
					t.Fatalf("job = %+v, want priority-%d cache_poisoning job", job, cachePoisoningPriority)
				}
				origins[cachePoisoningOrigin(job.Target.URL)] = true
			}
			if len(origins) != 3 {
				t.Fatalf("origins = %v, want 3 distinct origins", origins)
			}
		})
	}
}
