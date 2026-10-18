package web

import (
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// GET /metrics serves the Prometheus text exposition format 0.0.4, written by
// hand so the module gains no dependency.
//
// Label values come only from the request method (normalized to a fixed set),
// the mux route PATTERN (e.g. "GET /api/scans/{id}", never the raw path), and
// the status code. Client addresses, tokens, target URLs, finding content, and
// evidence paths never reach a label or a value.

// latencyBuckets are the fixed upper bounds (seconds) of the request-duration
// histogram.
var latencyBuckets = []float64{0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

// unmatchedRoute labels requests that match no mux pattern (404s, and 405s
// from the mux). It keeps arbitrary paths out of the label set.
const unmatchedRoute = "unmatched"

// knownMethods bounds the method label. Any other method is reported as
// "OTHER", so a client cannot create label values by inventing methods.
var knownMethods = map[string]bool{
	http.MethodGet: true, http.MethodHead: true, http.MethodPost: true,
	http.MethodPut: true, http.MethodPatch: true, http.MethodDelete: true,
	http.MethodOptions: true, http.MethodConnect: true, http.MethodTrace: true,
}

type reqKey struct {
	method, route, code string
}

type routeHist struct {
	counts []uint64 // non-cumulative per bucket; render accumulates
	count  uint64
	sum    float64
}

// httpMetrics holds the process-lifetime counters. All methods are nil-safe so
// a zero Server (used by some tests) never panics.
type httpMetrics struct {
	mu           sync.Mutex
	requests     map[reqKey]uint64
	hist         map[string]*routeHist
	rateLimited  uint64
	authRejected uint64
}

func newHTTPMetrics() *httpMetrics {
	return &httpMetrics{requests: make(map[reqKey]uint64), hist: make(map[string]*routeHist)}
}

func (m *httpMetrics) observe(method, route string, code int, d time.Duration) {
	if m == nil {
		return
	}
	if !knownMethods[method] {
		method = "OTHER"
	}
	secs := d.Seconds()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests[reqKey{method: method, route: route, code: strconv.Itoa(code)}]++
	h := m.hist[route]
	if h == nil {
		h = &routeHist{counts: make([]uint64, len(latencyBuckets))}
		m.hist[route] = h
	}
	h.count++
	h.sum += secs
	for i, ub := range latencyBuckets {
		if secs <= ub {
			h.counts[i]++
			break
		}
	}
}

func (m *httpMetrics) incRateLimited() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.rateLimited++
	m.mu.Unlock()
}

func (m *httpMetrics) incAuthRejected() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.authRejected++
	m.mu.Unlock()
}

// render produces the exposition text. The lock is held only to copy the
// state, so a slow scraper never blocks request accounting.
func (m *httpMetrics) render(version string) string {
	if m == nil {
		return ""
	}
	m.mu.Lock()
	reqs := make(map[reqKey]uint64, len(m.requests))
	for k, v := range m.requests {
		reqs[k] = v
	}
	hists := make(map[string]routeHist, len(m.hist))
	for route, h := range m.hist {
		c := routeHist{counts: append([]uint64(nil), h.counts...), count: h.count, sum: h.sum}
		hists[route] = c
	}
	rateLimited, authRejected := m.rateLimited, m.authRejected
	m.mu.Unlock()

	var b strings.Builder

	b.WriteString("# HELP indago_build_info Build information. The value is always 1.\n")
	b.WriteString("# TYPE indago_build_info gauge\n")
	b.WriteString("indago_build_info{version=\"" + escapeLabelValue(version) + "\"} 1\n")

	b.WriteString("# HELP indago_http_requests_total HTTP requests handled, by method, route pattern and status code.\n")
	b.WriteString("# TYPE indago_http_requests_total counter\n")
	keys := make([]reqKey, 0, len(reqs))
	for k := range reqs {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, c := keys[i], keys[j]
		if a.route != c.route {
			return a.route < c.route
		}
		if a.method != c.method {
			return a.method < c.method
		}
		return a.code < c.code
	})
	for _, k := range keys {
		b.WriteString("indago_http_requests_total{method=\"" + escapeLabelValue(k.method) +
			"\",route=\"" + escapeLabelValue(k.route) + "\",code=\"" + escapeLabelValue(k.code) + "\"} " +
			strconv.FormatUint(reqs[k], 10) + "\n")
	}

	b.WriteString("# HELP indago_http_request_duration_seconds HTTP request latency by route pattern.\n")
	b.WriteString("# TYPE indago_http_request_duration_seconds histogram\n")
	routes := make([]string, 0, len(hists))
	for r := range hists {
		routes = append(routes, r)
	}
	sort.Strings(routes)
	for _, route := range routes {
		h := hists[route]
		lbl := "route=\"" + escapeLabelValue(route) + "\""
		var cum uint64
		for i, ub := range latencyBuckets {
			cum += h.counts[i]
			b.WriteString("indago_http_request_duration_seconds_bucket{" + lbl + ",le=\"" +
				strconv.FormatFloat(ub, 'g', -1, 64) + "\"} " + strconv.FormatUint(cum, 10) + "\n")
		}
		b.WriteString("indago_http_request_duration_seconds_bucket{" + lbl + ",le=\"+Inf\"} " +
			strconv.FormatUint(h.count, 10) + "\n")
		b.WriteString("indago_http_request_duration_seconds_sum{" + lbl + "} " +
			strconv.FormatFloat(h.sum, 'g', -1, 64) + "\n")
		b.WriteString("indago_http_request_duration_seconds_count{" + lbl + "} " +
			strconv.FormatUint(h.count, 10) + "\n")
	}

	b.WriteString("# HELP indago_rate_limited_total Requests refused with 429 by the per-client-IP rate limiter.\n")
	b.WriteString("# TYPE indago_rate_limited_total counter\n")
	b.WriteString("indago_rate_limited_total " + strconv.FormatUint(rateLimited, 10) + "\n")

	b.WriteString("# HELP indago_auth_rejected_total Requests refused with 401 by the bearer-token check.\n")
	b.WriteString("# TYPE indago_auth_rejected_total counter\n")
	b.WriteString("indago_auth_rejected_total " + strconv.FormatUint(authRejected, 10) + "\n")

	return b.String()
}

// handleMetrics serves the exposition. Access control (bearer token when one
// is configured) and rate limiting are applied by the wrapping middleware.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, s.metrics.render(s.version))
}

// instrument counts every request that reaches it, with the status it actually
// got. The route is resolved through mux.Handler, not r.Pattern: the 401 and
// 429 answers are produced before the mux runs, so r.Pattern is still unset
// for them. The lookup repeats the mux's matching, which is cheap.
func (s *Server) instrument(mux *http.ServeMux, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		_, route := mux.Handler(r)
		if route == "" {
			route = unmatchedRoute
		}
		s.metrics.observe(r.Method, route, rec.status(), time.Since(start))
	})
}

// statusRecorder captures the status code written through a ResponseWriter. It
// forwards Flush and exposes Unwrap, so http.Flusher and http.ResponseController
// still reach the underlying writer for streaming responses.
type statusRecorder struct {
	http.ResponseWriter
	code  int
	wrote bool
}

func (w *statusRecorder) WriteHeader(code int) {
	// 1xx responses are informational and do not finish the response.
	if !w.wrote && code >= 200 {
		w.code, w.wrote = code, true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusRecorder) Write(b []byte) (int, error) {
	if !w.wrote {
		w.code, w.wrote = http.StatusOK, true
	}
	return w.ResponseWriter.Write(b)
}

func (w *statusRecorder) Flush() {
	if !w.wrote {
		w.code, w.wrote = http.StatusOK, true
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *statusRecorder) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *statusRecorder) status() int {
	if !w.wrote {
		return http.StatusOK
	}
	return w.code
}

// labelEscaper applies the exposition-format escapes for label values:
// backslash, double quote, and newline.
var labelEscaper = strings.NewReplacer(`\`, `\\`, "\n", `\n`, `"`, `\"`)

func escapeLabelValue(s string) string { return labelEscaper.Replace(s) }
