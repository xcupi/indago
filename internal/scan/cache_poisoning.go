package scan

// Read-only Web Cache Poisoning engine.
//
// Three read-only differentials run against ONE origin:
//
//  1. Unkeyed request headers (X-Forwarded-Host, X-Host, X-Original-URL,
//     X-Rewrite-URL, X-Forwarded-Scheme) whose values are reflected into a
//     response that an intermediary cache stores.
//  2. Unkeyed query parameters: a parameter value that changes the response is
//     absent from the cache key, so a clean request WITHOUT that value is
//     served the poisoned response. Candidates come from the endpoint's
//     discovered query parameters (or a tracking-parameter fallback) and each
//     probe overrides exactly one value.
//  3. Web cache deception: a dynamic document is served unchanged at a
//     static-looking path suffix and the cache reports a HIT for a repeated
//     request to that exact URL, proving the cache stored dynamic content under
//     a static URL.
//
// Boundaries:
//   - Read-only: GET or HEAD only, no request body, no state change.
//     State-changing/write-like endpoints are skipped without a request, and
//     state-shaped parameter names are never used as query candidates.
//   - Bounded: at most maxCachePoisoningOrigins origins per scan and a hard
//     maxCachePoisoningRequestsPerOrigin request ceiling per origin; the
//     baseline, header probes, query-parameter differentials and deception
//     probes all draw from that one budget.
//   - Cache-safe: every request carries a unique cache-buster query parameter
//     (indago_cb=<rand>), and probes use unique canaries/tokens, so real users
//     and shared cache keys are never affected. A cache-deception probe repeats
//     ONE already-unique probe URL to observe the HIT, never a URL a user would
//     request.
//   - Never followed: each request sets NoRedirects, so a poisoned Location or
//     Refresh header is recorded as evidence instead of being followed.
//   - Follow-up confirmed: an unkeyed header/parameter signal is emitted ONLY
//     when the canary appears in the probe response (and not in the baseline)
//     AND also appears in the immediate clean follow-up that does not carry the
//     probed value. A deception signal is emitted ONLY when the dynamic
//     baseline body is reproduced at the static-suffixed URL, that response is
//     explicitly cacheable, and a repeat request to the same unique URL is
//     reported as a cache HIT.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/evidence"
	"github.com/indago/indago/internal/httpengine"
	"github.com/indago/indago/internal/store"
	"github.com/indago/indago/internal/worker"
)

const (
	cpEngine           = "cache_poisoning"
	cpCacheBusterParam = "indago_cb"

	// cpQueryFallbackParameter is probed when the endpoint exposes no usable
	// query parameter of its own. Tracking parameters are the canonical
	// unkeyed-query case: many intermediaries strip utm_* from the cache key.
	cpQueryFallbackParameter = "utm_source"

	// maxCachePoisoningOrigins bounds the pass: one job per origin.
	maxCachePoisoningOrigins = 15
	// maxCachePoisoningQueryParams bounds how many query parameters one origin
	// is probed for, so the differential cannot grow with the crawl.
	maxCachePoisoningQueryParams = 3
	// maxCacheDeceptionSuffixes bounds the static suffixes one origin is
	// probed with.
	maxCacheDeceptionSuffixes = 2
	// maxCachePoisoningRequestsPerOrigin is the hard request ceiling for the
	// whole pass (baseline + header probes + query differentials + deception
	// probes and their confirmations). The worst-case sequence is 21 requests;
	// the cap leaves headroom while remaining a real bound.
	maxCachePoisoningRequestsPerOrigin = 24
	// cachePoisoningPriority places the cache-poisoning pass right after the
	// host-header pass.
	cachePoisoningPriority = 38
)

// cpDeceptionSuffixes are the static-looking path suffixes used by the web
// cache deception differential, in fixed order.
var cpDeceptionSuffixes = []string{".css", ".js"}

// cpUnsafeQueryNames are parameter names this read-only pass never overrides:
// they select a state-changing action or carry authentication material, so
// writing a canary into them could mutate the target or invalidate a session.
var cpUnsafeQueryNames = map[string]bool{
	"_method": true, "action": true, "approve": true, "auth": true,
	"checkout": true, "cmd": true, "command": true, "confirm": true,
	"create": true, "csrf": true, "delete": true, "do": true,
	"login": true, "logout": true, "password": true, "passwd": true,
	"process": true, "register": true, "reject": true, "remove": true,
	"reset": true, "role": true, "save": true, "secret": true,
	"session": true, "signout": true, "store": true, "submit": true,
	"token": true, "transfer": true, "update": true, "upload": true,
}

// cpHeaderSpec describes one unkeyed header candidate and how its canary
// value is constructed from a per-probe token.
type cpHeaderSpec struct {
	Header string
	Value  func(token string) string
}

var cpCandidateHeaders = []cpHeaderSpec{
	{Header: "X-Forwarded-Host", Value: func(tok string) string { return "indago-cp-" + tok + ".invalid" }},
	{Header: "X-Host", Value: func(tok string) string { return "indago-cp-" + tok + ".invalid" }},
	{Header: "X-Original-URL", Value: func(tok string) string { return "/indago-cp-" + tok }},
	{Header: "X-Rewrite-URL", Value: func(tok string) string { return "/indago-cp-" + tok }},
	{Header: "X-Forwarded-Scheme", Value: func(tok string) string { return "indago-cp-" + tok }},
}

// Signal kinds, one per response vector where the canary can surface, plus the
// two differential techniques.
const (
	cpKindBody     = "cache_poisoning_body"
	cpKindLocation = "cache_poisoning_location"
	cpKindRefresh  = "cache_poisoning_refresh"

	cpKindDeception = "cache_deception_static_suffix"
)

// Techniques label which differential produced a signal. They are stable
// identifiers (no probe tokens), so a resumed run can union signals by key.
const (
	cpTechniqueUnkeyedHeader  = "unkeyed_header"
	cpTechniqueUnkeyedQuery   = "unkeyed_query_parameter"
	cpTechniqueCacheDeception = "web_cache_deception"
)

// cachePoisoningProbe records one candidate header probe and, when reflected,
// its clean follow-up verification.
type cachePoisoningProbe struct {
	Header       string   `json:"header"`
	Value        string   `json:"value"`
	URL          string   `json:"url"`
	Status       int      `json:"status,omitempty"`
	FollowStatus int      `json:"follow_status,omitempty"`
	Reflected    bool     `json:"reflected"`
	Cached       bool     `json:"cached"`
	Vectors      []string `json:"vectors,omitempty"`
	Note         string   `json:"note,omitempty"`
}

// cachePoisoningQueryProbe records one unkeyed query-parameter differential:
// the same cache-busted URL with one parameter value changed, then the
// original value restored for the clean follow-up.
type cachePoisoningQueryProbe struct {
	Parameter    string   `json:"parameter"`
	Value        string   `json:"value"`
	URL          string   `json:"url"`
	Status       int      `json:"status,omitempty"`
	FollowStatus int      `json:"follow_status,omitempty"`
	Reflected    bool     `json:"reflected"`
	Unkeyed      bool     `json:"unkeyed"`
	Vectors      []string `json:"vectors,omitempty"`
	Note         string   `json:"note,omitempty"`
}

// cachePoisoningDeceptionProbe records one web cache deception differential:
// a dynamic document requested through a unique static-looking suffix, then
// the exact same unique URL again to observe the cache HIT.
type cachePoisoningDeceptionProbe struct {
	Suffix        string `json:"suffix"`
	URL           string `json:"url"`
	Status        int    `json:"status,omitempty"`
	ConfirmStatus int    `json:"confirm_status,omitempty"`
	BodyMatched   bool   `json:"body_matched"`
	Cacheable     bool   `json:"cacheable"`
	CacheHit      bool   `json:"cache_hit"`
	CacheState    string `json:"cache_state,omitempty"`
	Note          string `json:"note,omitempty"`
}

// cachePoisoningSignal is one confirmed cached-poisoning observation.
type cachePoisoningSignal struct {
	Key         string            `json:"key"`
	Kind        string            `json:"kind"`
	Technique   string            `json:"technique"`
	Header      string            `json:"header,omitempty"`
	Parameter   string            `json:"parameter,omitempty"`
	Suffix      string            `json:"suffix,omitempty"`
	Severity    domain.Severity   `json:"severity"`
	Confidence  domain.Confidence `json:"confidence"`
	Reason      string            `json:"reason"`
	Remediation string            `json:"remediation"`
	Title       string            `json:"title"`
}

// cachePoisoningDetail is the engine-specific JSON recorded in TestCase.Detail
// and Finding.Detail.
type cachePoisoningDetail struct {
	Engine           string                         `json:"engine"`
	URL              string                         `json:"url"`
	BaselineURL      string                         `json:"baseline_url,omitempty"`
	Origin           string                         `json:"origin"`
	Method           string                         `json:"method"`
	CacheBusterParam string                         `json:"cache_buster_param,omitempty"`
	FinalURL         string                         `json:"final_url,omitempty"`
	HTTPStatus       int                            `json:"http_status,omitempty"`
	DedupKey         string                         `json:"dedup_key,omitempty"`
	Occurrences      int                            `json:"occurrences,omitempty"`
	Verdict          domain.Verdict                 `json:"verdict"`
	Severity         domain.Severity                `json:"severity,omitempty"`
	Confidence       domain.Confidence              `json:"confidence,omitempty"`
	Reason           string                         `json:"reason,omitempty"`
	Probes           []cachePoisoningProbe          `json:"probes,omitempty"`
	QueryProbes      []cachePoisoningQueryProbe     `json:"query_probes,omitempty"`
	DeceptionProbes  []cachePoisoningDeceptionProbe `json:"deception_probes,omitempty"`
	Signals          []cachePoisoningSignal         `json:"signals,omitempty"`
	Throttled        bool                           `json:"throttled,omitempty"`
	BudgetExhausted  bool                           `json:"budget_exhausted,omitempty"`
	Skipped          bool                           `json:"skipped,omitempty"`
	SkipReason       string                         `json:"skip_reason,omitempty"`
	TestCaseIDs      []domain.ID                    `json:"test_case_ids,omitempty"`
	EvidenceIDs      []domain.ID                    `json:"evidence_ids,omitempty"`
}

// ---------------------------------------------------------------------------
// pure helpers
// ---------------------------------------------------------------------------

func cachePoisoningOrigin(rawURL string) string { return securityHeadersOrigin(rawURL) }

func cachePoisoningDedupKey(origin string) string {
	return cpEngine + "\x00" + strings.ToLower(origin)
}

func cachePoisoningSignalKey(origin, header, vector string) string {
	return cachePoisoningDedupKey(origin) + "\x00" + strings.ToLower(header) + "\x00" + vector
}

// cpCacheBusted appends indago_cb=<token> to rawURL, preserving any existing
// query parameters and fragment.
func cpCacheBusted(rawURL, token string) string {
	fragment := ""
	if i := strings.IndexByte(rawURL, '#'); i >= 0 {
		rawURL, fragment = rawURL[:i], rawURL[i:]
	}
	sep := "?"
	switch {
	case strings.HasSuffix(rawURL, "?") || strings.HasSuffix(rawURL, "&"):
		sep = ""
	case strings.Contains(rawURL, "?"):
		sep = "&"
	}
	return rawURL + sep + cpCacheBusterParam + "=" + token + fragment
}

// cpResponseVectors returns the response vectors (Location, Refresh, Body)
// that contain canary, case-insensitively.
func cpResponseVectors(resp *httpengine.Response, canary string) []string {
	if resp == nil || canary == "" {
		return nil
	}
	needle := strings.ToLower(canary)
	var out []string
	if loc := resp.Headers.Get("Location"); strings.Contains(strings.ToLower(loc), needle) {
		out = append(out, cpKindLocation)
	}
	if refresh := resp.Headers.Get("Refresh"); strings.Contains(strings.ToLower(refresh), needle) {
		out = append(out, cpKindRefresh)
	}
	if strings.Contains(strings.ToLower(string(resp.Body)), needle) {
		out = append(out, cpKindBody)
	}
	return out
}

// cpSubtractVectors returns vectors present in target that were not in base.
func cpSubtractVectors(base, target []string) []string {
	if len(target) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(base))
	for _, v := range base {
		seen[v] = true
	}
	var out []string
	for _, v := range target {
		if !seen[v] {
			out = append(out, v)
		}
	}
	return out
}

// cpIntersectVectors returns vectors present in both a and b.
func cpIntersectVectors(a, b []string) []string {
	if len(a) == 0 || len(b) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(b))
	for _, v := range b {
		seen[v] = true
	}
	var out []string
	for _, v := range a {
		if seen[v] {
			out = append(out, v)
		}
	}
	return out
}

func cpVectorLabel(kind string) string {
	switch kind {
	case cpKindLocation:
		return "Location header"
	case cpKindRefresh:
		return "Refresh header"
	case cpKindBody:
		return "response body"
	default:
		return "response"
	}
}

// cpRequestMethod maps the endpoint's method to the only methods this pass may
// send. cpSkip has already refused anything that is not GET/HEAD.
func cpRequestMethod(ep *domain.Endpoint) string {
	if ep != nil && ep.Method == domain.MethodHEAD {
		return http.MethodHead
	}
	return http.MethodGet
}

// cpUsableQueryName reports whether a parameter name is safe and well-formed
// enough to override with a benign canary in a read-only request.
func cpUsableQueryName(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 64 {
		return false
	}
	if strings.EqualFold(name, cpCacheBusterParam) {
		return false
	}
	if cpUnsafeQueryNames[strings.ToLower(name)] {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '_', r == '-', r == '.':
		default:
			return false
		}
	}
	return true
}

// cpQueryCandidateNames returns the bounded, deterministic set of query
// parameters to test: the endpoint's discovered query parameters plus any
// parameter names already present in its URL, filtered and sorted. When that
// set is empty a single tracking-parameter fallback is used, because a cache
// that strips utm_* is the canonical unkeyed-query case.
func cpQueryCandidateNames(ep *domain.Endpoint, params []*domain.Parameter) []string {
	seen := make(map[string]bool)
	var names []string
	add := func(raw string) {
		name := strings.TrimSpace(raw)
		if !cpUsableQueryName(name) || seen[name] {
			return
		}
		seen[name] = true
		names = append(names, name)
	}
	for _, p := range params {
		if p == nil || p.Location != domain.LocationQuery {
			continue
		}
		add(p.Name)
	}
	if ep != nil {
		if u, err := url.Parse(ep.URL); err == nil {
			values := u.Query()
			keys := make([]string, 0, len(values))
			for k := range values {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				add(k)
			}
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		return []string{cpQueryFallbackParameter}
	}
	if len(names) > maxCachePoisoningQueryParams {
		names = names[:maxCachePoisoningQueryParams]
	}
	return names
}

// cpQueryDifferentialURLs builds the pair the unkeyed-query differential
// compares: the same cache-busted URL with exactly ONE parameter value
// replaced by the canary, and the same URL with that parameter restored to
// its original value (or omitted when it was not present). Everything else —
// path, other parameters, cache-buster — is byte-identical, so the only
// difference between the two requests is the probed value.
func cpQueryDifferentialURLs(baseURL, name, canary string) (probeURL, followURL string, ok bool) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", "", false
	}
	original, hadOriginal := u.Query()[name]

	probe := *u
	q := u.Query()
	q.Set(name, canary)
	probe.RawQuery = q.Encode()

	follow := *u
	q = u.Query()
	if hadOriginal {
		q.Set(name, original[0])
	} else {
		q.Del(name)
	}
	follow.RawQuery = q.Encode()

	return probe.String(), follow.String(), true
}

// cpDeceptionURL rewrites rawURL's path to a unique static-looking suffix. The
// token keeps every probe path unique, so a cache entry created by the probe
// can never be served to a real user.
func cpDeceptionURL(rawURL, token, suffix string) (string, bool) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", false
	}
	path := strings.TrimSuffix(u.Path, "/")
	u.Path = path + "/indago-wcd-" + token + suffix
	u.RawPath = ""
	return u.String(), true
}

// cpHasStaticSuffix reports whether the endpoint's own path already ends in a
// static-asset extension. Such a URL is not a dynamic document, so the
// deception differential is skipped instead of being judged on it.
func cpHasStaticSuffix(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	path := strings.ToLower(strings.TrimSuffix(u.Path, "/"))
	for _, suffix := range cpDeceptionSuffixes {
		if strings.HasSuffix(path, suffix) {
			return true
		}
	}
	switch pathExt(path) {
	case ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
		".woff", ".woff2", ".ttf", ".eot", ".map", ".mp4", ".webm":
		return true
	}
	return false
}

// pathExt is filepath.Ext restricted to the URL path semantics used here.
func pathExt(path string) string {
	if i := strings.LastIndexByte(path, '.'); i >= 0 && i > strings.LastIndexByte(path, '/') {
		return path[i:]
	}
	return ""
}

// cpBaselineIsDocument reports whether the baseline response is a dynamic
// HTML document, which is the only thing web cache deception can expose.
func cpBaselineIsDocument(resp *httpengine.Response) bool {
	if resp == nil || len(resp.Body) == 0 || resp.Status < 200 || resp.Status >= 300 {
		return false
	}
	ct := strings.ToLower(resp.Headers.Get("Content-Type"))
	return strings.Contains(ct, "text/html") || strings.Contains(ct, "application/xhtml")
}

// cpNormalizeBody collapses whitespace and removes the probe's own tokens, so
// two responses that differ only by their cache-buster/canary still compare
// equal.
func cpNormalizeBody(body []byte, drop ...string) string {
	s := string(body)
	for _, token := range drop {
		if token != "" {
			s = strings.ReplaceAll(s, token, "")
		}
	}
	return strings.Join(strings.Fields(s), " ")
}

// cpBodySimilarity returns 1 for equal normalized bodies and the word-set
// Jaccard ratio otherwise. Short bodies must match exactly: a handful of words
// is not enough signal to call two documents the same.
func cpBodySimilarity(a, b string) float64 {
	if a == b {
		return 1
	}
	aw, bw := strings.Fields(a), strings.Fields(b)
	if len(aw) < 16 || len(bw) < 16 {
		return 0
	}
	set := make(map[string]bool, len(aw))
	for _, w := range aw {
		set[w] = true
	}
	other := make(map[string]bool, len(bw))
	inter := 0
	for _, w := range bw {
		if other[w] {
			continue
		}
		other[w] = true
		if set[w] {
			inter++
		}
	}
	union := len(set)
	for w := range other {
		if !set[w] {
			union++
		}
	}
	if union == 0 {
		return 0
	}
	return float64(inter) / float64(union)
}

// cpCacheObservation is the explicit cache state a response reports.
type cpCacheObservation struct {
	Cacheable bool
	Hit       bool
	State     string
}

// cpCacheObservationOf reads the response's own cache signals. It never
// guesses: an origin that exposes no Cache-Control/Expires and no cache
// status header is treated as not proven cacheable.
func cpCacheObservationOf(h http.Header, now time.Time) cpCacheObservation {
	var obs cpCacheObservation
	for _, name := range []string{
		"X-Cache", "X-Cache-Status", "X-Proxy-Cache", "CF-Cache-Status",
		"X-Varnish-Cache", "Akamai-Cache-Status", "X-Served-By-Cache",
	} {
		value := strings.TrimSpace(h.Get(name))
		if value == "" {
			continue
		}
		lower := strings.ToLower(value)
		switch {
		case strings.Contains(lower, "hit"):
			obs.Hit = true
			if obs.State == "" {
				obs.State = name + ": " + value
			}
		case strings.Contains(lower, "miss"):
			if obs.State == "" {
				obs.State = name + ": " + value
			}
		}
	}
	if age := strings.TrimSpace(h.Get("Age")); age != "" {
		if n, err := strconv.Atoi(age); err == nil && n > 0 {
			obs.Hit = true
			if obs.State == "" {
				obs.State = "Age: " + age
			}
		}
	}
	cc := strings.ToLower(h.Get("Cache-Control"))
	if cc != "" && !strings.Contains(cc, "no-store") &&
		!strings.Contains(cc, "private") && !strings.Contains(cc, "no-cache") {
		if strings.Contains(cc, "public") ||
			cpDirectiveSeconds(cc, "max-age") > 0 || cpDirectiveSeconds(cc, "s-maxage") > 0 {
			obs.Cacheable = true
			if obs.State == "" {
				obs.State = "Cache-Control: " + h.Get("Cache-Control")
			}
		}
	}
	if !obs.Cacheable {
		if expires := strings.TrimSpace(h.Get("Expires")); expires != "" {
			if t, err := http.ParseTime(expires); err == nil && t.After(now) {
				obs.Cacheable = true
				if obs.State == "" {
					obs.State = "Expires: " + expires
				}
			}
		}
	}
	return obs
}

// cpDirectiveSeconds returns the numeric value of one Cache-Control directive.
func cpDirectiveSeconds(cc, directive string) int {
	for _, part := range strings.Split(cc, ",") {
		part = strings.TrimSpace(part)
		key, value, found := strings.Cut(part, "=")
		if !found || !strings.EqualFold(strings.TrimSpace(key), directive) {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), `"`)
		if n, err := strconv.Atoi(value); err == nil && n > 0 {
			return n
		}
	}
	return 0
}

// cpSignalStrength returns the strongest severity/confidence pair in signals.
func cpSignalStrength(signals []cachePoisoningSignal) (domain.Severity, domain.Confidence) {
	sevRank := map[domain.Severity]int{
		domain.SeverityInfo: 0, domain.SeverityLow: 1, domain.SeverityMedium: 2,
		domain.SeverityHigh: 3, domain.SeverityCritical: 4,
	}
	confRank := map[domain.Confidence]int{
		domain.ConfidenceLow: 0, domain.ConfidenceMedium: 1, domain.ConfidenceHigh: 2,
	}
	bestSev, bestConf := domain.Severity(""), domain.Confidence("")
	for i, s := range signals {
		if i == 0 || sevRank[s.Severity] > sevRank[bestSev] {
			bestSev = s.Severity
		}
		if i == 0 || confRank[s.Confidence] > confRank[bestConf] {
			bestConf = s.Confidence
		}
	}
	return bestSev, bestConf
}

// cpMergeSignals unions two signal sets by key, preserving the first-seen
// order. Resumed runs re-observe the same stable keys, so this is bounded and
// a run that only re-confirms one technique never discards the others.
func cpMergeSignals(existing, add []cachePoisoningSignal) []cachePoisoningSignal {
	out := make([]cachePoisoningSignal, 0, len(existing)+len(add))
	seen := make(map[string]bool, len(existing)+len(add))
	for _, group := range [][]cachePoisoningSignal{existing, add} {
		for _, s := range group {
			if s.Key == "" || seen[s.Key] {
				continue
			}
			seen[s.Key] = true
			out = append(out, s)
		}
	}
	return out
}

func cachePoisoningSignalFor(origin, header, vector string) cachePoisoningSignal {
	return cachePoisoningSignal{
		Key:        cachePoisoningSignalKey(origin, header, vector),
		Kind:       vector,
		Technique:  cpTechniqueUnkeyedHeader,
		Header:     header,
		Severity:   domain.SeverityMedium,
		Confidence: domain.ConfidenceHigh,
		Reason: fmt.Sprintf("the unkeyed request header %s was reflected into the %s and served "+
			"to a subsequent clean GET request on the same cache-busted URL, proving the intermediary cache "+
			"stored the poisoned response", header, cpVectorLabel(vector)),
		Remediation: "Exclude unkeyed forwarding/override headers (X-Forwarded-Host, X-Host, " +
			"X-Original-URL, X-Rewrite-URL, X-Forwarded-Scheme) from application response generation, " +
			"strip untrusted client-supplied proxy headers at the edge, or include any trusted header in the cache key.",
		Title: fmt.Sprintf("Web cache poisoning via unkeyed %s (%s)", header, cpVectorLabel(vector)),
	}
}

// cachePoisoningQuerySignalFor renders one unkeyed query-parameter signal.
// The key uses the parameter NAME only, so a resumed run re-observes the same
// identity instead of accumulating one row per random canary.
func cachePoisoningQuerySignalFor(origin, parameter, vector string) cachePoisoningSignal {
	return cachePoisoningSignal{
		Key:        cachePoisoningSignalKey(origin, "query:"+strings.ToLower(parameter), vector),
		Kind:       vector,
		Technique:  cpTechniqueUnkeyedQuery,
		Parameter:  parameter,
		Severity:   domain.SeverityMedium,
		Confidence: domain.ConfidenceHigh,
		Reason: fmt.Sprintf("the query parameter %q was reflected into the %s and the poisoned response "+
			"was served to a clean follow-up request that did not carry that value, proving the "+
			"intermediary cache does not key on the parameter", parameter, cpVectorLabel(vector)),
		Remediation: "Include every query parameter that can change a response in the cache key, or strip and " +
			"normalize unknown/tracking parameters at the edge before the application sees them; never cache a " +
			"response whose body depends on a parameter the cache ignores.",
		Title: fmt.Sprintf("Web cache poisoning via unkeyed query parameter %q (%s)", parameter, cpVectorLabel(vector)),
	}
}

// cachePoisoningDeceptionSignalFor renders one web cache deception signal. The
// key uses the suffix only (not the random probe token) so repeated runs merge.
func cachePoisoningDeceptionSignalFor(origin, suffix string) cachePoisoningSignal {
	return cachePoisoningSignal{
		Key:        cachePoisoningSignalKey(origin, "deception:"+suffix, cpKindDeception),
		Kind:       cpKindDeception,
		Technique:  cpTechniqueCacheDeception,
		Suffix:     suffix,
		Severity:   domain.SeverityMedium,
		Confidence: domain.ConfidenceMedium,
		Reason: fmt.Sprintf("a dynamic HTML document was served unchanged at a path ending in %q and a "+
			"repeat request to that exact unique URL was reported as a cache HIT, so the intermediary "+
			"stored response-generated content under a static-looking URL", suffix),
		Remediation: "Do not cache a response for a path whose extension does not match the response content " +
			"type; set Cache-Control: no-store (or private) on authenticated/dynamic documents and make the " +
			"edge cache key on the normalized path plus the response content type.",
		Title: fmt.Sprintf("Web cache deception: dynamic page cached under a %q path", suffix),
	}
}

func cachePoisoningSummary(signals []cachePoisoningSignal) string {
	headers := make([]string, 0, len(signals))
	seenH := make(map[string]bool, len(signals))
	params := make([]string, 0, len(signals))
	seenP := make(map[string]bool, len(signals))
	suffixes := make([]string, 0, len(signals))
	seenS := make(map[string]bool, len(signals))
	vectors := make([]string, 0, len(signals))
	seenV := make(map[string]bool, len(signals))
	for _, s := range signals {
		switch s.Technique {
		case cpTechniqueUnkeyedQuery:
			if !seenP[s.Parameter] {
				seenP[s.Parameter] = true
				params = append(params, s.Parameter)
			}
		case cpTechniqueCacheDeception:
			if !seenS[s.Suffix] {
				seenS[s.Suffix] = true
				suffixes = append(suffixes, s.Suffix)
			}
		default:
			if !seenH[s.Header] {
				seenH[s.Header] = true
				headers = append(headers, s.Header)
			}
			if !seenV[s.Kind] {
				seenV[s.Kind] = true
				vectors = append(vectors, cpVectorLabel(s.Kind))
			}
		}
	}
	var parts []string
	if len(headers) > 0 {
		parts = append(parts, fmt.Sprintf("unkeyed header(s) %s reflected into %s",
			strings.Join(headers, ", "), strings.Join(vectors, ", ")))
	}
	if len(params) > 0 {
		parts = append(parts, fmt.Sprintf("unkeyed query parameter(s) %s", strings.Join(params, ", ")))
	}
	if len(suffixes) > 0 {
		parts = append(parts, fmt.Sprintf("dynamic document cached under %s path(s)", strings.Join(suffixes, ", ")))
	}
	if len(parts) == 0 {
		return "the intermediary cache stored a poisoned response"
	}
	return "the intermediary cache stored poisoned responses: " + strings.Join(parts, "; ")
}

// ---------------------------------------------------------------------------
// executor
// ---------------------------------------------------------------------------

type cachePoisoningExecutor struct {
	store      store.Store
	engine     httpengine.Engine
	evidence   evidence.Store
	cfg        ExecutorConfig
	log        *slog.Logger
	findingsMu *sync.Mutex
}

// newCachePoisoningExecutor constructs the read-only Web Cache Poisoning
// worker handler.
func newCachePoisoningExecutor(st store.Store, eng httpengine.Engine, ev evidence.Store, cfg ExecutorConfig, log *slog.Logger, findingsMu *sync.Mutex) worker.Handler {
	if findingsMu == nil {
		findingsMu = &sync.Mutex{}
	}
	if log == nil {
		log = slog.Default()
	}
	return &cachePoisoningExecutor{
		store:      st,
		engine:     eng,
		evidence:   ev,
		cfg:        cfg.withDefaults(),
		log:        log,
		findingsMu: findingsMu,
	}
}

var _ worker.Handler = (*cachePoisoningExecutor)(nil)

// Handle implements worker.Handler: one read-only baseline, then the three
// bounded differentials (unkeyed headers, unkeyed query parameters, web cache
// deception) against the same origin. Every request draws from one per-origin
// budget and carries a unique cache-buster.
func (e *cachePoisoningExecutor) Handle(ctx context.Context, job *domain.TestJob) error {
	started := time.Now()
	ep, err := hostHeaderTarget(ctx, e.store, job)
	if err != nil {
		return fmt.Errorf("%w: %w", worker.ErrPermanent, err)
	}
	method := string(ep.Method)
	if method == "" {
		method = http.MethodGet
	}
	tc := &domain.TestCase{
		ID: domain.NewID(), ScanID: job.ScanID, JobID: job.ID, Attempt: job.Attempts,
		VulnClass: domain.VulnCachePoisoning, Status: domain.TestCaseRunning, URL: ep.URL, Method: method,
		StartedAt: &started, CreatedAt: started, UpdatedAt: started,
	}
	if err := e.store.TestCases().Create(ctx, tc); err != nil {
		return fmt.Errorf("persist cache-poisoning test case: %w", err)
	}

	origin := cachePoisoningOrigin(ep.URL)
	d := &cachePoisoningDetail{
		Engine:           cpEngine,
		URL:              ep.URL,
		Origin:           origin,
		Method:           method,
		CacheBusterParam: cpCacheBusterParam,
		Verdict:          domain.VerdictRejected,
	}
	if reason, skip := e.cpSkip(ep); skip {
		d.Skipped, d.SkipReason = true, reason
		e.finish(ctx, tc, d, domain.TestCaseSkipped, "cache poisoning check skipped: "+reason)
		return nil
	}
	d.DedupKey = cachePoisoningDedupKey(origin)

	reqMethod := cpRequestMethod(ep)
	budget := maxCachePoisoningRequestsPerOrigin

	// 1. Clean baseline with a fresh cache-buster. This is also the clean
	// reference the query-parameter differential compares against.
	baseToken := markerToken("cpb")
	baselineURL := cpCacheBusted(ep.URL, baseToken)
	d.BaselineURL = baselineURL
	budget--
	baseReq := httpengine.NewRequest(reqMethod, baselineURL)
	baseReq.NoRedirects = true
	baseResp, outcome, reqErr := e.cpDo(ctx, baseReq)
	now := time.Now()
	tc.FinishedAt = &now
	if baseResp != nil {
		tc.HTTPStatus = baseResp.Status
	}
	if outcome != domain.OutcomeSuccess {
		d.Verdict = domain.VerdictInconclusive
		d.Reason = "the read-only baseline request to this origin did not complete"
		tc.Note = truncate("cache poisoning inconclusive: "+errorText(reqErr, outcome), 1024)
		e.finish(ctx, tc, d, domain.TestCaseFailed, tc.Note)
		return nil
	}
	tc.DurationMS = time.Since(started).Milliseconds()
	d.HTTPStatus = baseResp.Status
	d.FinalURL = baseResp.FinalURL
	e.persist(ctx, tc, "baseline", baseResp)

	if isThrottleStatus(baseResp.Status) {
		d.Throttled = true
		d.Verdict = domain.VerdictInconclusive
		d.Reason = fmt.Sprintf("the target answered HTTP %d on baseline, so no probe was sent", baseResp.Status)
		e.finish(ctx, tc, d, domain.TestCaseCompleted, "cache poisoning check inconclusive: target throttled the baseline request")
		return nil
	}

	completed := 0
	var signals []cachePoisoningSignal

	// 2. Probe each candidate unkeyed header with its own unique cache-buster
	// and canary token.
	for _, spec := range cpCandidateHeaders {
		if d.Throttled {
			break
		}
		if budget <= 0 {
			d.BudgetExhausted = true
			break
		}
		budget--
		token := markerToken("cp")
		canary := spec.Value(token)
		probeURL := cpCacheBusted(ep.URL, markerToken("cpp"))

		req := httpengine.NewRequest(reqMethod, probeURL)
		req.NoRedirects = true
		req.WithHeader(spec.Header, canary)

		resp, probeOutcome, probeErr := e.cpDo(ctx, req)
		probe := cachePoisoningProbe{
			Header: spec.Header,
			Value:  canary,
			URL:    probeURL,
		}
		switch {
		case probeOutcome != domain.OutcomeSuccess:
			probe.Note = "probe request did not complete: " + errorText(probeErr, probeOutcome)
		case isThrottleStatus(resp.Status):
			probe.Status = resp.Status
			probe.Note = fmt.Sprintf("the target answered HTTP %d, so this probe was not judged", resp.Status)
			d.Throttled = true
			e.persist(ctx, tc, spec.Header+" probe", resp)
		default:
			completed++
			probe.Status = resp.Status
			e.persist(ctx, tc, spec.Header+" probe", resp)

			// Ensure the canary wasn't already present in the baseline.
			baseVecs := cpResponseVectors(baseResp, canary)
			probeVecs := cpSubtractVectors(baseVecs, cpResponseVectors(resp, canary))
			if len(probeVecs) > 0 {
				probe.Reflected = true
				if budget <= 0 {
					d.BudgetExhausted = true
					probe.Note = "canary reflected but the per-origin request budget was exhausted before the clean follow-up"
				} else {
					// Clean follow-up to the exact same cache-busted URL
					// without the unkeyed header.
					budget--
					followReq := httpengine.NewRequest(reqMethod, probeURL)
					followReq.NoRedirects = true
					followResp, followOutcome, followErr := e.cpDo(ctx, followReq)
					switch {
					case followOutcome != domain.OutcomeSuccess:
						probe.Note = "clean follow-up request did not complete: " + errorText(followErr, followOutcome)
					case isThrottleStatus(followResp.Status):
						probe.FollowStatus = followResp.Status
						probe.Note = fmt.Sprintf("the target answered HTTP %d on clean follow-up", followResp.Status)
						d.Throttled = true
						e.persist(ctx, tc, spec.Header+" follow-up", followResp)
					default:
						probe.FollowStatus = followResp.Status
						e.persist(ctx, tc, spec.Header+" follow-up", followResp)
						followVecs := cpSubtractVectors(baseVecs, cpResponseVectors(followResp, canary))
						cachedVecs := cpIntersectVectors(probeVecs, followVecs)
						if len(cachedVecs) > 0 {
							probe.Cached = true
							probe.Vectors = cachedVecs
							for _, v := range cachedVecs {
								signals = append(signals, cachePoisoningSignalFor(origin, spec.Header, v))
							}
						} else {
							probe.Vectors = probeVecs
							probe.Note = "canary reflected in probe response but absent from clean follow-up (not cached)"
						}
					}
				}
			}
		}

		d.Probes = append(d.Probes, probe)
	}

	// 3. Unkeyed query-parameter differential. Each probe changes exactly one
	// parameter value on one unique cache-busted URL; the clean follow-up asks
	// for the same URL with the original value restored. A canary in the
	// follow-up can only come from a cache that ignored the parameter.
	if !d.Throttled {
		var params []*domain.Parameter
		if !ep.ID.Empty() {
			if rows, err := e.store.Parameters().ListByEndpoint(ctx, ep.ID); err == nil {
				params = rows
			}
		}
		for _, name := range cpQueryCandidateNames(ep, params) {
			if d.Throttled {
				break
			}
			if budget <= 0 {
				d.BudgetExhausted = true
				break
			}
			budget--
			canary := "indago-cpq-" + markerToken("q")
			probeBaseURL := cpCacheBusted(ep.URL, markerToken("cpq"))
			probeURL, followURL, ok := cpQueryDifferentialURLs(probeBaseURL, name, canary)
			if !ok {
				continue
			}
			req := httpengine.NewRequest(reqMethod, probeURL)
			req.NoRedirects = true
			resp, probeOutcome, probeErr := e.cpDo(ctx, req)
			probe := cachePoisoningQueryProbe{Parameter: name, Value: canary, URL: probeURL}
			judged := true
			switch {
			case probeOutcome != domain.OutcomeSuccess:
				probe.Note = "probe request did not complete: " + errorText(probeErr, probeOutcome)
				judged = false
			case isThrottleStatus(resp.Status):
				probe.Status = resp.Status
				probe.Note = fmt.Sprintf("the target answered HTTP %d, so this probe was not judged", resp.Status)
				d.Throttled = true
				e.persist(ctx, tc, "query "+name+" probe", resp)
				judged = false
			default:
				completed++
				probe.Status = resp.Status
				e.persist(ctx, tc, "query "+name+" probe", resp)
			}
			if judged {
				baseVecs := cpResponseVectors(baseResp, canary)
				probeVecs := cpSubtractVectors(baseVecs, cpResponseVectors(resp, canary))
				probe.Vectors = probeVecs
				if len(probeVecs) > 0 {
					probe.Reflected = true
					if budget <= 0 {
						d.BudgetExhausted = true
						probe.Note = "canary reflected but the per-origin request budget was exhausted before the clean follow-up"
					} else {
						budget--
						followReq := httpengine.NewRequest(reqMethod, followURL)
						followReq.NoRedirects = true
						followResp, followOutcome, followErr := e.cpDo(ctx, followReq)
						switch {
						case followOutcome != domain.OutcomeSuccess:
							probe.Note = "clean follow-up request did not complete: " + errorText(followErr, followOutcome)
						case isThrottleStatus(followResp.Status):
							probe.FollowStatus = followResp.Status
							probe.Note = fmt.Sprintf("the target answered HTTP %d on clean follow-up", followResp.Status)
							d.Throttled = true
							e.persist(ctx, tc, "query "+name+" follow-up", followResp)
						default:
							probe.FollowStatus = followResp.Status
							e.persist(ctx, tc, "query "+name+" follow-up", followResp)
							followVecs := cpSubtractVectors(baseVecs, cpResponseVectors(followResp, canary))
							unkeyedVecs := cpIntersectVectors(probeVecs, followVecs)
							if len(unkeyedVecs) > 0 {
								probe.Unkeyed = true
								probe.Vectors = unkeyedVecs
								for _, v := range unkeyedVecs {
									signals = append(signals, cachePoisoningQuerySignalFor(origin, name, v))
								}
							} else {
								probe.Note = "canary reflected in probe response but absent from the clean follow-up (the cache key includes the parameter)"
							}
						}
					}
				}
			}
			d.QueryProbes = append(d.QueryProbes, probe)
		}
	}

	// 4. Web cache deception differential: a dynamic HTML baseline is requested
	// through a unique static-looking path suffix and then requested again at
	// that exact unique URL. A cache HIT for the repeated request, with the
	// dynamic document still intact and the response explicitly cacheable,
	// proves the cache stored generated content under a static URL.
	if !d.Throttled && reqMethod == http.MethodGet && !cpHasStaticSuffix(ep.URL) && cpBaselineIsDocument(baseResp) {
		observedAt := time.Now()
		for i, suffix := range cpDeceptionSuffixes {
			if i >= maxCacheDeceptionSuffixes {
				break
			}
			if d.Throttled {
				break
			}
			if budget <= 0 {
				d.BudgetExhausted = true
				break
			}
			token := markerToken("wcd")
			buster := markerToken("wcdb")
			deceptionURL, ok := cpDeceptionURL(ep.URL, token, suffix)
			if !ok {
				continue
			}
			deceptionURL = cpCacheBusted(deceptionURL, buster)
			budget--
			probeReq := httpengine.NewRequest(http.MethodGet, deceptionURL)
			probeReq.NoRedirects = true
			probeResp, probeOutcome, probeErr := e.cpDo(ctx, probeReq)
			probe := cachePoisoningDeceptionProbe{Suffix: suffix, URL: deceptionURL}
			switch {
			case probeOutcome != domain.OutcomeSuccess:
				probe.Note = "probe request did not complete: " + errorText(probeErr, probeOutcome)
			case isThrottleStatus(probeResp.Status):
				probe.Status = probeResp.Status
				probe.Note = fmt.Sprintf("the target answered HTTP %d, so this probe was not judged", probeResp.Status)
				d.Throttled = true
				e.persist(ctx, tc, "cache deception "+suffix+" probe", probeResp)
			default:
				completed++
				probe.Status = probeResp.Status
				e.persist(ctx, tc, "cache deception "+suffix+" probe", probeResp)
				obs := cpCacheObservationOf(probeResp.Headers, observedAt)
				probe.Cacheable, probe.CacheState = obs.Cacheable, obs.State
				bodyMatched := cpBodySimilarity(
					cpNormalizeBody(baseResp.Body, baseToken),
					cpNormalizeBody(probeResp.Body, token, buster),
				) >= 0.9
				probe.BodyMatched = bodyMatched
				switch {
				case !bodyMatched:
					probe.Note = "the static-suffixed URL did not return the dynamic document, so no cache-deception check was made"
				case !obs.Cacheable:
					probe.Note = "the dynamic document was returned but the response is not explicitly cacheable"
				case obs.Hit:
					probe.Note = "the first request to this unique URL was already a cache HIT, so the stored entry cannot be attributed to this probe"
				case budget <= 0:
					d.BudgetExhausted = true
					probe.Note = "the response was cacheable but the per-origin request budget was exhausted before the confirmation request"
				default:
					budget--
					confirmReq := httpengine.NewRequest(http.MethodGet, deceptionURL)
					confirmReq.NoRedirects = true
					confirmResp, confirmOutcome, confirmErr := e.cpDo(ctx, confirmReq)
					switch {
					case confirmOutcome != domain.OutcomeSuccess:
						probe.Note = "confirmation request did not complete: " + errorText(confirmErr, confirmOutcome)
					case isThrottleStatus(confirmResp.Status):
						probe.ConfirmStatus = confirmResp.Status
						probe.Note = fmt.Sprintf("the target answered HTTP %d on the confirmation request", confirmResp.Status)
						d.Throttled = true
						e.persist(ctx, tc, "cache deception "+suffix+" confirm", confirmResp)
					default:
						completed++
						probe.ConfirmStatus = confirmResp.Status
						e.persist(ctx, tc, "cache deception "+suffix+" confirm", confirmResp)
						confirmObs := cpCacheObservationOf(confirmResp.Headers, observedAt)
						probe.CacheHit = confirmObs.Hit
						if confirmObs.State != "" {
							probe.CacheState = confirmObs.State
						}
						confirmMatched := cpBodySimilarity(
							cpNormalizeBody(baseResp.Body, baseToken),
							cpNormalizeBody(confirmResp.Body, token, buster),
						) >= 0.9
						switch {
						case !confirmObs.Hit:
							probe.Note = "the repeat request to the same unique URL was not reported as a cache HIT"
						case !confirmMatched:
							probe.Note = "the cached response no longer matched the dynamic document"
						default:
							signals = append(signals, cachePoisoningDeceptionSignalFor(origin, suffix))
						}
					}
				}
			}
			d.DeceptionProbes = append(d.DeceptionProbes, probe)
		}
	}

	d.Signals = signals
	tc.DurationMS = time.Since(started).Milliseconds()
	note := "cache poisoning: no unkeyed header or query parameter and no cache-deception condition was observed on this origin"
	switch {
	case len(signals) > 0:
		d.Verdict = domain.VerdictConfirmed
		d.Severity, d.Confidence = cpSignalStrength(signals)
		d.Reason = cachePoisoningSummary(signals)
		note = "cache poisoning: " + d.Reason
		e.correlate(ctx, job, ep, tc, d)
	case d.Throttled:
		d.Verdict = domain.VerdictInconclusive
		d.Reason = "the target throttled a request, so the origin was not judged"
		note = "cache poisoning check inconclusive: target throttled a request"
	case d.BudgetExhausted:
		d.Verdict = domain.VerdictInconclusive
		d.Reason = "the per-origin request budget was exhausted before every check completed, so the origin was not fully judged"
		note = "cache poisoning check inconclusive: request budget exhausted"
	case completed == 0:
		d.Verdict = domain.VerdictInconclusive
		d.Reason = "no probe request completed, so the origin was not judged"
		note = "cache poisoning check inconclusive: no probe request completed"
	}
	e.finish(ctx, tc, d, domain.TestCaseCompleted, note)
	return nil
}

// cpSkip enforces the read-only method boundary and the scan's write/download
// guards. A HEAD endpoint is allowed: the pass sends the endpoint's own safe
// method and never a state-changing one.
func (e *cachePoisoningExecutor) cpSkip(ep *domain.Endpoint) (string, bool) {
	if ep.Method != "" && ep.Method != domain.MethodGET && ep.Method != domain.MethodHEAD {
		return fmt.Sprintf("%s is not GET or HEAD; cache checks only send read-only GET/HEAD", ep.Method), true
	}
	if e.cfg.SkipWriteEndpoints && isWriteLikeEndpoint(ep, nil) {
		return "write-like endpoint " + endpointLabel(ep.URL) + " is disabled by skip_write_endpoints", true
	}
	if e.cfg.SkipDownloadEndpoints && isDownloadLikeEndpoint(ep) {
		return "export/download endpoint " + endpointLabel(ep.URL) + " is disabled by skip_download_endpoints", true
	}
	return "", false
}

func (e *cachePoisoningExecutor) cpDo(ctx context.Context, req *httpengine.Request) (*httpengine.Response, domain.TestOutcome, error) {
	if err := ctx.Err(); err != nil {
		return nil, domain.OutcomeCancelled, err
	}
	timed := *req
	timed.Timeout = e.cfg.RequestTimeout
	resp, err := e.engine.Do(ctx, &timed)
	switch {
	case err == nil:
		return resp, domain.OutcomeSuccess, nil
	case ctx.Err() != nil:
		return nil, domain.OutcomeCancelled, ctx.Err()
	case isTimeout(err):
		return nil, domain.OutcomeTimeout, err
	default:
		return nil, domain.OutcomeError, err
	}
}

func (e *cachePoisoningExecutor) persist(ctx context.Context, tc *domain.TestCase, label string, resp *httpengine.Response) {
	if e.evidence == nil || resp == nil {
		return
	}
	var ids []domain.ID
	if resp.Request != nil {
		captured := *resp.Request
		captured.Headers = resp.Request.Headers.Clone()
		note := "test_case=" + string(tc.ID) + " cache_poisoning " + label + " request"
		if redactRequestCookieValues(captured.Headers) {
			note += " (cookie values redacted)"
		}
		if id, err := putEvidenceBlob(ctx, e.store, e.evidence, tc.ScanID, domain.EvidenceRequest, ".http", "message/http",
			dumpRequest(&captured), note); err == nil {
			ids = append(ids, id)
		} else {
			e.log.Warn("cache poisoning: persist request evidence", "test_case", tc.ID, "err", err)
		}
	}
	recorded := *resp
	recorded.Headers = resp.Headers.Clone()
	note := "test_case=" + string(tc.ID) + " cache_poisoning " + label + " response"
	if redactSetCookieValues(recorded.Headers) {
		note += " (cookie values redacted)"
	}
	if id, err := putEvidenceBlob(ctx, e.store, e.evidence, tc.ScanID, domain.EvidenceResponse, ".http", "message/http",
		dumpResponse(&recorded), note); err == nil {
		ids = append(ids, id)
	} else {
		e.log.Warn("cache poisoning: persist response evidence", "test_case", tc.ID, "err", err)
	}
	tc.EvidenceIDs = appendUniqueIDs(tc.EvidenceIDs, ids)
}

func (e *cachePoisoningExecutor) finish(ctx context.Context, tc *domain.TestCase, d *cachePoisoningDetail, status domain.TestCaseStatus, note string) {
	now := time.Now()
	tc.FinishedAt, tc.UpdatedAt = &now, now
	tc.Status = status
	tc.Note = truncate(note, 1024)
	if status == domain.TestCaseSkipped {
		tc.Outcome = ""
	} else if d.Verdict == domain.VerdictInconclusive {
		tc.Outcome = domain.OutcomeError
	} else {
		tc.Outcome = domain.OutcomeSuccess
	}
	d.TestCaseIDs = appendUniqueIDs(d.TestCaseIDs, []domain.ID{tc.ID})
	d.EvidenceIDs = appendUniqueIDs(d.EvidenceIDs, tc.EvidenceIDs)
	tc.Detail, _ = json.Marshal(d)
	if err := e.store.TestCases().Update(ctx, tc); err != nil {
		e.log.Warn("cache poisoning: persist test case", "test_case", tc.ID, "err", err)
	}
}

func (e *cachePoisoningExecutor) correlate(ctx context.Context, job *domain.TestJob, ep *domain.Endpoint, tc *domain.TestCase, d *cachePoisoningDetail) {
	e.findingsMu.Lock()
	defer e.findingsMu.Unlock()

	sc, err := e.store.Scans().Get(ctx, job.ScanID)
	if err != nil {
		e.log.Warn("cache poisoning: load scan for finding", "scan", job.ScanID, "err", err)
		return
	}
	existing, err := e.store.Findings().ListByScan(ctx, job.ScanID)
	if err != nil {
		e.log.Warn("cache poisoning: list findings", "scan", job.ScanID, "err", err)
		return
	}
	now := time.Now()
	d.TestCaseIDs = appendUniqueIDs(d.TestCaseIDs, []domain.ID{tc.ID})
	d.EvidenceIDs = appendUniqueIDs(d.EvidenceIDs, tc.EvidenceIDs)

	var current *domain.Finding
	for _, f := range existing {
		if f.VulnClass != domain.VulnCachePoisoning {
			continue
		}
		var fd cachePoisoningDetail
		if err := json.Unmarshal(f.Detail, &fd); err != nil || fd.DedupKey == "" {
			continue
		}
		if fd.DedupKey == d.DedupKey {
			current = f
			break
		}
	}

	title := "Web cache poisoning: " + originHostLabel(d.Origin) + " caches unkeyed request headers"
	findingDetail := *d
	if findingDetail.Occurrences == 0 {
		findingDetail.Occurrences = 1
	}
	detail, _ := json.Marshal(&findingDetail)

	if current != nil {
		var fd cachePoisoningDetail
		if err := json.Unmarshal(current.Detail, &fd); err == nil {
			if fd.Occurrences == 0 {
				fd.Occurrences = 1
			}
			fd.Occurrences++
			fd.Reason = d.Reason
			fd.Probes = d.Probes
			fd.QueryProbes, fd.DeceptionProbes = d.QueryProbes, d.DeceptionProbes
			fd.Signals = cpMergeSignals(fd.Signals, d.Signals)
			fd.Severity, fd.Confidence = d.Severity, d.Confidence
			fd.TestCaseIDs = appendUniqueIDs(fd.TestCaseIDs, []domain.ID{tc.ID})
			fd.EvidenceIDs = appendUniqueIDs(fd.EvidenceIDs, tc.EvidenceIDs)
			if b, err := json.Marshal(fd); err == nil {
				current.Detail = b
			}
		}
		current.EvidenceIDs = appendUniqueIDs(current.EvidenceIDs, tc.EvidenceIDs)
		current.Title, current.Summary = title, d.Reason
		current.Severity, current.Confidence = d.Severity, d.Confidence
		current.UpdatedAt = now
		if err := e.store.Findings().Update(ctx, current); err != nil {
			e.log.Warn("cache poisoning: update finding", "scan", job.ScanID, "err", err)
		}
		return
	}

	f := &domain.Finding{
		ID: domain.NewID(), ScanID: job.ScanID, ProjectID: sc.ProjectID, VulnClass: domain.VulnCachePoisoning,
		Verdict: domain.VerdictConfirmed, Severity: d.Severity, Confidence: d.Confidence,
		Title: title, Summary: d.Reason, EndpointID: ep.ID,
		EvidenceIDs: appendUniqueIDs(nil, tc.EvidenceIDs),
		Provenance:  domain.Provenance{Engine: cpEngine, DiscoverySource: ep.Source, DetectedAt: now, VerifiedAt: &now},
		Detail:      detail, CreatedAt: now, UpdatedAt: now,
	}
	if err := e.store.Findings().Create(ctx, f); err != nil {
		e.log.Warn("cache poisoning: create finding", "scan", job.ScanID, "err", err)
	}
}

// ---------------------------------------------------------------------------
// bounded enqueue
// ---------------------------------------------------------------------------

// enqueueCachePoisoningProbes queues ONE JobCachePoisoning per unique origin,
// capped at maxCachePoisoningOrigins. Only read-only GET/HEAD endpoints are
// considered.
func (c *Controller) enqueueCachePoisoningProbes(ctx context.Context, scanID domain.ID) {
	sc, err := c.store.Scans().Get(ctx, scanID)
	if err != nil || sc.Config.SkipCachePoisoning {
		return
	}
	endpoints, err := c.store.Endpoints().ListByScan(ctx, scanID)
	if err != nil {
		return
	}
	now := time.Now()
	seen := make(map[string]struct{}, len(endpoints))
	queued := 0
	for _, ep := range endpoints {
		if queued >= maxCachePoisoningOrigins {
			break
		}
		if ep == nil || strings.TrimSpace(ep.URL) == "" {
			continue
		}
		if ep.Method != "" && ep.Method != domain.MethodGET && ep.Method != domain.MethodHEAD {
			continue
		}
		if sc.Config.SkipDownloadEndpoints && isDownloadLikeEndpoint(ep) {
			continue
		}
		if sc.Config.SkipWriteEndpoints && isWriteLikeEndpoint(ep, nil) {
			continue
		}
		origin := cachePoisoningOrigin(ep.URL)
		if origin == "" {
			continue
		}
		if _, ok := seen[origin]; ok {
			continue
		}
		seen[origin] = struct{}{}
		job := &domain.TestJob{
			ID:          domain.NewID(),
			ScanID:      scanID,
			Type:        domain.JobCachePoisoning,
			State:       domain.JobQueued,
			Priority:    cachePoisoningPriority,
			Target:      domain.JobTarget{EndpointID: ep.ID, URL: ep.URL},
			MaxAttempts: 2,
			AvailableAt: now,
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		if err := c.queue.Enqueue(ctx, job); err != nil {
			c.log.Warn("cache poisoning: enqueue", "scan", scanID, "err", err)
			continue
		}
		queued++
	}
	if queued > 0 {
		c.log.Info("cache poisoning probes: enqueued", "scan", scanID, "jobs", queued)
	}
}
