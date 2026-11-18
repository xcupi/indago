package discovery

// Bounded, read-only harvesting of the API paths an SPA declares in its own
// JavaScript bundles.
//
// The gap this fills: a crAPI-style application ships a thin HTML shell and
// puts its screens and API calls inside external bundles. Browser network
// capture only reports the calls the screens actually made, so a path such as
// "/workshop/api/mechanic/..." that is bound to a button, a role, or a route
// the crawl never opened is invisible — even though the bundle names it. The
// crawler's literal scan does read bundle paths, but only as bare GET targets,
// and it never relates a relative "api/..." literal to the service prefix the
// application actually serves it under.
//
// What is harvested:
//
//   - absolute API paths a bundle names: "/api/...", "/v1/...", "/v2/...",
//     "/graphql", and service-prefixed forms such as "/workshop/api/...";
//   - relative "api/..." literals, combined with the same-origin service
//     prefixes the browser itself observed ("/workshop/", "/identity/",
//     "/community/") and with the root "/". The prefix is evidence, not a
//     guess: when the browser has already called "/identity/api/v2/...", a
//     bundle literal "api/v2/user" means "/identity/api/v2/user".
//   - when a view's own API call was never observed, the service prefixes a
//     bundle declares itself (a quoted "workshop/" base, an absolute
//     "/workshop/api/..." path). Those are weaker evidence, so they are only
//     tried after every observed prefix and the probe still has to confirm
//     the derived path; the combined prefix set is bounded (maxServicePrefixes).
//
// Safety boundaries:
//
//   - Only read-only GET and OPTIONS are ever sent. A 405 answer (or an Allow
//     header naming POST/PUT/PATCH) registers the endpoint with that method
//     PASSIVELY — no state-changing request is sent during discovery. The
//     executor's own state-changing opt-ins remain the only path to sending it.
//   - Every candidate is scope-checked and fetch-guard-checked before its probe
//     is sent, and the sink deduplicates registration. A path the scan already
//     knows is not probed again.
//   - Probes are capped per rendered seed (maxBundleAPIProbes), candidate paths
//     are capped (maxBundleAPIPaths), and a path with an unresolved placeholder
//     ("<id>", "{id}", "${id}", "?id=null") is skipped: probing a template
//     would only ask the server about a route it does not have.

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/httpengine"
)

const (
	// maxBundleAPIPaths bounds how many API-shaped literals one rendered seed
	// may harvest, across all its bundles.
	maxBundleAPIPaths = 96
	// maxBundleAPIProbes bounds the GET/OPTIONS requests one rendered seed
	// spends on bundle-derived paths. Discovery must stay conservative; this
	// is the same order of magnitude as the route-render budget.
	maxBundleAPIProbes = 40
	// maxBundleAPIPathLen rejects minified blobs and embedded data.
	maxBundleAPIPathLen = 400
	// maxBundleAPIMatchScan bounds the regex scan of one bundle: RE2 itself is
	// linear, but a bundle can hold thousands of quoted strings and only the
	// first few thousand are worth examining.
	maxBundleAPIMatchScan = 4096
	// maxServicePrefixes bounds how many service prefixes one page may
	// contribute, whether the browser observed them, a bundle declared them,
	// or both: every prefix multiplies the relative "api/..." probe set.
	maxServicePrefixes = 8
	// maxServicePrefixLen bounds a derived prefix ("/workshop/") so a deep path
	// cannot become a prefix.
	maxServicePrefixLen = 64
)

// bundleAPILiteral is one API path a bundle names. A relative literal needs a
// service prefix before it can be requested.
type bundleAPILiteral struct {
	path     string // as written: "/api/v2/user" or "api/v2/user"
	relative bool
}

var (
	// bundleAPIAbsoluteLitRE matches a quoted root-relative path. The shape is
	// deliberately syntax-blind, exactly like ExtractScriptEndpointLiterals:
	// minified bundles defeat a parser, a path literal does not need one.
	bundleAPIAbsoluteLitRE = regexp.MustCompile(`["'](/[A-Za-z0-9._~!$&()*+,;=:@%/?-]{3,399})["']`)
	// bundleAPIRelativeLitRE matches a quoted literal that starts at "api/".
	// A path that merely contains "api/" somewhere is ambiguous (an asset
	// folder, a docs page), so this is the narrow, defensible shape.
	bundleAPIRelativeLitRE = regexp.MustCompile(`["'](api/[A-Za-z0-9._~!$&()*+,;=:@%/?-]{1,396})["']`)
	// apiVersionSegmentRE is a leading API version segment ("v1", "v2", "v3").
	apiVersionSegmentRE = regexp.MustCompile(`^v[0-9]{1,3}$`)
	// servicePrefixRE keeps a prefix derived from an observed URL path
	// path-shaped: ASCII, no markup, no spaces.
	servicePrefixRE = regexp.MustCompile(`^/[A-Za-z0-9._~!$&()*+,;=:@%/-]+$`)
	// bundleServiceLitRE matches a quoted single-segment literal ending in a
	// slash ("workshop/", 'identity/') — the shape a bundle writes when it
	// keeps a per-service base URL. It is only consulted for a bundle that
	// also carries a relative "api/..." literal.
	bundleServiceLitRE = regexp.MustCompile(`[\"']([a-z][a-z0-9_-]{1,20})/[\"']`)
	// bundleServiceAbsPrefixRE matches an absolute service-prefixed API path,
	// where the service segment sits directly in front of "/api/"
	// ("/workshop/api/...").
	bundleServiceAbsPrefixRE = regexp.MustCompile(`[\"']/([a-z][a-z0-9_-]{1,20})/api/`)
)

// bundleServiceSegmentReserved lists first segments that name build output,
// asset folders or the API surface itself rather than a service. Probing them
// would buy nothing and blur the "this prefix is a service" claim.
var bundleServiceSegmentReserved = map[string]struct{}{
	"api": {}, "apis": {}, "graphql": {}, "static": {}, "assets": {}, "asset": {},
	"public": {}, "dist": {}, "build": {}, "src": {}, "node_modules": {},
	"img": {}, "image": {}, "images": {}, "fonts": {}, "css": {}, "js": {}, "scripts": {},
}

// extractBundleAPIPaths returns the API-shaped path literals one JavaScript
// bundle names, in source order and deduplicated. Absolute and relative
// literals are returned separately (bundleAPILiteral.relative) because a
// relative one is only meaningful once combined with an observed service
// prefix.
//
// This is discovery input, not evidence: a literal may be a dead path, a
// third-party path, or a string that only looks like one. The collector still
// normalizes, scope-checks and deduplicates every candidate, and a probe is
// required before anything is registered.
func extractBundleAPIPaths(js string) []bundleAPILiteral {
	if js == "" {
		return nil
	}
	out := make([]bundleAPILiteral, 0, 8)
	seen := make(map[string]struct{}, 8)
	add := func(lit bundleAPILiteral) {
		if len(out) >= maxBundleAPIPaths {
			return
		}
		if _, dup := seen[lit.path]; dup {
			return
		}
		seen[lit.path] = struct{}{}
		out = append(out, lit)
	}
	for _, m := range bundleAPIAbsoluteLitRE.FindAllStringSubmatch(js, maxBundleAPIMatchScan) {
		p := m[1]
		if !usableBundleAPIPath(p) || !isAPIShapedPath(p) {
			continue
		}
		add(bundleAPILiteral{path: p})
	}
	for _, m := range bundleAPIRelativeLitRE.FindAllStringSubmatch(js, maxBundleAPIMatchScan) {
		p := m[1]
		if !usableBundleAPIPath(p) {
			continue
		}
		add(bundleAPILiteral{path: p, relative: true})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// usableBundleAPIPath rejects values that cannot be a concrete application
// path: markup, escapes, templates, placeholders, static assets, and call
// punctuation a syntax-blind scan mistakes for a path.
func usableBundleAPIPath(p string) bool {
	if len(p) < 4 || len(p) > maxBundleAPIPathLen {
		return false
	}
	if strings.HasPrefix(p, "//") {
		return false // protocol-relative: leaves the origin
	}
	if strings.ContainsAny(p, "\\`'\" \t\r\n") {
		return false
	}
	if hasUnresolvedBundlePlaceholder(p) {
		return false
	}
	pathPart := p
	if i := strings.IndexAny(pathPart, "?#"); i >= 0 {
		pathPart = pathPart[:i]
	}
	if pathPart == "" || pathPart == "/" {
		return false
	}
	if _, at := pathViolation(pathPart); at >= 0 {
		return false
	}
	if pathPunctuationArtifact(p) {
		return false
	}
	return !IsStaticAssetPath(pathPart)
}

// hasUnresolvedBundlePlaceholder reports whether a literal still contains a
// runtime placeholder. A template is not a route: "/api/v2/user/<id>" and
// "api/v2/user/${id}" describe a shape, and the concrete URL is only worth
// requesting after it has been hydrated from a real observed id (which the
// placeholder-hydration path does for network-observed URLs). A query value
// that is a bare placeholder token ("null") is the same case.
func hasUnresolvedBundlePlaceholder(p string) bool {
	if strings.ContainsAny(p, "<>{}") {
		return true
	}
	if i := strings.IndexByte(p, '?'); i >= 0 {
		if u, err := url.Parse(p); err == nil {
			for _, values := range u.Query() {
				for _, v := range values {
					if isPlaceholderToken(v) {
						return true
					}
				}
			}
		}
	}
	return false
}

// isAPIShapedPath reports whether a root-relative path names an API surface:
// it has an "api" or "graphql" segment anywhere ("/api/...",
// "/workshop/api/...", "/graphql"), or its first segment is an API version
// ("/v1/...", "/v2/...").
func isAPIShapedPath(p string) bool {
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") {
		return false
	}
	pathPart := p
	if i := strings.IndexAny(pathPart, "?#"); i >= 0 {
		pathPart = pathPart[:i]
	}
	for i, seg := range strings.Split(strings.Trim(pathPart, "/"), "/") {
		s := strings.ToLower(seg)
		if s == "api" || s == "graphql" {
			return true
		}
		if i == 0 && apiVersionSegmentRE.MatchString(s) {
			return true
		}
	}
	return false
}

// observedServicePrefixes derives the same-origin service prefixes the browser
// actually called from its network log: a URL whose path contains "/api/"
// names the service in front of that segment. "/workshop/api/mechanic" yields
// "/workshop/"; a root-mounted "/api/v2/user" yields "/". Prefixes are returned
// in observation order, deduplicated and bounded.
func observedServicePrefixes(network []browser.NetworkEvent, base string) []string {
	seen := make(map[string]struct{}, 4)
	out := make([]string, 0, 4)
	add := func(prefix string) {
		if prefix == "" {
			prefix = "/"
		}
		if !strings.HasSuffix(prefix, "/") {
			prefix += "/"
		}
		if len(prefix) > maxServicePrefixLen {
			return
		}
		if prefix != "/" && !servicePrefixRE.MatchString(prefix) {
			return
		}
		if _, dup := seen[prefix]; dup {
			return
		}
		if len(out) >= maxServicePrefixes {
			return
		}
		seen[prefix] = struct{}{}
		out = append(out, prefix)
	}
	for _, ev := range network {
		info, err := Normalize(ev.URL)
		if err != nil || !sameOrigin(info.Canonical, base) {
			continue
		}
		idx := strings.Index(strings.ToLower(info.Path), "/api/")
		if idx < 0 {
			continue
		}
		add(info.Path[:idx])
	}
	return out
}

// bundleServicePrefixes reads the service prefixes a bundle declares itself.
// It only answers for a bundle that also carries a relative "api/..." literal:
// without one there is nothing to prefix. Two shapes are evidence of a service
// base: an absolute service-prefixed API path ("/workshop/api/shop/products")
// and a quoted single-segment literal ending in a slash ("identity/",
// 'community/') — the shape a per-service base URL takes in code.
//
// This is weaker evidence than observedServicePrefixes: a quoted "workshop/"
// could be a folder or a translation key. The caller therefore keeps observed
// prefixes first, and every derived path still has to be confirmed by a probe
// before it is registered.
func bundleServicePrefixes(bodies []string) []string {
	out := make([]string, 0, maxServicePrefixes)
	seen := make(map[string]struct{}, maxServicePrefixes)
	add := func(segment string) {
		if len(out) >= maxServicePrefixes {
			return
		}
		segment = strings.ToLower(strings.TrimSpace(segment))
		if !usableBundleServiceSegment(segment) {
			return
		}
		prefix := "/" + segment + "/"
		if _, dup := seen[prefix]; dup {
			return
		}
		seen[prefix] = struct{}{}
		out = append(out, prefix)
	}
	for _, body := range bodies {
		if !bundleAPIRelativeLitRE.MatchString(body) {
			continue // no relative API literal: a prefix has nothing to carry
		}
		// A full service path is the stronger shape, so it is read first.
		for _, m := range bundleServiceAbsPrefixRE.FindAllStringSubmatch(body, maxBundleAPIMatchScan) {
			add(m[1])
		}
		for _, m := range bundleServiceLitRE.FindAllStringSubmatch(body, maxBundleAPIMatchScan) {
			add(m[1])
		}
		if len(out) >= maxServicePrefixes {
			break
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// usableBundleServiceSegment rejects a candidate service segment that cannot be
// a service name: reserved build/asset words, an API version, or anything the
// quoting scan may have mistaken for a path.
func usableBundleServiceSegment(segment string) bool {
	if len(segment) < 2 || len(segment) > 21 {
		return false
	}
	if apiVersionSegmentRE.MatchString(segment) {
		return false
	}
	_, reserved := bundleServiceSegmentReserved[segment]
	return !reserved
}

// mergeServicePrefixes puts the browser-observed prefixes first — they are
// evidence, the application really served those paths — and appends the
// bundle-declared ones, deduplicated and bounded. Observed-first is what keeps
// a bundle-only guess from displacing a prefix the page proved.
func mergeServicePrefixes(observed, declared []string) []string {
	out := make([]string, 0, len(observed)+len(declared))
	seen := make(map[string]struct{}, cap(out))
	for _, group := range [][]string{observed, declared} {
		for _, prefix := range group {
			if prefix == "" {
				continue
			}
			if _, dup := seen[prefix]; dup {
				continue
			}
			if len(out) >= maxServicePrefixes {
				return out
			}
			seen[prefix] = struct{}{}
			out = append(out, prefix)
		}
	}
	return out
}

// bundleAPIProbeCandidates expands harvested literals into concrete
// root-relative paths to probe. Absolute literals are already complete.
// Relative "api/..." literals are combined with each service prefix first
// (observed prefixes before bundle-declared ones, the evidence-backed reading)
// and with the root last (the fallback).
func bundleAPIProbeCandidates(literals []bundleAPILiteral, prefixes []string) []string {
	out := make([]string, 0, len(literals)*(len(prefixes)+1))
	seen := make(map[string]struct{}, cap(out))
	add := func(p string) {
		if len(out) >= maxBundleAPIPaths {
			return
		}
		if _, dup := seen[p]; dup {
			return
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	for _, lit := range literals {
		if !lit.relative {
			add(lit.path)
		}
	}
	for _, lit := range literals {
		if !lit.relative {
			continue
		}
		for _, prefix := range prefixes {
			add(prefix + lit.path)
		}
		add("/" + lit.path)
	}
	return out
}

// allowedBundleMethod reads the methods an Allow header names and returns the
// first one this scanner may register for a body-carrying endpoint: POST, PUT
// or PATCH. DELETE is deliberately not inferred, and an empty result means the
// header named none of them.
func allowedBundleMethod(resp *httpengine.Response) domain.HTTPMethod {
	if resp == nil || resp.Headers == nil {
		return ""
	}
	allowed := make(map[string]struct{}, 8)
	for _, field := range []string{"Allow", "Access-Control-Allow-Methods"} {
		for _, part := range strings.Split(resp.Headers.Get(field), ",") {
			if m := strings.ToUpper(strings.TrimSpace(part)); m != "" {
				allowed[m] = struct{}{}
			}
		}
	}
	for _, m := range []domain.HTTPMethod{domain.MethodPOST, domain.MethodPUT, domain.MethodPATCH} {
		if _, ok := allowed[string(m)]; ok {
			return m
		}
	}
	return ""
}

// bundleProbeConfirms reports whether a GET response proves the path exists.
// 401/403 is proof on its own (the server recognized the route and refused).
// A 2xx counts unless it is the origin's wildcard answer or a full HTML
// document — a SPA fallback serves its shell with 200 for every unknown path,
// which would otherwise turn every bundle literal into an endpoint.
func bundleProbeConfirms(resp *httpengine.Response, cal *calibration) bool {
	if resp == nil {
		return false
	}
	switch {
	case resp.Status == http.StatusUnauthorized || resp.Status == http.StatusForbidden:
		return true
	case resp.Status >= 200 && resp.Status < 300:
		if cal.explains(resp) {
			return false
		}
		return !looksLikeHTMLDocument(resp)
	default:
		return false
	}
}

// looksLikeHTMLDocument reports whether a response is a rendered page rather
// than an API answer. Only the head of the body is inspected; the point is to
// recognize the shell a SPA fallback returns, not to classify every response.
func looksLikeHTMLDocument(resp *httpengine.Response) bool {
	if resp == nil || len(resp.Body) == 0 || resp.Headers == nil {
		return false
	}
	if !strings.Contains(strings.ToLower(resp.Headers.Get("Content-Type")), "html") {
		return false
	}
	head := resp.Body
	if len(head) > 512 {
		head = head[:512]
	}
	body := strings.ToLower(strings.TrimSpace(string(head)))
	return strings.HasPrefix(body, "<!doctype html") || strings.HasPrefix(body, "<html")
}

// harvestScriptAPIs probes the API paths the application's own bundles name,
// so a screen the crawl never opened still contributes its endpoints.
//
// It spends at most maxBundleAPIProbes read-only requests, uses only the
// already-fetched bundle bodies (inspectScriptBundles), and registers an
// endpoint only after the server answered for it (2xx/401/403), or after a 405
// proved the path exists and named the method it accepts. Nothing is ever sent
// with that inferred method here.
func (n *networkSource) harvestScriptAPIs(ctx context.Context, in Input, sink Sink, base string, network []browser.NetworkEvent, bundles []string) error {
	if n.engine == nil || len(bundles) == 0 {
		return nil
	}
	var literals []bundleAPILiteral
	for _, body := range bundles {
		literals = append(literals, extractBundleAPIPaths(body)...)
		if len(literals) >= maxBundleAPIPaths {
			literals = literals[:maxBundleAPIPaths]
			break
		}
	}
	if len(literals) == 0 {
		return nil
	}
	candidates := bundleAPIProbeCandidates(literals, mergeServicePrefixes(
		observedServicePrefixes(network, base),
		bundleServicePrefixes(bundles),
	))
	if len(candidates) == 0 {
		return nil
	}
	baseInfo, err := Normalize(base)
	if err != nil {
		return nil
	}
	origin := baseInfo.Scheme + "://" + baseInfo.HostPort

	probes := 0
	doProbe := func(method, rawURL string) (*httpengine.Response, bool) {
		if probes >= maxBundleAPIProbes {
			return nil, false
		}
		probes++
		if err := in.wait(ctx); err != nil {
			return nil, false
		}
		resp, err := n.engine.Do(ctx, &httpengine.Request{Method: method, URL: rawURL})
		if err != nil || resp == nil {
			return nil, false
		}
		return resp, true
	}
	doGET := func(rawURL string) (*httpengine.Response, bool) { return doProbe(http.MethodGet, rawURL) }

	// One deterministic absent-path request per origin gives the soft-404
	// baseline. Without it (the request failed) bundleProbeConfirms still
	// refuses an HTML shell, so a wildcard cannot flood the queue.
	var cal *calibration
	if resp, ok := doGET(origin + "/" + calibrationPath(origin, 0)); ok {
		cal = &calibration{samples: []pageSignature{signatureOf(resp)}}
	}

	for _, raw := range candidates {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if probes >= maxBundleAPIProbes {
			break
		}
		info, err := NormalizeRef(base, raw)
		if err != nil || !in.Scope.Permits(info.Canonical).Allowed {
			continue
		}
		if info.Path == "" || IsStaticAssetPath(info.Path) {
			continue
		}
		// The fetch guard applies before the probe is sent: a GET that would
		// end the session or change data must not be requested at all.
		if !allowFetch(sink, info.Canonical, domain.SourceScriptLiteral, domain.MethodGET) {
			continue
		}
		if knowsEndpoint(sink, func(u string) bool {
			other, err := Normalize(u)
			return err == nil && other.Canonical == info.Canonical
		}) {
			continue // already known: do not spend a request asking again
		}

		resp, ok := doGET(info.Canonical)
		if !ok {
			continue
		}
		method := domain.MethodGET
		switch {
		case resp.Status == http.StatusMethodNotAllowed:
			// GET is refused but the route exists. Ask what it allows with a
			// read-only OPTIONS; if that fails too, infer POST (an API path
			// that will not answer a GET is a write endpoint). Either way the
			// inferred method is only REGISTERED — never sent here.
			method = allowedBundleMethod(resp)
			if method == "" {
				if opt, ok := doProbe(http.MethodOptions, info.Canonical); ok {
					method = allowedBundleMethod(opt)
				}
			}
			if method == "" {
				method = domain.MethodPOST
			}
		case bundleProbeConfirms(resp, cal):
			method = domain.MethodGET
		default:
			continue
		}
		if !allowFetch(sink, info.Canonical, domain.SourceScriptLiteral, method) {
			continue
		}
		if _, err := sink.AddEndpoint(ctx, EndpointCandidate{
			URL:    info.Canonical,
			Method: method,
			Source: domain.SourceScriptLiteral,
		}); err != nil {
			if errors.Is(err, ErrLimitReached) {
				return nil
			}
			return err
		}
	}
	return nil
}
