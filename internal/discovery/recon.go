package discovery

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/httpengine"
)

// Content and parameter discovery, driven by the embedded wordlists
// (wordlists.go) and gated by an opt-in ReconLevel.
//
// Three properties keep it honest:
//
//  1. Nothing happens unless recon was asked for. ReconOff with no explicitly
//     supplied wordlists returns immediately, so an existing scan is
//     byte-identical to one run before this source existed.
//  2. Every request spends from one hard per-scan budget (DefaultMaxReconRequests),
//     claimed before the request leaves. Calibration, path probes, extension
//     probes, parameter mining and recursion all draw from the same counter.
//  3. A probe is only recorded when the site's own wildcard behaviour cannot
//     explain it (soft-404 calibration, soft404.go), and a mined parameter is
//     only recorded when the response actually changed in a way the reflected
//     name/value does not account for.
//
// Requests go through the scan's scope-enforcing engine (see scan.scopedEngine):
// same rate limiter, same host scope, fail-closed redirects. This source only
// ever sends GET.

type contentSource struct {
	engine httpengine.Engine
	cfg    Config
}

// NewContentSource imports bounded wordlist content/parameter discovery.
//
// It probes paths from the configured (or embedded) wordlists under each seed
// origin, calibrated against the site's own soft-404 behaviour, and — at
// standard and above — mines parameter names by differential response
// comparison. Bounded by Config.ReconLevel and Config.MaxReconRequests.
func NewContentSource(engine httpengine.Engine, cfg Config) Source {
	return &contentSource{engine: engine, cfg: cfg.withDefaults()}
}

func (c *contentSource) Name() domain.DiscoverySource { return domain.SourceContentDiscovery }

// foundPath is a wordlist path that survived calibration, carrying what the
// later phases need to know about it.
type foundPath struct {
	url       string
	directory bool // path (or its redirect target) ends in "/"
	fileLike  bool // last segment looks like a file name, so extensions apply
	html      bool
}

func (c *contentSource) Run(ctx context.Context, in Input, sink Sink) error {
	level := c.cfg.ReconLevel

	paths := c.cfg.Wordlist
	if len(paths) == 0 && in.Wordlist != "" {
		loaded, err := loadWordlist(in.Wordlist)
		if err == nil { // a missing wordlist file is not fatal (legacy behaviour)
			paths = loaded
		}
	}
	if len(paths) == 0 && level.Enabled() {
		paths = level.Paths()
	}

	// Built-in parameter names are only used at standard and above; an
	// explicitly supplied ParamWordlist is honoured at any level, but at
	// standard+ it goes through the same real-signal mining as the built-in
	// names instead of being registered blindly.
	paramNames := append([]string(nil), c.cfg.ParamWordlist...)
	if level.UsesParams() {
		paramNames = append(paramNames, builtinParamNames()...)
	}
	mineParams := level.UsesParams() && len(paramNames) > 0
	// At off/safe an explicit ParamWordlist keeps its legacy meaning: the
	// crawler registers the names on pages it already fetched, without extra
	// requests (see crawlSource.applyParamWordlist).

	if len(paths) == 0 && !mineParams {
		// Nothing for this source to send. (An explicit ParamWordlist at
		// off/safe is registered by the crawler on pages it already fetched,
		// with no extra requests.)
		return nil
	}

	budget := newReconBudget(c.cfg.MaxReconRequests)
	pathProv := &ReconProvenance{List: "paths", Level: level}
	extProv := &ReconProvenance{List: "paths:extensions", Level: level}
	recProv := &ReconProvenance{List: "paths:recursive", Level: level}
	paramProv := &ReconProvenance{List: "params", Level: level}

	for _, origin := range uniqueOrigins(in.SeedURLs) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		cal, err := calibrate(ctx, c.engine, in, budget, origin)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			// No baseline means no way to tell a real path from a wildcard.
			// Probing blind would flood the scan with false endpoints, so
			// this origin is skipped entirely.
			continue
		}

		found, err := c.probePaths(ctx, in, sink, origin, paths, cal, budget, pathProv)
		if err != nil {
			if errors.Is(err, ErrLimitReached) {
				return nil
			}
			return err
		}
		if level.UsesExtensions() {
			if err := c.probeExtensions(ctx, in, sink, found, cal, budget, extProv); err != nil {
				if errors.Is(err, ErrLimitReached) {
					return nil
				}
				return err
			}
		}
		if mineParams {
			if err := c.mineParams(ctx, in, sink, origin, found, paramNames, budget, paramProv); err != nil {
				if errors.Is(err, ErrLimitReached) {
					return nil
				}
				return err
			}
		}
		if level.UsesRecursion() {
			if err := c.probeRecursive(ctx, in, sink, directoryURLs(found), cal, budget, recProv); err != nil {
				if errors.Is(err, ErrLimitReached) {
					return nil
				}
				return err
			}
		}
	}
	return nil
}

// probePaths sends the wordlist for one origin and returns the survivors.
func (c *contentSource) probePaths(ctx context.Context, in Input, sink Sink, origin string, words []string,
	cal *calibration, budget *reconBudget, prov *ReconProvenance) ([]foundPath, error) {

	var found []foundPath
	for _, w := range words {
		if ctx.Err() != nil {
			return found, ctx.Err()
		}
		candidate := origin + "/" + strings.TrimPrefix(strings.TrimSpace(w), "/")
		info, err := Normalize(candidate)
		if err != nil || !in.Scope.Permits(info.Canonical).Allowed {
			continue
		}
		if !allowFetch(sink, info.Canonical, domain.SourceContentDiscovery) {
			continue // probing it is itself the request that would end the session
		}
		if !budget.take() {
			return found, nil
		}
		if err := in.wait(ctx); err != nil {
			return found, err
		}
		resp, err := c.engine.Do(ctx, httpengine.GET(info.Canonical))
		if err != nil {
			if ctx.Err() != nil {
				return found, ctx.Err()
			}
			continue
		}
		if !cal.looksFound(resp) {
			continue
		}
		if _, err := sink.AddEndpoint(ctx, EndpointCandidate{
			URL: info.Canonical, Method: domain.MethodGET,
			Source: domain.SourceContentDiscovery, ContentType: responseContentType(resp),
			Provenance: prov,
		}); err != nil {
			return found, err
		}
		found = append(found, foundPath{
			url:       info.Canonical,
			directory: isDirectory(info, resp),
			fileLike:  fileLikePath(info.Path),
			html:      isHTMLResponse(resp),
		})
	}
	return found, nil
}

// probeExtensions appends the extension list to the file-like paths the
// wordlist itself turned up (config.php -> config.php.bak). It is bounded both
// by the number of bases and by the shared request budget.
func (c *contentSource) probeExtensions(ctx context.Context, in Input, sink Sink, found []foundPath,
	cal *calibration, budget *reconBudget, prov *ReconProvenance) error {

	bases := 0
	for _, f := range found {
		if bases >= maxExtensionBases {
			return nil
		}
		if !f.fileLike {
			continue
		}
		bases++
		for _, ext := range builtinExtensions() {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			probeURL := f.url + ext
			info, err := Normalize(probeURL)
			if err != nil || !in.Scope.Permits(info.Canonical).Allowed {
				continue
			}
			if !allowFetch(sink, info.Canonical, domain.SourceContentDiscovery) {
				continue
			}
			if !budget.take() {
				return nil
			}
			if err := in.wait(ctx); err != nil {
				return err
			}
			resp, err := c.engine.Do(ctx, httpengine.GET(info.Canonical))
			if err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				continue
			}
			if !cal.looksFound(resp) {
				continue
			}
			if _, err := sink.AddEndpoint(ctx, EndpointCandidate{
				URL: info.Canonical, Method: domain.MethodGET,
				Source: domain.SourceContentDiscovery, ContentType: responseContentType(resp),
				Provenance: prov,
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

// mineParams looks for parameter names whose presence actually changes the
// response, on a small, deterministic set of endpoints (the seeds first — the
// page an operator pointed at — then wordlist-discovered HTML pages).
func (c *contentSource) mineParams(ctx context.Context, in Input, sink Sink, origin string, found []foundPath,
	names []string, budget *reconBudget, prov *ReconProvenance) error {

	targets := paramMineTargets(origin, in, found)
	for i, target := range targets {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := c.mineEndpoint(ctx, in, sink, target, names, i, budget, prov); err != nil {
			return err
		}
	}
	return nil
}

// mineEndpoint is the differential: baseline the page twice (to prove it is
// stable), then send each candidate name with a unique marker value and keep
// only the names whose response really changed.
func (c *contentSource) mineEndpoint(ctx context.Context, in Input, sink Sink, target string,
	names []string, index int, budget *reconBudget, prov *ReconProvenance) error {

	base, err := c.fetch(ctx, in, target, budget)
	if err != nil || base == nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return nil // a target we cannot baseline is simply not mined
	}
	if base.Status < 200 || base.Status >= 300 {
		// Mining a page that does not render (404/403) produces requests
		// without a meaningful baseline to compare against.
		return nil
	}
	second, err := c.fetch(ctx, in, target, budget)
	if err != nil || second == nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return nil
	}
	if !sameBody(base, second) {
		// CSRF token, rotating nonce, live counter: every probe would look
		// like a change, so this endpoint's mining would be pure noise.
		return nil
	}

	for _, name := range paramNamesForEndpoint(names, index) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		token := paramMarker(name, index)
		probeURL, err := withQueryParam(target, name, token)
		if err != nil {
			continue
		}
		info, err := Normalize(probeURL)
		if err != nil || !in.Scope.Permits(info.Canonical).Allowed {
			continue
		}
		if !allowFetch(sink, info.Canonical, domain.SourceContentDiscovery) {
			continue
		}
		resp, err := c.fetch(ctx, in, info.Canonical, budget)
		if err != nil || resp == nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			continue
		}
		if !parameterChangedResponse(base, resp, name, token) {
			continue
		}
		if err := sink.AddParameter(ctx, ParamCandidate{
			EndpointURL:    target,
			EndpointMethod: domain.MethodGET,
			Name:           name,
			Location:       domain.LocationQuery,
			Example:        token,
			Source:         domain.SourceParamDiscovery,
			Provenance:     prov,
		}); err != nil {
			return err
		}
	}
	return nil
}

// fetch spends one budget unit and performs one GET. A nil response with a nil
// error means the request was skipped (budget exhausted or fetch failed).
func (c *contentSource) fetch(ctx context.Context, in Input, rawURL string, budget *reconBudget) (*httpengine.Response, error) {
	if !budget.take() {
		return nil, nil
	}
	if err := in.wait(ctx); err != nil {
		return nil, err
	}
	return c.engine.Do(ctx, httpengine.GET(rawURL))
}

// probeRecursive probes one level deeper under discovered directories. The
// discovered directory is depth 1; what is tried under it is depth 2, and the
// source never goes to depth 3. Bounded by maxRecursiveDirs,
// maxRecursiveWords and maxRecursionRequests on top of the shared budget.
func (c *contentSource) probeRecursive(ctx context.Context, in Input, sink Sink, dirs []string,
	cal *calibration, budget *reconBudget, prov *ReconProvenance) error {

	if len(dirs) == 0 {
		return nil
	}
	if len(dirs) > maxRecursiveDirs {
		dirs = dirs[:maxRecursiveDirs]
	}
	words := corePaths()
	if len(words) > maxRecursiveWords {
		words = words[:maxRecursiveWords]
	}
	used := 0
	for _, base := range dirs {
		for _, w := range words {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if used >= maxRecursionRequests {
				return nil
			}
			probeURL := base + strings.TrimPrefix(strings.TrimSpace(w), "/")
			info, err := Normalize(probeURL)
			if err != nil || !in.Scope.Permits(info.Canonical).Allowed {
				continue
			}
			if !allowFetch(sink, info.Canonical, domain.SourceContentDiscovery) {
				continue
			}
			if !budget.take() {
				return nil
			}
			used++
			if err := in.wait(ctx); err != nil {
				return err
			}
			resp, err := c.engine.Do(ctx, httpengine.GET(info.Canonical))
			if err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				continue
			}
			if !cal.looksFound(resp) {
				continue
			}
			if _, err := sink.AddEndpoint(ctx, EndpointCandidate{
				URL: info.Canonical, Method: domain.MethodGET,
				Source: domain.SourceContentDiscovery, ContentType: responseContentType(resp),
				Provenance: prov,
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// parameter differential
// ---------------------------------------------------------------------------

// paramMineTargets picks the endpoints parameter mining may spend requests on:
// the seed URL first, then wordlist-discovered HTML endpoints, deduplicated and
// capped at maxParamMineEndpoints. Deterministic order.
func paramMineTargets(origin string, in Input, found []foundPath) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(raw string) {
		if len(out) >= maxParamMineEndpoints {
			return
		}
		info, err := Normalize(raw)
		if err != nil || !in.Scope.Permits(info.Canonical).Allowed {
			return
		}
		if _, dup := seen[info.Canonical]; dup {
			return
		}
		seen[info.Canonical] = struct{}{}
		out = append(out, info.Canonical)
	}
	for _, s := range in.SeedURLs {
		info, err := Normalize(s)
		if err != nil || info.Scheme+"://"+info.HostPort != origin {
			continue
		}
		add(s)
	}
	for _, f := range found {
		if f.html {
			add(f.url)
		}
	}
	return out
}

// parameterChangedResponse reports whether the probe response differs from the
// baseline in a way the reflected parameter name/value cannot explain:
//
//   - a different status;
//   - a different/new Set-Cookie;
//   - a different application header (volatile headers are ignored);
//   - a body-length change larger than paramBodySlack once the echoed probe
//     text has been stripped from the probe body.
func parameterChangedResponse(base, probe *httpengine.Response, name, token string) bool {
	if base == nil || probe == nil {
		return false
	}
	if base.Status != probe.Status {
		return true
	}
	if !equalCookieHeader(base, probe) {
		return true
	}
	if !equalAppHeaders(base, probe) {
		return true
	}
	baseBody := string(base.Body)
	probeBody := stripProbeEcho(string(probe.Body), name, token)
	delta := len(probeBody) - len(baseBody)
	if delta < 0 {
		delta = -delta
	}
	return delta > paramBodySlack
}

// paramBodySlack is the byte slack allowed after stripping the echoed probe
// text. Anything smaller is treated as the same page (whitespace, a repeating
// templated counter, an analytics id).
const paramBodySlack = 32

// stripProbeEcho removes the probe's own text from a response body: the whole
// query pair first, then a bare token (a page that echoes just the value).
func stripProbeEcho(body, name, token string) string {
	if token == "" {
		return body
	}
	body = strings.ReplaceAll(body, "?"+name+"="+token, "")
	body = strings.ReplaceAll(body, "&amp;"+name+"="+token, "")
	body = strings.ReplaceAll(body, "&"+name+"="+token, "")
	body = strings.ReplaceAll(body, name+"="+token, "")
	body = strings.ReplaceAll(body, token, "")
	return body
}

// volatileHeaders never count as a "different response": they change on their
// own between two requests to the same URL.
var volatileHeaders = map[string]bool{
	"date": true, "content-length": true, "connection": true, "keep-alive": true,
	"transfer-encoding": true, "etag": true, "last-modified": true, "expires": true,
	"cache-control": true, "age": true, "vary": true, "via": true, "server": true,
	"x-request-id": true, "x-runtime": true, "x-served-by": true, "x-cache": true,
	"set-cookie": true, "content-security-policy": true, "report-to": true,
}

func equalCookieHeader(a, b *httpengine.Response) bool {
	if a == nil || b == nil {
		return true
	}
	return strings.Join(headerValues(a.Headers, "Set-Cookie"), "\n") ==
		strings.Join(headerValues(b.Headers, "Set-Cookie"), "\n")
}

func equalAppHeaders(a, b *httpengine.Response) bool {
	ha, hb := appHeaders(a), appHeaders(b)
	if len(ha) != len(hb) {
		return false
	}
	for k, va := range ha {
		if vb, ok := hb[k]; !ok || vb != va {
			return false
		}
	}
	return true
}

func appHeaders(resp *httpengine.Response) map[string]string {
	out := make(map[string]string)
	if resp == nil || resp.Headers == nil {
		return out
	}
	for name, values := range resp.Headers {
		lower := strings.ToLower(name)
		if volatileHeaders[lower] {
			continue
		}
		out[lower] = strings.Join(values, "\n")
	}
	return out
}

func headerValues(h http.Header, name string) []string {
	if h == nil {
		return nil
	}
	return h.Values(name)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// paramMarker builds the unique, alphanumeric value sent for one candidate
// name. Deterministic so the request sequence is reproducible from evidence.
func paramMarker(name string, index int) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("indago-param|%s|%d", name, index)))
	return "indago" + hex.EncodeToString(sum[:5])
}

// withQueryParam returns rawURL with name=value set, preserving existing query
// parameters.
func withQueryParam(rawURL, name, value string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set(name, value)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func responseContentType(resp *httpengine.Response) string {
	if resp == nil || resp.Headers == nil {
		return ""
	}
	return resp.Headers.Get("Content-Type")
}

func isHTMLResponse(resp *httpengine.Response) bool {
	if resp == nil {
		return false
	}
	return strings.Contains(strings.ToLower(responseContentType(resp)), "html")
}

// isDirectory reports whether a found path is a directory: it ends in "/", or
// the response's own redirect target (e.g. /admin -> /admin/) does.
func isDirectory(info URLInfo, resp *httpengine.Response) bool {
	if strings.HasSuffix(info.Path, "/") {
		return true
	}
	if resp == nil || resp.FinalURL == "" {
		return false
	}
	final, err := Normalize(resp.FinalURL)
	if err != nil || final.HostPort != info.HostPort {
		return false
	}
	return strings.HasSuffix(final.Path, "/")
}

// fileLikePath reports whether the path's last segment looks like a file name
// ("swagger.json", ".env"), which is what the extension probes apply to.
func fileLikePath(p string) bool {
	p = strings.TrimSuffix(p, "/")
	if p == "" || p == "/" {
		return false
	}
	seg := p[strings.LastIndex(p, "/")+1:]
	return seg != "" && strings.Contains(seg, ".")
}

// directoryURLs returns the distinct directory URLs in discovery order.
func directoryURLs(found []foundPath) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, f := range found {
		if !f.directory {
			continue
		}
		if _, dup := seen[f.url]; dup {
			continue
		}
		seen[f.url] = struct{}{}
		out = append(out, f.url)
	}
	return out
}

func contentExists(status int) bool {
	switch {
	case status >= 200 && status < 400:
		return true
	case status == 401 || status == 403:
		return true
	default:
		return false
	}
}

// loadWordlist reads an operator-supplied wordlist file (one entry per line,
// '#' comments and blank lines ignored). It exists for compatibility with the
// pre-embedding behaviour; built-in recon uses the embedded lists.
func loadWordlist(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out, sc.Err()
}
