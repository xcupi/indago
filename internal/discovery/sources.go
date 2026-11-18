package discovery

import (
	"context"
	"encoding/xml"
	"errors"
	"mime"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/httpengine"
)

// NewRealRegistry builds a registry of the real discovery sources. The browser
// may be nil (then network discovery is omitted).
func NewRealRegistry(engine httpengine.Engine, b browser.Browser, cfg Config) *Registry {
	r := NewRegistry()
	r.Register(NewSeedSource())
	r.Register(NewCrawlSource(engine, cfg))
	r.Register(NewSitemapSource(engine, cfg))
	r.Register(NewRobotsSource(engine, cfg))
	r.Register(NewContentSource(engine, cfg))
	r.Register(NewWellKnownSource(engine, cfg))
	r.Register(NewArchiveSource(cfg))
	if b != nil {
		r.Register(NewNetworkSourceWithEngine(b, engine, cfg))
	}
	return r
}

// ---------------------------------------------------------------------------
// seed
// ---------------------------------------------------------------------------

type seedSource struct{}

// NewSeedSource registers the operator-provided seed URLs as endpoints.
func NewSeedSource() Source { return seedSource{} }

func (seedSource) Name() domain.DiscoverySource { return domain.SourceUserProvided }

func (seedSource) Run(ctx context.Context, in Input, sink Sink) error {
	for _, u := range in.SeedURLs {
		if err := in.wait(ctx); err != nil {
			return err
		}
		if _, err := sink.AddEndpoint(ctx, EndpointCandidate{URL: u, Method: domain.MethodGET, Source: domain.SourceUserProvided}); err != nil {
			if errors.Is(err, ErrLimitReached) {
				return nil
			}
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// crawler (link + form + parameter extraction)
// ---------------------------------------------------------------------------

type crawlSource struct {
	engine httpengine.Engine
	cfg    Config
	conc   *liveConcurrency // crawl fetch concurrency; adjustable while running
	// scripts counts JavaScript assets fetched for literal mining across one
	// crawl (see harvestScriptEndpoints). It is a per-run budget, not a
	// per-level one: a site that references the same bundle on every page must
	// not multiply the fetches.
	scripts atomic.Int64
	// scriptSeen deduplicates those fetches by URL, so a bundle referenced
	// from every page is read once.
	scriptSeen *sync.Map
}

// NewCrawlSource crawls from the seeds, extracting links, forms, and parameters
// up to the configured depth and limits.
func NewCrawlSource(engine httpengine.Engine, cfg Config) Source {
	cfg = cfg.withDefaults()
	return &crawlSource{engine: engine, cfg: cfg, conc: newLiveConcurrency(cfg.Concurrency), scriptSeen: &sync.Map{}}
}

func (c *crawlSource) Name() domain.DiscoverySource { return domain.SourceCrawler }

// SetConcurrency implements ConcurrencyAdjustable. crawlLevel reads c.conc
// fresh for each depth level's semaphore, so this takes effect starting at
// the next level — it does not resize an already-running level's semaphore
// (that channel is already sized and in flight), which is an acceptable,
// bounded delay for a value that changes rarely.
func (c *crawlSource) SetConcurrency(n int) { c.conc.Set(n) }

var _ ConcurrencyAdjustable = (*crawlSource)(nil)

func (c *crawlSource) Run(ctx context.Context, in Input, sink Sink) error {
	var visited sync.Map
	var pages atomic.Int64
	c.scripts.Store(0)

	// Seed the first level with in-scope, normalized seed URLs.
	var level []string
	for _, s := range in.SeedURLs {
		info, err := Normalize(s)
		if err != nil {
			continue
		}
		if in.Scope.Permits(info.Canonical).Allowed {
			level = append(level, info.Canonical)
		}
	}

	for depth := 0; depth <= c.cfg.MaxDepth && len(level) > 0; depth++ {
		next, err := c.crawlLevel(ctx, in, sink, level, &visited, &pages)
		if err != nil {
			if errors.Is(err, ErrLimitReached) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return ctxOrNil(ctx, err)
			}
			return err
		}
		level = next
	}
	return nil
}

func (c *crawlSource) crawlLevel(ctx context.Context, in Input, sink Sink, urls []string, visited *sync.Map, pages *atomic.Int64) ([]string, error) {
	var (
		mu       sync.Mutex
		nextSet  = make(map[string]struct{})
		next     []string
		firstErr error
	)
	setErr := func(err error) {
		mu.Lock()
		if firstErr == nil {
			firstErr = err
		}
		mu.Unlock()
	}

	sem := make(chan struct{}, c.conc.Get())
	var wg sync.WaitGroup

	for _, u := range urls {
		if ctx.Err() != nil {
			break
		}
		if int(pages.Load()) >= c.cfg.MaxPages {
			break
		}
		if _, loaded := visited.LoadOrStore(u, true); loaded {
			continue
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(u string) {
			defer wg.Done()
			defer func() { <-sem }()

			if err := in.wait(ctx); err != nil {
				setErr(err)
				return
			}
			if pages.Add(1) > int64(c.cfg.MaxPages) {
				return
			}
			links, err := c.fetchPage(ctx, in, sink, u)
			if err != nil {
				setErr(err)
				return
			}
			mu.Lock()
			for _, l := range links {
				if _, ok := nextSet[l]; !ok {
					nextSet[l] = struct{}{}
					next = append(next, l)
				}
			}
			mu.Unlock()
		}(u)
	}
	wg.Wait()
	return next, firstErr
}

// fetchPage fetches a page, emits its endpoint/forms/params, and returns the
// in-scope link targets for the next crawl level.
func (c *crawlSource) fetchPage(ctx context.Context, in Input, sink Sink, pageURL string) ([]string, error) {
	resp, err := c.engine.Do(ctx, &httpengine.Request{Method: "GET", URL: pageURL})
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, nil // skip a page that failed to fetch
	}

	ct := resp.Headers.Get("Content-Type")
	if _, err := sink.AddEndpoint(ctx, EndpointCandidate{URL: pageURL, Method: domain.MethodGET, Source: domain.SourceCrawler, ContentType: ct}); err != nil {
		return nil, err
	}
	// A seed such as https://example.com/ commonly redirects to
	// https://www.example.com/. Resolve relative links and register the final
	// page too; otherwise the crawler can discover only the redirect source
	// and never see the real site's navigation.
	baseURL := pageURL
	if resp.FinalURL != "" && resp.FinalURL != pageURL {
		if final, err := Normalize(resp.FinalURL); err == nil && in.Scope.Permits(final.Canonical).Allowed {
			if _, err := sink.AddEndpoint(ctx, EndpointCandidate{URL: final.Canonical, Method: domain.MethodGET, Source: domain.SourceCrawler, ContentType: ct}); err != nil {
				return nil, err
			}
			baseURL = final.Canonical
		}
	}
	c.applyParamWordlist(ctx, sink, baseURL)

	if !strings.Contains(strings.ToLower(ct), "html") {
		return nil, nil // only parse HTML
	}
	body := string(resp.Body)
	for _, name := range ExtractScriptParamNames(body) {
		_ = sink.AddParameter(ctx, ParamCandidate{EndpointURL: baseURL, EndpointMethod: domain.MethodGET,
			Name: name, Location: domain.LocationQuery, Source: domain.SourceScriptLiteral})
	}

	// Forms. ExtractForms promotes handler-derived submit targets to POST,
	// so their inputs follow the same body-parameter path as declared POST forms.
	for _, f := range ExtractForms(body) {
		actionInfo, err := NormalizeRef(baseURL, f.Action)
		if err != nil || !in.Scope.Permits(actionInfo.Canonical).Allowed {
			continue
		}
		if _, err := sink.AddEndpoint(ctx, EndpointCandidate{URL: actionInfo.Canonical, Method: f.Method, Source: domain.SourceForm}); err != nil {
			return nil, err
		}
		loc := domain.LocationQuery
		if f.Method == domain.MethodPOST {
			loc = domain.LocationForm
		}
		for _, field := range f.Inputs {
			if err := sink.AddParameter(ctx, ParamCandidate{
				EndpointURL:    actionInfo.Canonical,
				EndpointMethod: f.Method,
				Name:           field.Name,
				Location:       loc,
				Example:        field.Value,
				Source:         domain.SourceForm,
				FormGroup:      f.Group,
			}); err != nil {
				return nil, err
			}
		}
	}

	// Links → endpoints + next level.
	var nextLinks []string
	for _, ref := range ExtractLinks(body) {
		info, err := NormalizeRef(baseURL, ref)
		if err != nil || !in.Scope.Permits(info.Canonical).Allowed {
			continue
		}
		// Ask before queueing: a link queued for the next level is requested
		// by fetchPage before the sink ever sees it, so a registration refusal
		// alone would still send the request.
		if !allowFetch(sink, info.Canonical, domain.SourceCrawler, domain.MethodGET) {
			continue
		}
		// A referenced stylesheet, image, font or media file has no reflection
		// surface of its own: it is never registered as a test target and never
		// queued for the next crawl level. JavaScript is the exception — a
		// bundle names the endpoints the application calls — so a bounded
		// number of script assets are fetched for their literals instead of
		// being tested themselves.
		if IsStaticAssetPath(info.Path) {
			if IsScriptAssetPath(info.Path) {
				c.harvestScriptEndpoints(ctx, in, sink, info)
			}
			continue
		}
		id, err := sink.AddEndpoint(ctx, EndpointCandidate{URL: info.Canonical, Method: domain.MethodGET, Source: domain.SourceCrawler})
		if err != nil {
			return nil, err
		}
		if id == "" {
			continue // refused by the sink (out of scope, malformed): never follow it
		}
		nextLinks = append(nextLinks, info.Canonical)
	}
	return nextLinks, nil
}

// maxScriptAssetFetches bounds how many JavaScript assets one crawl fetches to
// mine endpoint literals. A modern site ships several bundles per page; a
// dozen is enough to cover the application's own code without turning the
// crawler into a downloader for every vendor chunk and source map.
const maxScriptAssetFetches = 12

// harvestScriptEndpoints reads one JavaScript asset and registers the
// application paths its string literals name. The asset itself is never
// registered: it is a static file with no injection surface, which is exactly
// what the queue filter drops. Its *contents* are still discovery input, so a
// crawl that sees /static/app.js learns about /api/invoices even when no page
// links there.
//
// Bounded and fail-soft: a per-crawl fetch budget, a per-asset literal cap
// (ExtractScriptEndpointLiterals), scope checks on every resolved path, and no
// error is ever returned — losing a harvest costs candidates, not the crawl.
func (c *crawlSource) harvestScriptEndpoints(ctx context.Context, in Input, sink Sink, script URLInfo) {
	if c.cfg.MaxDepth <= 0 {
		return // seeds-only scans do not fetch extra resources
	}
	if _, loaded := c.scriptSeen.LoadOrStore(script.Canonical, struct{}{}); loaded {
		return // already read in this crawl
	}
	if c.scripts.Add(1) > maxScriptAssetFetches {
		return
	}
	if err := in.wait(ctx); err != nil {
		return
	}
	resp, err := c.engine.Do(ctx, &httpengine.Request{Method: "GET", URL: script.Canonical})
	if err != nil || resp == nil || len(resp.Body) == 0 {
		return
	}
	for _, literal := range ExtractScriptEndpointLiterals(string(resp.Body)) {
		ref, err := NormalizeRef(script.Canonical, literal)
		if err != nil || !in.Scope.Permits(ref.Canonical).Allowed {
			continue
		}
		if IsStaticAssetPath(ref.Path) {
			continue
		}
		if !allowFetch(sink, ref.Canonical, domain.SourceCrawler, domain.MethodGET) {
			continue
		}
		// SourceScriptLiteral already means "a literal in the site's own
		// script", which is the honest provenance for these endpoints too.
		if _, err := sink.AddEndpoint(ctx, EndpointCandidate{
			URL: ref.Canonical, Method: domain.MethodGET, Source: domain.SourceScriptLiteral,
		}); err != nil {
			return
		}
	}
}

func (c *crawlSource) applyParamWordlist(ctx context.Context, sink Sink, endpointURL string) {
	// Legacy path only: an operator-supplied ParamWordlist is registered on
	// pages the crawler already fetched, with no extra requests. At standard
	// and above, parameter mining (recon.go) replaces this with a real
	// differential, so blindly registering the same names here would only add
	// injection points nothing established as live.
	if c.cfg.ReconLevel.UsesParams() {
		return
	}
	for _, name := range c.cfg.ParamWordlist {
		_ = sink.AddParameter(ctx, ParamCandidate{
			EndpointURL:    endpointURL,
			EndpointMethod: domain.MethodGET,
			Name:           name,
			Location:       domain.LocationQuery,
			Source:         domain.SourceParamDiscovery,
		})
	}
}

// ---------------------------------------------------------------------------
// sitemap.xml
// ---------------------------------------------------------------------------

type sitemapSource struct {
	engine httpengine.Engine
	cfg    Config
}

// NewSitemapSource fetches and parses /sitemap.xml for each seed origin.
func NewSitemapSource(engine httpengine.Engine, cfg Config) Source {
	return &sitemapSource{engine: engine, cfg: cfg.withDefaults()}
}

func (s *sitemapSource) Name() domain.DiscoverySource { return domain.SourceSitemap }

type sitemapLoc struct {
	Loc string `xml:"loc"`
}

type sitemapDoc struct {
	URLs     []sitemapLoc `xml:"url"`
	Sitemaps []sitemapLoc `xml:"sitemap"`
}

func (s *sitemapSource) Run(ctx context.Context, in Input, sink Sink) error {
	for _, origin := range uniqueOrigins(in.SeedURLs) {
		if err := s.process(ctx, in, sink, origin+"/sitemap.xml", 0); err != nil {
			if errors.Is(err, ErrLimitReached) {
				return nil
			}
			return err
		}
	}
	return nil
}

func (s *sitemapSource) process(ctx context.Context, in Input, sink Sink, sitemapURL string, depth int) error {
	if depth > 3 { // bound sitemap-index recursion
		return nil
	}
	if depth > 0 {
		// A nested sitemap URL comes from document content, so it is untrusted:
		// it must be in scope and must not be a session-terminating endpoint
		// before it is requested. The top-level /sitemap.xml is built from the
		// operator's seed origin.
		info, err := Normalize(sitemapURL)
		if err != nil || !in.Scope.Permits(info.Canonical).Allowed || !allowFetch(sink, info.Canonical, domain.SourceSitemap, domain.MethodGET) {
			return nil
		}
		sitemapURL = info.Canonical
	}
	if err := in.wait(ctx); err != nil {
		return err
	}
	resp, err := s.engine.Do(ctx, &httpengine.Request{Method: "GET", URL: sitemapURL})
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return nil
	}
	var doc sitemapDoc
	if err := xml.Unmarshal(resp.Body, &doc); err != nil {
		return nil // not a sitemap; skip
	}
	for _, u := range doc.URLs {
		if u.Loc == "" {
			continue
		}
		if _, err := sink.AddEndpoint(ctx, EndpointCandidate{URL: u.Loc, Method: domain.MethodGET, Source: domain.SourceSitemap}); err != nil {
			return err
		}
	}
	for _, sm := range doc.Sitemaps {
		if sm.Loc == "" {
			continue
		}
		if err := s.process(ctx, in, sink, sm.Loc, depth+1); err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// robots.txt
// ---------------------------------------------------------------------------

type robotsSource struct {
	engine httpengine.Engine
	cfg    Config
}

// NewRobotsSource fetches /robots.txt and emits the paths and sitemap URLs it
// references as candidate endpoints. (Robots is used for discovery only; it is
// not used to evade or to restrict authorized testing.)
func NewRobotsSource(engine httpengine.Engine, cfg Config) Source {
	return &robotsSource{engine: engine, cfg: cfg.withDefaults()}
}

func (r *robotsSource) Name() domain.DiscoverySource { return domain.SourceRobots }

func (r *robotsSource) Run(ctx context.Context, in Input, sink Sink) error {
	for _, origin := range uniqueOrigins(in.SeedURLs) {
		if err := in.wait(ctx); err != nil {
			return err
		}
		resp, err := r.engine.Do(ctx, &httpengine.Request{Method: "GET", URL: origin + "/robots.txt"})
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			continue
		}
		for _, raw := range strings.Split(string(resp.Body), "\n") {
			line := strings.TrimSpace(raw)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			key, val, ok := splitDirective(line)
			if !ok {
				continue
			}
			switch strings.ToLower(key) {
			case "disallow", "allow":
				p := cleanRobotsPath(val)
				if p == "" {
					continue
				}
				if _, err := sink.AddEndpoint(ctx, EndpointCandidate{URL: origin + p, Method: domain.MethodGET, Source: domain.SourceRobots}); err != nil {
					if errors.Is(err, ErrLimitReached) {
						return nil
					}
					return err
				}
			case "sitemap":
				if _, err := sink.AddEndpoint(ctx, EndpointCandidate{URL: strings.TrimSpace(val), Method: domain.MethodGET, Source: domain.SourceRobots}); err != nil {
					if errors.Is(err, ErrLimitReached) {
						return nil
					}
					return err
				}
			}
		}
	}
	return nil
}

func splitDirective(line string) (key, val string, ok bool) {
	i := strings.IndexByte(line, ':')
	if i < 0 {
		return "", "", false
	}
	return strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+1:]), true
}

// cleanRobotsPath strips wildcard/anchor characters and ensures a leading slash.
func cleanRobotsPath(p string) string {
	p = strings.TrimSpace(p)
	if idx := strings.IndexAny(p, "*$"); idx >= 0 {
		p = p[:idx]
	}
	p = strings.TrimSpace(p)
	if p == "" || p == "/" {
		return ""
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
}

// ---------------------------------------------------------------------------
// browser network observation (XHR/fetch)
// ---------------------------------------------------------------------------

type networkSource struct {
	browser browser.Browser
	cfg     Config
	// engine is optional. When present, route-menu JSON responses are fetched
	// through the scan's scoped, authenticated HTTP engine instead of being
	// re-rendered in the browser. Tests and browser-only registries can leave
	// it nil.
	engine httpengine.Engine
}

// NewNetworkSource loads each seed in a real browser and emits the network
// requests it observes (including XHR/fetch) as endpoints.
func NewNetworkSource(b browser.Browser, cfg Config) Source {
	return &networkSource{browser: b, cfg: cfg.withDefaults()}
}

// NewNetworkSourceWithEngine is NewNetworkSource plus the scoped HTTP engine
// used to read small route-menu JSON responses. It keeps the constructor
// backward-compatible for tests that only provide a browser.
func NewNetworkSourceWithEngine(b browser.Browser, engine httpengine.Engine, cfg Config) Source {
	return &networkSource{browser: b, cfg: cfg.withDefaults(), engine: engine}
}

func (n *networkSource) Name() domain.DiscoverySource { return domain.SourceBrowserNetwork }

func (n *networkSource) Run(ctx context.Context, in Input, sink Sink) error {
	if n.browser == nil {
		return nil
	}
	seenHTML := make(map[string]struct{})
	for _, s := range in.SeedURLs {
		info, err := Normalize(s)
		if err != nil || !in.Scope.Permits(info.Canonical).Allowed {
			continue
		}
		if err := in.wait(ctx); err != nil {
			return err
		}
		// Two layers: the browser aborts out-of-scope requests before they are sent
		// (so no third-party traffic is generated), and every observation is
		// re-checked below before it reaches the sink.
		res, err := n.browser.Render(ctx, info.Canonical, browser.RenderOptions{
			Limiter:           n.cfg.Limiter,
			WaitUntil:         browser.WaitLoad,
			ObservationWindow: 750 * time.Millisecond,
			AllowRequest:      func(u string) bool { return in.Scope.Permits(u).Allowed },
			SessionStatePath:  in.SessionStatePath,
			UserAgent:         n.cfg.HuntingUserAgent,
		})
		if err != nil {
			if errors.Is(err, browser.ErrNotImplemented) {
				return nil // stub browser: nothing to do
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			continue
		}
		if err := n.emitNetworkWithHTML(ctx, in, sink, res.Network, seenHTML); err != nil {
			if errors.Is(err, ErrLimitReached) {
				return nil
			}
			return err
		}
		if err := n.emitForms(ctx, in, sink, info.Canonical, res.HTML); err != nil {
			if errors.Is(err, ErrLimitReached) {
				return nil
			}
			return err
		}
		// extractSPARoutes and harvestRouteAPIs return bare route fragments
		// ("/search?q=test"); marking them keeps renderSPARoutes from reading a
		// leading slash as a path-based route.
		hashRoutes := append(extractSPARoutes(res.HTML), n.harvestRouteAPIs(ctx, in, sink, info.Canonical, res.Network)...)
		routes := hashRouteEntries(hashRoutes)
		routes = append(routes, n.harvestScriptRoutes(ctx, in, sink, info.Canonical, res.HTML, res.Network)...)
		if err := n.renderSPARoutes(ctx, in, sink, info.Canonical, routes, seenHTML); err != nil {
			if errors.Is(err, ErrLimitReached) {
				return nil
			}
			return err
		}
	}
	return nil
}

const maxNetworkHTMLFormFetches = 128

// emitNetwork turns browser observations into endpoints and JSON body
// parameters. It is shared by the initial seed render and each SPA route render.
func (n *networkSource) emitNetwork(ctx context.Context, in Input, sink Sink, network []browser.NetworkEvent) error {
	return n.emitNetworkWithHTML(ctx, in, sink, network, nil)
}

func (n *networkSource) emitNetworkWithHTML(ctx context.Context, in Input, sink Sink, network []browser.NetworkEvent, seenHTML map[string]struct{}) error {
	for _, ev := range network {
		if !in.Scope.Permits(ev.URL).Allowed {
			continue // never persist or enqueue an out-of-scope observation
		}
		if isAutomaticFaviconRequest(ev.URL) {
			continue // browsers request favicon.ico automatically; it is not a useful XSS input surface
		}
		// A browser loads every stylesheet, font and image the page references.
		// None of them is a test target (see IsStaticAssetPath); skipping them
		// here keeps the sink from even considering the noise. JavaScript is
		// not exempt from the filter either — the crawler mines literals from
		// script assets, the browser network only sees the request.
		info, normErr := Normalize(ev.URL)
		if normErr == nil && IsStaticAssetPath(info.Path) {
			continue
		}
		method := domain.HTTPMethod(strings.ToUpper(ev.Method))
		if !method.IsValid() {
			method = domain.MethodGET
		}
		body := ""
		if isXMLContentType(ev.ContentType) {
			body = ev.PostData
		}
		if _, err := sink.AddEndpoint(ctx, EndpointCandidate{URL: ev.URL, Method: method, Source: domain.SourceBrowserNetwork, ContentType: ev.ContentType, RequestBody: body}); err != nil {
			return err
		}
		if method == domain.MethodGET && seenHTML != nil && n.engine != nil && normErr == nil && len(seenHTML) < maxNetworkHTMLFormFetches {
			if _, ok := seenHTML[info.Canonical]; !ok && allowFetch(sink, info.Canonical, domain.SourceBrowserNetwork, domain.MethodGET) {
				seenHTML[info.Canonical] = struct{}{}
				if err := in.wait(ctx); err != nil {
					return err
				}
				resp, err := n.engine.Do(ctx, httpengine.GET(info.Canonical))
				if err == nil && resp != nil && len(resp.Body) > 0 && strings.Contains(strings.ToLower(resp.Headers.Get("Content-Type")), "html") {
					if err := n.emitForms(ctx, in, sink, info.Canonical, string(resp.Body)); err != nil {
						return err
					}
				}
			}
		}
		if ev.PostData == "" || !isJSONContentType(ev.ContentType) {
			continue
		}
		for _, field := range ExtractJSONBodyParams(ev.PostData) {
			if err := in.wait(ctx); err != nil {
				return err
			}
			if err := sink.AddParameter(ctx, ParamCandidate{
				EndpointURL: ev.URL, EndpointMethod: method,
				Name: field.Name, Location: domain.LocationJSON,
				Example: field.RawValue, Source: domain.SourceBrowserNetwork,
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

// maxSPARouteRenders bounds routes rendered after the seed page. A route can
// trigger an unbounded application navigation graph; this is deliberately a
// bounded budget rather than a second crawler. WebGoat's menu alone has 45
// lessons; 64 leaves room for one menu plus nearby routes without unbounded
// navigation.
const maxSPARouteRenders = 64

// hashRouteEntries marks bare hash-route fragments ("/search?q=test",
// "lesson/x") so renderSPARoutes can tell them apart from a path-based route
// ("/dashboard"), which is navigated to without a '#'.
func hashRouteEntries(routes []string) []string {
	out := make([]string, 0, len(routes))
	for _, route := range routes {
		route = strings.TrimSpace(route)
		if route == "" {
			continue
		}
		if strings.HasPrefix(route, "#") {
			out = append(out, route)
			continue
		}
		out = append(out, "#"+route)
	}
	return out
}

// spaRouteURL resolves one renderSPARoutes entry into the URL to render.
//
//   - "#/basket" or "lesson/x": a hash route, rendered as base + "#" + route in
//     the seed document. Fragments are client-side state, never their own URL.
//   - "/dashboard": a path-based same-origin route (BrowserRouter style),
//     resolved against the base origin with NO fragment — the view exists only
//     at its own URL, so the browser has to navigate there for the router to
//     mount it and issue the view's own API calls.
//   - "https://host/profile" on the base origin: the same, spelled absolutely.
//
// Anything else (off-origin absolute URLs, protocol-relative "//host/x",
// malformed paths) is refused. The caller's scope check would reject it too,
// but refusing here keeps the renderer honest about what it sends.
func spaRouteURL(base, route string) (string, bool) {
	base = strings.SplitN(base, "#", 2)[0]
	route = strings.TrimSpace(route)
	if route == "" || len(route) > 512 {
		return "", false
	}
	if strings.HasPrefix(route, "#") {
		frag := strings.TrimPrefix(route, "#")
		if frag == "" || strings.HasPrefix(frag, "//") {
			return "", false
		}
		return base + "#" + frag, true
	}
	if strings.HasPrefix(route, "http://") || strings.HasPrefix(route, "https://") {
		info, err := Normalize(route)
		if err != nil || !sameOrigin(info.Canonical, base) {
			return "", false
		}
		return info.Canonical, true
	}
	if strings.HasPrefix(route, "/") {
		if strings.HasPrefix(route, "//") {
			return "", false // protocol-relative: leaves the origin
		}
		info, err := NormalizeRef(base, route)
		if err != nil || !sameOrigin(info.Canonical, base) {
			return "", false
		}
		return info.Canonical, true
	}
	// Application-style hash route without a leading '#': "lesson/name".
	return base + "#" + route, true
}

// sameOrigin reports whether rawURL and base share scheme and host[:port].
func sameOrigin(rawURL, base string) bool {
	a, err := Normalize(rawURL)
	if err != nil {
		return false
	}
	b, err := Normalize(base)
	if err != nil {
		return false
	}
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.HostPort, b.HostPort)
}

// spaHashRoute returns a route-like hash fragment from a raw href/script
// reference. Plain anchors (#section), CSS colors (#fff) and fragments without
// a path separator are not routes. Both #/path and application-style
// #lesson/name routes are accepted; the route is never sent over HTTP, only
// rendered in the browser context.
func spaHashRoute(ref string) string {
	s := strings.TrimSpace(ref)
	if !strings.HasPrefix(s, "#") {
		return ""
	}
	frag := s[1:]
	if frag == "" || len(frag) > 512 || strings.HasPrefix(frag, "//") {
		return ""
	}
	if strings.ContainsAny(frag, " \t\r\n\"'<>") {
		return ""
	}
	if !strings.HasPrefix(frag, "/") && !strings.Contains(frag, "/") {
		return ""
	}
	return frag
}

var hashRouteLiteralRe = regexp.MustCompile(`(?:#[A-Za-z0-9_][A-Za-z0-9_./?=&%+-]*|#/[A-Za-z0-9_][A-Za-z0-9_./?=&%+-]*)`)

func extractSPARoutes(body string) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, 8)
	add := func(raw string) {
		route := spaHashRoute(raw)
		if route == "" {
			return
		}
		if _, ok := seen[route]; ok {
			return
		}
		seen[route] = struct{}{}
		out = append(out, route)
	}
	for _, ref := range ExtractLinks(body) {
		add(ref)
	}
	for _, raw := range hashRouteLiteralRe.FindAllString(body, -1) {
		add(raw)
	}
	return out
}

// maxSPARouteAPIProbes bounds the JSON endpoints inspected for route links.
// The lesson-menu shape is common in SPA frameworks, but an arbitrary JSON API
// can be large and expensive to probe; the cap keeps discovery bounded while
// covering a menu and its neighboring bootstrap endpoints.
const maxSPARouteAPIProbes = 16

// harvestRouteAPIs renders a small number of observed dynamic GET endpoints in
// the authenticated browser context and extracts route-like hash links from
// their response. A lesson menu, for example, may expose #lesson/... links only
// through an API response, never in the initial HTML. Request events do not
// reliably carry the response MIME type, so the bounded probe uses path/scope
// filters and the rendered body rather than guessing from the request headers.
func routeAPIProbeScore(rawURL string) int {
	info, err := Normalize(rawURL)
	if err != nil {
		return 0
	}
	p := strings.ToLower(info.Path)
	score := 1
	for _, hint := range []string{"menu", "navigation", "nav", "route", "lesson", "sitemap"} {
		if strings.Contains(p, hint) {
			score += 4
		}
	}
	if strings.Contains(p, "service") || strings.Contains(p, "api") {
		score += 2
	}
	return score
}

func (n *networkSource) harvestRouteAPIs(ctx context.Context, in Input, sink Sink, base string, network []browser.NetworkEvent) []string {
	var out []string
	seen := make(map[string]struct{})
	candidates := make([]browser.NetworkEvent, 0, len(network))
	for _, ev := range network {
		if !strings.EqualFold(strings.TrimSpace(ev.Method), "GET") || !in.Scope.Permits(ev.URL).Allowed ||
			!allowFetch(sink, ev.URL, domain.SourceBrowserNetwork, domain.MethodGET) {
			continue
		}
		info, err := Normalize(ev.URL)
		if err != nil || IsStaticAssetPath(info.Path) || strings.EqualFold(info.Canonical, base) {
			continue
		}
		candidates = append(candidates, ev)
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		return routeAPIProbeScore(candidates[i].URL) > routeAPIProbeScore(candidates[j].URL)
	})
	probes := 0
	for _, ev := range candidates {
		if probes >= maxSPARouteAPIProbes {
			break
		}
		if err := in.wait(ctx); err != nil {
			return out
		}
		if n.engine != nil {
			resp, err := n.engine.Do(ctx, httpengine.GET(ev.URL))
			if err == nil && resp != nil && len(resp.Body) > 0 {
				probes++
				for _, route := range extractSPARoutes(string(resp.Body)) {
					if _, ok := seen[route]; ok {
						continue
					}
					seen[route] = struct{}{}
					out = append(out, route)
				}
				continue
			}
		}
		res, err := n.browser.Render(ctx, ev.URL, browser.RenderOptions{
			Limiter:           n.cfg.Limiter,
			WaitUntil:         browser.WaitLoad,
			ObservationWindow: 100 * time.Millisecond,
			AllowRequest:      func(u string) bool { return in.Scope.Permits(u).Allowed },
			SessionStatePath:  in.SessionStatePath,
			UserAgent:         n.cfg.HuntingUserAgent,
		})
		if err != nil {
			continue
		}
		probes++
		for _, route := range extractSPARoutes(res.HTML) {
			if _, ok := seen[route]; ok {
				continue
			}
			seen[route] = struct{}{}
			out = append(out, route)
		}
	}
	return out
}

// maxSPAScriptBundles bounds how many script assets the browser-network source
// reads for router definitions. A page typically ships one application bundle
// plus vendor chunks (skipped below); three covers the application's own code
// without turning discovery into an asset downloader.
const maxSPAScriptBundles = 3

// maxSPAScriptBodyBytes caps how much of one bundle is inspected. A router
// table sits near the top of an application bundle; the 2 MiB window keeps an
// unusually large file from dominating the scan's memory budget.
const maxSPAScriptBodyBytes = 2 << 20

// spaRouterPathRE matches a client-router route definition as React Router,
// Vue Router and Angular all write it: path: 'dashboard'. The captured literal
// is one route segment, never an API path.
var spaRouterPathRE = regexp.MustCompile(`path:\s*["']([a-zA-Z0-9][a-zA-Z0-9_-]{1,40})["']`)

// spaRouteSlugRE is the shape of a router-declared route segment.
var spaRouteSlugRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,40}$`)

// spaRouteHints are the route segments that make a script-derived path worth
// rendering first: the authenticated views whose screens issue their own API
// calls. Rendering them is what lets browser_network observe those calls.
var spaRouteHints = []string{"dashboard", "forum", "orders", "profile", "basket", "search", "contact", "admin"}

// spaAssetPathPrefixes name infrastructure rather than an application view.
// A bundle names both ("/api/invoices", "/static/app.js"); neither is a router
// page, and rendering one only spends a navigation.
var spaAssetPathPrefixes = map[string]struct{}{
	"api": {}, "graphql": {}, "static": {}, "assets": {}, "js": {}, "css": {},
	"img": {}, "images": {}, "fonts": {}, "media": {}, "uploads": {}, "public": {},
}

// spaPathRoute turns a router path literal ("dashboard") or a script-named path
// ("/orders") into a same-origin path route renderSPARoutes can navigate to.
// Empty when the input is not a plausible application view: a static asset, an
// API path, a session-terminating route, or something too deep to be a page.
func spaPathRoute(raw string) string {
	p := strings.TrimSpace(raw)
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	if p == "" || len(p) > 128 || strings.HasPrefix(p, "//") {
		return ""
	}
	if !strings.HasPrefix(p, "/") {
		// A client router declares a segment, not a document-relative
		// reference; anything with a dot or slash is not one.
		if !spaRouteSlugRE.MatchString(p) {
			return ""
		}
		p = "/" + p
	}
	if _, at := pathViolation(p); at >= 0 {
		return ""
	}
	p = path.Clean(p)
	if p == "/" || p == "." || strings.HasPrefix(p, "//") {
		return ""
	}
	if IsStaticAssetPath(p) || looksSessionTerminating(p) {
		return ""
	}
	segments := strings.Split(strings.Trim(p, "/"), "/")
	if len(segments) > 2 {
		return "" // deep paths are API/resource URLs, not router views
	}
	if _, asset := spaAssetPathPrefixes[strings.ToLower(segments[0])]; asset {
		return ""
	}
	return p
}

// spaPathRouteScore ranks a script-derived path route: hinted views first, a
// root-level view above a nested resource, discovery order otherwise. It orders
// candidates only; the render cap still bounds how many are visited.
func spaPathRouteScore(route string) int {
	p := strings.ToLower(strings.Trim(route, "/"))
	score := 0
	for _, hint := range spaRouteHints {
		if strings.Contains(p, hint) {
			score += 10
			break
		}
	}
	if !strings.Contains(p, "/") {
		score++
	}
	return score
}

// extractScriptEndpoints returns the application views a document or bundle
// names as path literals ("/dashboard", "/orders"), best candidates first. It
// is the script-literal scan (ExtractScriptEndpointLiterals) narrowed to paths
// a client router can serve, so a bundle's "/api/v1/users" is not rendered as
// a page.
func extractScriptEndpoints(body string) []string {
	out := make([]string, 0, 8)
	seen := make(map[string]struct{})
	for _, literal := range ExtractScriptEndpointLiterals(body) {
		route := spaPathRoute(literal)
		if route == "" {
			continue
		}
		if _, dup := seen[route]; dup {
			continue
		}
		seen[route] = struct{}{}
		out = append(out, route)
	}
	sort.SliceStable(out, func(i, j int) bool { return spaPathRouteScore(out[i]) > spaPathRouteScore(out[j]) })
	return out
}

// isVendorScriptPath reports whether a script asset is third-party framework
// code rather than the application's own bundle. Router definitions live in the
// latter; a vendor chunk is only worth reading when nothing else was observed.
func isVendorScriptPath(p string) bool {
	lower := strings.ToLower(p)
	for _, marker := range []string{"vendor", "node_modules", "polyfill", "framework"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// spaScriptBundles returns up to maxSPAScriptBundles same-origin, non-vendor
// JavaScript assets the browser observed, in observation order.
func spaScriptBundles(base string, network []browser.NetworkEvent) []string {
	seen := make(map[string]struct{}, len(network))
	out := make([]string, 0, maxSPAScriptBundles)
	for _, ev := range network {
		info, err := Normalize(ev.URL)
		if err != nil || !IsScriptAssetPath(info.Path) || !sameOrigin(info.Canonical, base) {
			continue
		}
		if isVendorScriptPath(info.Path) {
			continue
		}
		if _, dup := seen[info.Canonical]; dup {
			continue
		}
		seen[info.Canonical] = struct{}{}
		out = append(out, info.Canonical)
		if len(out) >= maxSPAScriptBundles {
			break
		}
	}
	return out
}

// looksLikeSPAShell reports whether a document is an SPA mount point rather
// than a complete server-rendered page: the bundle/router fills it after load.
func looksLikeSPAShell(html string) bool {
	lower := strings.ToLower(html)
	for _, marker := range []string{
		`<div id="root"`, `<div id="app"`, `<div id="__next"`, `<div id="__nuxt"`, `<app-root`,
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// spaWantsScriptPathRoutes reports whether script-named paths should become
// rendered views: the seed is an SPA shell, or the route harvest is still well
// below the render budget. A classic server-rendered page yields few routes, so
// the second condition keeps the harvest available there too; the render cap
// still bounds it.
func spaWantsScriptPathRoutes(html string, routes int) bool {
	return routes < maxSPARouteRenders || looksLikeSPAShell(html)
}

// harvestScriptRoutes reads the application's own JavaScript for routes the
// seed HTML does not link. A React/Vue/Angular bundle declares its router as
// path literals ("path: 'dashboard'") and often embeds hash routes; the browser
// network log names the bundles but never their contents.
//
// Up to maxSPAScriptBundles same-origin, non-vendor bundles are fetched through
// the scan's scoped, authenticated engine (never a second identity) and
// inspected, bounded to maxSPAScriptBodyBytes each. The seed document's inline
// script and links are inspected too.
//
// The result is ready for renderSPARoutes: hash entries keep their '#' marker,
// path routes stay "/slug". When the page or its bundle uses hash routing the
// fragments are offered first; a BrowserRouter-style page offers its path
// routes first. Nothing here registers an endpoint or makes a verdict.
func (n *networkSource) harvestScriptRoutes(ctx context.Context, in Input, sink Sink, base, html string, network []browser.NetworkEvent) []string {
	bodies := make([]string, 0, maxSPAScriptBundles+1)
	if n.engine != nil {
		for _, script := range spaScriptBundles(base, network) {
			if !in.Scope.Permits(script).Allowed || !allowFetch(sink, script, domain.SourceBrowserNetwork, domain.MethodGET) {
				continue
			}
			if err := in.wait(ctx); err != nil {
				return nil
			}
			resp, err := n.engine.Do(ctx, httpengine.GET(script))
			if err != nil || resp == nil || resp.Status >= 400 || len(resp.Body) == 0 {
				continue
			}
			body := resp.Body
			if len(body) > maxSPAScriptBodyBytes {
				body = body[:maxSPAScriptBodyBytes]
			}
			bodies = append(bodies, string(body))
		}
	}
	// The shell's own inline script is a router declaration too: many SPA
	// templates inline the route table before any bundle loads.
	bodies = append(bodies, html)

	hashRoutes := make([]string, 0, 8)
	pathRoutes := make([]string, 0, 8)
	seenHash := make(map[string]struct{}, 8)
	seenPath := make(map[string]struct{}, 8)
	addHash := func(route string) {
		route = strings.TrimSpace(route)
		if route == "" {
			return
		}
		if _, dup := seenHash[route]; dup {
			return
		}
		seenHash[route] = struct{}{}
		hashRoutes = append(hashRoutes, route)
	}
	addPath := func(raw string) {
		route := spaPathRoute(raw)
		if route == "" {
			return
		}
		if _, dup := seenPath[route]; dup {
			return
		}
		seenPath[route] = struct{}{}
		pathRoutes = append(pathRoutes, route)
	}
	for _, body := range bodies {
		for _, route := range extractSPARoutes(body) {
			addHash(route)
		}
		for _, m := range spaRouterPathRE.FindAllStringSubmatch(body, -1) {
			addPath(m[1])
		}
	}
	// Links on the shell are views the router owns even when no bundle literal
	// names them ("/dashboard" in the nav).
	for _, ref := range ExtractLinks(html) {
		if strings.HasPrefix(strings.TrimSpace(ref), "/") {
			addPath(ref)
		}
	}
	if spaWantsScriptPathRoutes(html, len(hashRoutes)+len(pathRoutes)) {
		for _, body := range bodies {
			for _, route := range extractScriptEndpoints(body) {
				addPath(route)
			}
		}
	}
	sort.SliceStable(pathRoutes, func(i, j int) bool {
		return spaPathRouteScore(pathRoutes[i]) > spaPathRouteScore(pathRoutes[j])
	})
	out := make([]string, 0, len(hashRoutes)+len(pathRoutes))
	// A page that links "#/" or whose bundle carries hash routes is a
	// hash-routed SPA: its fragments are the reachable screens, so they render
	// first. A BrowserRouter-style app offers its path views first instead.
	if strings.Contains(html, "#/") || len(hashRoutes) > 0 {
		for _, route := range hashRoutes {
			out = append(out, "#"+route)
		}
		return append(out, pathRoutes...)
	}
	out = append(out, pathRoutes...)
	for _, route := range hashRoutes {
		out = append(out, "#"+route)
	}
	return out
}

// renderSPARoutes loads routes found on a rendered page in the same browser
// context and emits the network requests they cause. A route entry is either a
// hash route ("#/basket", "lesson/x"), rendered as a fragment of the seed
// document, or a path-based same-origin route ("/dashboard"), navigated to as
// its own URL so a client router mounts the view. It never changes the HTTP
// crawler's URL set: fragments are client-side state, so ordinary HTTP
// discovery would only request the same document again; a path route is a real
// view the browser has to load to reveal the API calls behind it.
func (n *networkSource) renderSPARoutes(ctx context.Context, in Input, sink Sink, base string, routes []string, seenHTML map[string]struct{}) error {
	if len(routes) == 0 {
		return nil
	}
	base = strings.SplitN(base, "#", 2)[0]
	rendered := 0
	seen := make(map[string]struct{}, len(routes))
	for _, route := range routes {
		if _, ok := seen[route]; ok {
			continue
		}
		seen[route] = struct{}{}
		if rendered >= maxSPARouteRenders {
			break
		}
		routeURL, ok := spaRouteURL(base, route)
		if !ok {
			continue
		}
		if !in.Scope.Permits(routeURL).Allowed || !allowFetch(sink, routeURL, domain.SourceBrowserNetwork, domain.MethodGET) {
			continue
		}
		if err := in.wait(ctx); err != nil {
			return err
		}
		res, err := n.browser.Render(ctx, routeURL, browser.RenderOptions{
			Limiter:           n.cfg.Limiter,
			WaitUntil:         browser.WaitLoad,
			ObservationWindow: 750 * time.Millisecond,
			AllowRequest:      func(u string) bool { return in.Scope.Permits(u).Allowed },
			SessionStatePath:  in.SessionStatePath,
			UserAgent:         n.cfg.HuntingUserAgent,
		})
		if err != nil {
			if errors.Is(err, browser.ErrNotImplemented) {
				return nil
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			continue
		}
		rendered++
		if err := n.emitNetworkWithHTML(ctx, in, sink, res.Network, seenHTML); err != nil {
			return err
		}
		if err := n.emitForms(ctx, in, sink, routeURL, res.HTML); err != nil {
			return err
		}
	}
	return nil
}

// emitForms registers forms present in a browser-rendered document, not just
// forms in the initial HTML. SPA routes often construct their forms after
// JavaScript runs, so the HTTP crawler alone cannot see them. Registration is
// passive: no form is submitted here.
func (n *networkSource) emitForms(ctx context.Context, in Input, sink Sink, base, body string) error {
	for _, form := range ExtractForms(body) {
		action := strings.TrimSpace(form.Action)
		if action == "" {
			action = base
		}
		info, err := NormalizeRef(base, action)
		method := form.Method
		if method == "" {
			method = domain.MethodGET
		}
		// Registration is passive, but the method still decides which guards
		// apply: a destructive-looking GET form action is refused, while a
		// POST target is kept for the executor's state-changing opt-in.
		if err != nil || !in.Scope.Permits(info.Canonical).Allowed ||
			!allowFetch(sink, info.Canonical, domain.SourceBrowserNetwork, method) {
			continue
		}
		if _, err := sink.AddEndpoint(ctx, EndpointCandidate{
			URL: info.Canonical, Method: method, Source: domain.SourceBrowserNetwork,
		}); err != nil {
			return err
		}
		loc := domain.LocationQuery
		if method == domain.MethodPOST {
			loc = domain.LocationForm
		}
		for _, field := range form.Inputs {
			if err := in.wait(ctx); err != nil {
				return err
			}
			if err := sink.AddParameter(ctx, ParamCandidate{
				EndpointURL: info.Canonical, EndpointMethod: method,
				Name: field.Name, Location: loc, Example: field.Value,
				Source: domain.SourceBrowserNetwork, FormGroup: form.Group,
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

func isAutomaticFaviconRequest(raw string) bool {
	info, err := Normalize(raw)
	return err == nil && strings.EqualFold(path.Base(info.Path), "favicon.ico")
}

func isJSONContentType(raw string) bool {
	mediaType, _, err := mime.ParseMediaType(raw)
	if err != nil {
		return false
	}
	mediaType = strings.ToLower(mediaType)
	return mediaType == "application/json" || strings.HasSuffix(mediaType, "+json")
}

func isXMLContentType(raw string) bool {
	mediaType, _, err := mime.ParseMediaType(raw)
	if err != nil {
		return false
	}
	mediaType = strings.ToLower(mediaType)
	return mediaType == "application/xml" || mediaType == "text/xml" || strings.HasSuffix(mediaType, "+xml")
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// uniqueOrigins returns the distinct scheme://host[:port] origins of the seeds.
func uniqueOrigins(seeds []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, s := range seeds {
		info, err := Normalize(s)
		if err != nil {
			continue
		}
		origin := info.Scheme + "://" + info.HostPort
		if _, ok := seen[origin]; !ok {
			seen[origin] = struct{}{}
			out = append(out, origin)
		}
	}
	return out
}

// ctxOrNil returns ctx.Err() if the context is done, else nil. It lets crawl
// treat a limit-reached stop as success while still surfacing cancellation.
func ctxOrNil(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, ErrLimitReached) {
		return nil
	}
	return nil
}
