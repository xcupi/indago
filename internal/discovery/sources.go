package discovery

import (
	"bufio"
	"context"
	"encoding/xml"
	"errors"
	"os"
	"strings"
	"sync"
	"sync/atomic"

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
	if b != nil {
		r.Register(NewNetworkSource(b, cfg))
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
}

// NewCrawlSource crawls from the seeds, extracting links, forms, and parameters
// up to the configured depth and limits.
func NewCrawlSource(engine httpengine.Engine, cfg Config) Source {
	cfg = cfg.withDefaults()
	return &crawlSource{engine: engine, cfg: cfg, conc: newLiveConcurrency(cfg.Concurrency)}
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
	c.applyParamWordlist(ctx, sink, pageURL)

	if !strings.Contains(strings.ToLower(ct), "html") {
		return nil, nil // only parse HTML
	}
	body := string(resp.Body)

	// Forms.
	for _, f := range ExtractForms(body) {
		actionInfo, err := NormalizeRef(pageURL, f.Action)
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
			}); err != nil {
				return nil, err
			}
		}
	}

	// Links → endpoints + next level.
	var nextLinks []string
	for _, ref := range ExtractLinks(body) {
		info, err := NormalizeRef(pageURL, ref)
		if err != nil || !in.Scope.Permits(info.Canonical).Allowed {
			continue
		}
		if _, err := sink.AddEndpoint(ctx, EndpointCandidate{URL: info.Canonical, Method: domain.MethodGET, Source: domain.SourceCrawler}); err != nil {
			return nil, err
		}
		nextLinks = append(nextLinks, info.Canonical)
	}
	return nextLinks, nil
}

func (c *crawlSource) applyParamWordlist(ctx context.Context, sink Sink, endpointURL string) {
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
// content discovery (wordlist)
// ---------------------------------------------------------------------------

type contentSource struct {
	engine httpengine.Engine
	cfg    Config
}

// NewContentSource probes paths from a wordlist under each seed origin.
func NewContentSource(engine httpengine.Engine, cfg Config) Source {
	return &contentSource{engine: engine, cfg: cfg.withDefaults()}
}

func (c *contentSource) Name() domain.DiscoverySource { return domain.SourceContentDiscovery }

func (c *contentSource) Run(ctx context.Context, in Input, sink Sink) error {
	words := c.cfg.Wordlist
	if len(words) == 0 && in.Wordlist != "" {
		loaded, err := loadWordlist(in.Wordlist)
		if err != nil {
			return nil // missing wordlist is not fatal
		}
		words = loaded
	}
	if len(words) == 0 {
		return nil
	}

	for _, origin := range uniqueOrigins(in.SeedURLs) {
		for _, w := range words {
			if err := in.wait(ctx); err != nil {
				return err
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			candidate := origin + "/" + strings.TrimPrefix(strings.TrimSpace(w), "/")
			info, err := Normalize(candidate)
			if err != nil || !in.Scope.Permits(info.Canonical).Allowed {
				continue
			}
			resp, err := c.engine.Do(ctx, &httpengine.Request{Method: "GET", URL: info.Canonical})
			if err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				continue
			}
			if !contentExists(resp.Status) {
				continue
			}
			if _, err := sink.AddEndpoint(ctx, EndpointCandidate{URL: info.Canonical, Method: domain.MethodGET, Source: domain.SourceContentDiscovery}); err != nil {
				if errors.Is(err, ErrLimitReached) {
					return nil
				}
				return err
			}
		}
	}
	return nil
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

// ---------------------------------------------------------------------------
// browser network observation (XHR/fetch)
// ---------------------------------------------------------------------------

type networkSource struct {
	browser browser.Browser
	cfg     Config
}

// NewNetworkSource loads each seed in a real browser and emits the network
// requests it observes (including XHR/fetch) as endpoints.
func NewNetworkSource(b browser.Browser, cfg Config) Source {
	return &networkSource{browser: b, cfg: cfg.withDefaults()}
}

func (n *networkSource) Name() domain.DiscoverySource { return domain.SourceBrowserNetwork }

func (n *networkSource) Run(ctx context.Context, in Input, sink Sink) error {
	if n.browser == nil {
		return nil
	}
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
			WaitUntil:        browser.WaitLoad,
			AllowRequest:     func(u string) bool { return in.Scope.Permits(u).Allowed },
			SessionStatePath: in.SessionStatePath,
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
		for _, ev := range res.Network {
			if !in.Scope.Permits(ev.URL).Allowed {
				continue // never persist or enqueue an out-of-scope observation
			}
			method := domain.HTTPMethod(strings.ToUpper(ev.Method))
			if !method.IsValid() {
				method = domain.MethodGET
			}
			if _, err := sink.AddEndpoint(ctx, EndpointCandidate{URL: ev.URL, Method: method, Source: domain.SourceBrowserNetwork}); err != nil {
				if errors.Is(err, ErrLimitReached) {
					return nil
				}
				return err
			}
		}
	}
	return nil
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
