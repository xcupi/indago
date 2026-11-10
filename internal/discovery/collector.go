package discovery

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/store"
)

// Collector is the Sink implementation. For every candidate it normalizes the
// URL, enforces scope (fail closed), deduplicates, persists the survivor, and
// enqueues a test job — so testing can begin immediately. It is safe for
// concurrent use by many sources.
// MaxObservedExamples caps how many distinct values the crawl keeps per
// parameter. An object-identifier differential only needs a handful of foreign
// ids, and the cap bounds both the row size and the memory of a crawl that sees
// a listing page with hundreds of links.
const MaxObservedExamples = 20

type Collector struct {
	store         store.Store
	queue         queue.Queue
	log           *slog.Logger
	scanID        domain.ID
	scope         domain.Scope
	authenticated bool // true when the scan carries a session; see AddEndpoint
	cfg           Config

	mu            sync.Mutex
	seenEndpoints map[string]domain.ID // endpoint key → canonical ID
	seenParams    map[string]domain.ID // param key → parameter ID
	endpointCount int
	paramCount    int
	jobCount      int
	reconCounts   map[string]int // "list/level" → candidates recorded by recon
	// rawQueryProbes counts raw-query injection points registered so far,
	// hydrated from persisted rows and capped by MaxRawQueryProbesPerScan.
	rawQueryProbes int
}

var _ Sink = (*Collector)(nil)

// NewCollector builds a collector for one scan. authenticated marks whether
// the scan is running with a session (non-empty RunParams.SessionStatePath)
// — see AddEndpoint for why this changes which crawler-found links get
// followed.
func NewCollector(st store.Store, q queue.Queue, scanID domain.ID, scope domain.Scope, authenticated bool, cfg Config, log *slog.Logger) *Collector {
	if log == nil {
		log = slog.Default()
	}
	return &Collector{
		store:         st,
		queue:         q,
		log:           log,
		scanID:        scanID,
		scope:         scope,
		authenticated: authenticated,
		cfg:           cfg.withDefaults(),
		seenEndpoints: make(map[string]domain.ID),
		seenParams:    make(map[string]domain.ID),
		reconCounts:   make(map[string]int),
	}
}

// noteRecon tallies a wordlist guess by list and level. The tally is exposed
// through ReconCounts so a discovery run can report "paths/standard=12" — the
// distinguishing record between an endpoint that was linked and one that was
// guessed. Nothing here affects scope, testing, or any verdict.
func (c *Collector) noteRecon(p *ReconProvenance) {
	if p == nil || p.List == "" {
		return
	}
	key := p.List
	if p.Level != "" {
		key += "/" + string(p.Level)
	}
	c.mu.Lock()
	c.reconCounts[key]++
	c.mu.Unlock()
}

// ReconCounts returns a copy of the wordlist-provenance tally ("list/level" →
// count of candidates recorded this run).
func (c *Collector) ReconCounts() map[string]int {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]int, len(c.reconCounts))
	for k, v := range c.reconCounts {
		out[k] = v
	}
	return out
}

// Hydrate rebuilds the collector's deduplication state from what is already
// persisted for the scan, then reconciles anything a previous run persisted
// only partially. It must be called before sources run when a scan is resumed
// after a restart: without it, re-running discovery would re-register every
// known endpoint/parameter and re-enqueue duplicate test jobs.
//
// Endpoints are keyed by their persisted Fingerprint (the EndpointKey computed
// at insert time); parameters are re-keyed from their endpoint's fingerprint.
//
// Reconciliation: registering a target is several separate writes (endpoint →
// its job → its query parameters → parameter → injection point → its job), and
// a shutdown or crash can land between any two of them. Marking such a target
// "seen" would make the rest of that sequence unreachable forever — the next
// run's sources rediscover the endpoint, hit the dedup check, and never
// register its parameters or enqueue its jobs, so it is silently never tested
// and the scan still completes. Hydrate therefore finishes every incomplete
// registration sequence it finds: an endpoint with no endpoint-level job gets
// one, an endpoint missing any query or fragment-route parameters from its own
// URL gets them, a parameter with no injection point gets one, and an injection
// point with no test job gets one. Hydrate is idempotent.
func (c *Collector) Hydrate(ctx context.Context) error {
	endpoints, err := c.store.Endpoints().ListByScan(ctx, c.scanID)
	if err != nil {
		return err
	}
	params, err := c.store.Parameters().ListByScan(ctx, c.scanID)
	if err != nil {
		return err
	}
	ips, err := c.store.InjectionPoints().ListByScan(ctx, c.scanID)
	if err != nil {
		return err
	}
	jobs, err := c.queue.Jobs(ctx, c.scanID)
	if err != nil {
		return err
	}

	c.mu.Lock()
	fingerprintByID := make(map[domain.ID]string, len(endpoints))
	for _, e := range endpoints {
		if e.Fingerprint == "" {
			continue // legacy row without a key; cannot be deduplicated
		}
		fingerprintByID[e.ID] = e.Fingerprint
		if _, ok := c.seenEndpoints[e.Fingerprint]; !ok {
			c.seenEndpoints[e.Fingerprint] = e.ID
			c.endpointCount++
		}
	}
	for _, p := range params {
		fp, ok := fingerprintByID[p.EndpointID]
		if !ok {
			continue
		}
		if isRawQueryLocation(p.Location) {
			// Restore the per-scan raw-query budget across a restart; the
			// persisted rows are the authority on what was already sent.
			c.rawQueryProbes++
		}
		key := fp + "#" + string(p.Location) + ":" + p.Name
		if _, dup := c.seenParams[key]; !dup {
			c.seenParams[key] = p.ID
			c.paramCount++
		}
	}
	c.mu.Unlock()

	return c.reconcile(ctx, endpoints, params, ips, jobs)
}

// reconcile completes registration sequences a previous run left unfinished
// (see Hydrate). Every step is idempotent against the already-hydrated dedup
// state and against the jobs that exist, so running it on a scan with nothing
// missing changes nothing.
func (c *Collector) reconcile(ctx context.Context, endpoints []*domain.Endpoint, params []*domain.Parameter, ips []*domain.InjectionPoint, jobs []*domain.TestJob) error {
	// Discovery-enqueued test jobs: a reflection/candidate child of an
	// injection-point job also targets that injection point, which is fine —
	// its existence proves the injection point's own job existed.
	endpointJob := map[domain.ID]bool{}
	ipJob := map[domain.ID]bool{}
	for _, j := range jobs {
		if j.Type != domain.JobTest {
			continue
		}
		if ipID := j.Target.InjectionPointID; !ipID.Empty() {
			ipJob[ipID] = true
		} else if !j.Target.EndpointID.Empty() {
			endpointJob[j.Target.EndpointID] = true
		}
	}
	ipByParam := make(map[domain.ID]*domain.InjectionPoint, len(ips))
	for _, ip := range ips {
		ipByParam[ip.ParameterID] = ip
	}
	endpointByID := make(map[domain.ID]*domain.Endpoint, len(endpoints))
	for _, e := range endpoints {
		endpointByID[e.ID] = e
	}

	for _, e := range endpoints {
		if e.Fingerprint == "" {
			continue
		}
		if c.cfg.EnqueueEndpointJobs && !endpointJob[e.ID] {
			if err := c.enqueueJob(ctx, domain.JobTarget{EndpointID: e.ID, URL: e.URL}); err != nil {
				return fmt.Errorf("reconcile endpoint job %s: %w", e.ID, err)
			}
		}
		// The endpoint's own query parameters are registered right after it;
		// registerParam skips any already hydrated, so only the missing ones
		// are created (each with its injection point and job).
		info, err := Normalize(e.URL)
		if err != nil {
			continue
		}
		for _, name := range info.ParamNames {
			c.registerParam(ctx, e.ID, e.Method, info, name, domain.LocationQuery, info.Query.Get(name), e.Source)
		}
		for _, name := range info.FragmentParams {
			c.registerParam(ctx, e.ID, e.Method, info, name, domain.LocationFragment, "", e.Source)
		}
		// Header/Cookie/Path registration is also reconciled on every Hydrate
		// pass — registerParam's own dedup makes this a no-op for anything
		// already persisted, so this only fills in what a prior run (or a
		// pre-existing endpoint from before this feature existed) is missing.
		c.registerHeaderInjectionPoints(ctx, e.ID, e.Method, info, e.Source)
		c.registerCookieInjectionPoints(ctx, e.ID, e.Method, info, e.Source)
		c.registerPathInjectionPoints(ctx, e.ID, e.Method, info, e.Source)
		c.registerRawQueryInjectionPoints(ctx, e.ID, e.Method, info, e.Source)
	}

	for _, p := range params {
		if p.Location == domain.LocationFragment {
			// DOM-only parameters must never be reconciled into HTTP injection points.
			continue
		}
		ep, ok := endpointByID[p.EndpointID]
		if !ok {
			continue
		}
		ip, ok := ipByParam[p.ID]
		if !ok {
			ip = &domain.InjectionPoint{
				ID: domain.NewID(), ScanID: c.scanID, EndpointID: p.EndpointID,
				ParameterID: p.ID, Location: p.Location, CreatedAt: time.Now(),
			}
			if err := c.store.InjectionPoints().Create(ctx, ip); err != nil {
				return fmt.Errorf("reconcile injection point for parameter %s: %w", p.ID, err)
			}
		}
		if !ipJob[ip.ID] {
			if err := c.enqueueJob(ctx, domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID, URL: ep.URL}); err != nil {
				return fmt.Errorf("reconcile injection point job %s: %w", ip.ID, err)
			}
			ipJob[ip.ID] = true
		}
	}
	return nil
}

// Counts returns discovery progress counters (for UI/tests).
func (c *Collector) Counts() (endpoints, params, jobs int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.endpointCount, c.paramCount, c.jobCount
}

// AllowFetch implements fetchGuard: on an authenticated scan a discovered URL
// that looks like it ends the session must be neither registered nor
// requested. An operator-provided seed is explicit intent and always allowed;
// an unauthenticated scan has no session to lose.
func (c *Collector) AllowFetch(rawURL string, source domain.DiscoverySource) bool {
	return !(c.authenticated && source != domain.SourceUserProvided && looksSessionTerminating(rawURL))
}

// AddEndpoint implements Sink.
func (c *Collector) AddEndpoint(ctx context.Context, ep EndpointCandidate) (domain.ID, error) {
	info, err := Normalize(ep.URL)
	if err != nil {
		return "", nil // skip malformed/non-http URLs (not a fatal error)
	}
	method := ep.Method
	if method == "" {
		method = domain.MethodGET
	}
	if d := c.scope.Permits(info.Canonical); !d.Allowed {
		return "", nil // out of scope: silently skip (fail closed)
	}
	if c.cfg.SkipStaticAssets && ep.Source != domain.SourceUserProvided && IsStaticAssetPath(info.Path) {
		c.log.Debug("discovery: skipping static asset", "url", info.Canonical, "source", ep.Source)
		return "", nil
	}

	// An authenticated scan's crawler-style sources (crawler, forms, browser
	// network capture, sitemap, robots, content discovery) must not follow a
	// link that looks like it logs the session out — e.g. a "Logout" link
	// present in the nav of almost every authenticated page. Doing so would
	// silently end the session mid-scan: every test after that point runs
	// unauthenticated and the scan never finds anything behind the login it
	// was specifically given a session to get past. An operator-provided
	// seed URL is NEVER skipped here, even if it happens to match — that is
	// explicit intent (e.g. deliberately testing the logout endpoint
	// itself), not an accidental link-follow. Unauthenticated scans have no
	// session to lose, so nothing is skipped for them either.
	if !c.AllowFetch(info.Canonical, ep.Source) {
		c.log.Debug("discovery: skipping likely session-terminating link", "url", info.Canonical, "source", ep.Source)
		return "", nil
	}

	key := EndpointKey(method, info)

	c.mu.Lock()
	if id, ok := c.seenEndpoints[key]; ok {
		c.mu.Unlock()
		// Duplicate endpoint: the URL collapses into the first one, but its
		// parameter VALUES are still new information. Keep them — an
		// object-identifier differential (IDOR) can only propose a foreign id
		// it has seen, and other users' ids arrive exactly this way (measured:
		// /blogs?userId=<other user> on an already-seen path).
		c.recordObservedValues(ctx, id, method, info)
		return id, nil
	}
	if c.endpointCount >= c.cfg.MaxEndpoints {
		c.mu.Unlock()
		return "", ErrLimitReached
	}
	id := domain.NewID()
	c.seenEndpoints[key] = id
	c.endpointCount++
	c.mu.Unlock()

	now := time.Now()
	e := &domain.Endpoint{
		ID:          id,
		ScanID:      c.scanID,
		URL:         info.Canonical,
		Method:      method,
		Source:      ep.Source,
		ContentType: ep.ContentType,
		Fingerprint: key,
		CreatedAt:   now,
	}
	if err := c.store.Endpoints().Create(ctx, e); err != nil {
		c.mu.Lock()
		delete(c.seenEndpoints, key)
		c.endpointCount--
		c.mu.Unlock()
		return "", err
	}

	if ep.Provenance != nil {
		// Structured record of the guess: which embedded list and level
		// produced this endpoint (see ReconProvenance).
		c.log.Debug("discovery: wordlist endpoint recorded",
			"url", info.Canonical, "list", ep.Provenance.List, "level", ep.Provenance.Level)
		c.noteRecon(ep.Provenance)
	}

	if c.cfg.EnqueueEndpointJobs {
		_ = c.enqueueJob(ctx, domain.JobTarget{EndpointID: id, URL: info.Canonical})
	}

	// Query-string parameters are injection points — register them immediately.
	for _, name := range info.ParamNames {
		c.registerParam(ctx, id, method, info, name, domain.LocationQuery, info.Query.Get(name), ep.Source)
	}
	// Fragment route parameters are DOM-only selectors. Register them at the
	// endpoint boundary so crawler-discovered links and operator seeds behave
	// identically; registerParam deliberately creates no HTTP injection point.
	for _, name := range info.FragmentParams {
		c.registerParam(ctx, id, method, info, name, domain.LocationFragment, "", ep.Source)
	}
	// Header/Cookie/Path injection points (see extra_locations.go /
	// path_segments.go) — location-agnostic coverage alongside Query/Form/JSON.
	c.registerHeaderInjectionPoints(ctx, id, method, info, ep.Source)
	c.registerCookieInjectionPoints(ctx, id, method, info, ep.Source)
	c.registerPathInjectionPoints(ctx, id, method, info, ep.Source)
	c.registerRawQueryInjectionPoints(ctx, id, method, info, ep.Source)
	return id, nil
}

func firstExample(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	return []string{v}
}

// recordObservedValues stores the query values a duplicate URL carried, so the
// crawl keeps every distinct identifier it saw for an already-known endpoint.
func (c *Collector) recordObservedValues(ctx context.Context, endpointID domain.ID, method domain.HTTPMethod, info URLInfo) {
	for _, name := range info.ParamNames {
		v := info.Query.Get(name)
		if v == "" {
			continue
		}
		pkey := ParamKey(method, info, name, domain.LocationQuery)
		c.mu.Lock()
		paramID, ok := c.seenParams[pkey]
		c.mu.Unlock()
		if !ok {
			continue
		}
		c.appendParamExample(ctx, paramID, v)
	}
}

// appendParamExample records one observed value for a parameter. Failures are
// logged, never fatal: losing an example costs a candidate, not the scan.
func (c *Collector) appendParamExample(ctx context.Context, paramID domain.ID, value string) {
	if paramID.Empty() || value == "" {
		return
	}
	if err := c.store.Parameters().AppendExamples(ctx, paramID, []string{value}, MaxObservedExamples); err != nil {
		c.log.Debug("discovery: append parameter example", "param", paramID, "err", err)
	}
}

// AddParameter implements Sink.
// isTableControlParam reports whether a parameter is generated by the
// DataTables client protocol rather than supplied by the application. These
// names occur in sets of ten+ per request and are not user-controlled fields.
func isTableControlParam(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	switch n {
	case "_", "draw", "start", "length", "search[value]", "search[regex]":
		return true
	}
	return strings.HasPrefix(n, "columns[") ||
		strings.HasPrefix(n, "order[")
}

func (c *Collector) AddParameter(ctx context.Context, p ParamCandidate) error {
	// DataTables sends its own paging/sorting/column state on every request.
	// Those fields are framework controls, not application inputs: treating
	// them as XSS injection points wastes the candidate budget and produces
	// 403 "blocks" when the server rejects a mutated protocol field. Keep an
	// explicitly operator-supplied parameter even if it happens to share a
	// name, because that is a deliberate declaration.
	if p.Source != domain.SourceUserProvided && isTableControlParam(p.Name) {
		return nil
	}
	info, err := Normalize(p.EndpointURL)
	if err != nil {
		return nil
	}
	method := p.EndpointMethod
	if method == "" {
		method = domain.MethodGET
	}
	if d := c.scope.Permits(info.Canonical); !d.Allowed {
		return nil
	}

	key := EndpointKey(method, info)
	c.mu.Lock()
	endpointID, ok := c.seenEndpoints[key]
	c.mu.Unlock()
	if !ok {
		// Register the endpoint first (this also handles scope/limit).
		id, err := c.AddEndpoint(ctx, EndpointCandidate{URL: p.EndpointURL, Method: method, Source: p.Source})
		if err != nil {
			return err
		}
		if id == "" {
			return nil // skipped (out of scope)
		}
		endpointID = id
	}

	loc := p.Location
	if loc == "" {
		loc = domain.LocationQuery
	}
	c.registerParam(ctx, endpointID, method, info, p.Name, loc, p.Example, p.Source)
	c.noteRecon(p.Provenance)
	return nil
}

// registerParam persists a parameter + injection point and enqueues a test job,
// deduplicating by parameter key. It reports whether a NEW parameter was
// persisted (false for a duplicate), which the raw-query registrar needs to
// charge its per-scan budget only for real probes.
func (c *Collector) registerParam(ctx context.Context, endpointID domain.ID, method domain.HTTPMethod, info URLInfo, name string, loc domain.ParamLocation, example string, source domain.DiscoverySource) bool {
	if name == "" {
		return false
	}
	// AddEndpoint registers query parameters directly from the URL, bypassing
	// AddParameter; apply the framework-control filter here as well. Otherwise
	// a DataTables-backed page registers every column/draw/order field as an
	// injection point and floods the queue with protocol noise.
	if loc == domain.LocationQuery && source != domain.SourceUserProvided && isTableControlParam(name) {
		return false
	}
	pkey := ParamKey(method, info, name, loc)

	c.mu.Lock()
	if existing, ok := c.seenParams[pkey]; ok {
		c.mu.Unlock()
		c.appendParamExample(ctx, existing, example)
		return false
	}
	c.paramCount++
	c.mu.Unlock()

	now := time.Now()
	param := &domain.Parameter{
		ID:         domain.NewID(),
		ScanID:     c.scanID,
		EndpointID: endpointID,
		Name:       name,
		Location:   loc,
		Example:    example,
		// Seed the observed-value list with the first value so a later
		// duplicate is recognised and the list is the complete record.
		Examples:  firstExample(example),
		Source:    source,
		CreatedAt: now,
	}
	if err := c.store.Parameters().Create(ctx, param); err != nil {
		c.mu.Lock()
		delete(c.seenParams, pkey)
		c.paramCount--
		c.mu.Unlock()
		c.log.Warn("discovery: persist parameter", "err", err)
		return false
	}
	c.mu.Lock()
	c.seenParams[pkey] = param.ID
	c.mu.Unlock()

	if loc == domain.LocationFragment {
		// DOM-only: no HTTP injection point, so no HTTP engine ever sends it.
		return true
	}
	ip := &domain.InjectionPoint{
		ID:          domain.NewID(),
		ScanID:      c.scanID,
		EndpointID:  endpointID,
		ParameterID: param.ID,
		Location:    loc,
		CreatedAt:   now,
	}
	if err := c.store.InjectionPoints().Create(ctx, ip); err != nil {
		c.log.Warn("discovery: persist injection point", "err", err)
		return false
	}

	if !c.cfg.SkipReflectedXSS {
		_ = c.enqueueJob(ctx, domain.JobTarget{
			EndpointID:       endpointID,
			InjectionPointID: ip.ID,
			URL:              info.Canonical,
		})
	}
	return true
}

// enqueueJob enqueues a test job for a discovered target. Enqueue failures are
// logged (and returned for callers that care), not fatal to discovery: the
// endpoint/param is already persisted, and the next Hydrate re-enqueues it.
func (c *Collector) enqueueJob(ctx context.Context, target domain.JobTarget) error {
	now := time.Now()
	job := &domain.TestJob{
		ID:          domain.NewID(),
		ScanID:      c.scanID,
		Type:        domain.JobTest,
		State:       domain.JobQueued,
		Target:      target,
		MaxAttempts: 3,
		AvailableAt: now,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := c.queue.Enqueue(ctx, job); err != nil {
		c.log.Warn("discovery: enqueue test job", "err", err)
		return err
	}
	c.mu.Lock()
	c.jobCount++
	c.mu.Unlock()
	return nil
}
