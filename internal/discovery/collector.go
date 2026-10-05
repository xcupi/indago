package discovery

import (
	"context"
	"fmt"
	"log/slog"
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
type Collector struct {
	store  store.Store
	queue  queue.Queue
	log    *slog.Logger
	scanID domain.ID
	scope  domain.Scope
	cfg    Config

	mu            sync.Mutex
	seenEndpoints map[string]domain.ID // endpoint key → canonical ID
	seenParams    map[string]struct{}  // param key
	endpointCount int
	paramCount    int
	jobCount      int
}

var _ Sink = (*Collector)(nil)

// NewCollector builds a collector for one scan.
func NewCollector(st store.Store, q queue.Queue, scanID domain.ID, scope domain.Scope, cfg Config, log *slog.Logger) *Collector {
	if log == nil {
		log = slog.Default()
	}
	return &Collector{
		store:         st,
		queue:         q,
		log:           log,
		scanID:        scanID,
		scope:         scope,
		cfg:           cfg.withDefaults(),
		seenEndpoints: make(map[string]domain.ID),
		seenParams:    make(map[string]struct{}),
	}
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
// sequence it finds: an endpoint with no endpoint-level job gets one, an
// endpoint missing any of its own URL's query parameters gets them, a
// parameter with no injection point gets one, and an injection point with no
// test job gets one. Hydrate is idempotent.
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
		key := fp + "#" + string(p.Location) + ":" + p.Name
		if _, dup := c.seenParams[key]; !dup {
			c.seenParams[key] = struct{}{}
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
	}

	for _, p := range params {
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

	key := EndpointKey(method, info)

	c.mu.Lock()
	if id, ok := c.seenEndpoints[key]; ok {
		c.mu.Unlock()
		return id, nil // duplicate
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

	if c.cfg.EnqueueEndpointJobs {
		_ = c.enqueueJob(ctx, domain.JobTarget{EndpointID: id, URL: info.Canonical})
	}

	// Query-string parameters are injection points — register them immediately.
	for _, name := range info.ParamNames {
		c.registerParam(ctx, id, method, info, name, domain.LocationQuery, info.Query.Get(name), ep.Source)
	}
	return id, nil
}

// AddParameter implements Sink.
func (c *Collector) AddParameter(ctx context.Context, p ParamCandidate) error {
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
	return nil
}

// registerParam persists a parameter + injection point and enqueues a test job,
// deduplicating by parameter key.
func (c *Collector) registerParam(ctx context.Context, endpointID domain.ID, method domain.HTTPMethod, info URLInfo, name string, loc domain.ParamLocation, example string, source domain.DiscoverySource) {
	if name == "" {
		return
	}
	pkey := ParamKey(method, info, name, loc)

	c.mu.Lock()
	if _, ok := c.seenParams[pkey]; ok {
		c.mu.Unlock()
		return
	}
	c.seenParams[pkey] = struct{}{}
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
		Source:     source,
		CreatedAt:  now,
	}
	if err := c.store.Parameters().Create(ctx, param); err != nil {
		c.mu.Lock()
		delete(c.seenParams, pkey)
		c.paramCount--
		c.mu.Unlock()
		c.log.Warn("discovery: persist parameter", "err", err)
		return
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
		return
	}

	_ = c.enqueueJob(ctx, domain.JobTarget{
		EndpointID:       endpointID,
		InjectionPointID: ip.ID,
		URL:              info.Canonical,
	})
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
