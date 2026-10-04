package discovery

import (
	"context"
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
// persisted for the scan. It must be called before sources run when a scan is
// resumed after a restart: without it, re-running discovery would re-register
// every known endpoint/parameter and re-enqueue duplicate test jobs.
//
// Endpoints are keyed by their persisted Fingerprint (the EndpointKey computed
// at insert time); parameters are re-keyed from their endpoint's fingerprint.
// Hydrate is idempotent.
func (c *Collector) Hydrate(ctx context.Context) error {
	endpoints, err := c.store.Endpoints().ListByScan(ctx, c.scanID)
	if err != nil {
		return err
	}
	params, err := c.store.Parameters().ListByScan(ctx, c.scanID)
	if err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

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
		c.enqueueJob(ctx, domain.JobTarget{EndpointID: id, URL: info.Canonical})
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

	c.enqueueJob(ctx, domain.JobTarget{
		EndpointID:       endpointID,
		InjectionPointID: ip.ID,
		URL:              info.Canonical,
	})
}

// enqueueJob enqueues a test job for a discovered target. Enqueue failures are
// logged, not fatal: the endpoint/param is already persisted and recoverable.
func (c *Collector) enqueueJob(ctx context.Context, target domain.JobTarget) {
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
		return
	}
	c.mu.Lock()
	c.jobCount++
	c.mu.Unlock()
}
