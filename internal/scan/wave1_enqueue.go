package scan

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"time"

	"github.com/indago/indago/internal/domain"
)

const (
	maxSSRFProbes         = 80
	maxCORSProbes         = 60
	maxOpenRedirectProbes = 80
	maxGraphQLProbes      = 20
)

// enqueueSSRFProbes queues one bounded JobSSRF per eligible URL/callback-like
// injection point.
func (c *Controller) enqueueSSRFProbes(ctx context.Context, scanID domain.ID) {
	sc, err := c.store.Scans().Get(ctx, scanID)
	if err != nil || sc.Config.SkipSSRF {
		return
	}
	ips, err := c.store.InjectionPoints().ListByScan(ctx, scanID)
	if err != nil {
		return
	}
	now := time.Now()
	queued := 0
	for _, ip := range ips {
		if queued >= maxSSRFProbes {
			break
		}
		if ip == nil || !ssrfInjectableLocation(ip.Location) {
			continue
		}
		ep, err := c.store.Endpoints().Get(ctx, ip.EndpointID)
		if err != nil || ep == nil {
			continue
		}
		params, err := c.store.Parameters().ListByEndpoint(ctx, ep.ID)
		if err != nil {
			continue
		}
		var focus *domain.Parameter
		for _, p := range params {
			if p.ID == ip.ParameterID {
				focus = p
				break
			}
		}
		if focus == nil || isDynamicTokenName(focus.Name) || !ssrfCandidateParameter(focus) {
			continue
		}
		payload, _ := json.Marshal(map[string]string{
			"endpoint_id":  string(ep.ID),
			"parameter_id": string(focus.ID),
		})
		job := &domain.TestJob{
			ID:          domain.NewID(),
			ScanID:      scanID,
			Type:        domain.JobSSRF,
			State:       domain.JobQueued,
			Priority:    44,
			Target:      domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID, URL: ep.URL},
			Payload:     payload,
			MaxAttempts: 2,
			AvailableAt: now,
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		if err := c.queue.Enqueue(ctx, job); err != nil {
			c.log.Warn("ssrf: enqueue", "scan", scanID, "err", err)
			continue
		}
		queued++
	}
	if queued > 0 {
		c.log.Info("ssrf probes: enqueued", "scan", scanID, "jobs", queued)
	}
}

// enqueueCORSProbes queues one bounded JobCORS per unique endpoint path/query.
func (c *Controller) enqueueCORSProbes(ctx context.Context, scanID domain.ID) {
	sc, err := c.store.Scans().Get(ctx, scanID)
	if err != nil || sc.Config.SkipCORS {
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
		if queued >= maxCORSProbes {
			break
		}
		if ep == nil || strings.TrimSpace(ep.URL) == "" {
			continue
		}
		if _, ok := seen[ep.URL]; ok {
			continue
		}
		seen[ep.URL] = struct{}{}
		job := &domain.TestJob{
			ID:          domain.NewID(),
			ScanID:      scanID,
			Type:        domain.JobCORS,
			State:       domain.JobQueued,
			Priority:    35,
			Target:      domain.JobTarget{EndpointID: ep.ID, URL: ep.URL},
			MaxAttempts: 2,
			AvailableAt: now,
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		if err := c.queue.Enqueue(ctx, job); err != nil {
			c.log.Warn("cors: enqueue", "scan", scanID, "err", err)
			continue
		}
		queued++
	}
	if queued > 0 {
		c.log.Info("cors probes: enqueued", "scan", scanID, "jobs", queued)
	}
}

// enqueueOpenRedirectProbes queues one bounded JobOpenRedirect per endpoint
// that has parameters or a query string.
func (c *Controller) enqueueOpenRedirectProbes(ctx context.Context, scanID domain.ID) {
	sc, err := c.store.Scans().Get(ctx, scanID)
	if err != nil || sc.Config.SkipOpenRedirect {
		return
	}
	endpoints, err := c.store.Endpoints().ListByScan(ctx, scanID)
	if err != nil {
		return
	}
	now := time.Now()
	queued := 0
	for _, ep := range endpoints {
		if queued >= maxOpenRedirectProbes {
			break
		}
		if ep == nil || strings.TrimSpace(ep.URL) == "" {
			continue
		}
		params, _ := c.store.Parameters().ListByEndpoint(ctx, ep.ID)
		hasRawQuery := false
		if u, parseErr := url.Parse(ep.URL); parseErr == nil && u.RawQuery != "" {
			hasRawQuery = true
		}
		if len(params) == 0 && !hasRawQuery {
			continue
		}
		job := &domain.TestJob{
			ID:          domain.NewID(),
			ScanID:      scanID,
			Type:        domain.JobOpenRedirect,
			State:       domain.JobQueued,
			Priority:    38,
			Target:      domain.JobTarget{EndpointID: ep.ID, URL: ep.URL},
			MaxAttempts: 2,
			AvailableAt: now,
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		if err := c.queue.Enqueue(ctx, job); err != nil {
			c.log.Warn("open_redirect: enqueue", "scan", scanID, "err", err)
			continue
		}
		queued++
	}
	if queued > 0 {
		c.log.Info("open_redirect probes: enqueued", "scan", scanID, "jobs", queued)
	}
}

// enqueueGraphQLProbes queues one bounded JobGraphQL per candidate GraphQL endpoint.
func (c *Controller) enqueueGraphQLProbes(ctx context.Context, scanID domain.ID) {
	sc, err := c.store.Scans().Get(ctx, scanID)
	if err != nil || sc.Config.SkipGraphQL {
		return
	}
	endpoints, err := c.store.Endpoints().ListByScan(ctx, scanID)
	if err != nil {
		return
	}
	now := time.Now()
	seen := make(map[string]struct{})
	queued := 0
	for _, ep := range endpoints {
		if queued >= maxGraphQLProbes {
			break
		}
		if ep == nil || strings.TrimSpace(ep.URL) == "" {
			continue
		}
		u, parseErr := url.Parse(ep.URL)
		if parseErr != nil {
			continue
		}
		lowerPath := strings.ToLower(u.Path)
		if !strings.Contains(lowerPath, "graphql") && lowerPath != "/query" && lowerPath != "/api/query" {
			continue
		}
		norm := u.Scheme + "://" + u.Host + u.Path
		if _, ok := seen[norm]; ok {
			continue
		}
		seen[norm] = struct{}{}
		job := &domain.TestJob{
			ID:          domain.NewID(),
			ScanID:      scanID,
			Type:        domain.JobGraphQL,
			State:       domain.JobQueued,
			Priority:    42,
			Target:      domain.JobTarget{EndpointID: ep.ID, URL: norm},
			MaxAttempts: 2,
			AvailableAt: now,
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		if err := c.queue.Enqueue(ctx, job); err != nil {
			c.log.Warn("graphql: enqueue", "scan", scanID, "err", err)
			continue
		}
		queued++
	}
	if queued > 0 {
		c.log.Info("graphql probes: enqueued", "scan", scanID, "jobs", queued)
	}
}
