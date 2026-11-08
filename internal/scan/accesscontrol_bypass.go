package scan

// Access-control bypass probes (cases 28 and 29).
//
// Both cases are DIFFERENTIAL and server-side: nothing executes in a browser and
// nothing state-changing is sent. For each bounded privileged path the executor
// records how the caller is treated by the gateway and then asks whether the
// SAME surface answers a request the gate should have covered:
//
//   - header override (case 28): GET <origin>/ with X-Original-URL / X-Rewrite-URL
//     naming the path. Only tried when the plain request was DENIED (401/403), and
//     it must return the administrative surface, not merely a 200.
//   - method bypass (case 29): the path is gated for POST but the handler answers
//     GET with its OWN validation error ("Missing parameter 'username'"), which
//     only the handler produces. The POST probe carries NO body and NO query, so
//     the action's parameters can never be supplied and nothing can be changed.
//
// A finding is created only when the pure rules in internal/accesscontrol agree.

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/indago/indago/internal/accesscontrol"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/httpengine"
)

const accessModeBypass = "bypass"

// maxBypassRequestsPerPath bounds one path's probes: GET baseline, POST
// baseline, and two header overrides.
const maxBypassRequestsPerPath = 4

func (e *accessControlExecutor) runBypass(ctx context.Context, job *domain.TestJob, tc *domain.TestCase) (accessControlDetail, domain.TestOutcome, error, bool, bool) {
	d := accessControlDetail{Engine: accessControlEngine, Kind: accessModeBypass, URL: job.Target.URL}
	tc.Method, tc.URL = "GET", job.Target.URL

	u, err := url.Parse(strings.TrimSpace(job.Target.URL))
	if err != nil || u.Host == "" {
		d.Skipped, d.SkipReason = true, "bypass job has no usable privileged URL"
		return d, domain.OutcomeSuccess, nil, false, true
	}
	origin := u.Scheme + "://" + u.Host
	path := u.Path
	if path == "" {
		path = "/"
	}
	d.Origin, d.PrivilegedPath = origin, path

	// 1. The caller's own view of the surface.
	getResp, outcome, _ := e.do(ctx, httpengine.GET(job.Target.URL))
	if outcome != domain.OutcomeSuccess {
		// An unreachable privileged path proves nothing either way; it is not a
		// failure of the scan (the panel pass already records reachability).
		d.Skipped, d.SkipReason = true, "the privileged path could not be fetched"
		return d, domain.OutcomeSuccess, nil, false, true
	}
	d.GetStatus = getResp.Status
	getBody := string(getResp.Body)

	// 2. The gateway's view of the same path for a POST with NO body/query: the
	// action's parameters can never be present, so this cannot mutate anything.
	postResp, outcome, _ := e.do(ctx, httpengine.NewRequest("POST", job.Target.URL))
	if outcome != domain.OutcomeSuccess {
		d.PostStatus = 0 // unknown: the method comparison cannot be made
	} else {
		d.PostStatus = postResp.Status
	}

	// 3. Method bypass: the POST is denied, but the GET reached the handler.
	if accesscontrol.MethodBypassReached(d.PostStatus, d.GetStatus, getBody) {
		d.Verdict = domain.VerdictConfirmed
		d.Bypass = string(accesscontrol.BypassMethod)
		d.Reason = fmt.Sprintf("the path is denied for POST (%d) but answered GET with the application's own validation error (%d) — the authorization check gates the method, not the handler",
			d.PostStatus, d.GetStatus)
		e.correlate(ctx, job.ScanID, accessControlFinding{
			Key:        accessControlPathDedupKey(job.Target.URL) + "\x00method",
			Title:      fmt.Sprintf("Access control: method-based bypass at %s %s", "GET", path),
			Summary:    d.Reason,
			Severity:   domain.SeverityHigh,
			EndpointID: job.Target.EndpointID,
			Detail:     findingDetailFrom(d, nil, nil),
		}, tc.ID)
		return d, domain.OutcomeSuccess, nil, false, false
	}

	// 4. Header override: only meaningful when the plain request was denied.
	if accesscontrol.IsDenialStatus(d.GetStatus) {
		for _, header := range []string{"X-Original-URL", "X-Rewrite-URL"} {
			if ctx.Err() != nil {
				return d, domain.OutcomeCancelled, ctx.Err(), false, false
			}
			req := httpengine.GET(origin + "/")
			req.Headers = map[string]string{header: path}
			resp, outcome, _ := e.do(ctx, req)
			if outcome != domain.OutcomeSuccess {
				continue // this header could not be tested; try the next one
			}
			body := string(resp.Body)
			d.HeaderProbes = append(d.HeaderProbes, accessControlHeaderProbe{
				Header: header, Path: path, Status: resp.Status, Reached: accesscontrol.HeaderOverrideReached(d.GetStatus, resp.Status, body),
			})
			if accesscontrol.HeaderOverrideReached(d.GetStatus, resp.Status, body) {
				d.Verdict = domain.VerdictConfirmed
				d.Bypass = string(accesscontrol.BypassHeaderURL)
				d.Reason = fmt.Sprintf("the path is denied directly (%d) but the administrative surface answered %d when %s named it — the gateway gates the URL, the origin trusts the header",
					d.GetStatus, resp.Status, header)
				e.correlate(ctx, job.ScanID, accessControlFinding{
					Key:        accessControlPathDedupKey(job.Target.URL) + "\x00header",
					Title:      fmt.Sprintf("Access control: header path override reaches %s", path),
					Summary:    d.Reason,
					Severity:   domain.SeverityHigh,
					EndpointID: job.Target.EndpointID,
					Detail:     findingDetailFrom(d, nil, nil),
				}, tc.ID)
				return d, domain.OutcomeSuccess, nil, false, false
			}
		}
	}

	d.Verdict = domain.VerdictRejected
	d.Reason = fmt.Sprintf("no bypass: direct GET %d, POST %d, and no header override reached the surface", d.GetStatus, d.PostStatus)
	return d, domain.OutcomeSuccess, nil, false, false
}

// enqueueAccessBypassProbes queues ONE bypass job per bounded privileged path
// per origin. It runs from the same one-time access-control pass, so a scan adds
// at most len(BypassPaths) jobs per origin and each job costs at most
// maxBypassRequestsPerPath requests.
func (c *Controller) enqueueAccessBypassProbes(ctx context.Context, scanID domain.ID) {
	endpoints, err := c.store.Endpoints().ListByScan(ctx, scanID)
	if err != nil {
		c.log.Warn("access bypass: list endpoints", "scan", scanID, "err", err)
		return
	}
	now := time.Now()
	seen := map[string]struct{}{}
	n := 0
	for _, ep := range endpoints {
		u, err := url.Parse(strings.TrimSpace(ep.URL))
		if err != nil || u.Host == "" {
			continue
		}
		origin := u.Scheme + "://" + u.Host
		for _, path := range accesscontrol.BypassPaths {
			key := origin + path
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			job := &domain.TestJob{
				ID: domain.NewID(), ScanID: scanID, Type: domain.JobAccessControl, State: domain.JobQueued,
				Priority: 24, Target: domain.JobTarget{URL: origin + path},
				Payload:     accessControlModePayload(accessModeBypass),
				MaxAttempts: 2, AvailableAt: now, CreatedAt: now, UpdatedAt: now,
			}
			if err := c.queue.Enqueue(ctx, job); err != nil {
				c.log.Warn("access bypass: enqueue job", "scan", scanID, "url", job.Target.URL, "err", err)
				continue
			}
			n++
		}
	}
	if n > 0 {
		c.log.Info("access bypass: enqueued", "scan", scanID, "jobs", n)
	}
}
