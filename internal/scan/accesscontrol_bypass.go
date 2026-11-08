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

// accessModeMutation is cases 35/36: the admin ACTION step is probed with a
// request the caller should not be able to complete, targeting a user that does
// not exist so no role can change whatever the answer is.
const accessModeMutation = "mutation_step"

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

// probeRoleUsername is the username every mutation probe names. It does not
// exist, so the action can never apply to anybody: whatever the server answers,
// no role changes. It is a fixed literal, not a wordlist.
const probeRoleUsername = "indago-probe-nonexistent-user"

// runMutationProbe proves cases 35 and 36 without changing state.
//
//	step 1 (baseline): POST <origin>/admin-roles action=upgrade&username=<probe>
//	                   → the caller is refused (401/403)
//	step 2 (confirm):  the same request plus confirmed=true
//	step 2 (referer):  the same request plus Referer: <origin>/admin
//	anonymous:         the confirmed request without the session
//
// A finding needs all three: the baseline refused, at least one variant reaching
// the application handler, and the anonymous variant refused (so the gap is the
// caller's missing authorization, not a public endpoint). Because the username
// never exists, the handler's own lookup fails — which is exactly the proof that
// the handler ran.
func (e *accessControlExecutor) runMutationProbe(ctx context.Context, job *domain.TestJob, tc *domain.TestCase) (accessControlDetail, domain.TestOutcome, error, bool, bool) {
	d := accessControlDetail{Engine: accessControlEngine, Kind: accessModeMutation, URL: job.Target.URL}
	tc.Method, tc.URL = "POST", job.Target.URL

	u, err := url.Parse(strings.TrimSpace(job.Target.URL))
	if err != nil || u.Host == "" {
		d.Skipped, d.SkipReason = true, "mutation job has no usable privileged URL"
		return d, domain.OutcomeSuccess, nil, false, true
	}
	origin := u.Scheme + "://" + u.Host
	path := u.Path
	if path == "" {
		path = "/admin-roles"
	}
	d.Origin, d.PrivilegedPath = origin, path

	form := url.Values{"action": {"upgrade"}, "username": {probeRoleUsername}}.Encode()
	denied := httpengine.NewRequest("POST", job.Target.URL)
	denied.Headers = map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	denied.Body = []byte(form)
	baseResp, outcome, _ := e.do(ctx, denied)
	if outcome != domain.OutcomeSuccess {
		d.Skipped, d.SkipReason = true, "the admin action step could not be fetched"
		return d, domain.OutcomeSuccess, nil, false, true
	}
	d.StepBaseline = baseResp.Status

	// Anonymous control: the same confirmed request without the caller's session.
	// This is what separates a missing authorization check from a public endpoint.
	anonReq := httpengine.NewRequest("POST", job.Target.URL)
	anonReq.NoCookies = true
	anonReq.Headers = map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	anonReq.Body = []byte(url.Values{"action": {"upgrade"}, "username": {probeRoleUsername}, "confirmed": {"true"}}.Encode())
	if anonResp, anonOut, _ := e.do(ctx, anonReq); anonOut == domain.OutcomeSuccess {
		d.StepAnonymous = anonResp.Status
	}

	if !accesscontrol.IsDenialStatus(d.StepBaseline) {
		d.Verdict = domain.VerdictRejected
		d.Reason = fmt.Sprintf("the admin action step refused nothing (HTTP %d without the extra step): no missing authorization to prove", d.StepBaseline)
		return d, domain.OutcomeSuccess, nil, false, false
	}

	type variant struct {
		name   string
		header map[string]string
		body   url.Values
		status *int
	}
	variants := []variant{
		{name: "confirmation", header: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			body: url.Values{"action": {"upgrade"}, "username": {probeRoleUsername}, "confirmed": {"true"}}, status: &d.StepConfirm},
		{name: "referer", header: map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Referer": origin + "/admin"},
			body: url.Values{"action": {"upgrade"}, "username": {probeRoleUsername}}, status: &d.StepReferer},
	}
	for _, v := range variants {
		if ctx.Err() != nil {
			return d, domain.OutcomeCancelled, ctx.Err(), false, false
		}
		req := httpengine.NewRequest("POST", job.Target.URL)
		req.Headers = v.header
		req.Body = []byte(v.body.Encode())
		resp, out, _ := e.do(ctx, req)
		if out != domain.OutcomeSuccess {
			continue
		}
		*v.status = resp.Status
		if !accesscontrol.HandlerRan(d.StepBaseline, resp.Status, string(baseResp.Body), string(resp.Body)) {
			continue
		}
		if accesscontrol.IsDenialStatus(d.StepAnonymous) || d.StepAnonymous == 0 {
			// The anonymous control must refuse, otherwise this is not an
			// authorization gap at all.
			d.Verdict = domain.VerdictConfirmed
			d.Bypass = v.name
			d.Reason = fmt.Sprintf("the admin action step refused the caller (HTTP %d) but the same request with %s reached the application handler (HTTP %d, %q) while the anonymous control was refused (HTTP %d) — the authorization check covers one step, not the action",
				d.StepBaseline, variantLabel(v.name), resp.Status, truncate(strings.TrimSpace(string(resp.Body)), 60), d.StepAnonymous)
			e.correlate(ctx, job.ScanID, accessControlFinding{
				Key:        accessControlPathDedupKey(job.Target.URL) + "\x00mutation\x00" + v.name,
				Title:      fmt.Sprintf("Access control: %s bypass of the admin action at %s", variantLabel(v.name), path),
				Summary:    d.Reason,
				Severity:   domain.SeverityHigh,
				EndpointID: job.Target.EndpointID,
				Detail:     findingDetailFrom(d, nil, nil),
			}, tc.ID)
			return d, domain.OutcomeSuccess, nil, false, false
		}
	}

	d.Verdict = domain.VerdictRejected
	d.Reason = fmt.Sprintf("the admin action step refused the caller (HTTP %d) and neither the confirmation nor the referer variant reached the handler (confirmed=%d referer=%d)", d.StepBaseline, d.StepConfirm, d.StepReferer)
	return d, domain.OutcomeSuccess, nil, false, false
}

func variantLabel(name string) string {
	switch name {
	case "confirmation":
		return "confirmation-step"
	case "referer":
		return "referer-based"
	}
	return name
}

// enqueueMutationProbes queues ONE admin-action probe per origin when the scan
// opted in. It is bounded (a single path per origin) and non-mutating by
// construction: the username it names never exists.
func (c *Controller) enqueueMutationProbes(ctx context.Context, scanID domain.ID) {
	sc, err := c.store.Scans().Get(ctx, scanID)
	if err != nil || !sc.Config.EnableAdminStepProbe {
		return
	}
	endpoints, err := c.store.Endpoints().ListByScan(ctx, scanID)
	if err != nil {
		c.log.Warn("admin step probe: list endpoints", "scan", scanID, "err", err)
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
		if _, dup := seen[origin]; dup {
			continue
		}
		seen[origin] = struct{}{}
		job := &domain.TestJob{
			ID: domain.NewID(), ScanID: scanID, Type: domain.JobAccessControl, State: domain.JobQueued,
			Priority: 24, Target: domain.JobTarget{URL: origin + "/admin-roles"},
			Payload:     accessControlModePayload(accessModeMutation),
			MaxAttempts: 2, AvailableAt: now, CreatedAt: now, UpdatedAt: now,
		}
		if err := c.queue.Enqueue(ctx, job); err != nil {
			c.log.Warn("admin step probe: enqueue", "scan", scanID, "err", err)
			continue
		}
		n++
	}
	if n > 0 {
		c.log.Info("admin step probe: enqueued", "scan", scanID, "jobs", n)
	}
}
