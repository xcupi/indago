package scan

// Access-control bypass probes (cases 28 and 29).
//
// Both cases are DIFFERENTIAL and server-side: nothing executes in a browser.
// For each bounded privileged path the executor records how the caller is
// treated by the gateway and then asks whether the SAME surface answers a
// request the gate should have covered:
//
//   - header override (case 28): GET <origin>/ with X-Original-URL / X-Rewrite-URL
//     naming the path. Only tried when the plain request was DENIED (401/403), and
//     it must return the administrative surface, not merely a 200.
//   - method bypass (case 29): the path is gated for POST but the handler answers
//     GET with its OWN validation error ("Missing parameter 'username'"), which
//     only the handler produces. The POST probe carries no body or query, but a
//     target can still act on the method alone; that is why it is gated like every
//     other non-GET probe and no "cannot mutate" guarantee is claimed.
//
// The POST and TRACE probes are non-GET methods, so they run only with the
// server's AllowStateChanging opt-in and only while skip_write_endpoints is off.
// The default path sends only the GET baseline and the header-override GETs; the
// client-IP GETs need a TRACE echo, so they also require the opt-in. The skipped
// probes are recorded instead of silently claiming they were tested.
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
// request the caller should not be able to complete, targeting a username that
// does not exist. That non-existent username is the detection premise, not a
// guarantee about how every target handles the request.
const accessModeMutation = "mutation_step"

// maxBypassRequestsPerPath bounds one path's probes: GET baseline, POST
// baseline, two header overrides, one TRACE echo, and up to three disclosed
// client-IP header spoofs.
const maxBypassRequestsPerPath = 7

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
	allowNonGET := e.cfg.AllowStateChanging && !e.cfg.SkipWriteEndpoints
	if !allowNonGET {
		if !e.cfg.AllowStateChanging {
			d.SkippedProbes = append(d.SkippedProbes,
				"POST method-bypass probe skipped: AllowStateChanging is off",
				"TRACE client-IP echo skipped: AllowStateChanging is off")
		}
		if e.cfg.SkipWriteEndpoints {
			d.SkippedProbes = append(d.SkippedProbes,
				"POST method-bypass probe skipped: skip_write_endpoints is on",
				"TRACE client-IP echo skipped: skip_write_endpoints is on")
		}
	}

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

	// 2. The gateway's view of the same path for a POST with no body/query. It is
	// still a POST and a target may act on the method alone, so this probe is
	// gated by AllowStateChanging and SkipWriteEndpoints; no mutation guarantee
	// is claimed.
	if allowNonGET {
		postResp, outcome, _ := e.do(ctx, httpengine.NewRequest("POST", job.Target.URL))
		if outcome != domain.OutcomeSuccess {
			d.PostStatus = 0 // unknown: the method comparison cannot be made
		} else {
			d.PostStatus = postResp.Status
		}
	}

	// 3. Method bypass: the POST is denied, but the GET reached the handler.
	if allowNonGET && accesscontrol.MethodBypassReached(d.PostStatus, d.GetStatus, getBody) {
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
				d.Reason = bypassReason(fmt.Sprintf("the path is denied directly (%d) but the administrative surface answered %d when %s named it — the gateway gates the URL, the origin trusts the header",
					d.GetStatus, resp.Status, header), d.SkippedProbes)
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

	// 5. Client-IP header disclosed by the server's own TRACE echo (the
	// authentication-bypass-via-information-disclosure case). The header name
	// is READ from the echo, never guessed: the lab's name is
	// application-specific. The trusted value is the loopback literal, and the
	// same denial/admin-marker rule decides. TRACE is not state-changing, but it
	// is a non-GET method: the default path does not send it.
	if allowNonGET {
		if traceResp, outcome, _ := e.do(ctx, httpengine.NewRequest("TRACE", origin+"/")); outcome == domain.OutcomeSuccess {
			for _, header := range accesscontrol.DisclosedIPHeaders(string(traceResp.Body)) {
				if ctx.Err() != nil {
					return d, domain.OutcomeCancelled, ctx.Err(), false, false
				}
				req := httpengine.GET(job.Target.URL)
				req.Headers = map[string]string{header: accesscontrol.LoopbackSpoofValue}
				resp, outcome, _ := e.do(ctx, req)
				if outcome != domain.OutcomeSuccess {
					continue
				}
				body := string(resp.Body)
				reached := accesscontrol.HeaderOverrideReached(d.GetStatus, resp.Status, body)
				d.HeaderProbes = append(d.HeaderProbes, accessControlHeaderProbe{
					Header: header, Path: path, Status: resp.Status, Reached: reached,
				})
				if reached {
					d.Verdict = domain.VerdictConfirmed
					d.Bypass = string(accesscontrol.BypassHeaderClientIP)
					d.Reason = fmt.Sprintf("the path is denied directly (%d) but answered %d when the server-disclosed header %s was set to %s — the edge trusts a client-supplied IP header it prints in its own TRACE echo",
						d.GetStatus, resp.Status, header, accesscontrol.LoopbackSpoofValue)
					e.correlate(ctx, job.ScanID, accessControlFinding{
						Key:        accessControlPathDedupKey(job.Target.URL) + "\x00clientip",
						Title:      fmt.Sprintf("Access control: client-IP header bypass reaches %s", path),
						Summary:    d.Reason,
						Severity:   domain.SeverityHigh,
						EndpointID: job.Target.EndpointID,
						Detail:     findingDetailFrom(d, nil, nil),
					}, tc.ID)
					return d, domain.OutcomeSuccess, nil, false, false
				}
			}
		}
	}

	d.Verdict = domain.VerdictRejected
	if allowNonGET {
		d.Reason = fmt.Sprintf("no bypass: direct GET %d, POST %d, and no header override reached the surface", d.GetStatus, d.PostStatus)
	} else {
		d.Reason = fmt.Sprintf("no bypass: direct GET %d; no header override reached the surface", d.GetStatus)
	}
	d.Reason = bypassReason(d.Reason, d.SkippedProbes)
	return d, domain.OutcomeSuccess, nil, false, false
}

// bypassReason appends the methods the default path deliberately did not send,
// so a Rejected or header-only result cannot be mistaken for a complete test of
// POST/TRACE behavior.
func bypassReason(reason string, skipped []string) string {
	if len(skipped) == 0 {
		return reason
	}
	return reason + " (skipped: " + strings.Join(skipped, "; ") + ")"
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

// probeRoleUsername is the username every mutation probe names. It is a fixed
// literal, not a wordlist; the probe relies on the target's own lookup failing,
// not on the scanner being able to guarantee that no handler acts on it.
const probeRoleUsername = "indago-probe-nonexistent-user"

// runMutationProbe probes cases 35 and 36. It sends POSTs, so it requires the
// server's AllowStateChanging opt-in, the per-scan EnableAdminStepProbe opt-in
// at enqueue time, and skip_write_endpoints to be off. The non-existent username
// is the detection premise; no "cannot mutate" guarantee is claimed.
//
//	step 1 (baseline): POST <origin>/admin-roles action=upgrade&username=<probe>
//	                   → the caller is refused (401/403)
//	step 2 (confirm):  the same request plus confirmed=true
//	step 2 (referer):  the same request plus Referer: <origin>/admin
//	anonymous:         the confirmed request without the session
//
// A finding needs all three: the baseline refused, at least one variant reaching
// the application handler, and the anonymous variant refused (so the gap is the
// caller's missing authorization, not a public endpoint). The non-existent
// username is expected to make the handler's own lookup fail; that observation
// is the detection premise, not a guarantee about every target handler.
func (e *accessControlExecutor) runMutationProbe(ctx context.Context, job *domain.TestJob, tc *domain.TestCase) (accessControlDetail, domain.TestOutcome, error, bool, bool) {
	d := accessControlDetail{Engine: accessControlEngine, Kind: accessModeMutation, URL: job.Target.URL}
	tc.Method, tc.URL = "POST", job.Target.URL
	if !e.cfg.AllowStateChanging {
		d.Skipped, d.SkipReason = true, "admin-step probe sends POST and AllowStateChanging is off"
		return d, domain.OutcomeSuccess, nil, false, true
	}
	if e.cfg.SkipWriteEndpoints {
		d.Skipped, d.SkipReason = true, "admin-step probe is write-like and skip_write_endpoints is on"
		return d, domain.OutcomeSuccess, nil, false, true
	}

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

// adminStepProbeEnabled is the fail-closed gate for cases 35/36. A per-scan
// EnableAdminStepProbe flag can never authorize a POST by itself: the server's
// AllowStateChanging opt-in is mandatory, and skip_write_endpoints suppresses
// the probe as well.
func adminStepProbeEnabled(cfg domain.ScanConfig, allowStateChanging bool) bool {
	return allowStateChanging && cfg.EnableAdminStepProbe && !cfg.SkipWriteEndpoints
}

// enqueueMutationProbes queues ONE admin-action probe per origin only when both
// opt-ins are present. The username it names does not exist, but that is a
// detection premise, not a mutation guarantee.
func (c *Controller) enqueueMutationProbes(ctx context.Context, scanID domain.ID) {
	sc, err := c.store.Scans().Get(ctx, scanID)
	if err != nil {
		return
	}
	if !adminStepProbeEnabled(sc.Config, c.opts.Executor.AllowStateChanging) {
		if sc.Config.EnableAdminStepProbe && !c.opts.Executor.AllowStateChanging {
			c.log.Info("admin step probe skipped: server AllowStateChanging is off", "scan", scanID)
		}
		if sc.Config.EnableAdminStepProbe && sc.Config.SkipWriteEndpoints {
			c.log.Info("admin step probe skipped: write-like endpoints disabled", "scan", scanID)
		}
		return
	}
	// Either path needs a real caller: the probe compares what the gateway
	// refuses for THIS session with what the handler accepts for it.
	if !c.idorCallerIdentity(ctx, sc) {
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
