package scan

// Cases 20 and 21: the two access-control slices that need a before/after
// differential rather than a single anonymous response.
//
//	case 20  role_flag   a client-controlled value (query parameter or cookie)
//	                      decides authorization on a privileged endpoint.
//	case 21  role_field  a profile update accepts a role field the client should
//	                      not control; a privileged surface denied before the
//	                      write must be reachable after it.
//
// Both use the SAME executor (accessControlExecutor), the SAME evidence and
// correlation helpers, the SAME privileged-surface selection, and the SAME pure
// decision rule (accesscontrol.DecideElevation). What differs — how the request
// carrying the change is built and what corroborating evidence is collected —
// is the only thing that lives in a per-case function.
//
// Boundaries:
//   - case 20 is GET only and same-origin; a cookie override is never carried
//     across an origin boundary (see scopedEngine.cookiesForURL);
//   - case 21 must have the server's AllowStateChanging opt-in and an
//     authenticated session, only ever writes the CALLER'S OWN profile, and
//     refuses a path that names another principal before sending anything.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/indago/indago/internal/accesscontrol"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/httpengine"
	"github.com/indago/indago/internal/idor"
)

// accessSurfaceTarget is one privileged endpoint the differential runs
// against. Case 20 only needs its URL; case 21 also needs the path it re-probes
// and whether discovery actually found it.
type accessSurfaceTarget struct {
	URL        string
	Path       string
	EndpointID domain.ID
	Discovered bool
}

// accessControlPrivilegedTargets returns the privileged surfaces on one
// origin: endpoints discovery already found inside a privileged area (bounded),
// and — only when there are none — the bounded conventional fallbacks. No
// wordlist, no directory brute force.
func accessControlPrivilegedTargets(origin string, endpoints []*domain.Endpoint, fallbacks []string) []accessSurfaceTarget {
	var found []accessSurfaceTarget
	seen := map[string]bool{}
	for _, ep := range endpoints {
		if ep == nil || !sameOriginURL(origin, ep.URL) || !isNavigationMethod(ep.Method) {
			continue
		}
		u, err := url.Parse(ep.URL)
		if err != nil || !accesscontrol.PrivilegedPath(u.Path) {
			continue
		}
		key := strings.ToLower(ep.URL)
		if seen[key] {
			continue
		}
		seen[key] = true
		found = append(found, accessSurfaceTarget{URL: ep.URL, Path: u.Path, EndpointID: ep.ID, Discovered: true})
	}
	sort.SliceStable(found, func(i, j int) bool { return found[i].URL < found[j].URL })
	if len(found) > maxPrivilegedTargetsPerOrigin {
		found = found[:maxPrivilegedTargetsPerOrigin]
	}
	if len(found) > 0 {
		return found
	}
	for _, path := range fallbacks {
		found = append(found, accessSurfaceTarget{URL: origin + path, Path: path})
		if len(found) >= maxPrivilegedTargetsPerOrigin {
			break
		}
	}
	return found
}

// isNavigationMethod reports whether a request for this endpoint is a plain
// document fetch the differential may repeat.
func isNavigationMethod(m domain.HTTPMethod) bool {
	switch m {
	case domain.MethodGET, domain.MethodHEAD, "":
		return true
	default:
		return false
	}
}

// accessControlOrigin normalizes a job's target URL to its scheme://host
// origin.
func accessControlOrigin(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("target %q is not an absolute URL", raw)
	}
	return strings.ToLower(u.Scheme) + "://" + u.Host, nil
}

// ---------------------------------------------------------------------------
// case 20: authorization decided by a client-controlled flag
// ---------------------------------------------------------------------------

// runRoleFlag performs the flag differential for one origin.
func (e *accessControlExecutor) runRoleFlag(ctx context.Context, job *domain.TestJob, tc *domain.TestCase) (accessControlDetail, domain.TestOutcome, error, bool, bool) {
	d := accessControlDetail{Engine: accessControlEngine, Kind: accessModeRoleFlag}
	origin, err := accessControlOrigin(job.Target.URL)
	if err != nil {
		return d, domain.OutcomeError, fmt.Errorf("access-control role-flag job has no usable origin: %w", err), true, false
	}
	d.URL = origin
	tc.URL = origin

	skip := func(reason string) (accessControlDetail, domain.TestOutcome, error, bool, bool) {
		d.Skipped, d.SkipReason, d.Reason = true, reason, reason
		return d, domain.OutcomeSuccess, nil, false, true
	}

	endpoints, err := e.store.Endpoints().ListByScan(ctx, job.ScanID)
	if err != nil {
		return d, domain.OutcomeError, fmt.Errorf("list endpoints: %w", err), true, false
	}
	params, err := e.store.Parameters().ListByScan(ctx, job.ScanID)
	if err != nil {
		return d, domain.OutcomeError, fmt.Errorf("list parameters: %w", err), true, false
	}

	targets := accessControlPrivilegedTargets(origin, endpoints, []string{"/admin"})
	flags := accesscontrol.DeriveFlags(observedAccessFlags(origin, targets, endpoints, params))
	if len(flags) == 0 {
		return skip("no client-controlled authorization flag could be derived for this origin")
	}

	d.ProbesBudget = maxAccessControlFlagProbesPerScan
	verdict := domain.VerdictInconclusive
	inconclusive := false
	var reasons []string
	confirmed := false

	for _, target := range targets {
		if ctx.Err() != nil {
			return d, domain.OutcomeCancelled, ctx.Err(), false, false
		}
		d.SurfacesTested = append(d.SurfacesTested, target.URL)

		// Baseline: the SAME privileged endpoint as the current caller. The
		// flag is absent (or at the negative value the observed URL already
		// carries), so this is what the caller can reach today.
		if !e.budget.takeFlag() {
			d.BudgetExhausted = true
			reasons = append(reasons, "the scan-wide role-flag probe budget was exhausted before every endpoint was tried")
			break
		}
		baseline, outcome, baseErr := e.do(ctx, httpengine.GET(target.URL))
		if outcome != domain.OutcomeSuccess {
			if outcome == domain.OutcomeCancelled && ctx.Err() != nil {
				return d, outcome, baseErr, false, false
			}
			reasons = append(reasons, fmt.Sprintf("baseline request to %s failed: %s", target.URL, truncate(errText(baseErr), 160)))
			continue
		}
		baseEvidence, evErr := e.persistPair(ctx, tc, baseline, "access control role-flag baseline "+target.URL)
		if evErr != nil {
			tc.Note = strings.TrimSpace(tc.Note + " | evidence incomplete: " + truncate(evErr.Error(), 200))
		}
		tc.EvidenceIDs = appendUniqueIDs(tc.EvidenceIDs, baseEvidence)
		before := acSurfaceSnapshot(baseline)
		d.BeforeStatus = baseline.Status
		d.BeforeReach = accesscontrol.ClassifySurface(baseline.Status, baseline.FinalURL, baseline.Body)

		for _, flag := range flags {
			if !e.budget.takeFlag() {
				d.BudgetExhausted = true
				reasons = append(reasons, "the scan-wide role-flag probe budget was exhausted before every flag was tried")
				break
			}
			req, buildErr := buildAccessFlagRequest(target.URL, flag)
			if buildErr != nil {
				reasons = append(reasons, buildErr.Error())
				continue
			}
			resp, outcome, reqErr := e.do(ctx, req)
			if outcome != domain.OutcomeSuccess {
				if outcome == domain.OutcomeCancelled && ctx.Err() != nil {
					return d, outcome, reqErr, false, false
				}
				d.Attempts = append(d.Attempts, accessControlAttempt{
					Kind: accessModeRoleFlag, URL: target.URL,
					FlagName: flag.Name, FlagLocation: flag.Location, FlagValue: flag.Value, FlagSource: flag.Source,
					BaselineStatus: baseline.Status, BeforeReach: d.BeforeReach,
					Outcome: string(accesscontrol.OutcomeInconclusive),
					Reason:  "request failed: " + truncate(errText(reqErr), 200),
				})
				inconclusive = true
				continue
			}
			// Evidence BEFORE the decision, so a Confirmed verdict can never
			// exist without the request/response pair that proves it.
			probeEvidence, evErr := e.persistPair(ctx, tc, resp, "access control role-flag "+flag.Describe()+" "+target.URL)
			if evErr != nil {
				tc.Note = strings.TrimSpace(tc.Note + " | evidence incomplete: " + truncate(evErr.Error(), 200))
			}
			tc.EvidenceIDs = appendUniqueIDs(tc.EvidenceIDs, probeEvidence)

			dec := accesscontrol.DecideElevation(target.URL, before, acSurfaceSnapshot(resp), "setting "+flag.Describe())
			// Evidence integrity: a Confirmed verdict must be reproducible from
			// the stored baseline and probe pairs.
			if dec.Outcome == accesscontrol.OutcomeConfirmed && e.evidence != nil &&
				(len(baseEvidence) == 0 || len(probeEvidence) == 0) {
				dec.Outcome = accesscontrol.OutcomeInconclusive
				dec.Reason = "the flag made an administrative capability reachable, but the request/response evidence pair could not be stored; not Confirmed without reproducible evidence"
			}

			d.Attempts = append(d.Attempts, accessControlAttempt{
				Kind: accessModeRoleFlag, URL: target.URL,
				FlagName: flag.Name, FlagLocation: flag.Location, FlagValue: flag.Value, FlagSource: flag.Source,
				Status: resp.Status, BaselineStatus: baseline.Status,
				BeforeReach: dec.Before, AfterReach: dec.After, Capabilities: dec.Capabilities,
				Outcome: string(dec.Outcome), Reason: dec.Reason, EvidenceIDs: probeEvidence,
			})
			reasons = append(reasons, dec.Reason)

			if dec.Outcome == accesscontrol.OutcomeConfirmed {
				d.PrivilegedURL, d.DiscoverySource = target.URL, accessControlDiscoverySource(target)
				d.FlagName, d.FlagLocation, d.FlagValue, d.FlagSource = flag.Name, flag.Location, flag.Value, flag.Source
				d.AfterStatus, d.AfterReach, d.Capabilities = resp.Status, dec.After, dec.Capabilities
				d.Verdict, d.Reason = domain.VerdictConfirmed, dec.Reason
				verdict = domain.VerdictConfirmed
				confirmed = true
				break
			}
			if dec.Outcome == accesscontrol.OutcomeInconclusive {
				inconclusive = true
			}
		}
		if confirmed {
			break // one proven flag escalation is enough; stop spending requests
		}
	}

	if !confirmed {
		switch {
		case inconclusive:
			verdict = domain.VerdictInconclusive
		case len(d.Attempts) > 0:
			verdict = domain.VerdictRejected
		default:
			verdict = domain.VerdictInconclusive
		}
		d.Verdict = verdict
		d.Reason = joinReasons(reasons)
		if d.Reason == "" {
			d.Reason = "no role-flag differential result was produced"
		}
	}
	d.ProbesLeft = e.budget.flagRemaining()

	if d.Verdict == domain.VerdictConfirmed {
		evidence := appendUniqueIDs(nil, d.AnonymousEvidence)
		for _, a := range d.Attempts {
			if a.Outcome == string(accesscontrol.OutcomeConfirmed) {
				evidence = appendUniqueIDs(evidence, a.EvidenceIDs)
			}
		}
		evidence = appendUniqueIDs(evidence, d.NonAdminEvidence)
		e.correlate(ctx, job.ScanID, accessControlFinding{
			Key:             roleFlagFindingDedupKey(d.URL, d.FlagName, d.FlagLocation),
			Title:           fmt.Sprintf("Access control: the %s %q grants administrative access to %s", flagKind(d.FlagLocation), d.FlagName, endpointLabel(d.PrivilegedURL)),
			Summary:         d.Reason,
			Severity:        domain.SeverityHigh,
			EndpointID:      targetEndpointID(d),
			DiscoverySource: d.DiscoverySource,
			Detail:          findingDetailFromDifferential(d),
			Evidence:        evidence,
		}, tc.ID)
	}
	return d, domain.OutcomeSuccess, nil, false, false
}

// buildAccessFlagRequest builds the SAME privileged request with the flag set.
// The URL is derived from the target's OWN URL, so a query flag is never placed
// on a request to another origin; a cookie override is scoped by the engine's
// own origin rule.
func buildAccessFlagRequest(privilegedURL string, f accesscontrol.Flag) (*httpengine.Request, error) {
	raw, err := accesscontrol.FlagRequestURL(privilegedURL, f)
	if err != nil {
		return nil, err
	}
	req := httpengine.GET(raw)
	switch f.Location {
	case accesscontrol.LocationQuery:
	case accesscontrol.LocationCookie:
		// Appended as an override only: scopedEngine keeps every other session
		// cookie and lets this one win over a same-named stored cookie for THIS
		// origin. It is not carried to a different origin on a redirect.
		req.Cookies = []*http.Cookie{{Name: f.Name, Value: f.Value}}
	default:
		return nil, fmt.Errorf("unsupported flag location %q", f.Location)
	}
	if !sameOriginURL(privilegedURL, req.URL) {
		return nil, fmt.Errorf("refusing to set %s on a different origin (%s)", f.Describe(), req.URL)
	}
	return req, nil
}

// observedAccessFlags collects the client-controlled authorization flags the
// scan already saw: role-shaped query parameters ON the privileged endpoints,
// and role-shaped non-session cookies the scan's session carries for THIS
// origin. Cookie position is not endpoint-specific (a cookie applies
// origin-wide), so a cookie discovered on any endpoint of this origin
// qualifies; a query parameter is only meaningful on the endpoint that carries
// it.
func observedAccessFlags(origin string, targets []accessSurfaceTarget, endpoints []*domain.Endpoint, params []*domain.Parameter) []accesscontrol.Observed {
	privileged := map[domain.ID]bool{}
	for _, t := range targets {
		if !t.EndpointID.Empty() {
			privileged[t.EndpointID] = true
		}
	}
	originOfEndpoint := map[domain.ID]bool{}
	for _, ep := range endpoints {
		if ep != nil && sameOriginURL(origin, ep.URL) {
			originOfEndpoint[ep.ID] = true
		}
	}

	var out []accesscontrol.Observed
	seen := map[string]bool{}
	add := func(o accesscontrol.Observed) {
		key := string(o.Location) + "\x00" + strings.ToLower(o.Name)
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, o)
	}
	for _, p := range params {
		if p == nil || !accesscontrol.RoleName(p.Name) {
			continue
		}
		switch p.Location {
		case domain.LocationCookie:
			if originOfEndpoint[p.EndpointID] {
				add(accesscontrol.Observed{Name: p.Name, Location: accesscontrol.LocationCookie, Value: p.Example})
			}
		case domain.LocationQuery:
			if privileged[p.EndpointID] {
				add(accesscontrol.Observed{Name: p.Name, Location: accesscontrol.LocationQuery, Value: p.Example})
			}
		}
	}
	return out
}

func roleFlagFindingDedupKey(origin, flagName string, location accesscontrol.Location) string {
	return "access_control\x00role_flag\x00" + strings.ToLower(origin) + "\x00" +
		string(location) + ":" + strings.ToLower(flagName)
}

func flagKind(l accesscontrol.Location) string {
	if l == accesscontrol.LocationCookie {
		return "cookie"
	}
	return "request parameter"
}

// targetEndpointID is the privileged endpoint's ID when discovery found it.
// The conventional fallback path was never discovered, so it has none.
func targetEndpointID(d accessControlDetail) domain.ID {
	for _, t := range d.SurfacesTested {
		if t == d.PrivilegedURL {
			return d.EndpointID
		}
	}
	return d.EndpointID
}

func accessControlDiscoverySource(t accessSurfaceTarget) domain.DiscoverySource {
	if t.Discovered {
		return domain.SourceCrawler
	}
	return ""
}

// ---------------------------------------------------------------------------
// case 21: a profile update that accepts a role field
// ---------------------------------------------------------------------------

// runRoleField tests ONE profile-update endpoint: re-read the caller's own
// profile, prove a privileged surface is denied, add a role field to the
// update, and re-probe the same surface.
func (e *accessControlExecutor) runRoleField(ctx context.Context, job *domain.TestJob, tc *domain.TestCase) (accessControlDetail, domain.TestOutcome, error, bool, bool) {
	ep, params, _, err := resolveJobTarget(ctx, e.store, job)
	if err != nil {
		return accessControlDetail{Engine: accessControlEngine, Kind: accessModeRoleField}, domain.OutcomeError, err, true, false
	}
	tc.Method, tc.URL = string(ep.Method), ep.URL
	d := accessControlDetail{Engine: accessControlEngine, Kind: accessModeRoleField,
		Method: ep.Method, URL: ep.URL, DiscoverySource: ep.Source}
	skip := func(reason string) (accessControlDetail, domain.TestOutcome, error, bool, bool) {
		d.Skipped, d.SkipReason, d.Reason = true, reason, reason
		return d, domain.OutcomeSuccess, nil, false, true
	}

	// State-changing guard: no request at all is sent unless the operator
	// explicitly opted into writes (AGENTS.md §2). Scan creation refuses to
	// enable this mode without the opt-in; this is the job-level enforcement.
	if !e.cfg.AllowStateChanging {
		return skip(fmt.Sprintf("%s %s is state-changing and AllowStateChanging is off", ep.Method, endpointLabel(ep.URL)))
	}
	if !hasBody(ep.Method) {
		return skip(fmt.Sprintf("method %s carries no request body; the role-field slice needs a form/JSON profile update", ep.Method))
	}
	if !accesscontrol.ProfileUpdateEndpoint(ep.Method, ep.URL, params) {
		return skip("the endpoint is not a form/JSON profile update on a profile path")
	}
	if loc, ok := accessUpdateLocation(params); ok {
		d.Method, d.URL = loc.method, ep.URL
	}

	profile, reason, outcome, reqErr := e.callerProfile(ctx, tc, ep)
	if profile == nil {
		if outcome != domain.OutcomeSuccess {
			return d, outcome, reqErr, false, false
		}
		return skip(reason)
	}
	d.RoleField, d.RoleValueBefore = profile.roleField, profile.roleValue

	// Never modify another principal's profile: a path that names somebody
	// else is refused before a single request is built.
	callerValues := make([]string, 0, len(profile.identity.Fields))
	for _, f := range profile.identity.Fields {
		callerValues = append(callerValues, f.Value)
	}
	if ok, why := accesscontrol.OwnProfilePath(ep.URL, callerValues); !ok {
		return skip(why)
	}

	// Prove a privileged surface is denied BEFORE the write. Without a denied
	// starting point no later observation can be attributed to the update.
	endpoints, _ := e.store.Endpoints().ListByScan(ctx, job.ScanID)
	surfaces := accessControlPrivilegedTargets(accessControlOriginOf(ep.URL), endpoints, accesscontrol.PrivilegedPaths)
	before, reason, outcome, reqErr := e.deniedSurface(ctx, tc, surfaces)
	if before == nil {
		if outcome != domain.OutcomeSuccess {
			return d, outcome, reqErr, false, false
		}
		return skip(reason)
	}
	d.PrivilegedURL, d.SurfacesTested = before.target.URL, surfaceURLs(surfaces)
	d.BeforeStatus, d.BeforeReach = before.status, before.reach

	fields := accesscontrol.CandidateFields(endpointRoleNames(params), accesscontrol.RoleFieldNames(profile.body))
	if len(fields) == 0 {
		return skip("no role-bearing field name could be derived for this profile update")
	}

	d.ProbesBudget = accesscontrol.MaxWritesPerScan
	var reasons []string
	confirmed, inconclusive := false, false
	for _, f := range fields {
		if !e.budget.takeWrite() {
			d.BudgetExhausted = true
			reasons = append(reasons, "the scan-wide profile-update write budget was exhausted before every field name was tried")
			break
		}
		a := e.roleFieldAttempt(ctx, tc, ep, params, profile, before, f)
		d.Attempts = append(d.Attempts, a)
		reasons = append(reasons, a.Reason)
		switch a.Outcome {
		case string(accesscontrol.OutcomeConfirmed):
			confirmed = true
			d.RoleField, d.RoleFieldFrom = f.Name, f.Source
			d.RoleValueAfter, d.ProfileChange = a.FieldValue, string(accesscontrol.ProfileChanged)
			d.AfterStatus, d.AfterReach, d.Capabilities = a.Status, a.AfterReach, a.Capabilities
		case string(accesscontrol.OutcomeInconclusive):
			inconclusive = true
		}
		if confirmed {
			break
		}
		if a.Outcome == string(accesscontrol.OutcomeInconclusive) && a.Status == 0 {
			// The write itself never completed (transport/redirect failure):
			// further writes would hit the same wall.
			break
		}
	}

	d.ProbesLeft = e.budget.writeRemaining()
	switch {
	case confirmed:
		d.Verdict = domain.VerdictConfirmed
	case inconclusive:
		d.Verdict = domain.VerdictInconclusive
	case len(d.Attempts) > 0:
		d.Verdict = domain.VerdictRejected
	default:
		d.Verdict = domain.VerdictInconclusive
		reasons = append(reasons, "no profile update was sent")
	}
	d.Reason = joinReasons(reasons)

	if d.Verdict == domain.VerdictConfirmed {
		var evidence []domain.ID
		evidence = appendUniqueIDs(evidence, before.evidence)
		for _, a := range d.Attempts {
			if a.Outcome == string(accesscontrol.OutcomeConfirmed) {
				evidence = appendUniqueIDs(evidence, a.EvidenceIDs)
			}
		}
		e.correlate(ctx, job.ScanID, accessControlFinding{
			Key:             roleFieldFindingDedupKey(ep),
			Title:           fmt.Sprintf("Access control: %s %s accepted a client-controlled %q field and unlocked %s", ep.Method, endpointLabel(ep.URL), d.RoleField, endpointLabel(before.target.URL)),
			Summary:         d.Reason,
			Severity:        domain.SeverityHigh,
			EndpointID:      ep.ID,
			DiscoverySource: ep.Source,
			Detail:          findingDetailFromDifferential(d),
			Evidence:        evidence,
		}, tc.ID)
	}
	return d, domain.OutcomeSuccess, nil, false, false
}

// roleFieldAttempt sends ONE profile update carrying the candidate role field,
// then re-reads the caller's profile and re-probes the same privileged surface.
func (e *accessControlExecutor) roleFieldAttempt(ctx context.Context, tc *domain.TestCase, ep *domain.Endpoint,
	params []*domain.Parameter, profile *callerProfile, before *accessSurface, f accesscontrol.Field) accessControlAttempt {

	a := accessControlAttempt{Kind: accessModeRoleField, URL: ep.URL, Field: f.Name, FieldValue: f.Value, FieldKind: string(f.Kind)}
	a.BeforeReach = before.reach
	a.BaselineStatus = before.status

	req, err := buildRequest(ep, params, nil)
	if err != nil {
		a.Outcome, a.Reason = string(accesscontrol.OutcomeInconclusive), "build profile update: "+truncate(err.Error(), 200)
		return a
	}
	if err := addAccessUpdateField(req, f); err != nil {
		a.Outcome, a.Reason = string(accesscontrol.OutcomeInconclusive), "encode "+f.Name+" into the profile update: "+truncate(err.Error(), 200)
		return a
	}

	resp, outcome, reqErr := e.do(ctx, req)
	a.Status = statusOf(resp)
	if outcome != domain.OutcomeSuccess {
		a.Outcome = string(accesscontrol.OutcomeInconclusive)
		a.Reason = fmt.Sprintf("the profile update carrying %q failed: %s", f.Name, truncate(errText(reqErr), 200))
		return a
	}
	if ids, evErr := e.persistPair(ctx, tc, resp, "access control profile update "+f.Name); evErr != nil {
		tc.Note = strings.TrimSpace(tc.Note + " | evidence incomplete: " + truncate(evErr.Error(), 200))
	} else {
		a.EvidenceIDs = appendUniqueIDs(a.EvidenceIDs, ids)
		tc.EvidenceIDs = appendUniqueIDs(tc.EvidenceIDs, ids)
	}

	// A login page in place of the update means the session could not write
	// the profile at all: nothing about roles was exercised.
	if idor.LooksLikeLoginPage(resp.Body) {
		a.Outcome = string(accesscontrol.OutcomeInconclusive)
		a.Reason = "the profile update response was a login page: the session did not reach the profile"
		return a
	}

	// Corroborating evidence only: whether the caller's own profile shows the
	// new role. It never decides the verdict.
	change, roleAfter, profileEvidence := e.profileAfter(ctx, tc, profile)
	a.FieldValue, a.ProfileChange = roleAfter, string(change)
	a.EvidenceIDs = appendUniqueIDs(a.EvidenceIDs, profileEvidence)

	after := e.probeSurface(ctx, tc, before.target)
	if after == nil {
		a.Outcome = string(accesscontrol.OutcomeInconclusive)
		a.Reason = "the privileged surface could not be re-probed after the update"
		return a
	}
	a.Status, a.AfterReach, a.Capabilities = after.status, after.reach, after.capabilities
	a.EvidenceIDs = appendUniqueIDs(a.EvidenceIDs, after.evidence)

	dec := accesscontrol.DecideElevation(before.target.URL, before.snapshot, after.snapshot,
		fmt.Sprintf("the profile update carrying %q=%q", f.Name, f.Value))
	a.Outcome, a.Reason = string(dec.Outcome), dec.Reason
	a.BeforeReach, a.AfterReach, a.Capabilities = dec.Before, dec.After, dec.Capabilities
	switch change {
	case accesscontrol.ProfileChanged:
		a.Reason += fmt.Sprintf("; the caller's own profile %s changed from %q to %q", profile.roleField, profile.roleValue, roleAfter)
	case accesscontrol.ProfileUnchanged:
		if profile.roleField != "" {
			a.Reason += fmt.Sprintf("; the caller's own profile %s is still %q", profile.roleField, roleAfter)
		}
	}
	return a
}

// callerProfile is the caller's own profile as observed before the write.
type callerProfile struct {
	source    string
	body      []byte
	identity  idor.Identity
	roleField string
	roleValue string
	evidence  []domain.ID
}

// accessSurface is one privileged-surface probe.
type accessSurface struct {
	target       accessSurfaceTarget
	status       int
	reach        accesscontrol.Reach
	snapshot     accesscontrol.Snapshot
	evidence     []domain.ID
	capabilities []accesscontrol.Action
}

// callerProfile establishes WHO the caller is from the target itself, using
// only the scan's own session and bounded, common account paths (plus the
// endpoint's own path as a REST-style fallback). No identity means no test:
// this slice refuses to modify an account it cannot attribute to the caller.
func (e *accessControlExecutor) callerProfile(ctx context.Context, tc *domain.TestCase, ep *domain.Endpoint) (*callerProfile, string, domain.TestOutcome, error) {
	origin := accessControlOriginOf(ep.URL)
	if origin == "" {
		return nil, "the endpoint URL has no usable origin", domain.OutcomeSuccess, nil
	}
	paths := []string{"/my-account", "/profile", "/account", "/me"}
	if u, err := url.Parse(ep.URL); err == nil && u.Path != "" {
		paths = append(paths, u.Path)
	}
	var tried []string
	for _, path := range paths {
		u := origin + path
		tried = append(tried, path)
		resp, outcome, reqErr := e.do(ctx, httpengine.GET(u))
		if outcome != domain.OutcomeSuccess {
			if outcome == domain.OutcomeCancelled && ctx.Err() != nil {
				return nil, "", outcome, reqErr
			}
			continue
		}
		if resp.Status < 200 || resp.Status >= 300 {
			continue
		}
		if idor.LooksLikeLoginPage(resp.Body) {
			return nil, "the account page is a login page: the session is not authenticated", domain.OutcomeSuccess, nil
		}
		ident := idor.ExtractIdentity(resp.Body)
		if ident.Empty() {
			continue
		}
		p := &callerProfile{source: u, body: resp.Body, identity: ident}
		if names := accesscontrol.RoleFieldNames(resp.Body); len(names) > 0 {
			p.roleField = names[0]
			p.roleValue, _ = accesscontrol.RoleValue(resp.Body, p.roleField)
		}
		if ids, evErr := e.persistPair(ctx, tc, resp, "access control caller profile baseline"); evErr != nil {
			tc.Note = strings.TrimSpace(tc.Note + " | evidence incomplete: " + truncate(evErr.Error(), 200))
		} else {
			p.evidence = ids
			tc.EvidenceIDs = appendUniqueIDs(tc.EvidenceIDs, ids)
		}
		return p, "", domain.OutcomeSuccess, nil
	}
	return nil, fmt.Sprintf("caller identity could not be established from the target with this session (tried %s)", strings.Join(tried, ", ")), domain.OutcomeSuccess, nil
}

// profileAfter re-reads the caller's own profile after the update and reports
// whether the role field the profile itself exposes changed. It never fails the
// attempt: the privileged surface is the verdict gate.
func (e *accessControlExecutor) profileAfter(ctx context.Context, tc *domain.TestCase, profile *callerProfile) (accesscontrol.ProfileChange, string, []domain.ID) {
	if profile.roleField == "" {
		return accesscontrol.ProfileUnknown, "", nil
	}
	resp, outcome, _ := e.do(ctx, httpengine.GET(profile.source))
	if outcome != domain.OutcomeSuccess || resp == nil || resp.Status < 200 || resp.Status >= 300 || idor.LooksLikeLoginPage(resp.Body) {
		return accesscontrol.ProfileUnknown, "", nil
	}
	var ids []domain.ID
	if ev, err := e.persistPair(ctx, tc, resp, "access control caller profile after update"); err == nil {
		ids = ev
		tc.EvidenceIDs = appendUniqueIDs(tc.EvidenceIDs, ev)
	}
	after, ok := accesscontrol.RoleValue(resp.Body, profile.roleField)
	if !ok {
		return accesscontrol.ProfileUnknown, "", ids
	}
	if after == profile.roleValue {
		return accesscontrol.ProfileUnchanged, after, ids
	}
	return accesscontrol.ProfileChanged, after, ids
}

// deniedSurface finds the ONE privileged surface that is explicitly denied for
// the current session. A surface that is already reachable cannot be attributed
// to a later update, so it aborts the job instead.
func (e *accessControlExecutor) deniedSurface(ctx context.Context, tc *domain.TestCase, surfaces []accessSurfaceTarget) (*accessSurface, string, domain.TestOutcome, error) {
	var notes []string
	for _, target := range surfaces {
		obs, outcome, reqErr := e.probeSurfaceDetailed(ctx, tc, target)
		if outcome != domain.OutcomeSuccess {
			if outcome == domain.OutcomeCancelled && ctx.Err() != nil {
				return nil, "", outcome, reqErr
			}
			continue
		}
		switch obs.reach {
		case accesscontrol.ReachDenied:
			return obs, "", domain.OutcomeSuccess, nil
		case accesscontrol.ReachGranted:
			return nil, fmt.Sprintf("the privileged surface %s is already reachable (HTTP %d) before any update; access cannot be attributed to a role field", target.URL, obs.status), domain.OutcomeSuccess, nil
		default:
			notes = append(notes, fmt.Sprintf("%s HTTP %d (%s)", target.URL, obs.status, obs.reach))
		}
	}
	return nil, "no privileged surface was explicitly denied before the update: " + strings.Join(notes, ", "), domain.OutcomeSuccess, nil
}

func (e *accessControlExecutor) probeSurface(ctx context.Context, tc *domain.TestCase, target accessSurfaceTarget) *accessSurface {
	obs, outcome, _ := e.probeSurfaceDetailed(ctx, tc, target)
	if outcome != domain.OutcomeSuccess {
		return nil
	}
	return obs
}

// probeSurfaceDetailed re-probes one privileged surface through the scan's
// scope-enforcing engine and classifies the response.
func (e *accessControlExecutor) probeSurfaceDetailed(ctx context.Context, tc *domain.TestCase, target accessSurfaceTarget) (*accessSurface, domain.TestOutcome, error) {
	resp, outcome, reqErr := e.do(ctx, httpengine.GET(target.URL))
	if outcome != domain.OutcomeSuccess {
		return nil, outcome, reqErr
	}
	obs := &accessSurface{target: target, status: resp.Status,
		reach:    accesscontrol.ClassifySurface(resp.Status, resp.FinalURL, resp.Body),
		snapshot: acSurfaceSnapshot(resp), capabilities: accesscontrol.Analyze(acSurfaceSnapshot(resp)).Actions}
	if ids, evErr := e.persistPair(ctx, tc, resp, "access control privileged surface "+target.URL); evErr != nil {
		tc.Note = strings.TrimSpace(tc.Note + " | evidence incomplete: " + truncate(evErr.Error(), 200))
	} else {
		obs.evidence = ids
		tc.EvidenceIDs = appendUniqueIDs(tc.EvidenceIDs, ids)
	}
	return obs, domain.OutcomeSuccess, nil
}

func surfaceURLs(surfaces []accessSurfaceTarget) []string {
	out := make([]string, 0, len(surfaces))
	for _, s := range surfaces {
		out = append(out, s.URL)
	}
	return out
}

func accessControlOriginOf(raw string) string {
	o, err := accessControlOrigin(raw)
	if err != nil {
		return ""
	}
	return o
}

func roleFieldFindingDedupKey(ep *domain.Endpoint) string {
	return "access_control\x00role_field\x00" + string(ep.Method) + "\x00" + ep.URL
}

// endpointRoleNames returns the role-bearing parameter names already observed
// on the update endpoint, in deterministic order.
func endpointRoleNames(params []*domain.Parameter) []string {
	var out []string
	sorted := append([]*domain.Parameter(nil), params...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	for _, p := range sorted {
		if p != nil && (p.Location == domain.LocationForm || p.Location == domain.LocationJSON) && accesscontrol.RoleName(p.Name) {
			out = append(out, p.Name)
		}
	}
	return out
}

// updateLocation reports which body kind the endpoint actually carries, so the
// detail record says form or JSON rather than guessing.
func accessUpdateLocation(params []*domain.Parameter) (struct {
	method domain.HTTPMethod
	loc    domain.ParamLocation
}, bool) {
	var out struct {
		method domain.HTTPMethod
		loc    domain.ParamLocation
	}
	for _, p := range params {
		if p != nil && p.Location == domain.LocationForm {
			out.loc = domain.LocationForm
			return out, true
		}
	}
	for _, p := range params {
		if p != nil && p.Location == domain.LocationJSON {
			out.loc = domain.LocationJSON
			return out, true
		}
	}
	return out, false
}

// addAccessUpdateField adds (or overrides) one field in a form or JSON body. It
// preserves the request's observed content type and every other field.
func addAccessUpdateField(req *httpengine.Request, f accesscontrol.Field) error {
	ct := strings.ToLower(req.ContentType)
	switch {
	case strings.Contains(ct, "json"):
		body := map[string]json.RawMessage{}
		if len(bytes.TrimSpace(req.Body)) > 0 {
			if err := json.Unmarshal(req.Body, &body); err != nil {
				return fmt.Errorf("the observed body is not a JSON object: %w", err)
			}
		}
		raw, err := f.RawValue()
		if err != nil {
			return err
		}
		body[f.Name] = raw
		b, err := json.Marshal(body) // map keys marshal sorted
		if err != nil {
			return err
		}
		req.Body = b
		return nil
	case strings.Contains(ct, "x-www-form-urlencoded") || ct == "":
		vals, err := url.ParseQuery(string(req.Body))
		if err != nil {
			return err
		}
		vals.Set(f.Name, f.Value)
		req.Body = []byte(vals.Encode())
		if req.ContentType == "" {
			req.ContentType = "application/x-www-form-urlencoded"
		}
		return nil
	default:
		return fmt.Errorf("unsupported body content type %q", req.ContentType)
	}
}

// findingDetailFromDifferential maps a differential detail onto the correlated
// record.
func findingDetailFromDifferential(d accessControlDetail) accessControlFindingDetail {
	return accessControlFindingDetail{
		Kind: d.Kind, Method: d.Method, URL: d.URL, DiscoverySource: d.DiscoverySource,
		PrivilegedURL: d.PrivilegedURL,
		FlagName:      d.FlagName, FlagLocation: d.FlagLocation, FlagValue: d.FlagValue, FlagSource: d.FlagSource,
		RoleField: d.RoleField, RoleValueBefore: d.RoleValueBefore, RoleValueAfter: d.RoleValueAfter,
		BeforeStatus: d.BeforeStatus, AfterStatus: d.AfterStatus,
		BeforeReach: d.BeforeReach, AfterReach: d.AfterReach,
		Capabilities: d.Capabilities, Actions: d.Actions,
		Attempts: d.Attempts, Verdict: domain.VerdictConfirmed, Reason: d.Reason,
		PageURL: d.PageURL, Refs: d.Refs,
	}
}

// ---------------------------------------------------------------------------
// probe passes for cases 20 and 21
// ---------------------------------------------------------------------------

// enqueueRoleFlagProbes queues one role-flag differential per discovered
// origin, for a scan that explicitly opted in.
func (c *Controller) enqueueRoleFlagProbes(ctx context.Context, scanID domain.ID) {
	sc, err := c.store.Scans().Get(ctx, scanID)
	if err != nil {
		c.log.Warn("access-control role-flag probes: load scan", "scan", scanID, "err", err)
		return
	}
	if !sc.Config.EnableRoleParam {
		return
	}
	origins, err := c.accessControlOrigins(ctx, scanID, sc)
	if err != nil {
		c.log.Warn("access-control role-flag probes: origins", "scan", scanID, "err", err)
		return
	}
	done := c.accessControlDone(ctx, scanID, accessModeRoleFlag, func(d accessControlDetail) string { return d.URL })

	now := time.Now()
	for _, origin := range origins {
		if done[origin] {
			continue
		}
		job := &domain.TestJob{
			ID: domain.NewID(), ScanID: scanID, Type: domain.JobAccessControl, State: domain.JobQueued,
			Priority: 25, Target: domain.JobTarget{URL: origin},
			Payload:     accessControlModePayload(accessModeRoleFlag),
			MaxAttempts: 2, AvailableAt: now, CreatedAt: now, UpdatedAt: now,
		}
		if err := c.queue.Enqueue(ctx, job); err != nil {
			c.log.Warn("access-control role-flag probes: enqueue job", "scan", scanID, "origin", origin, "err", err)
			continue
		}
	}
}

// enqueueRoleFieldProbes queues one role-field test per plausible profile-update
// endpoint, for a scan that explicitly opted into the write.
func (c *Controller) enqueueRoleFieldProbes(ctx context.Context, scanID domain.ID) {
	sc, err := c.store.Scans().Get(ctx, scanID)
	if err != nil {
		c.log.Warn("access-control role-field probes: load scan", "scan", scanID, "err", err)
		return
	}
	if !sc.Config.EnableRoleWrite {
		return
	}
	endpoints, err := c.store.Endpoints().ListByScan(ctx, scanID)
	if err != nil {
		c.log.Warn("access-control role-field probes: list endpoints", "scan", scanID, "err", err)
		return
	}
	params, err := c.store.Parameters().ListByScan(ctx, scanID)
	if err != nil {
		c.log.Warn("access-control role-field probes: list parameters", "scan", scanID, "err", err)
		return
	}
	byEndpoint := map[domain.ID][]*domain.Parameter{}
	for _, p := range params {
		byEndpoint[p.EndpointID] = append(byEndpoint[p.EndpointID], p)
	}
	sort.SliceStable(endpoints, func(i, j int) bool { return endpoints[i].URL < endpoints[j].URL })
	done := c.accessControlDone(ctx, scanID, accessModeRoleField, func(d accessControlDetail) string { return d.URL })

	now := time.Now()
	n := 0
	for _, ep := range endpoints {
		if n >= accesscontrol.MaxTargetsPerScan {
			break
		}
		if ep == nil || done[ep.URL] {
			continue
		}
		if !accesscontrol.ProfileUpdateEndpoint(ep.Method, ep.URL, byEndpoint[ep.ID]) {
			continue
		}
		job := &domain.TestJob{
			ID: domain.NewID(), ScanID: scanID, Type: domain.JobAccessControl, State: domain.JobQueued,
			Priority: 25, Target: domain.JobTarget{EndpointID: ep.ID, URL: ep.URL},
			Payload:     accessControlModePayload(accessModeRoleField),
			MaxAttempts: 2, AvailableAt: now, CreatedAt: now, UpdatedAt: now,
		}
		if err := c.queue.Enqueue(ctx, job); err != nil {
			c.log.Warn("access-control role-field probes: enqueue job", "scan", scanID, "url", ep.URL, "err", err)
			continue
		}
		n++
	}
	if n > 0 {
		c.log.Info("access-control role-field probes: enqueued", "scan", scanID, "jobs", n)
	}
}

// accessControlOrigins returns the bounded, deterministic set of origins the
// differential probes: the origins discovery actually reached, falling back to
// the scan's seeds when discovery found nothing at all.
func (c *Controller) accessControlOrigins(ctx context.Context, scanID domain.ID, sc *domain.Scan) ([]string, error) {
	endpoints, err := c.store.Endpoints().ListByScan(ctx, scanID)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []string
	add := func(raw string) {
		o, err := accessControlOrigin(raw)
		if err != nil || seen[o] || len(out) >= maxRoleFlagOrigins {
			return
		}
		seen[o] = true
		out = append(out, o)
	}
	for _, ep := range endpoints {
		if ep != nil {
			add(ep.URL)
		}
	}
	if len(out) == 0 && sc != nil {
		for _, seed := range sc.SeedURLs {
			add(seed)
		}
	}
	sort.Strings(out)
	return out, nil
}

// accessControlDone reports which sites a previous execution already tested, so
// a resumed scan does not re-send the differential (or the write).
func (c *Controller) accessControlDone(ctx context.Context, scanID domain.ID, mode string, key func(accessControlDetail) string) map[string]bool {
	done := map[string]bool{}
	cases, err := c.store.TestCases().ListByScan(ctx, scanID)
	if err != nil {
		return done
	}
	for _, tc := range cases {
		if tc.VulnClass != domain.VulnAccessControl || len(tc.Detail) == 0 {
			continue
		}
		var d accessControlDetail
		if json.Unmarshal(tc.Detail, &d) != nil || d.Kind != mode {
			continue
		}
		if k := key(d); k != "" {
			done[k] = true
		}
	}
	return done
}
