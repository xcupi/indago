package scan

// This file implements the browser-backed DOM-XSS detection engine — see
// docs/dom-xss.md for the full design and its explicit scope boundary.
// Reflected XSS only inspects the SERVER's HTTP response body; a page's OWN
// client-side JavaScript can instead read sources such as location.hash,
// location.search, window.name, postMessage, document.referrer, or web storage
// and feed them to a dangerous sink. That browser-only data flow is outside
// the response-based pipeline.
//
// This engine actually renders the page in a real browser, lets its OWN
// JavaScript run, and observes the live DOM/JS runtime. Every navigation it
// performs goes through the SAME scope-enforcing browser.Manager the rest of
// the product already uses (AllowRequest is checked on every request, exactly
// like discovery and Reflected XSS verification).
//
// Implemented scope (deliberately narrow — see docs/dom-xss.md):
//   - seven sources: hash, query, window.name, postMessage, document.referrer,
//     localStorage, and sessionStorage.
//   - query probes each distinct discovered query name; storage probes keys
//     present in target-origin storage or requested by the page's getItem calls
//     (capped at 32 per backend/endpoint).
//   - bounded HTML injection (innerHTML/outerHTML, document.write/writeln,
//     insertAdjacentHTML, createContextualFragment) and primitive-string
//     setTimeout/setInterval handlers — see detection.DOMXSSSink.
//   - at most one reachable sink is verified per endpoint/source/selector
//     pass: if a page reaches more than one hooked sink, only the first (by
//     whichever the page happened to call first) is tested.
//
// Two-phase design, mirroring Reflected XSS's reflect-then-verify split:
//  1. REACHABILITY (canary): inject a benign, inert canary through the selected
//     source using its source-specific navigation mechanism, with an init-script
//     harness installed before the page's own scripts run. The harness reports
//     via a uniquely-prefixed console.log whenever a canary-containing value
//     reaches a hooked sink. Reachability is not itself a confirmed finding.
//  2. VERIFICATION (real payload): after a reachable pair is found, build the
//     sink-specific candidate (marker image for HTML; bare marker expression
//     for string timers) and repeat
//     the source-specific navigation. Confirm only on the exact same
//     deterministic browser signal Reflected XSS verification uses
//     (verification.MatchExecutionSignal / verification.Decide), attributed
//     strictly to this navigation.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/indago/indago/internal/ratelimit"
	"html"
	"log/slog"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/evidence"
	"github.com/indago/indago/internal/store"
	"github.com/indago/indago/internal/verification"
	"github.com/indago/indago/internal/worker"
)

// ---------------------------------------------------------------------------
// job payload + the one-time, scan-wide enqueue pass
// ---------------------------------------------------------------------------

// domXSSJob is the JobDOMXSS queue payload: which endpoint and which
// client-side SOURCE to probe (one job per (endpoint, source) — see
// enqueueDOMXSSProbes). The sink is never part of the job: it is
// discovered during phase 1, not chosen in advance.
type domXSSJob struct {
	EndpointID domain.ID `json:"endpoint_id"`
	// Source is retained for jobs created before grouping. New jobs carry
	// Sources and run every implemented source in one endpoint-level job.
	Source  detection.DOMXSSSource   `json:"source,omitempty"`
	Sources []detection.DOMXSSSource `json:"sources,omitempty"`
}

// sourceList returns the job's sources in deterministic order, accepting the
// legacy single-source payload used by older scans and retries.
func (j domXSSJob) sourceList() []detection.DOMXSSSource {
	out := make([]detection.DOMXSSSource, 0, len(j.Sources)+1)
	seen := map[detection.DOMXSSSource]bool{}
	for _, source := range j.Sources {
		if source.IsValid() && !seen[source] {
			out = append(out, source)
			seen[source] = true
		}
	}
	if len(out) == 0 && j.Source.IsValid() {
		out = append(out, j.Source)
	}
	return out
}

func parseDOMXSSJob(job *domain.TestJob) (domXSSJob, error) {
	var dj domXSSJob
	if len(job.Payload) == 0 {
		return dj, errors.New("dom-xss job has no payload")
	}
	if err := json.Unmarshal(job.Payload, &dj); err != nil {
		return dj, fmt.Errorf("decode dom-xss job payload: %w", err)
	}
	if dj.EndpointID.Empty() || len(dj.sourceList()) == 0 {
		return dj, errors.New("dom-xss job payload incomplete")
	}
	return dj, nil
}

// domXSSNavigable reports whether method is safe to probe by browser GET
// navigation: ordinary GET/HEAD (navigating to a URL is ALWAYS a GET
// request, so a discovered POST/PUT/… endpoint is never probed this way —
// doing so would not exercise the method the operator actually cares
// about, and could be state-changing without the explicit opt-in that
// guards every other state-changing request in this product).
func domXSSNavigable(m domain.HTTPMethod) bool {
	switch m {
	case domain.MethodGET, domain.MethodHEAD, "":
		return true
	default:
		return false
	}
}

// domXSSContentTypeAllowsDOM reports whether a discovered endpoint's response
// media type can host a DOM at all. A non-HTML media type (an image, PDF, JSON,
// XML, plain text, …) carries no HTML document and therefore no DOM sink, so
// browser-probing it can only manufacture noise or a dead job. An EMPTY/unknown
// content type is still probed: absence of a recorded type is not evidence of
// "no DOM here".
func domXSSContentTypeAllowsDOM(raw string) bool {
	media := strings.ToLower(strings.TrimSpace(raw))
	if i := strings.IndexByte(media, ';'); i >= 0 {
		media = strings.TrimSpace(media[:i])
	}
	switch media {
	case "", "text/html", "application/xhtml+xml":
		return true
	default:
		return false
	}
}

// selectDOMXSSEndpoints returns, in input order, the distinct (by URL)
// GET/HEAD-navigable endpoints to probe. Pure (no store/queue), so the
// enqueue dedup/filter logic is unit-testable without either.
func selectDOMXSSEndpoints(endpoints []*domain.Endpoint) []*domain.Endpoint {
	seen := map[string]bool{}
	var out []*domain.Endpoint
	for _, ep := range endpoints {
		if ep == nil || !domXSSNavigable(ep.Method) || seen[ep.URL] {
			continue
		}
		seen[ep.URL] = true
		out = append(out, ep)
	}
	return out
}

// enqueueDOMXSSProbes is the one-time, scan-wide DOM-XSS pass (see
// execution.go's domXSSPassDone/evaluate — the SAME "run once when the
// ordinary job queue goes quiet" shape combined.go's
// enqueueCombinedCandidates uses): one JobDOMXSS per distinct discovered
// GET/HEAD-navigable Endpoint URL (see selectDOMXSSEndpoints) per implemented
// source. Each source job performs its own query-parameter or storage-key
// selection inside Handle. It reuses the scan's existing Endpoint registry —
// never a parallel discovery mechanism. Best-effort throughout: a failure
// here is logged, never fatal.
// defaultMaxDOMXSSEndpoints keeps the browser group bounded on large sites:
// each selected page expands into every DOM source, and browser work is the
// slowest group. Operators can raise max_dom_xss_endpoints explicitly.
const defaultMaxDOMXSSEndpoints = 25

func (c *Controller) enqueueDOMXSSProbes(ctx context.Context, scanID domain.ID) {
	endpoints, err := c.store.Endpoints().ListByScan(ctx, scanID)
	if err != nil {
		c.log.Warn("dom-xss probes: list endpoints", "scan", scanID, "err", err)
		return
	}
	sc, err := c.store.Scans().Get(ctx, scanID)
	if err != nil {
		c.log.Warn("dom-xss probes: load scan", "scan", scanID, "err", err)
		return
	}
	targets := selectDOMXSSEndpoints(endpoints)
	if sc.Config.SkipDownloadEndpoints {
		filtered := targets[:0]
		for _, ep := range targets {
			if !isDownloadLikeEndpoint(ep) {
				filtered = append(filtered, ep)
			}
		}
		targets = filtered
	}
	limit := sc.Config.MaxDOMXSSEndpoints
	if limit <= 0 {
		limit = defaultMaxDOMXSSEndpoints
	}
	if len(targets) > limit {
		c.log.Info("dom-xss probes: endpoint cap applied", "scan", scanID, "discovered", len(targets), "cap", limit)
		targets = targets[:limit]
	}
	now := time.Now()
	n := 0
	for _, ep := range targets {
		// One browser job per endpoint; the handler runs every source inside
		// it. This keeps the queue and retry surface endpoint-sized instead of
		// endpoint×source, while preserving one TestCase per source.
		payload, err := json.Marshal(domXSSJob{EndpointID: ep.ID, Sources: append([]detection.DOMXSSSource(nil), detection.DOMXSSSources...)})
		if err != nil {
			c.log.Warn("dom-xss probes: marshal job", "scan", scanID, "err", err)
			continue
		}
		job := &domain.TestJob{
			ID: domain.NewID(), ScanID: scanID, Type: domain.JobDOMXSS, State: domain.JobQueued,
			Priority: 50, Target: domain.JobTarget{EndpointID: ep.ID, URL: ep.URL},
			Payload: payload, MaxAttempts: 2,
			AvailableAt: now, CreatedAt: now, UpdatedAt: now,
		}
		if err := c.queue.Enqueue(ctx, job); err != nil {
			c.log.Warn("dom-xss probes: enqueue job", "scan", scanID, "err", err)
			continue
		}
		n++
	}
	if n > 0 {
		c.log.Info("dom-xss probes: enqueued", "scan", scanID, "jobs", n, "endpoints", len(targets))
	}
}

// ---------------------------------------------------------------------------
// the init-script harness and its console-message report format
// ---------------------------------------------------------------------------

// domXSSConsolePrefix uniquely tags a sink-reachability report so it can
// be told apart from any console.log the page's own code might emit.
const domXSSConsolePrefix = "__INDAGO_DOMXSS__"

// domXSSActivationEvidencePrefix tags the browser-log evidence line that
// records which bounded activation step (if any) verification performed before
// reading the execution signal. It is evidence, never verdict authority.
const domXSSActivationEvidencePrefix = "__INDAGO_DOMXSS_ACTIVATION__"

// domXSSSinkReport is the JSON payload the harness logs (after
// domXSSConsolePrefix) each time a value containing the marker reaches a
// hooked sink.
type domXSSSinkReport struct {
	Sink      string `json:"sink"`
	Value     string `json:"value"`
	Connected bool   `json:"connected,omitempty"`
	// Text marks the angular_expression report: the marker was observed as
	// the content of a rendered text node after the page's load event, not
	// as an argument to a hooked DOM setter. Count is how many such text
	// nodes were seen (evidence only).
	Text  bool `json:"text,omitempty"`
	Count int  `json:"count,omitempty"`
	// Binding marks a text report that was read from Angular's own compiled
	// interpolation function ($binding) with the element's scope instead of
	// from a rendered body text node. Text is still true: it is an
	// evaluated interpolation result, never a hooked setter call.
	Binding bool `json:"binding,omitempty"`
	// TextOnly marks the DIAGNOSTIC innerText/textContent report: the marker
	// reached a text write, which cannot execute. Such a report is never
	// reachability and never evidence of a sink; it only lets a negative say
	// where the marker actually went.
	TextOnly bool `json:"text_only,omitempty"`
}

// domXSSTextSink is one text-only write the harness observed. A closed
// allow-list: a page-authored report cannot invent a sink name that reads as
// something this engine executes.
var domXSSTextSinks = map[string]bool{
	"innerText":   true,
	"textContent": true,
}

// parseDOMXSSTextSinks returns the distinct text-only sinks that received a
// marker-containing value, in first-seen order. These are DIAGNOSTIC: they are
// never reachability (see parseDOMXSSReachability, which skips them) and never
// influence a verdict.
func parseDOMXSSTextSinks(msgs []browser.ConsoleMessage, marker string) []string {
	if marker == "" {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, m := range msgs {
		if !strings.HasPrefix(m.Text, domXSSConsolePrefix) {
			continue
		}
		var rep domXSSSinkReport
		if json.Unmarshal([]byte(strings.TrimPrefix(m.Text, domXSSConsolePrefix)), &rep) != nil {
			continue
		}
		if !rep.TextOnly || !domXSSTextSinks[rep.Sink] || seen[rep.Sink] {
			continue
		}
		if !strings.Contains(rep.Value, marker) {
			continue
		}
		seen[rep.Sink] = true
		out = append(out, rep.Sink)
	}
	return out
}

// domXSSConsoleCSPPrefix tags a Content-Security-Policy violation the harness
// observed during the page load. It is evidence about why a sink might not
// have executed, and — for angular_expression only — the authority behind the
// distinct csp_blocked outcome. It is never confirmation evidence.
//
// It MUST start with domXSSConsolePrefix: the browser layer only attributes a
// console report to the installed init script when the first argument begins
// with that exact prefix, and the rest of the message is then skipped by the
// sink-report parser because it is not JSON.
const domXSSConsoleCSPPrefix = domXSSConsolePrefix + "CSP:"

// domXSSCSPViolation is the subset of a SecurityPolicyViolationEvent this
// engine records. Blocked is "eval" for a blocked new Function/eval
// (Chromium reports blockedURI "eval" and effectiveDirective "script-src"),
// which is exactly how a CSP without 'unsafe-eval' stops AngularJS's
// expression compiler.
type domXSSCSPViolation struct {
	Directive   string `json:"directive"`
	Blocked     string `json:"blocked"`
	Disposition string `json:"disposition"`
	Sample      string `json:"sample"`
}

// parseDOMXSSCSPViolations returns the CSP violation reports the installed
// harness emitted, in emission order. Duplicates (the harness listens on both
// window and document) are collapsed by (directive, blocked, sample).
func parseDOMXSSCSPViolations(msgs []browser.ConsoleMessage) []domXSSCSPViolation {
	var out []domXSSCSPViolation
	seen := map[string]bool{}
	for _, m := range msgs {
		if !strings.HasPrefix(m.Text, domXSSConsoleCSPPrefix) {
			continue
		}
		var v domXSSCSPViolation
		if json.Unmarshal([]byte(strings.TrimPrefix(m.Text, domXSSConsoleCSPPrefix)), &v) != nil {
			continue
		}
		key := v.Directive + "\x00" + v.Blocked + "\x00" + v.Disposition + "\x00" + v.Sample
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, v)
	}
	return out
}

// domXSSEvalBlockedByCSP reports whether any observed violation blocked
// dynamic script evaluation. Only an enforced eval refusal is meaningful here:
// a report-only policy or an inline-script block does not explain a missing
// interpolation result.
func domXSSEvalBlockedByCSP(violations []domXSSCSPViolation) (bool, domXSSCSPViolation) {
	for _, v := range violations {
		if v.Blocked != "eval" {
			continue
		}
		if v.Disposition != "" && v.Disposition != "enforce" {
			continue
		}
		switch v.Directive {
		case "script-src", "script-src-elem", "default-src":
			return true, v
		}
	}
	return false, domXSSCSPViolation{}
}

// domXSSAngularResult reports whether the installed harness observed this
// attempt's evaluated interpolation result, and whether that result was read
// from Angular's compiled binding (an element's $binding interpolate
// function evaluated with its scope) rather than from a rendered text node.
//
// The marker-specificity rule is the same for both readings: the candidate
// never contains the contiguous marker, so a marker named by the report can
// only be the expression's evaluated result, not a reflection.
func domXSSAngularResult(msgs []browser.ConsoleMessage, marker string) (compiled, viaBinding bool) {
	if marker == "" {
		return false, false
	}
	for _, m := range msgs {
		if !strings.HasPrefix(m.Text, domXSSConsolePrefix) {
			continue
		}
		var rep domXSSSinkReport
		if json.Unmarshal([]byte(strings.TrimPrefix(m.Text, domXSSConsolePrefix)), &rep) != nil {
			continue
		}
		if !rep.Text || rep.Sink != string(detection.DOMSinkAngularExpression) || !strings.Contains(rep.Value, marker) {
			continue
		}
		return true, rep.Binding
	}
	return false, false
}

// hasDOMXSSAngularTextResult reports whether the installed harness observed
// the marker as the content of a rendered text node or as the result of
// Angular's own compiled interpolation binding. For the angular_expression
// sink this is the confirmation signal: the candidate does not contain the
// contiguous marker, so only evaluating the interpolation can produce it.
func hasDOMXSSAngularTextResult(msgs []browser.ConsoleMessage, marker string) bool {
	compiled, _ := domXSSAngularResult(msgs, marker)
	return compiled
}

// parseDOMXSSReachability scans console messages the init-script harness
// produced for a report naming a sink whose reported value contains
// marker, returning the DISTINCT sinks found, in first-seen order
// (deterministic given msgs' own order — the order the page's OWN script
// happened to call the sinks in, genuinely meaningful information, not an
// artifact of this parser). This is the one piece of "sink-hook harness
// logic" unit-testable without a real browser: everything upstream of it
// (the hooks themselves) only runs inside one — see domxss_test.go.
func parseDOMXSSReachability(msgs []browser.ConsoleMessage, marker string) []detection.DOMXSSSink {
	if marker == "" {
		return nil
	}
	seen := map[detection.DOMXSSSink]bool{}
	var out []detection.DOMXSSSink
	for _, m := range msgs {
		if !strings.HasPrefix(m.Text, domXSSConsolePrefix) {
			continue
		}
		var rep domXSSSinkReport
		if err := json.Unmarshal([]byte(strings.TrimPrefix(m.Text, domXSSConsolePrefix)), &rep); err != nil {
			continue
		}
		if !strings.Contains(rep.Value, marker) {
			continue
		}
		// A text-only report is diagnostic, never reachability: text writes
		// cannot execute (see parseDOMXSSTextSinks).
		if rep.TextOnly {
			continue
		}
		sink := detection.DOMXSSSink(rep.Sink)
		if !sink.IsValid() || seen[sink] {
			continue
		}
		seen[sink] = true
		out = append(out, sink)
	}
	return out
}

// hasConnectedDOMXSSFragment requires observational evidence that the target
// inserted a node returned by createContextualFragment. Detached image errors
// alone do not satisfy this sink's insertion requirement.
func hasConnectedDOMXSSFragment(messages []browser.ConsoleMessage, marker string) bool {
	for _, message := range messages {
		if !strings.HasPrefix(message.Text, domXSSConsolePrefix) {
			continue
		}
		var report domXSSSinkReport
		if json.Unmarshal([]byte(strings.TrimPrefix(message.Text, domXSSConsolePrefix)), &report) == nil && report.Sink == string(detection.DOMSinkCreateContextualFragment) && report.Connected && strings.Contains(report.Value, marker) {
			return true
		}
	}
	return false
}

// jQuery activation. Two implemented sinks cannot execute on load at all:
// an href write needs the link to be activated, and a page that only wires a
// hashchange listener has not run its own selector code yet. Verification is
// therefore allowed exactly ONE deterministic activation step before the
// engine reads the execution signal. The activation never carries a payload of
// its own: it clicks the element the harness itself tagged, or re-issues the
// hash change the page itself listens for.
type domXSSActivation int

const (
	domXSSActivateNone domXSSActivation = iota
	// domXSSActivateHashChange re-issues the fragment the navigation already
	// carried, so a hashchange-driven page runs its own handler with exactly
	// this candidate value (the realistic iframe delivery: load, then change
	// the hash).
	domXSSActivateHashChange
	// domXSSActivateHrefClick clicks the exact element whose href the harness
	// observed and tagged. No target discovered is not an error: it means the
	// page never performed the write this attempt was verifying.
	domXSSActivateHrefClick
)

const (
	domXSSActivationClicked       = "clicked"
	domXSSActivationTargetMissing = "missing"
	// domXSSActivationWindow bounds the observation wait after an activation.
	// It reuses the engine's existing URL-source observation window.
	domXSSActivationWindow = 250 * time.Millisecond
)

// label names the activation in evidence logs and verification notes.
func (a domXSSActivation) label() string {
	switch a {
	case domXSSActivateHashChange:
		return "hash_change"
	case domXSSActivateHrefClick:
		return "href_click"
	default:
		return "none"
	}
}

// describe is the operator-facing wording used in a verification note.
func (a domXSSActivation) describe() string {
	switch a {
	case domXSSActivateHashChange:
		return "one bounded hash change issued by the engine so the page's own hashchange handler runs"
	case domXSSActivateHrefClick:
		return "one click on the exact element the harness located for the observed href write"
	default:
		return "none"
	}
}

// domXSSPrimarySink applies the engine's first-reachable-sink bound with two
// attribution rules. jQuery's own HTML parsing assigns innerHTML INSIDE the
// factory call, so a marker-carrying $(...) can legitimately report both
// sinks; the page-authored jQuery.selector call is the site's identity, and
// choosing innerHTML there would silently drop the activation that factory
// call needs. angular_expression's reachability is a PASSIVE text observation
// taken at the load event, so it must never displace a sink the page's own
// code actively reached (that would change every existing sink's attribution,
// and a page that writes markup at its own load handler would lose its real
// sink). It is therefore the fallback: chosen only when nothing else is
// reachable. Every other combination keeps the original first-seen order.
func domXSSPrimarySink(reachable []detection.DOMXSSSink) detection.DOMXSSSink {
	for _, sink := range reachable {
		if sink == detection.DOMSinkJQuerySelector {
			return sink
		}
	}
	for _, sink := range reachable {
		if sink != detection.DOMSinkAngularExpression {
			return sink
		}
	}
	if len(reachable) == 0 {
		return ""
	}
	return detection.DOMSinkAngularExpression
}

// withoutDOMXSSSink returns sinks without the given one (nil-safe). The
// passive angular text observation is not a hooked sink call, so it must not
// appear in another sink's "hooked sinks that received the payload" note.
func withoutDOMXSSSink(sinks []detection.DOMXSSSink, drop detection.DOMXSSSink) []detection.DOMXSSSink {
	if len(sinks) == 0 {
		return sinks
	}
	out := make([]detection.DOMXSSSink, 0, len(sinks))
	for _, sink := range sinks {
		if sink != drop {
			out = append(out, sink)
		}
	}
	return out
}

// domXSSActivationForSink maps a reachable sink to its bounded activation.
// hashActivated records that phase one only reached the sink after the engine
// issued a hash change, so a load-time selector call needs no extra event.
func domXSSActivationForSink(sink detection.DOMXSSSink, hashActivated bool) domXSSActivation {
	switch sink {
	case detection.DOMSinkJQueryAttr:
		return domXSSActivateHrefClick
	case detection.DOMSinkJQuerySelector:
		if hashActivated {
			return domXSSActivateHashChange
		}
	}
	return domXSSActivateNone
}

// domXSSHashChangeActivationScript re-issues value as the fragment. Resetting
// the fragment first makes the assignment a real change even when the
// navigation URL already carried the same value; the page's hashchange handler
// reads the final value (verified in Chromium: both queued events see it).
func domXSSHashChangeActivationScript(value string) string {
	return "(() => { location.hash = ''; location.hash = " + goQuoteJS(value) + "; return location.href; })()"
}

// domXSSHrefClickScript clicks the element the harness tagged for marker. It
// is the browser's own default activation of that element, not a navigation
// the engine invents; a missing target is reported, never fabricated.
func domXSSHrefClickScript(marker string) string {
	return "(() => { var el = document.querySelector('[data-indago-xss-target=\"' + " + goQuoteJS(marker) + " + '\"]'); if (!el) return " + goQuoteJS(domXSSActivationTargetMissing) + "; el.click(); return " + goQuoteJS(domXSSActivationClicked) + "; })()"
}

// applyDOMXSSActivation performs the one activation step. It reports whether a
// step actually happened; an error means the page could not be driven and the
// caller must surface it to the worker's bounded retry, never treat it as a
// negative.
func (e *domXSSExecutor) applyDOMXSSActivation(ctx context.Context, page *browser.Page, act domXSSActivation, marker, value string) (bool, error) {
	switch act {
	case domXSSActivateHashChange:
		if _, err := evaluateDOMXSSScript(ctx, page, domXSSHashChangeActivationScript(value), domXSSEvaluateBound); err != nil {
			return false, fmt.Errorf("hash-change activation: %w", err)
		}
		return true, nil
	case domXSSActivateHrefClick:
		raw, err := evaluateDOMXSSScript(ctx, page, domXSSHrefClickScript(marker), domXSSEvaluateBound)
		if err != nil {
			return false, fmt.Errorf("href-click activation: %w", err)
		}
		status, _ := raw.(string)
		return status == domXSSActivationClicked, nil
	default:
		return false, nil
	}
}

// domXSSExecutionSignalBudget bounds the post-activation wait for the
// marker-specific execution signal. It exists because a fixed settle is a
// network-latency race: markup that jQuery parses out of a fragment creates an
// image whose error (and the marker's ReferenceError) only arrives after the
// browser's request round trip, and on a real host that lands just past a
// 250 ms window (measured live at ~262 ms). Polling ends as soon as the signal
// is present; the budget is the ceiling, never a retry.
const (
	domXSSExecutionSignalBudget = 1500 * time.Millisecond
	domXSSExecutionSignalPoll   = 50 * time.Millisecond
)

// awaitDOMXSSExecutionSignal polls the page's own execution-provenance
// observations until the marker-specific signal (an uncaught ReferenceError
// naming the marker) appears, or the budget expires. It returns whether the
// signal was seen. Cancellation wins unchanged.
func awaitDOMXSSExecutionSignal(ctx context.Context, page *browser.Page, marker string, budget time.Duration) (bool, error) {
	if marker == "" {
		return false, nil
	}
	if budget <= 0 {
		budget = domXSSExecutionSignalBudget
	}
	deadline := time.Now().Add(budget)
	for {
		if _, _, matched := verification.MatchRuntimeExecution(marker, page.RuntimeObservations()); matched {
			return true, nil
		}
		if !time.Now().Before(deadline) {
			return false, nil
		}
		timer := time.NewTimer(domXSSExecutionSignalPoll)
		select {
		case <-ctx.Done():
			timer.Stop()
			return false, ctx.Err()
		case <-timer.C:
		}
	}
}

// waitDOMXSSActivationWindow lets the activated page finish its own work
// before observations are read back. It uses the scan context, so
// cancellation still wins.
func waitDOMXSSActivationWindow(ctx context.Context) error {
	timer := time.NewTimer(domXSSActivationWindow)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// finishSourceNavigation applies activation after a source-specific
// navigation (window.name, postMessage, referrer, storage). Navigation that
// carries the value in the URL uses navigate's own copy of this logic, because
// its hash probe also needs the pre-activation observation.
func (e *domXSSExecutor) finishSourceNavigation(ctx context.Context, page *browser.Page, act domXSSActivation, marker, value string) error {
	if act == domXSSActivateNone {
		return nil
	}
	ok, err := e.applyDOMXSSActivation(ctx, page, act, marker, value)
	if err != nil {
		return err
	}
	if ok {
		matched, err := awaitDOMXSSExecutionSignal(ctx, page, marker, 0)
		if err != nil {
			return err
		}
		if matched {
			return nil
		}
		return waitDOMXSSActivationWindow(ctx)
	}
	return nil
}

// goQuoteJS renders s as a JS double-quoted string literal. Go's %q
// produces backslash escapes JS also accepts for every byte that can
// appear in marker/domXSSConsolePrefix (both are plain ASCII
// alphanumeric/underscore by construction — see detection.NewProbe and
// domXSSConsolePrefix).
func goQuoteJS(s string) string { return fmt.Sprintf("%q", s) }

// domXSSEvaluateBound bounds one in-page script evaluation. Every script this
// engine evaluates runs page-adjacent code, and page code can block the main
// thread (a click handler that never returns) or sabotage the very timer a
// script-level fallback relies on. Page.Evaluate already returns as soon as its
// context is done (browser.callCtx), so giving each call its own deadline is a
// hard, scan-side guarantee that a wedged page cannot hold a browser worker for
// the worker pool's whole job deadline (15 minutes by default).
const domXSSEvaluateBound = 10 * time.Second

// errDOMXSSEvaluateDeadline marks an in-page script that outlived its
// evaluation bound. It is deliberately not a verdict: the script may or may not
// have had its effect.
var errDOMXSSEvaluateDeadline = errors.New("dom-xss in-page script exceeded its evaluation bound")

// evaluateDOMXSSScript runs one in-page script under its own deadline. A
// deadline it imposed itself is reported as errDOMXSSEvaluateDeadline; the
// caller's own cancellation is preserved unchanged, so a paused/cancelled scan
// is never mistaken for a page failure.
func evaluateDOMXSSScript(ctx context.Context, page *browser.Page, script string, bound time.Duration) (any, error) {
	if bound <= 0 {
		bound = domXSSEvaluateBound
	}
	ectx, cancel := context.WithTimeout(ctx, bound)
	defer cancel()
	raw, err := page.Evaluate(ectx, script)
	if err == nil {
		return raw, nil
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if errors.Is(ectx.Err(), context.DeadlineExceeded) {
		return nil, fmt.Errorf("%w (%s): %v", errDOMXSSEvaluateDeadline, bound, err)
	}
	return nil, err
}

// domXSSHarnessScript builds the init-script harness: monkey-patches
// the implemented HTML and primitive-string timer sinks to
// report (via a uniquely-prefixed console.log) whenever a value
// CONTAINING marker reaches one of them. Installed via
// browser.Page.AddInitScript, BEFORE any page script runs: attaching a
// listener AFTER the page has already loaded would miss an onload-style
// handler that already fired (see docs/dom-xss.md).
func domXSSHarnessScript(marker string) string {
	return fmt.Sprintf(domXSSHarnessTemplate, goQuoteJS(marker), goQuoteJS(domXSSConsolePrefix), goQuoteJS(domXSSConsoleCSPPrefix))
}

const domXSSHarnessTemplate = `(() => {
  const MARKER = %s;
  const PREFIX = %s;
  const CSP_PREFIX = %s;
  // Capture the natives before any page script runs. A page (many production
  // builds do) that neutralizes console.log or JSON.stringify later must not be
  // able to silence the reports, which would read as "no sink reachable".
  const LOG = (function () { try { return console.log.bind(console); } catch (e) { return function () {}; } })();
  const STRINGIFY = JSON.stringify.bind(JSON);
  const TOSTRING = String;
  // Capture the native slice before any page script runs: the evidence bound
  // must hold even on a page that later replaces String.prototype.slice.
  const SLICE = String.prototype.slice;
  // excerpt() must not read page-mutable globals either: a page replacing
  // Math.floor or String.prototype.charCodeAt after load previously emptied
  // the excerpt or made report() drop it, hiding a natively executing sink.
  const FLOOR = Math.floor;
  const CHARCODEAT = String.prototype.charCodeAt;
  const VALUE_LIMIT = 500;
  // Bounded value evidence. The parser downstream requires the REAL marker to
  // survive the excerpt, so clip AROUND the marker. Clipping from offset 0 let
  // a harmless prefix longer than VALUE_LIMIT push the marker out of the
  // excerpt, so a genuinely executable sink looked unreachable.
  function excerpt(v, at) {
    if (v.length <= VALUE_LIMIT) return v;
    if (MARKER.length > VALUE_LIMIT) return SLICE.call(v, at, at + VALUE_LIMIT);
    var start = at - FLOOR((VALUE_LIMIT - MARKER.length) / 2);
    if (start < 0) start = 0;
    if (start + VALUE_LIMIT > v.length) start = v.length - VALUE_LIMIT;
    var end = start + VALUE_LIMIT;
    // Never split a surrogate pair at either edge. The marker is plain ASCII,
    // so these trims can only remove harmless context around it.
    if (start > 0 && CHARCODEAT.call(v, start) >= 0xDC00 && CHARCODEAT.call(v, start) <= 0xDFFF &&
        CHARCODEAT.call(v, start - 1) >= 0xD800 && CHARCODEAT.call(v, start - 1) <= 0xDBFF) start++;
    if (end < v.length && CHARCODEAT.call(v, end - 1) >= 0xD800 && CHARCODEAT.call(v, end - 1) <= 0xDBFF &&
        CHARCODEAT.call(v, end) >= 0xDC00 && CHARCODEAT.call(v, end) <= 0xDFFF) end--;
    return SLICE.call(v, start, end);
  }
  function report(sink, value, connected) {
    try {
      var v = TOSTRING(value);
      var at = v.indexOf(MARKER);
      if (at === -1) return;
      LOG(PREFIX + STRINGIFY({ sink: sink, value: excerpt(v, at), connected: connected === true }));
    } catch (e) {}
  }
  // Text-only sinks (innerText/textContent). These are DIAGNOSTIC: a text write
  // can never execute, so this report never counts as sink reachability and
  // never reaches a verdict. It exists so a negative can say the marker DID
  // arrive in the page (in a position that cannot execute) instead of implying
  // the harness observed nothing at all - the measured page puts the echoed
  // term into innerText, and "no sink reachable" alone read like a blind hook.
  // text_only=true is what keeps the two apart in the parsers below.
  function reportText(sink, value) {
    try {
      var v = TOSTRING(value);
      var at = v.indexOf(MARKER);
      if (at === -1) return;
      LOG(PREFIX + STRINGIFY({ sink: sink, value: excerpt(v, at), text_only: true }));
    } catch (e) {}
  }
  // Native-first, observational. Only a primitive string is inspected: the
  // setter's own coercion must not be repeated or replaced.
  function hookTextSink(proto, prop, label) {
    try {
      var desc = Object.getOwnPropertyDescriptor(proto, prop);
      if (!desc || !desc.set) return;
      var origSet = desc.set;
      Object.defineProperty(proto, prop, {
        configurable: true,
        enumerable: desc.enumerable,
        get: desc.get,
        set: function (v) {
          var result = origSet.call(this, v);
          if (typeof v === 'string') reportText(label, v);
          return result;
        }
      });
    } catch (e) {}
  }
  function hookProp(proto, prop) {
    try {
      var desc = Object.getOwnPropertyDescriptor(proto, prop);
      if (!desc || !desc.set) return;
      var origSet = desc.set;
      Object.defineProperty(proto, prop, {
        configurable: true,
        enumerable: desc.enumerable,
        get: desc.get,
        set: function (v) {
          report(prop, v);
          return origSet.call(this, v);
        }
      });
    } catch (e) {}
  }
  hookProp(Element.prototype, 'innerHTML');
  hookProp(Element.prototype, 'outerHTML');
  // eval is deliberately NOT wrapped. Replacing window.eval turns a target's
  // DIRECT eval(...) (which reads and writes the caller's local scope) into an
  // indirect, global-scope call, changing the page's behavior. Eval and
  // Function compilations that receive the marker are instead observed from
  // outside the page by the browser engine's runtime provenance
  // (Runtime.Compilations, see domXSSHarnessMessages), which leaves the
  // native call untouched.
  // Diagnostic-only text sinks: see reportText. These hooks are installed
  // AFTER the HTML hooks so the HTML hooks stay first in this script, and they
  // are the reason a negative can name where the marker actually went.
  if (typeof HTMLElement === 'function') hookTextSink(HTMLElement.prototype, 'innerText', 'innerText');
  try { hookTextSink(Node.prototype, 'textContent', 'textContent'); } catch (e) {}
  // Native-first, observational string timer hook. Strict mode preserves even
  // null/undefined receivers for native Web IDL validation. Never coerce a
  // handler, replace a callback, evaluate code, or schedule an extra timer.
  for (const name of ['setTimeout', 'setInterval']) {
    try {
      const desc = Object.getOwnPropertyDescriptor(window, name);
      const native = desc.value;
      Object.defineProperty(window, name, {
        ...desc,
        value: function () {
          'use strict';
          const result = native.apply(this, arguments);
          if (typeof arguments[0] === 'string') report(name, arguments[0]);
          return result;
        }
      });
    } catch (_) {}
  }
  // Call native first with the original receiver and every argument. Observe
  // only primitive strings: logging must not repeat Web IDL object coercion.
  try {
    const desc = Object.getOwnPropertyDescriptor(Element.prototype, 'insertAdjacentHTML');
    const native = desc.value;
    Object.defineProperty(Element.prototype, 'insertAdjacentHTML', {
      ...desc,
      value: function () {
        const result = native.apply(this, arguments);
        if (typeof arguments[1] === 'string') report('insertAdjacentHTML', arguments[1]);
        return result;
      }
    });
  } catch (_) {}
  // URL sinks: an iframe/image/script src write. Only a frame executes a
  // javascript: URL; the other elements are observed so the engine can say
  // where the value landed instead of guessing.
  function hookURLProp(proto, prop, label) {
    try {
      var desc = Object.getOwnPropertyDescriptor(proto, prop);
      if (!desc || !desc.set) return;
      var origSet = desc.set;
      Object.defineProperty(proto, prop, {
        configurable: true,
        enumerable: desc.enumerable,
        get: desc.get,
        set: function (v) {
          report(label, v);
          return origSet.call(this, v);
        }
      });
    } catch (e) {}
  }
  if (typeof HTMLIFrameElement === 'function') hookURLProp(HTMLIFrameElement.prototype, 'src', 'element.src');
  if (typeof HTMLImageElement === 'function') hookURLProp(HTMLImageElement.prototype, 'src', 'element.src');
  if (typeof HTMLScriptElement === 'function') hookURLProp(HTMLScriptElement.prototype, 'src', 'element.src');
  // Cookie write: reachability only, never an execution claim on its own.
  try {
    var cookieDesc = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie');
    if (cookieDesc && cookieDesc.set) {
      var origCookieSet = cookieDesc.set;
      Object.defineProperty(Document.prototype, 'cookie', {
        configurable: true,
        enumerable: cookieDesc.enumerable,
        get: cookieDesc.get,
        set: function (v) {
          report('document.cookie', v);
          return origCookieSet.call(this, v);
        }
      });
    }
  } catch (e) {}
  // Navigation assignments. Location's own properties are exotic; the
  // method hooks are the portable half, and href is attempted separately.
  try {
    var hrefDesc = Object.getOwnPropertyDescriptor(Location.prototype, 'href');
    if (hrefDesc && hrefDesc.set) {
      var origHrefSet = hrefDesc.set;
      Object.defineProperty(Location.prototype, 'href', {
        configurable: true,
        enumerable: hrefDesc.enumerable,
        get: hrefDesc.get,
        set: function (v) {
          report('location.assign', v);
          return origHrefSet.call(this, v);
        }
      });
    }
  } catch (e) {}
  for (const m of ['assign', 'replace']) {
    try {
      var mDesc = Object.getOwnPropertyDescriptor(Location.prototype, m);
      if (!mDesc || typeof mDesc.value !== 'function') continue;
      var nativeM = mDesc.value;
      Object.defineProperty(Location.prototype, m, {
        ...mDesc,
        value: function (v) {
          report('location.assign', v);
          return nativeM.apply(this, arguments);
        }
      });
    } catch (e) {}
  }

  try {
    const desc = Object.getOwnPropertyDescriptor(Range.prototype, 'createContextualFragment');
    const native = desc.value;
    Object.defineProperty(Range.prototype, 'createContextualFragment', {
      ...desc,
      value: function () {
        const result = native.apply(this, arguments);
        if (typeof arguments[0] === 'string') {
          const value = arguments[0];
          report('Range.createContextualFragment', value);
          // Chromium may fire image errors in detached fragments. Confirm only
          // after observing the target attach a returned node; never insert it.
          try {
            if (value.indexOf(MARKER) !== -1) {
              // Track the actual canonical marker handler, not an innocent sibling
              // text node that the target might insert while leaving the image detached.
              const nodes = Array.from(result.querySelectorAll('[onerror]')).filter(
                node => node.getAttribute('onerror') === MARKER);
              const observer = new MutationObserver(() => {
                if (nodes.some(node => node.isConnected && node.ownerDocument === document)) {
                  report('Range.createContextualFragment', value, true);
                  observer.disconnect();
                }
              });
              observer.observe(document, {childList: true, subtree: true});
            }
          } catch (_) {}
        }
        return result; // Observation only: never insert the returned fragment.
      }
    });
  } catch (_) {}
  try {
    var origWrite = document.write.bind(document);
    document.write = function () {
      var s = Array.prototype.join.call(arguments, '');
      report('document.write', s);
      return origWrite.apply(document, arguments);
    };
    var origWriteln = document.writeln.bind(document);
    document.writeln = function () {
      var s = Array.prototype.join.call(arguments, '');
      report('document.write', s);
      return origWriteln.apply(document, arguments);
    };
  } catch (e) {}
  // jQuery sinks. jQuery is normally loaded by the page AFTER this init
  // script, so intercept the global assignments instead of assuming it
  // exists. Wrapping is observational: native init/attr always run FIRST with
  // the original receiver and every argument, and the native result is
  // returned unchanged. Only a primitive-string selector/attribute value that
  // contains the marker is reported, and only an href write is tagged for the
  // engine's one activation click.
  const JQ_TARGET_ATTR = 'data-indago-xss-target';
  const JQ_WRAPPED = new WeakSet();
  function wrapJQuery(jq) {
    if (typeof jq !== 'function' || !jq.fn || JQ_WRAPPED.has(jq)) return;
    JQ_WRAPPED.add(jq);
    try {
      const fn = jq.fn;
      const nativeInit = fn.init;
      if (typeof nativeInit === 'function') {
        // jQuery's factory calls new jQuery.fn.init(...). Keeping the native
        // prototype preserves instanceof/prototype identity exactly.
        const init = function (selector) {
          const result = nativeInit.apply(this, arguments);
          if (typeof selector === 'string') report('jQuery.selector', selector);
          return result;
        };
        init.prototype = fn;
        fn.init = init;
      }
      const nativeAttr = fn.attr;
      if (typeof nativeAttr === 'function') {
        fn.attr = function (name, value) {
          const result = nativeAttr.apply(this, arguments);
          try {
            if (arguments.length >= 2 && typeof name === 'string' && name.toLowerCase() === 'href' &&
                typeof value === 'string' && value.indexOf(MARKER) !== -1) {
              var tagged = false;
              for (var i = 0; i < this.length; i++) {
                var el = this[i];
                if (el && typeof el.setAttribute === 'function') { el.setAttribute(JQ_TARGET_ATTR, MARKER); tagged = true; }
              }
              if (tagged) report('jQuery.attr', value);
            }
          } catch (e) {}
          return result;
        };
      }
    } catch (e) {}
  }
  ['jQuery', '$'].forEach(function (prop) {
    try {
      const desc = Object.getOwnPropertyDescriptor(window, prop);
      var current = desc && desc.value;
      Object.defineProperty(window, prop, {
        configurable: true,
        enumerable: true,
        get: function () { return current; },
        set: function (v) { current = v; wrapJQuery(v); }
      });
      if (current) wrapJQuery(current);
    } catch (e) {}
  });
  // angular_expression sink: AngularJS's text-node interpolation writes the
  // EVALUATED RESULT back into the text node, so there is no DOM setter call
  // to hook (innerHTML/document.write never happen). Two observations are
  // taken, both at the page's load event and on every DOM mutation that
  // brings the marker into text (MutationObserver, NOT a timer: the harness
  // must not schedule anything a page or a native-contract test can observe):
  //
  //   1. the rendered text of the page, and
  //   2. the result of the interpolate function Angular itself linked for a
  //      text node whose source carries this attempt's split marker
  //      ($binding), evaluated with that element's own scope. That is the
  //      same value Angular writes into the text node, but it is still
  //      readable when the write is not part of rendered body text (a
  //      textarea/title binding, a node replaced later, a write that landed
  //      before the text walk).
  //
  // Both are gated on AngularJS actually being present in the document:
  // every page that displays a value as text looks identical from the DOM
  // alone, so without that gate the engine would open a candidate on every
  // reflected search page. Script/style/noscript text nodes are excluded
  // from the text walk (Angular does not interpolate there); textarea/title
  // are covered by the binding read instead. The engine's candidate never
  // contains the contiguous marker, so any hit on the verification
  // navigation is the expression's evaluated result.
  function angularPresent() {
    try {
      if (typeof window.angular !== 'undefined' && window.angular) return true;
      return !!(document.querySelector('[ng-app],[data-ng-app],[x-ng-app],[ng\\:app],[data-ng\\:app],[x-ng\\:app],[ng-csp],[data-ng-csp],[ng-controller],[data-ng-controller]'));
    } catch (e) { return false; }
  }
  function angularTextHits() {
    try {
      var root = document.body || document.documentElement;
      if (!root) return 0;
      var walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, null);
      var hits = 0;
      var node;
      while ((node = walker.nextNode())) {
        var parent = node.parentNode;
        if (!parent) continue;
        var tag = parent.nodeName;
        if (tag === 'SCRIPT' || tag === 'STYLE' || tag === 'NOSCRIPT' || tag === 'TEXTAREA' || tag === 'TITLE') continue;
        var data = node.nodeValue;
        if (typeof data === 'string' && data.indexOf(MARKER) !== -1) hits++;
      }
      return hits;
    } catch (e) { return 0; }
  }
  // angularBindingHits reads the result of the interpolate function Angular
  // itself linked for this candidate's text node. Only bindings whose
  // template source carries BOTH halves of the marker (so: our split-marker
  // expression, never a page-authored binding such as {{value}}) are
  // invoked, so the observation never evaluates page expressions and can
  // only report this attempt's result. A page that did not compile the
  // candidate has no such binding; one that compiled it returns the
  // contiguous marker. Absence of fn.exp (an Angular build that does not
  // expose it) means no hit — never a fabricated one.
  function angularBindingHits() {
    try {
      if (typeof window.angular === 'undefined' || !window.angular ||
          typeof window.angular.element !== 'function') return 0;
      var root = document.body || document.documentElement;
      if (!root) return 0;
      var cut = Math.floor(MARKER.length / 2);
      var head = MARKER.slice(0, cut), tail = MARKER.slice(cut);
      var els = root.querySelectorAll('*');
      var hits = 0;
      for (var i = 0; i < els.length; i++) {
        var bindings;
        try { bindings = window.angular.element(els[i]).data('$binding'); } catch (e) { continue; }
        if (!bindings || !bindings.length) continue;
        var scope;
        try { scope = window.angular.element(els[i]).scope(); } catch (e) { scope = null; }
        if (!scope) continue;
        for (var j = 0; j < bindings.length; j++) {
          var fn = bindings[j];
          if (typeof fn !== 'function') continue;
          var src = typeof fn.exp === 'string' ? fn.exp : '';
          if (src.indexOf(head) === -1 || src.indexOf(tail) === -1) continue;
          if (src.indexOf(MARKER) !== -1) continue; // literal text, not this candidate's expression
          var result;
          try { result = fn(scope); } catch (e) { continue; }
          if (typeof result === 'string' && result.indexOf(MARKER) !== -1) hits++;
        }
      }
      return hits;
    } catch (e) { return 0; }
  }
  // One extra call frame for the same provenance reason as the CSP reporter:
  // a console call whose only frame is the installed function is not
  // attributed by the browser layer, and a load listener can be the top frame.
  function emitAngularTextReport(hits, viaBinding) {
    if (viaBinding) {
      LOG(PREFIX + STRINGIFY({ sink: 'angular_expression', value: MARKER, text: true, binding: true, count: hits }));
      return;
    }
    LOG(PREFIX + STRINGIFY({ sink: 'angular_expression', value: MARKER, text: true, count: hits }));
  }
  function reportAngularText() {
    try {
      if (!angularPresent()) return;
      var hits = angularTextHits();
      if (hits > 0) { emitAngularTextReport(hits, false); return; }
      var bound = angularBindingHits();
      if (bound > 0) emitAngularTextReport(bound, true);
    } catch (e) {}
  }
  try {
    window.addEventListener('load', reportAngularText);
    var angularObserver = new MutationObserver(function (records) {
      try {
        for (var i = 0; i < records.length; i++) {
          var record = records[i];
          var changed = record.type === 'characterData' ? record.target : null;
          if (changed && typeof changed.nodeValue === 'string' && changed.nodeValue.indexOf(MARKER) !== -1) { reportAngularText(); return; }
          var added = record.addedNodes || [];
          for (var j = 0; j < added.length; j++) {
            var node = added[j];
            if (node.nodeType === 3 && typeof node.nodeValue === 'string' && node.nodeValue.indexOf(MARKER) !== -1) { reportAngularText(); return; }
            if (node.nodeType === 1 && typeof node.textContent === 'string' && node.textContent.indexOf(MARKER) !== -1) { reportAngularText(); return; }
          }
        }
      } catch (e) {}
    });
    angularObserver.observe(document, { childList: true, subtree: true, characterData: true });
  } catch (e) {}
  // CSP outcome evidence: a document whose policy refuses dynamic evaluation
  // stops Angular's expression compiler before it can write any result. The
  // report is engine-attributed (same init script) and is only used to turn a
  // missing result into the distinct csp_blocked outcome, never to confirm
  // anything. Both targets are listened to because the event is dispatched at
  // the document in current Chromium.
  function reportCSP(event) {
    try {
      emitCSP({
        directive: TOSTRING(event.effectiveDirective || event.violatedDirective || ''),
        blocked: TOSTRING(event.blockedURI || ''),
        disposition: TOSTRING(event.disposition || ''),
        sample: SLICE.call(TOSTRING(event.sample || ''), 0, 200)
      });
    } catch (e) {}
  }
  // One extra call frame: the browser layer attributes a report to the
  // installed init script only when the console call has a caller frame
  // beyond itself, and an event-listener invocation can otherwise be the
  // top frame.
  function emitCSP(payload) { LOG(CSP_PREFIX + STRINGIFY(payload)); }
  try { window.addEventListener('securitypolicyviolation', reportCSP, true); } catch (e) {}
  try { document.addEventListener('securitypolicyviolation', reportCSP, true); } catch (e) {}
})();`

// ---------------------------------------------------------------------------
// URL/fragment helpers (pure)
// ---------------------------------------------------------------------------

// stripFragment removes any existing "#..." suffix from rawURL.
func stripFragment(rawURL string) string {
	if i := strings.IndexByte(rawURL, '#'); i >= 0 {
		return rawURL[:i]
	}
	return rawURL
}

// domXSSHashURL builds the navigation URL carrying fragmentValue
// (percent-encoded by jsEncodeURIComponent) as the fragment, replacing
// any fragment the endpoint URL already had.
func domXSSHashURL(endpointURL, fragmentValue string) string {
	return stripFragment(endpointURL) + "#" + jsEncodeURIComponent(fragmentValue)
}

// domXSSQueryURL builds the navigation URL with the query parameter named
// param set to value, preserving every other existing query parameter and
// the endpoint's own fragment (if any). It uses percent-encoding for spaces
// (%20), not form-encoding (+): pages that inspect location.href directly and
// call decodeURIComponent do not translate plus to space. URLSearchParams also
// decodes %20 correctly. For the selected value only, a reserved slash stays
// literal so decodeURI-based readers can parse closing tags; query separators
// remain escaped.
func domXSSQueryURL(endpointURL, param, value string) string {
	u, err := url.Parse(endpointURL)
	if err != nil {
		// Defensive fallback for a malformed endpoint URL; should not
		// happen in practice since the endpoint was already navigated
		// once by discovery.
		sep := "?"
		if strings.Contains(endpointURL, "?") {
			sep = "&"
		}
		return endpointURL + sep + param + "=" + strings.ReplaceAll(url.QueryEscape(value), "+", "%20")
	}
	q := u.Query()
	q.Set(param, value)
	u.RawQuery = encodeDOMXSSQuery(q, param)
	return u.String()
}

// domXSSNamedExpressionAnchorValue is the fixed, marker-free value carried by
// the ordinary parameter while a named-expression candidate is delivered. It is
// what a human sends in the search box; it must not contain the marker, because
// a page that ignores the name channel would render exactly this value and a
// marker-carrying anchor would be indistinguishable from a confirmed result.
const domXSSNamedExpressionAnchorValue = "1"

// domXSSQueryNameURL builds the navigation URL that delivers expr as a query
// parameter NAME (with a fixed benign value), keeping every other query
// parameter and the fragment. Two details are load-bearing and measured:
//
//   - the ordinary parameter (anchorParam) must still be present, because a
//     page that only emits the vulnerable binding when its search parameter
//     exists renders nothing without it;
//   - expr is appended LAST and never sorted. The measured page emits one
//     `var key = '<NAME>'; …; $scope.value = $parse(key)(…)` block per
//     parameter, in URL order, so the LAST block wins the rendered scope value.
//     Sorting the names (as encodeDOMXSSQuery does for value delivery) would
//     put an expression beginning with '[' before "search" and the page would
//     render the anchor value instead of the expression's result.
func domXSSQueryNameURL(endpointURL, anchorParam, anchorValue, expr string) string {
	u, err := url.Parse(endpointURL)
	if err != nil {
		sep := "?"
		if strings.Contains(endpointURL, "?") {
			sep = "&"
		}
		return endpointURL + sep + anchorParam + "=" + url.QueryEscape(anchorValue) + "&" + url.QueryEscape(expr) + "=1"
	}
	q := u.Query()
	if anchorParam != "" {
		q.Set(anchorParam, anchorValue)
	}
	keys := make([]string, 0, len(q))
	for key := range q {
		if key == expr {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	pairs := make([]string, 0, len(keys)+1)
	for _, key := range keys {
		for _, value := range q[key] {
			pairs = append(pairs, url.QueryEscape(key)+"="+strings.ReplaceAll(url.QueryEscape(value), "+", "%20"))
		}
	}
	pairs = append(pairs, url.QueryEscape(expr)+"=1")
	u.RawQuery = strings.Join(pairs, "&")
	return u.String()
}

// encodeDOMXSSQuery keeps the selected payload's reserved slash literal in
// addition to percent-encoding ordinary query syntax. Some pages call
// decodeURI(location.href); by spec that decoder leaves an encoded "%2F"
// untouched, so markup such as a closing script tag would stay inert. Leaving
// slash raw is safe inside a query value, while ampersands, hashes, and other
// structure-changing characters remain escaped. URLSearchParams and
// decodeURIComponent readers observe the same payload bytes.
func encodeDOMXSSQuery(values url.Values, payloadParam string) string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var pairs []string
	for _, key := range keys {
		for _, value := range values[key] {
			encoded := url.QueryEscape(value)
			if key == payloadParam {
				encoded = strings.ReplaceAll(encoded, "%2F", "/")
			}
			encoded = strings.ReplaceAll(encoded, "+", "%20")
			pairs = append(pairs, url.QueryEscape(key)+"="+encoded)
		}
	}
	return strings.Join(pairs, "&")
}

// domXSSOriginURL returns the scheme+host origin ROOT ("https://host/") of
// endpointURL — the same-origin neutral page the localStorage/
// sessionStorage source's navigateWithStorage navigates to BEFORE writing
// to storage (see detection.DOMSourceLocalStorage's doc comment: storage
// is ORIGIN-scoped, so the write must happen on a page already on the
// target's own origin, unlike window.name which tolerates any neutral
// page at all). Pure/testable; a malformed endpointURL is reported as an
// error rather than silently falling back, since there is no safe default
// origin to guess.
func domXSSOriginURL(endpointURL string) (string, error) {
	u, err := url.Parse(endpointURL)
	if err != nil {
		return "", fmt.Errorf("parse endpoint URL for origin: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("endpoint URL %q has no scheme/host to derive an origin from", endpointURL)
	}
	return u.Scheme + "://" + u.Host + "/", nil
}

// jsEncodeURIComponent percent-encodes s exactly like JavaScript's
// encodeURIComponent (unreserved set: A-Z a-z 0-9 - _ . ! ~ * ' ( )) — NOT
// Go's url.QueryEscape, which turns a space into "+" (application/
// x-www-form-urlencoded semantics): a page that does
// decodeURIComponent(location.hash) expects "%20" for a space, not a
// literal "+". This also matches real browser behavior for a hash
// fragment: the WHATWG URL parser itself always percent-encodes space/
// '"'/'<'/'>'/'`' in a fragment regardless of what the caller sends, so a
// payload needing "<"/">" can only ever reach a page that decodes it back
// — exactly the realistic, common DOM-XSS pattern this engine targets.
func jsEncodeURIComponent(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			b.WriteByte(c)
		case c == '-' || c == '_' || c == '.' || c == '!' || c == '~' || c == '*' || c == '\'' || c == '(' || c == ')':
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// Finding correlation — the DOM-XSS analog of finding.go's Reflected-XSS
// correlation, deliberately a SEPARATE, smaller shape: a DOM-XSS "site" is
// (Endpoint, source, sink), not (InjectionPoint, category, context) — see
// docs/dom-xss.md. Verdict promotion reuses the EXACT SAME monotonic
// lattice/rank (verdictRank, finding.go) Reflected XSS already uses, and
// the finding's Detail reuses the EXACT SAME findingDetail/
// verificationAttempt JSON shape (finding.go) so every existing
// presentation surface renders it with no new plumbing.
// ---------------------------------------------------------------------------

// domXSSFindingDedupKey distinguishes a DOM-XSS finding from a Reflected
// XSS one (disjoint tag), a different sink or endpoint, and (for query and
// storage sources) a different parameter/key. The source backend remains
// part of the identity, so localStorage and sessionStorage never collide.
func domXSSFindingDedupKey(endpointID domain.ID, source detection.DOMXSSSource, sink detection.DOMXSSSink, parameter string) string {
	key := string(endpointID) + "\x00dom_xss\x00" + string(source) + "\x00" + string(sink)
	// A hash source carries a selector only for fragment-route parameters; the
	// plain whole-fragment probe has none and keeps its single finding.
	if source == detection.DOMSourceQuery || source == detection.DOMSourceLocalStorage || source == detection.DOMSourceSessionStorage ||
		(source == detection.DOMSourceHash && parameter != "") {
		key += fmt.Sprintf("\x00parameter:%d:%s", len(parameter), parameter)
	}
	return key
}

func domXSSFindingTitle(ep *domain.Endpoint, source detection.DOMXSSSource, sink detection.DOMXSSSink, parameter string) string {
	switch source {
	case detection.DOMSourceQuery:
		return fmt.Sprintf("DOM XSS candidate: %s parameter %q reaches %s at %s %s", source, parameter, sink, ep.Method, endpointLabel(ep.URL))
	case detection.DOMSourcePostMessage:
		return fmt.Sprintf("DOM XSS candidate: %s reaches %s at %s %s", source, sink, ep.Method, endpointLabel(ep.URL))
	case detection.DOMSourceLocalStorage, detection.DOMSourceSessionStorage:
		return fmt.Sprintf("DOM XSS candidate: %s key %q reaches %s at %s %s", source, parameter, sink, ep.Method, endpointLabel(ep.URL))
	case detection.DOMSourceHash:
		if parameter != "" {
			return fmt.Sprintf("DOM XSS candidate: %s parameter %q reaches %s at %s %s", source, parameter, sink, ep.Method, endpointLabel(ep.URL))
		}
		return fmt.Sprintf("DOM XSS candidate: %s reaches %s at %s %s", source, sink, ep.Method, endpointLabel(ep.URL))
	default:
		return fmt.Sprintf("DOM XSS candidate: %s reaches %s at %s %s", source, sink, ep.Method, endpointLabel(ep.URL))
	}
}

// confirmedDOMXSSTitle drops "candidate" once verification has confirmed
// the finding — mirrors confirmedTitle's exact same idea for Reflected XSS.
func confirmedDOMXSSTitle(title string) string {
	return strings.Replace(title, "DOM XSS candidate:", "DOM XSS:", 1)
}

// upsertDOMXSSFinding creates (or absorbs a repeat reachability signal
// into) the Finding for one reachable (Endpoint, source, sink) DOM-XSS
// site. Verdict starts Pending: reachability alone is never itself a
// confirmed vulnerability (AGENTS.md §2.6 / §3) — only
// correlateDOMXSSVerification, after the payload-verification phase, can
// promote it. The caller MUST hold findingsMu (mirrors upsertPendingFinding,
// which is also unlocked itself and relies on its caller to serialize it).
// source is derived from cand.ContextSub (see detection.DOMXSSPayloadFor's
// field-repurposing doc comment) — NOT hardcoded to any one source, so all
// seven implemented sources produce distinct, correctly labeled findings;
// query/storage selectors are also part of their finding identity.
func upsertDOMXSSFinding(ctx context.Context, st store.Store, scanID domain.ID, ep *domain.Endpoint, cand detection.Candidate, canaryValue string, reachTestCaseID domain.ID) (*domain.Finding, error) {
	source := detection.DOMXSSSource(cand.ContextSub)
	sink := detection.DOMXSSSink(cand.Context)
	key := domXSSFindingDedupKey(ep.ID, source, sink, cand.Parameter)
	parameterName := cand.Parameter
	if source != detection.DOMSourceQuery && source != detection.DOMSourceLocalStorage && source != detection.DOMSourceSessionStorage &&
		!(source == detection.DOMSourceHash && cand.Parameter != "") {
		parameterName = string(source)
	}
	now := time.Now()
	reachAttempt := verificationAttempt{
		CandidateValue:   canaryValue,
		VerifyTestCaseID: reachTestCaseID,
		Verdict:          domain.VerdictPending,
		Confidence:       domain.ConfidenceLow,
		Notes:            fmt.Sprintf("reachability probe: a benign canary in %s reached this sink — reachability only, not yet a confirmed vulnerability", source),
		At:               now,
	}

	existing, err := st.Findings().ListByScan(ctx, scanID)
	if err != nil {
		return nil, fmt.Errorf("list findings for dom-xss correlation: %w", err)
	}
	for _, f := range existing {
		if f.VulnClass != domain.VulnDOMXSS {
			continue
		}
		d := decodeFindingDetail(f.Detail)
		if d.DedupKey != key {
			continue
		}
		d.Occurrences++
		d.TestCaseIDs = appendUniqueID(d.TestCaseIDs, reachTestCaseID)
		d.Candidates = appendUniqueCandidate(d.Candidates, cand)
		d.Attempts = appendAttempt(d.Attempts, reachAttempt)
		if d.ParameterSource == "" {
			d.ParameterSource = cand.ParameterSource
		}
		f.Detail = d.encode()
		f.UpdatedAt = now
		if err := st.Findings().Update(ctx, f); err != nil {
			return nil, fmt.Errorf("update correlated dom-xss finding: %w", err)
		}
		return f, nil
	}

	sc, err := st.Scans().Get(ctx, scanID)
	if err != nil {
		return nil, fmt.Errorf("load scan: %w", err)
	}
	d := findingDetail{
		Method: ep.Method, ParameterName: parameterName, ParameterSource: cand.ParameterSource,
		DedupKey: key, Occurrences: 1,
		TestCaseIDs: []domain.ID{reachTestCaseID}, Candidates: []detection.Candidate{cand}, Attempts: []verificationAttempt{reachAttempt},
	}
	f := &domain.Finding{
		ID: domain.NewID(), ScanID: scanID, ProjectID: sc.ProjectID, VulnClass: domain.VulnDOMXSS,
		Verdict: domain.VerdictPending, Severity: domain.SeverityHigh, Confidence: domain.ConfidenceLow,
		Title:      domXSSFindingTitle(ep, source, sink, cand.Parameter),
		Summary:    cand.Rationale,
		EndpointID: ep.ID,
		Provenance: domain.Provenance{Engine: "dom-xss", DiscoverySource: ep.Source, DetectedAt: now, AIAssisted: false},
		Detail:     d.encode(),
		CreatedAt:  now, UpdatedAt: now,
	}
	if err := st.Findings().Create(ctx, f); err != nil {
		return nil, fmt.Errorf("create dom-xss finding: %w", err)
	}
	return f, nil
}

// correlateDOMXSSVerification mirrors correlateVerification's monotonic
// verdict-promotion rule and evidence union exactly (verdictRank is
// shared, unchanged) for the payload-verification phase's result.
func (e *domXSSExecutor) correlateDOMXSSVerification(ctx context.Context, findingID domain.ID, cand detection.Candidate, verdict domain.Verdict, confidence domain.Confidence, notes string, verifyTestCaseID domain.ID, evidenceIDs []domain.ID, verifiedURL string) {
	e.findingsMu.Lock()
	defer e.findingsMu.Unlock()

	f, err := e.store.Findings().Get(ctx, findingID)
	if err != nil {
		e.log.Warn("dom-xss: load finding for verification update", "finding", findingID, "err", err)
		return
	}

	now := time.Now()
	if verdictRank(verdict) > verdictRank(f.Verdict) {
		f.Verdict = verdict
		f.Confidence = confidence
		if notes != "" {
			f.Summary = notes
		}
		if f.Verdict == domain.VerdictConfirmed {
			f.Title = confirmedDOMXSSTitle(f.Title)
		}
	}
	f.EvidenceIDs = appendUniqueIDs(f.EvidenceIDs, evidenceIDs)

	d := decodeFindingDetail(f.Detail)
	d.TestCaseIDs = appendUniqueID(d.TestCaseIDs, verifyTestCaseID)
	d.Candidates = appendUniqueCandidate(d.Candidates, cand)
	d.Attempts = appendAttempt(d.Attempts, verificationAttempt{
		CandidateValue: cand.Value, CandidateDedupKey: cand.DedupKey, VerifyTestCaseID: verifyTestCaseID,
		URL: verifiedURL, Verdict: verdict, Confidence: confidence, Notes: notes, EvidenceIDs: evidenceIDs, At: now,
	})
	f.Detail = d.encode()

	f.Provenance.VerifiedAt = &now
	f.UpdatedAt = now
	if err := e.store.Findings().Update(ctx, f); err != nil {
		e.log.Warn("dom-xss: persist finding verification result", "finding", findingID, "err", err)
	}
}

// ---------------------------------------------------------------------------
// domXSSExecutor: runs JobDOMXSS jobs
// ---------------------------------------------------------------------------

// domXSSExecutor runs JobDOMXSS jobs: it probes one discovered Endpoint
// for one source, iterating every query name or bounded storage key when the
// source has selectors, through the SAME scope-enforcing browser.Manager the
// rest of the product already uses.
type domXSSExecutor struct {
	store    store.Store
	browser  *browser.Manager // nil: jobs are recorded skipped, never failed (no browser configured for this scan — mirrors verifyExecutor's Stub behavior)
	evidence evidence.Store   // nil: outcomes are recorded without evidence blobs
	scope    domain.Scope
	log      *slog.Logger
	// findingsMu — see newExecutor's doc comment. MUST be the SAME mutex
	// shared with this scan's executor/verifyExecutor.
	findingsMu *sync.Mutex
	limiter    *ratelimit.Limiter
	userAgent  string
	proxyPool  []string
	proxyNext  atomic.Uint64
	// scripts is the per-SCAN bounded, content-addressed cache of same-origin
	// external script bodies (and the recorder for everything that could not be
	// read). One loader per scan is what makes the total-byte ceiling and the
	// "same script analysed once" property hold across endpoints and workers.
	scripts *detection.DOMXSSScriptLoader
}

func newDOMXSSExecutor(st store.Store, mgr *browser.Manager, ev evidence.Store, scope domain.Scope, log *slog.Logger, findingsMu *sync.Mutex) *domXSSExecutor {
	if findingsMu == nil {
		findingsMu = &sync.Mutex{}
	}
	return &domXSSExecutor{store: st, browser: mgr, evidence: ev, scope: scope, log: log, findingsMu: findingsMu,
		scripts: detection.NewDOMXSSScriptLoader()}
}

func (e *domXSSExecutor) nextProxy() string {
	if len(e.proxyPool) == 0 {
		return ""
	}
	return e.proxyPool[(e.proxyNext.Add(1)-1)%uint64(len(e.proxyPool))]
}

var _ worker.Handler = (*domXSSExecutor)(nil)

// Handle implements worker.Handler. Return-value → job-state mapping
// mirrors executor.Handle/verifyExecutor.Handle: nil succeeds; a
// cancellation error cancels; worker.ErrPermanent-wrapped errors are not
// retried; any other error is retried up to the job's MaxAttempts.
func (e *domXSSExecutor) Handle(ctx context.Context, job *domain.TestJob) error {
	dj, err := parseDOMXSSJob(job)
	if err != nil {
		return fmt.Errorf("%w: %w", worker.ErrPermanent, err)
	}
	ep, err := e.store.Endpoints().Get(ctx, dj.EndpointID)
	if err != nil {
		return fmt.Errorf("%w: resolve endpoint: %w", worker.ErrPermanent, err)
	}
	if !domXSSNavigable(ep.Method) {
		return nil // defensive; enqueueDOMXSSProbes already filters this
	}
	allow := func(u string) bool { return e.scope.Permits(u).Allowed }
	if !allow(ep.URL) {
		return fmt.Errorf("%w: endpoint is out of scope", worker.ErrPermanent)
	}

	if e.browser == nil {
		for _, source := range dj.sourceList() {
			tc := e.newTestCase(ctx, job, ep.URL)
			tc.Status = domain.TestCaseSkipped
			e.finishTestCase(ctx, tc, nil, "dom-xss probe skipped: no browser configured for this scan (source "+string(source)+")")
		}
		return nil
	}
	for _, source := range dj.sourceList() {
		if err := e.handleDOMXSSSource(ctx, job, ep, source); err != nil {
			return err
		}
	}
	return nil
}

// handleDOMXSSSource runs one implemented DOM source for an endpoint-level
// job. The endpoint job carries every source; this helper preserves the
// per-source TestCase and verdict semantics while removing endpoint×source
// queue entries.
func (e *domXSSExecutor) handleDOMXSSSource(ctx context.Context, job *domain.TestJob, ep *domain.Endpoint, source detection.DOMXSSSource) error {
	allow := func(u string) bool { return e.scope.Permits(u).Allowed }
	// "No DOM here" is the honest answer for a non-HTML response, and it is
	// decided BEFORE any browser context, selector discovery, or navigation:
	// the crawler also registers image/asset URLs, and browser-probing those
	// used to error (and retry into a dead job) instead of recording that the
	// source simply does not apply.
	if ct := strings.TrimSpace(ep.ContentType); !domXSSContentTypeAllowsDOM(ct) {
		tc := e.newTestCase(ctx, job, ep.URL)
		tc.Status = domain.TestCaseSkipped
		e.finishTestCase(ctx, tc, nil, fmt.Sprintf("DOM-XSS %s probe not applicable: endpoint content type %q is not an HTML document, so there is no DOM for a client-side source to reach; not a clean negative, and no browser navigation was made", source, ct))
		return nil
	}

	marker := detection.NewProbe(job.ScanID, ep.ID).Token
	sessionStatePath := e.sessionStatePathFor(ctx, job.ScanID)
	proxy := e.nextProxy() // one proxy per job, shared by every per-selector context below
	newContext := func() (*browser.Context, error) {
		opts := browser.ContextOptions{AllowRequest: allow, StorageStatePath: sessionStatePath, ProxyServer: proxy}
		if e.userAgent != "" {
			opts.ExtraHeaders = map[string]string{"User-Agent": e.userAgent}
		}
		return e.browser.NewContext(ctx, opts)
	}
	bctx, err := newContext()
	if err != nil {
		tc := e.newTestCase(ctx, job, ep.URL)
		e.finishTestCase(ctx, tc, err, "open browser context")
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	defer bctx.Close()

	var selectors []domXSSQuerySelector
	// pageScripts carries the served HTML and the same-origin external script
	// bodies/skips from the ONE discovery load. It is empty for sources that do
	// not read the query string.
	var pageScripts domXSSPageScripts
	switch source {
	case detection.DOMSourcePostMessage:
		// Inline message handlers are invisible to the browser harness when
		// their sink is location.href (Location's properties cannot be
		// redefined). The same document load feeds the static pass, which can
		// see the handler body and name the sink.
		if ps, scriptErr := e.discoverScriptQueryParams(ctx, bctx, ep.URL); scriptErr == nil {
			pageScripts = ps
		}
		selectors = []domXSSQuerySelector{{}}
	case detection.DOMSourceQuery:
		selectors, err = e.queryParamSelectors(ctx, ep.ID)
		if err != nil {
			tc := e.newTestCase(ctx, job, ep.URL)
			e.finishTestCase(ctx, tc, err, "query-string DOM-XSS parameter discovery")
			return err
		}
		// The page's own scripts can read a name that appears in no URL or
		// form at all (see detection.DOMXSSQueryParamNamesFromScripts). This
		// is a bounded discovery step, not another probe pipeline: one
		// document load plus at most DOMXSSScriptFetchLimit same-origin
		// script reads, and at most DOMXSSScriptParamLimit extra selectors.
		// The same load also hands the static pass the page HTML and the
		// external script bodies it needs (see pageScripts below).
		var scriptErr error
		pageScripts, scriptErr = e.discoverScriptQueryParams(ctx, bctx, ep.URL)
		if scriptErr != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			tc := e.newTestCase(ctx, job, ep.URL)
			e.finishTestCase(ctx, tc, nil, "page-script query-name discovery failed ("+scriptErr.Error()+"); testing only parameters discovery already found")
			pageScripts = domXSSPageScripts{}
		} else if len(pageScripts.Params) > 0 {
			tc := e.newTestCase(ctx, job, ep.URL)
			e.finishTestCase(ctx, tc, nil, pageScripts.Note)
		}
		if domXSSHasRedirectLink(pageScripts.HTML) {
			e.probeClientOpenRedirect(ctx, bctx, job, ep, marker)
		}
		if domXSSCookieWritePattern(pageScripts.HTML) {
			e.probeCookieReflection(ctx, bctx, job, ep, marker)
		}
		if domXSSClobberingCommentForm(pageScripts.HTML) {
			e.probeDOMClobbering(ctx, bctx, job, ep, marker, pageScripts.HTML)
		}
		selectors = mergeDOMXSSQuerySelectors(selectors, pageScripts.Params)
		if len(selectors) == 0 {
			tc := e.newTestCase(ctx, job, ep.URL)
			tc.Status = domain.TestCaseSkipped
			e.finishTestCase(ctx, tc, nil, "query-string DOM-XSS source not tested: no discovered query parameter on this endpoint and no literal query name read by the page's own scripts")
			return nil
		}
	case detection.DOMSourceLocalStorage, detection.DOMSourceSessionStorage:
		names, err := e.discoverStorageKeys(ctx, bctx, source, ep.URL)
		if err != nil {
			tc := e.newTestCase(ctx, job, ep.URL)
			e.finishTestCase(ctx, tc, err, "storage key discovery")
			return err
		}
		discoveryTC := e.newTestCase(ctx, job, ep.URL)
		if len(names) == 0 {
			discoveryTC.Status = domain.TestCaseSkipped
			e.finishTestCase(ctx, discoveryTC, nil, fmt.Sprintf("%s source not tested: no storage key was present and no getItem key was observed", source))
			return nil
		}
		skipped := 0
		if len(names) > domXSSStorageKeyLimit {
			skipped = len(names) - domXSSStorageKeyLimit
			names = names[:domXSSStorageKeyLimit]
		}
		discoveryNote := fmt.Sprintf("%s key discovery observed %d distinct key(s); deterministic ceiling=%d, testing %d", source, len(names)+skipped, domXSSStorageKeyLimit, len(names))
		if skipped > 0 {
			discoveryNote += fmt.Sprintf("; skipped %d additional key(s)", skipped)
		}
		e.finishTestCase(ctx, discoveryTC, nil, discoveryNote)
		selectors = domXSSSelectorsFromNames(names)
	case detection.DOMSourceHash:
		names, err := e.paramNamesAt(ctx, ep.ID, domain.LocationFragment)
		if err != nil {
			tc := e.newTestCase(ctx, job, ep.URL)
			e.finishTestCase(ctx, tc, err, "fragment-route parameter discovery")
			return err
		}
		if len(names) == 0 {
			// No route parameter: keep the whole-fragment probe for plain hashes.
			names = []string{""}
		}
		selectors = domXSSSelectorsFromNames(names)
	default:
		selectors = []domXSSQuerySelector{{}}
	}

	// Every selector gets a context of its own. Origin storage, cookies and
	// service state written while probing one selector (for example a storage
	// key's payload) must never be visible to the next selector's attempt, or
	// execution caused by the first is attributed to the second.
	for _, selector := range selectors {
		if err := e.probeSelectorInFreshContext(ctx, newContext, job, ep, source, selector.Name, selector.Source, marker, pageScripts); err != nil {
			return err
		}
	}
	return nil
}

// domXSSQuerySelector is one selector the DOM pass will test, plus the
// provenance of its NAME: empty for a parameter discovery found in a URL or
// form, detection.ParameterSourcePageScript for a literal only the page's own
// JavaScript reads.
type domXSSQuerySelector struct {
	Name   string
	Source string
}

func domXSSSelectorsFromNames(names []string) []domXSSQuerySelector {
	out := make([]domXSSQuerySelector, 0, len(names))
	for _, name := range names {
		out = append(out, domXSSQuerySelector{Name: name})
	}
	return out
}

// mergeDOMXSSQuerySelectors keeps the discovered selectors EXACTLY as they
// were — same names, same order, same provenance — and appends only
// script-derived names discovery did not already carry. That is what makes
// the default plan for a page whose scripts read no query name unchanged: the
// discovered list passes through untouched and nothing is appended. Additions
// are bounded by DOMXSSScriptParamLimit, so a script that reads many names
// cannot turn one endpoint into an unbounded number of browser attempts.
func mergeDOMXSSQuerySelectors(discovered []domXSSQuerySelector, scriptParams []detection.DOMXSSScriptParam) []domXSSQuerySelector {
	out := make([]domXSSQuerySelector, 0, len(discovered)+len(scriptParams))
	seen := make(map[string]bool, len(discovered)+len(scriptParams))
	for _, sel := range discovered {
		if sel.Name == "" || seen[sel.Name] {
			continue
		}
		seen[sel.Name] = true
		out = append(out, sel)
	}
	added := 0
	for _, p := range scriptParams {
		if p.Name == "" || seen[p.Name] {
			continue
		}
		if added >= detection.DOMXSSScriptParamLimit {
			break
		}
		seen[p.Name] = true
		added++
		out = append(out, domXSSQuerySelector{Name: p.Name, Source: detection.ParameterSourcePageScript})
	}
	return out
}

func (e *domXSSExecutor) probeSelectorInFreshContext(ctx context.Context, newContext func() (*browser.Context, error), job *domain.TestJob, ep *domain.Endpoint, source detection.DOMXSSSource, selector, paramSource, marker string, pageScripts domXSSPageScripts) error {
	sctx, err := newContext()
	if err != nil {
		tc := e.newTestCase(ctx, job, ep.URL)
		e.finishTestCase(ctx, tc, err, "open browser context for "+domXSSSelectorLabel(source, selector))
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	defer sctx.Close()
	return e.probeDOMXSSCandidate(ctx, sctx, job, ep, source, selector, paramSource, marker, pageScripts)
}

// queryParamSelectors returns every distinct discovered LocationQuery
// parameter for endpointID in lexicographic name order — exactly the selector
// list the DOM pass used before page-script discovery existed. A parameter
// discovery itself recorded from an inline script literal is marked as
// page-script provenance too: the name already came from the page's script,
// and a report should say so.
func (e *domXSSExecutor) queryParamSelectors(ctx context.Context, endpointID domain.ID) ([]domXSSQuerySelector, error) {
	params, err := e.store.Parameters().ListByEndpoint(ctx, endpointID)
	if err != nil {
		return nil, err
	}
	source := make(map[string]domain.DiscoverySource)
	for _, p := range params {
		if p == nil || p.Location != domain.LocationQuery || p.Name == "" {
			continue
		}
		if _, ok := source[p.Name]; !ok {
			source[p.Name] = p.Source
		}
	}
	names := make([]string, 0, len(source))
	for name := range source {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]domXSSQuerySelector, 0, len(names))
	for _, name := range names {
		sel := domXSSQuerySelector{Name: name}
		if source[name] == domain.SourceScriptLiteral {
			sel.Source = detection.ParameterSourcePageScript
		}
		out = append(out, sel)
	}
	return out, nil
}

// domXSSPageScripts is everything ONE bounded document load of an endpoint
// gave the DOM pass: the served HTML, the literal query-parameter names its
// scripts read, and the same-origin external script bodies (or recorded skips).
// It is discovery/advisory input, never evidence: the browser verdict still
// decides whether any name reaches an executable sink.
type domXSSPageScripts struct {
	HTML    string
	Params  []detection.DOMXSSScriptParam
	Scripts []detection.DOMXSSExternalScript
	Note    string
}

// discoverScriptQueryParams reads the literal query-parameter names the page's
// own JavaScript reads — inline first, then same-origin external scripts — and
// keeps the external bodies for the static pass, from ONE bounded document
// load.
//
// Budget, stated exactly (docs/dom-xss.md "Same-origin external scripts"):
//   - one document load of the endpoint in the already-open DOM context;
//   - at most detection.DOMXSSScriptFetchLimit (8) same-origin external
//     script FILES per page, each at most DOMXSSScriptByteLimit (256 KiB), and
//     at most detection.DOMXSSScriptScanByteBudget (4 MiB) of NEW script bytes
//     per scan. A body over the per-file cap is skipped WHOLE, never truncated;
//   - at most detection.DOMXSSScriptParamLimit (12) extra selectors, applied
//     by the merge, and no name is ever invented: it must be a literal in a
//     recognised read shape.
//
// Every fetch goes THROUGH the page itself (see domXSSPageScriptFetcher), so
// the scan's session, proxy, rate limiter and the context's AllowRequest scope
// gate apply exactly as they do to every other browser request. No new network
// path is introduced, and no third-party host is ever contacted: only
// same-origin references are resolved.
//
// A failure here is never fatal: the caller keeps the discovered selectors and
// records why page-script discovery produced nothing.
func (e *domXSSExecutor) discoverScriptQueryParams(ctx context.Context, bctx *browser.Context, targetURL string) (domXSSPageScripts, error) {
	page, err := bctx.NewPage(ctx)
	if err != nil {
		return domXSSPageScripts{}, err
	}
	defer page.Close()
	if _, err := page.Navigate(ctx, targetURL, browser.NavOptions{Limiter: e.limiter, WaitUntil: browser.WaitLoad}); err != nil {
		return domXSSPageScripts{}, err
	}
	html, err := page.Content(ctx)
	if err != nil {
		return domXSSPageScripts{}, err
	}

	params := detection.DOMXSSQueryParamNamesFromHTML(html)
	inlineNames := len(params)

	// The loader resolves only same-origin references, applies the per-page,
	// per-file and per-scan ceilings, and caches by URL and content hash. A
	// bare executor (tests construct one without the constructor) gets a
	// throw-away loader rather than a nil dereference; its result is identical
	// for that one page, it simply loses the cross-page cache.
	loader := e.scripts
	if loader == nil {
		loader = detection.NewDOMXSSScriptLoader()
	}
	scripts := loader.ScriptsFor(domXSSPageScriptFetcher{ctx: ctx, page: page, limiter: e.limiter}, targetURL, detection.DOMXSSScriptSrcs(html))
	var available, unavailable, foreign int
	for _, s := range scripts {
		switch {
		case s.Err == detection.DOMXSSScriptSkipForeign:
			foreign++
		case s.Unavailable():
			unavailable++
		default:
			available++
			params = append(params, detection.DOMXSSQueryParamNamesFromScript(s.Body, s.URL)...)
		}
	}

	params = detection.DOMXSSMergeScriptParams(params, detection.DOMXSSScriptParamLimit)
	stats := loader.Stats()
	note := fmt.Sprintf("page-script query-name discovery: %d literal name(s) read by the page's own scripts; %d inline name(s), %d same-origin external script(s) analysed (caps: %d files/page, %d KiB/file, %d MiB/scan; %d unreadable, %d third-party; scan total %d bytes in %d distinct bodies)",
		len(params), inlineNames, available,
		detection.DOMXSSScriptFetchLimit, detection.DOMXSSScriptByteLimit>>10, detection.DOMXSSScriptScanByteBudget>>20,
		unavailable, foreign, stats.BytesRead, stats.Bodies)
	if len(params) > 0 {
		provenance := make([]string, 0, len(params))
		for _, p := range params {
			provenance = append(provenance, fmt.Sprintf("%s (%s line %d)", p.Name, p.Script, p.Line))
		}
		note = fmt.Sprintf("page-script query-name discovery: %d literal name(s) read by the page's own scripts: %s; %d inline name(s), %d same-origin external script(s) analysed (caps: %d files/page, %d KiB/file, %d MiB/scan; %d unreadable, %d third-party)",
			len(params), strings.Join(provenance, ", "), inlineNames, available,
			detection.DOMXSSScriptFetchLimit, detection.DOMXSSScriptByteLimit>>10, detection.DOMXSSScriptScanByteBudget>>20,
			unavailable, foreign)
	}
	return domXSSPageScripts{HTML: html, Params: params, Scripts: scripts, Note: note}, nil
}

// domXSSPageScriptFetcher reads one same-origin script body THROUGH the
// already-loaded page, so the context's session cookies, proxy, rate limiter
// and AllowRequest scope gate are the same ones the rest of the browser pass
// uses. Nothing here widens what may be fetched: the URL has already been
// resolved and origin-checked by detection.DOMXSSScriptLoader.
//
// The body is NEVER truncated. A response whose declared or actual length
// exceeds DOMXSSScriptByteLimit is reported as ErrDOMXSSScriptTooLarge and the
// loader skips it whole — half a minified bundle parses into nonsense, and a
// nonsense "no sink" is worse than an explicit skip.
type domXSSPageScriptFetcher struct {
	ctx     context.Context
	page    *browser.Page
	limiter *ratelimit.Limiter
}

func (f domXSSPageScriptFetcher) FetchDOMXSSScript(src string) (string, error) {
	// Every script read consumes one rate-limiter slot, so the bounded set of
	// script fetches is paced by the same limiter as the scan's other requests
	// instead of riding along unmetered on the page load.
	if f.limiter != nil {
		if err := f.limiter.Wait(f.ctx); err != nil {
			return "", err
		}
	}
	quoted, err := json.Marshal(src)
	if err != nil {
		return "", err
	}
	expr := fmt.Sprintf(`(() => { try {
  const x = new XMLHttpRequest();
  x.open('GET', %s, false);
  x.send();
  if (x.status < 200 || x.status >= 300) return { error: 'HTTP ' + x.status };
  const declared = Number(x.getResponseHeader('Content-Length') || '0');
  if (declared > %d) return { tooLarge: true };
  const body = String(x.responseText || '');
  if (body.length > %d) return { tooLarge: true };
  return { body: body };
} catch (e) { return { error: String(e) }; } })()`, quoted, detection.DOMXSSScriptByteLimit, detection.DOMXSSScriptByteLimit)
	raw, err := f.page.Evaluate(f.ctx, expr)
	if err != nil {
		return "", err
	}
	m, ok := raw.(map[string]any)
	if !ok {
		return "", fmt.Errorf("script fetch returned an unexpected value (%T)", raw)
	}
	if v, ok := m["tooLarge"]; ok && v == true {
		return "", detection.ErrDOMXSSScriptTooLarge
	}
	if v, ok := m["error"]; ok {
		return "", fmt.Errorf("script fetch: %v", v)
	}
	body, _ := m["body"].(string)
	return body, nil
}

// domXSSSameOriginScriptURL is the scan-side name for the one origin policy,
// which lives in detection with the rest of the bounded script layer.
func domXSSSameOriginScriptURL(raw, base string) (string, bool) {
	return detection.DOMXSSSameOriginScriptURL(raw, base)
}

// domXSSStaticProvenanceNote renders the bounded static pass's view of where a
// sink lives. It is ADVISORY (never a verdict): the browser's marker signal
// remains the only confirmation. It exists so a "no sink observed" result names
// the script the pass did find a path through, instead of implying the page has
// no sink anywhere.
func domXSSStaticProvenanceNote(res detection.DOMXSSStaticResult) string {
	if len(res.Sites) > 0 {
		site := res.Sites[0]
		where := "an inline script"
		if site.Script != "" {
			where = site.Script
		}
		return fmt.Sprintf("static pass (advisory, no verdict): %s reachable at %s line %d", site.Sink, where, site.Line)
	}
	if len(res.ScriptProblems) > 0 {
		return fmt.Sprintf("static pass (advisory, no verdict): %d referenced script(s) could not be analysed, e.g. %s, so absence of a sink is not established",
			len(res.ScriptProblems), res.ScriptProblems[0].Describe())
	}
	// Nothing the browser did not already say: a page whose external scripts
	// were all analysed and contain no sink keeps exactly the note it had
	// before this layer existed.
	return ""
}

// paramNamesAt returns every distinct discovered parameter name at loc for
// endpointID, sorted (deterministic probe order).
func (e *domXSSExecutor) paramNamesAt(ctx context.Context, endpointID domain.ID, loc domain.ParamLocation) ([]string, error) {
	params, err := e.store.Parameters().ListByEndpoint(ctx, endpointID)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool)
	var names []string
	for _, p := range params {
		if p == nil || p.Location != loc || p.Name == "" || seen[p.Name] {
			continue
		}
		seen[p.Name] = true
		names = append(names, p.Name)
	}
	sort.Strings(names)
	return names, nil
}

func domXSSSelectorLabel(source detection.DOMXSSSource, selector string) string {
	switch source {
	case detection.DOMSourceQuery:
		return fmt.Sprintf("%s parameter %q", source, selector)
	case detection.DOMSourcePostMessage:
		return string(source)
	case detection.DOMSourceLocalStorage, detection.DOMSourceSessionStorage:
		return fmt.Sprintf("%s key %q", source, selector)
	default:
		return string(source)
	}
}

func domXSSCandidateForSelector(cand detection.Candidate, source detection.DOMXSSSource, selector, paramSource string) detection.Candidate {
	cand.ParameterSource = paramSource
	if paramSource == detection.ParameterSourcePageScript {
		// Surfaced through the finding's Summary without any report change:
		// the name exists only in the page's own script, so an operator
		// cannot reproduce the attempt by looking at URLs or forms.
		cand.Rationale += " The parameter name itself was read from the page's own JavaScript (a literal in an inline or same-origin external script), not from a URL or form, so it does not appear in discovery's parameter list."
	}
	if source == detection.DOMSourceHash && selector != "" {
		cand.Parameter = selector
		cand.Location = domain.LocationFragment
		cand.DedupKey += fmt.Sprintf("\x00selector:%d:%s", len(selector), selector)
		return cand
	}
	if source != detection.DOMSourceQuery && source != detection.DOMSourceLocalStorage && source != detection.DOMSourceSessionStorage {
		return cand
	}
	cand.Parameter = selector
	if source == detection.DOMSourceQuery {
		cand.Location = domain.LocationQuery
	}
	cand.DedupKey += fmt.Sprintf("\x00selector:%d:%s", len(selector), selector)
	return cand
}

func (e *domXSSExecutor) probeDOMXSSCandidate(ctx context.Context, bctx *browser.Context, job *domain.TestJob, ep *domain.Endpoint, source detection.DOMXSSSource, selector, paramSource, marker string, pageScripts domXSSPageScripts) error {
	label := domXSSSelectorLabel(source, selector)
	if paramSource == detection.ParameterSourcePageScript {
		label += " (name read by the page's own script)"
	}
	canary := detection.DOMXSSCanary(marker)
	if source == detection.DOMSourcePostMessage {
		// A page that only navigates for http(s)-looking messages will never
		// hand a plain marker to its sink, so the reachability canary must
		// look like a URL. Same-origin with a fragment: if the page assigns it
		// to location, the navigation stays inside scope and does not reload.
		if u, uerr := url.Parse(ep.URL); uerr == nil && u.Host != "" {
			canary = u.Scheme + "://" + u.Host + "/#" + canary
		}
	}

	// The bounded static pass gets the SAME source and selector the browser is
	// about to probe, over the page bytes and the same-origin external script
	// bodies the discovery load already fetched. It is advisory: it never
	// creates a finding and never decides a verdict. It is consulted only for
	// pages that actually have external scripts, so an inline-only page's
	// recorded notes are byte-for-byte what they were before this layer.
	staticNote := ""
	if source == detection.DOMSourceQuery && pageScripts.HTML != "" && len(pageScripts.Scripts) > 0 {
		static := detection.DOMXSSStaticReachabilityWithScripts(pageScripts.HTML, ep.URL, source, selector, pageScripts.Scripts)
		staticNote = domXSSStaticProvenanceNote(static)
	}

	// --- Phase 1: reachability ---
	// probeHashChange is phase-one only and hash-source only: a page that
	// wires a hashchange listener has not run it for the fragment the URL
	// already carried, so when nothing is reachable the engine re-issues the
	// same fragment once and observes again. A sink found that way is marked
	// so verification repeats the delivery it needed.
	obs1, canaryNavURL, hashActivated, navErr := e.navigateSourceWithActivation(ctx, bctx, source, ep, selector, marker, canary, domXSSActivateNone, source == detection.DOMSourceHash)
	reachTC := e.newTestCase(ctx, job, canaryNavURL)
	if errors.Is(navErr, errDOMXSSSourceNotApplicable) {
		reachTC.Status = domain.TestCaseSkipped
		e.finishTestCase(ctx, reachTC, nil, fmt.Sprintf("%s not applicable for this endpoint: the loaded document has no attachable root element (no body and no documentElement), so nothing could receive this source's value here; no DOM-XSS coverage was exercised for it and this is not a clean negative", label))
		return nil
	}
	if errors.Is(navErr, errDOMXSSPostMessageIndeterminate) {
		// The delivery mechanism itself could not be observed working (see
		// errDOMXSSPostMessageIndeterminate). Recording "no sink reachable"
		// here would turn an unknown into a negative, so the outcome is its
		// own explicit skip naming the missing coverage. The job is not
		// retried: the probe has already spent its bounded wait once, and a
		// page that refused the frame will refuse it again.
		reachTC.Status = domain.TestCaseSkipped
		e.finishTestCase(ctx, reachTC, nil, fmt.Sprintf("%s coverage could not be determined: the sender frame never reported load within the probe's %s bounded fallback, so whether the message was posted is unknown (the page may have removed or refused the sender frame, or the document may have changed mid-probe); this is not a delivery and not a clean negative", label, domXSSPostMessageFallback))
		return nil
	}
	if navErr == nil {
		navErr = requireDOMXSSProvenance(obs1)
	}
	if navErr != nil {
		e.finishTestCase(ctx, reachTC, navErr, "reachability probe for "+label)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return navErr
	}
	// Reachability comes only from reports the harness itself emitted: a page
	// calling console.log with the harness prefix is not a hooked sink.
	reachable := parseDOMXSSReachability(domXSSHarnessMessages(obs1.Runtime), marker)
	if len(reachable) == 0 && len(parseDOMXSSReachability(obs1.Console, marker)) > 0 {
		// The page printed harness-shaped reports for this marker but none was
		// traced to the installed harness: forged output or an instrumentation
		// mismatch. Either way this is untested, not a negative.
		err := errors.New("harness-shaped console reports were not attributable to the installed harness; sink reachability is untested")
		e.finishTestCase(ctx, reachTC, err, "reachability probe for "+label)
		return err
	}
	// A text canary reaching a text-only sink does not establish that the page
	// has no HTML sink: a page may route only markup-looking values to
	// innerHTML. So before concluding negative, send the markup payload once
	// and let the deterministic execution signal decide.
	textSinks := parseDOMXSSTextSinks(domXSSHarnessMessages(obs1.Runtime), marker)
	markupProbed, markupExecuted := false, false
	if len(reachable) == 0 && len(textSinks) > 0 {
		markupProbed = true
		markupExecuted = e.probeDOMXSSMarkup(ctx, bctx, source, ep, selector, marker)
	}
	if len(reachable) == 0 && source == detection.DOMSourcePostMessage && pageScripts.HTML != "" {
		// A message handler that writes to location/src cannot be observed by
		// the init-script harness (those properties are not redefinable).
		// The static pass executes the page's own message handler with a
		// message-event taint, so a named sink here is a planning hint; the
		// verdict still comes from the browser executing the payload.
		static := detection.DOMXSSStaticReachabilityWithScripts(pageScripts.HTML, ep.URL, source, "", pageScripts.Scripts)
		for _, site := range static.Sites {
			if site.Sink == detection.DOMSinkLocationAssign || site.Sink == detection.DOMSinkElementSrc || site.Sink == detection.DOMSinkCookie {
				reachable = append(reachable, site.Sink)
				staticNote = fmt.Sprintf("static message-handler analysis named sink %s (the runtime harness cannot hook this property)", site.Sink)
				break
			}
		}
	}
	if len(reachable) == 0 && !markupExecuted {
		note := fmt.Sprintf("no implemented DOM-XSS sink reachable from %s (negative result)", label)
		if len(textSinks) > 0 {
			// The marker DID arrive in the page, but only in a position that
			// cannot execute. Saying so keeps this negative honest: it
			// distinguishes "the harness saw nothing" from "the value landed
			// somewhere harmless", which is what the measured application page
			// does (it writes the echoed term with innerText).
			note += fmt.Sprintf("; the marker did reach a text-only sink (%s), which cannot execute, so the value arrived in the page but never reached an HTML or timer sink", strings.Join(textSinks, ", "))
			if markupProbed {
				note += "; a markup payload sent afterwards produced no marker execution either"
			}
		}
		if obs1.SettleBusy {
			note += fmt.Sprintf("; the bounded network settle (%s) expired with requests still in flight, so an async-driven sink may not have run yet", domXSSURLSourceObservationDelay(canaryNavURL)+domXSSNetworkSettleBudget)
		}
		if staticNote != "" {
			note += "; " + staticNote
		}
		e.finishTestCase(ctx, reachTC, nil, note)
		return nil
	}
	// Bounded to the first reachable sink (deterministic: whichever the
	// page's own script used first) — see this file's header comment. jQuery's
	// factory is the one exception, explained on domXSSPrimarySink.
	var sink detection.DOMXSSSink
	var reachNote string
	if len(reachable) == 0 {
		// Only the markup payload reached an executable position; the text
		// canary never did. The exact sink is not known, so the generic HTML
		// shapes are verified under innerHTML.
		sink = detection.DOMSinkInnerHTML
		reachNote = fmt.Sprintf("reachable sink: %s from %s (the text canary only reached a text-only sink; a markup payload then executed the marker, so the page routes markup to an HTML sink)", sink, label)
	} else {
		sink = domXSSPrimarySink(reachable)
		reachNote = fmt.Sprintf("reachable sink: %s from %s (canary observed in the hooked setter/call)", sink, label)
	}
	if staticNote != "" {
		reachNote += "; " + staticNote
	}
	if sink == detection.DOMSinkAngularExpression {
		reachNote = fmt.Sprintf("reachable sink: %s from %s (the canary was observed as rendered text after the page's load event, the precondition for AngularJS text-node interpolation; this is reachability, not proof of compilation)", sink, label)
	}
	if hashActivated {
		reachNote += "; the page only reached the sink after the engine's bounded hash change, because its own load-time scripts did not run the handler for the fragment the URL already carried"
	}
	e.finishTestCase(ctx, reachTC, nil, reachNote)

	// Every candidate SHAPE for this (source, sink) is tried in the planner's
	// deterministic order. The first shape whose navigation produces a REAL
	// marker execution ends verification; a shape that merely reflects is
	// rejected and the next shape gets its own navigation. All shapes at one
	// site correlate into the SAME finding (finding identity is
	// endpoint/source/sink/selector, never the payload value), so trying an
	// extra shape never creates a near-duplicate row.
	shapes := detection.DOMXSSPayloadsFor(source, sink, marker)
	e.log.Debug("dom-xss: shape plan", "scan", job.ScanID, "source", source, "sink", sink, "selector", selector, "shapes", len(shapes))
	for _, shape := range shapes {
		e.log.Debug("dom-xss: trying shape", "scan", job.ScanID, "shape", shape.Shape)
		cand := domXSSCandidateForSelector(shape, source, selector, paramSource)

		e.findingsMu.Lock()
		finding, err := upsertDOMXSSFinding(ctx, e.store, job.ScanID, ep, cand, canary, reachTC.ID)
		e.findingsMu.Unlock()
		if err != nil {
			e.log.Warn("dom-xss: upsert finding", "job", job.ID, "err", err)
			return nil
		}

		stop, err := e.verifyDOMXSSShape(ctx, bctx, job, ep, source, selector, marker, sink, hashActivated, cand, finding.ID, label)
		if err != nil {
			return err
		}
		if stop {
			return nil
		}
	}
	return nil
}

// probeDOMXSSMarkup navigates once with the benign markup payload and reports
// whether the browser attributed a marker execution to it. It records nothing
// and creates no finding: a true result only sends the caller on to the normal
// shape verification, which does.
func (e *domXSSExecutor) probeDOMXSSMarkup(ctx context.Context, bctx *browser.Context, source detection.DOMXSSSource, ep *domain.Endpoint, selector, marker string) bool {
	cands := detection.DOMXSSPayloadsFor(source, detection.DOMSinkInnerHTML, marker)
	if len(cands) == 0 {
		return false
	}
	obs, _, _, err := e.navigateSourceWithActivation(ctx, bctx, source, ep, selector, marker, cands[0].Value, domXSSActivateNone, false)
	if err != nil || requireDOMXSSProvenance(obs) != nil {
		return false
	}
	_, _, matched := verification.MatchRuntimeExecution(marker, obs.Runtime)
	return matched
}

// verifyDOMXSSShape runs phase 2 (VERIFICATION) for ONE candidate shape and
// correlates its verdict into the already-upserted finding. It returns
// stop=true when the site's verification is finished — a shape produced a
// genuine Confirmed execution, the source proved not applicable to this
// document, or a failure was surfaced for the worker's bounded retry — and
// false when the next shape should be tried because this one only reflected.
//
// Execution is attributed by the browser engine (the paused instruction is
// the bare marker identifier, in the main frame), never by matching
// page-controlled error or console text.
func (e *domXSSExecutor) verifyDOMXSSShape(ctx context.Context, bctx *browser.Context, job *domain.TestJob, ep *domain.Endpoint, source detection.DOMXSSSource, selector, marker string, sink detection.DOMXSSSink, hashActivated bool, cand detection.Candidate, findingID domain.ID, label string) (bool, error) {
	act := domXSSActivationForSink(sink, hashActivated)
	var obs2 domXSSObservation
	var payloadNavURL string
	var activationApplied bool
	var verr error
	if detection.DOMXSSShapeNeedsParameterName(cand.Shape) {
		// A candidate that reaches its sink as a query parameter NAME cannot
		// be delivered by any of the value-carrying routes: navigate it
		// directly, and refuse the shape anywhere else rather than silently
		// sending it as a value (which cannot reach the sink).
		if source != detection.DOMSourceQuery {
			return true, fmt.Errorf("dom-xss: shape %q requires the query source, got %s", cand.Shape, source)
		}
		obs2, payloadNavURL, verr = e.navigateNamedDOMXSSExpression(ctx, bctx, ep, selector, cand.Value, marker)
	} else {
		obs2, payloadNavURL, activationApplied, verr = e.navigateSourceWithActivation(ctx, bctx, source, ep, selector, marker, cand.Value, act, false)
	}
	verifyTC := e.newTestCase(ctx, job, payloadNavURL)
	if errors.Is(verr, errDOMXSSSourceNotApplicable) {
		verifyTC.Status = domain.TestCaseSkipped
		e.finishTestCase(ctx, verifyTC, nil, fmt.Sprintf("%s not applicable for this endpoint: the loaded document has no attachable root element, so this shape could not be delivered; not a clean negative", label))
		return true, nil
	}
	if errors.Is(verr, errDOMXSSPostMessageIndeterminate) {
		// The payload may never have been posted, so no execution signal
		// could be attributable to it. Stopping without a verdict leaves the
		// finding Pending (unknown) — never Confirmed, and never a Rejected
		// derived from the absence of a signal that had no chance to appear.
		verifyTC.Status = domain.TestCaseSkipped
		e.finishTestCase(ctx, verifyTC, nil, fmt.Sprintf("%s verification could not be determined: the sender frame never reported load within the probe's %s bounded fallback, so whether the payload was delivered is unknown; the finding stays pending rather than being confirmed or rejected from an undelivered probe", label, domXSSPostMessageFallback))
		return true, nil
	}
	if verr == nil {
		verr = requireDOMXSSProvenance(obs2)
	}
	if verr != nil {
		e.finishTestCase(ctx, verifyTC, verr, "verification navigation for "+label)
		// Surface the failure to the worker instead of returning nil: a nil
		// result makes the queue complete the job while its verification
		// TestCase is recorded as failed, so the existing bounded
		// MaxAttempts/backoff retry (and eventual dead-job state) never runs.
		// The failure stays retryable — a dropped connection or a transient
		// provenance failure is not a permanent verdict.
		if ctx.Err() != nil {
			return true, ctx.Err() // preserve cancellation; never mask it as success
		}
		return true, fmt.Errorf("verification navigation for %s: %w", label, verr)
	}

	harness2 := domXSSHarnessMessages(obs2.Runtime)
	var consoleErrs []string
	for _, cm := range obs2.Console {
		if cm.Type == "error" {
			consoleErrs = append(consoleErrs, cm.Text)
		}
	}
	_, sigText, matched := verification.MatchRuntimeExecution(marker, obs2.Runtime)
	childFrameExecution := false
	if !matched && sink == detection.DOMSinkElementSrc && domXSSChildFrameExecution(obs2.Runtime, marker) {
		// An iframe/javascript: URL runs in the child frame, so the main-frame
		// exception check can never see it. Accept it only when the main-frame
		// harness also observed this exact marker being written to an
		// element.src, which ties the child execution to our payload.
		matched = true
		childFrameExecution = true
	}
	fragmentNotInserted := sink == detection.DOMSinkCreateContextualFragment && !hasConnectedDOMXSSFragment(harness2, marker)
	if fragmentNotInserted {
		matched = false
	}
	markerInDOM := strings.Contains(obs2.HTML, marker)
	var verdict domain.Verdict
	var confidence domain.Confidence
	var notes string
	// dialogConfirmed records that the verdict rests on EXECUTION (a dialog
	// carrying the marker), so the compilation-only caveat below must not be
	// appended: it would claim "no alert was executed" directly after the
	// evidence that one was.
	dialogConfirmed := false
	if sink == detection.DOMSinkAngularExpression {
		// The ReferenceError channel cannot decide this sink: Angular resolves
		// an unknown identifier to undefined, so the marker-specific signal is
		// the evaluated RESULT appearing in rendered text (see
		// detection.domXSSAngularInterpolation for why that cannot be a
		// reflection match). A document that refused dynamic evaluation gets
		// its own outcome instead of being read as a negative.
		// Execution first: a dialog carrying the marker means the candidate's
		// code RAN, which is strictly stronger than "the expression compiled".
		// The sandbox-escape shape is built for this, and the marker is random
		// per scan, so the page cannot fabricate one by echoing text.
		if msg, ok := verification.MarkerDialog(marker, obs2.Dialogs); ok {
			dialogConfirmed = true
			verdict, confidence = domain.VerdictConfirmed, domain.ConfidenceHigh
			notes = "outcome=sandbox_escape_executed: the candidate's code EXECUTED in the browser — a JavaScript dialog carried this scan's marker, which only running code can produce; evidence: " + msg
		} else {
			cspViolations := parseDOMXSSCSPViolations(harness2)
			cspBlocked, violation := domXSSEvalBlockedByCSP(cspViolations)
			compiled, viaBinding := domXSSAngularResult(harness2, marker)
			if detection.DOMXSSShapeNeedsParameterName(cand.Shape) {
				// The parameter-NAME binding never puts the candidate's bytes in a
				// text node (they sit in the page's own inline script), so the
				// interpolation shape's "inert text" test would be measuring the
				// wrong place. Its absence of a result is therefore untested, not
				// a rejection — see decideDOMXSSAngularParse.
				verdict, confidence, notes = decideDOMXSSAngularParse(compiled, cspBlocked, violation)
			} else {
				verdict, confidence, notes = decideDOMXSSAngular(compiled, viaBinding, domXSSAngularInertText(obs2.HTML, cand.Value), cspBlocked, violation)
			}
		}
	} else {
		verdict, confidence, notes = verification.DecideWithProvenance(marker, matched, markerInDOM, obs2.Runtime)
	}
	if fragmentNotInserted {
		notes += "; target insertion of the parsed fragment was not observed; detached-fragment runtime errors alone do not confirm this sink"
	}
	if childFrameExecution {
		notes += "; execution was attributed to the child frame this page created from the element.src write (the main-frame harness saw the marker reach element.src); this is a frame execution, not a main-frame one"
	}
	if sink != detection.DOMSinkAngularExpression && matched && sigText != "" {
		notes = notes + " (" + sigText + ")"
	}
	if matched {
		observed := parseDOMXSSReachability(harness2, marker)
		if sink != detection.DOMSinkAngularExpression {
			observed = withoutDOMXSSSink(observed, detection.DOMSinkAngularExpression)
		}
		notes += domXSSAttributionNotes(source, sink, observed)
	}
	if sink == detection.DOMSinkAngularExpression && verdict == domain.VerdictConfirmed && !dialogConfirmed {
		if detection.DOMXSSShapeNeedsParameterName(cand.Shape) {
			notes += "; confirmation is the $parse evaluation RESULT of the parameter-name expression, not a sandbox escape: no alert, cookie, network request or escape gadget was executed"
		} else {
			notes += "; confirmation is the compiled interpolation RESULT, not a sandbox escape: no alert, cookie, network request or escape gadget was executed"
		}
	}
	if source == detection.DOMSourceLocalStorage || source == detection.DOMSourceSessionStorage {
		notes += "; attacker-relevant ability to write or poison this storage key is not established by this isolated probe and requires manual exploitability review unless the target flow demonstrates it"
	}
	if act != domXSSActivateNone {
		if activationApplied {
			notes += "; activation step: " + act.describe() + ", performed once before the execution signal was read"
		} else {
			notes += "; activation step (" + act.label() + ") found no target element the harness had located, so execution was not attemptable on this run"
		}
	}

	var evidenceIDs []domain.ID
	if e.evidence != nil {
		logLines := append(append([]string(nil), consoleErrs...), obs2.PageErrors...)
		for _, message := range harness2 {
			logLines = append(logLines, message.Text)
		}
		if act != domXSSActivateNone {
			state := "not-applied"
			if activationApplied {
				state = "applied"
			}
			logLines = append(logLines, domXSSActivationEvidencePrefix+act.label()+":"+state)
		}
		if raw, err := json.Marshal(obs2.Runtime); err == nil {
			logLines = append(logLines, "__INDAGO_RUNTIME_PROVENANCE__"+string(raw))
		}
		evidenceIDs = e.persistDOMXSSEvidence(ctx, job.ScanID, verifyTC.ID, obs2.Screenshot, obs2.HTML, logLines)
	}
	verifyTC.EvidenceIDs = evidenceIDs
	e.finishTestCase(ctx, verifyTC, nil, notes)

	e.correlateDOMXSSVerification(ctx, findingID, cand, verdict, confidence, notes, verifyTC.ID, evidenceIDs, payloadNavURL)
	return verdict == domain.VerdictConfirmed, nil
}

// Angular-expression outcomes. These are recorded verbatim in the attempt
// notes (and the verification TestCase note) so an operator — and any
// downstream consumer — can tell a CSP refusal apart from a plain negative.
// They are deliberately NOT new domain verdict values: the verdict lattice is
// shared with every other engine and csp_blocked is honestly an Inconclusive
// (the sink was reachable, but the compile was refused by policy before
// execution could be observed).
const (
	domXSSAngularOutcomeCompiled   = "compiled"
	domXSSAngularOutcomeCSPBlocked = "csp_blocked"
	domXSSAngularOutcomeInertText  = "inert_text"
	domXSSAngularOutcomeUnobserved = "unobserved"
	// domXSSAngularOutcomeParseUnobserved is the parameter-NAME binding's
	// negative outcome. It is deliberately NOT domXSSAngularOutcomeInertText:
	// the candidate bytes never reach a text node on this binding (they are
	// compiled, not interpolated), so "the source is still rendered as text"
	// says nothing about whether it was evaluated.
	domXSSAngularOutcomeParseUnobserved = "parse_unobserved"
)

// domXSSAngularInertText reports whether the rendered page still carries the
// candidate's expression SOURCE as inert text, i.e. Angular never compiled
// it. The rendered DOM is HTML, so a page that passed the value through an
// HTML encoder shows character references instead of our exact bytes — the
// measured without-strings lab stores '{{&apos;MARK…}}' in its scope and
// renders that literal string as text, which a raw substring check misses.
// Decode the serialization once (the browser's own serializer escapes '&' as
// '&amp;', so one pass recovers the text the page actually holds), then
// normalise the references that can stand in for the candidate's quotes. A
// compiled interpolation replaces its source with the evaluated result, so
// this cannot match a page that evaluated it; a page that both compiled the
// candidate and echoed its source elsewhere is still Confirmed, because
// decideDOMXSSAngular checks compiled first.
func domXSSAngularInertText(renderedHTML, candidate string) bool {
	if candidate == "" {
		return false
	}
	if strings.Contains(renderedHTML, candidate) {
		return true
	}
	text := html.UnescapeString(renderedHTML)
	for _, ref := range [][2]string{
		{"&apos;", "'"}, {"&#39;", "'"}, {"&#x27;", "'"},
	} {
		text = strings.ReplaceAll(text, ref[0], ref[1])
	}
	return strings.Contains(text, candidate)
}

// decideDOMXSSAngular is the angular_expression sink's single verdict rule. It
// is a pure function of four observations:
//
//   - compiled: the marker — which the candidate never contains contiguously —
//     was observed as the result of the interpolation: either as the content
//     of a rendered text node, or (viaBinding) as the value Angular's own
//     compiled $binding function returns for the element that carries this
//     candidate's expression. This is Confirmed; nothing further is executed.
//   - cspBlocked: the document's own CSP refused dynamic evaluation during
//     this navigation and no result appeared. The compile could not happen,
//     so the honest outcome is Inconclusive with its own token — never a
//     silent Rejected and never a Confirmed.
//   - payloadPresent: the candidate's expression source is still in the
//     rendered page (after HTML character references are normalised) but
//     compiled is false, so the page carried it as inert text. Rejected.
//
// Anything else (the candidate could not even be re-observed) is
// Inconclusive: the attempt had no chance to prove or disprove compilation.
func decideDOMXSSAngular(compiled, viaBinding, payloadPresent, cspBlocked bool, violation domXSSCSPViolation) (domain.Verdict, domain.Confidence, string) {
	switch {
	case compiled:
		how := "wrote its result into the rendered text node"
		if viaBinding {
			how = "produced the result through its compiled interpolation binding, read with the element's own scope because the write was not present in rendered body text"
		}
		return domain.VerdictConfirmed, domain.ConfidenceHigh,
			"outcome=" + domXSSAngularOutcomeCompiled + ": AngularJS evaluated the double-brace interpolation and " + how + "; the candidate never contains the marker contiguously, so the observed marker is the expression's evaluated result, not a reflection"
	case cspBlocked:
		return domain.VerdictInconclusive, domain.ConfidenceLow,
			fmt.Sprintf("outcome=%s: the document's Content-Security-Policy refused dynamic script evaluation during this verification navigation (directive=%q blocked=%q), so AngularJS's expression compiler could not run and the marker result was never produced; the sink was reachable, so this is not a rejection, and no compilation was observed, so it is not a confirmation",
				domXSSAngularOutcomeCSPBlocked, violation.Directive, violation.Blocked)
	case payloadPresent:
		return domain.VerdictRejected, domain.ConfidenceHigh,
			"outcome=" + domXSSAngularOutcomeInertText + ": the interpolation candidate reached the page as inert text and Angular never evaluated it; a page that echoes the source as text cannot produce the contiguous marker"
	default:
		return domain.VerdictInconclusive, domain.ConfidenceLow,
			"outcome=" + domXSSAngularOutcomeUnobserved + ": neither the interpolation candidate nor its evaluated result could be re-observed in the rendered page, so compilation could not be attempted or ruled out"
	}
}

// decideDOMXSSAngularParse is the parameter-NAME binding's verdict rule. Same
// confidence and the same csp_blocked token as the interpolation shape, but no
// Rejected branch: on this binding the candidate bytes are compiled by the
// page's own $parse call and never occupy a text node, so "the marker did not
// appear" proves only that this navigation did not observe a result — the page
// may not emit the binding for an added parameter, or the result may not reach
// a rendered node. That is untested, and it is recorded as its own outcome
// rather than as a rejection derived from a signal that had no chance to appear.
func decideDOMXSSAngularParse(compiled, cspBlocked bool, violation domXSSCSPViolation) (domain.Verdict, domain.Confidence, string) {
	switch {
	case compiled:
		return domain.VerdictConfirmed, domain.ConfidenceHigh,
			"outcome=" + domXSSAngularOutcomeCompiled + ": the page's own $parse call compiled the expression delivered as the query parameter NAME and its evaluated result was written into rendered text; the candidate never contains the marker contiguously, so the observed marker is the expression's evaluated result, not a reflection; confirmation is $parse evaluation, not a sandbox escape: no alert, cookie, network request or escape gadget was executed"
	case cspBlocked:
		return domain.VerdictInconclusive, domain.ConfidenceLow,
			fmt.Sprintf("outcome=%s: the document's Content-Security-Policy refused dynamic script evaluation during this verification navigation (directive=%q blocked=%q), so the page's $parse call could not compile the expression delivered as the parameter name and the marker result was never produced; the sink was reachable, so this is not a rejection, and no compilation was observed, so it is not a confirmation",
				domXSSAngularOutcomeCSPBlocked, violation.Directive, violation.Blocked)
	default:
		return domain.VerdictInconclusive, domain.ConfidenceLow,
			"outcome=" + domXSSAngularOutcomeParseUnobserved + ": the expression was delivered as a query parameter NAME but neither its evaluated result nor a compilation refusal was observed in the rendered page (the page may not emit this binding for an added parameter, and this binding never renders the source as text); on this binding that is untested, not a rejection — the interpolation attempt's own verdict is recorded separately"
	}
}

func requireDOMXSSProvenance(obs domXSSObservation) error {
	if obs.Runtime.Available {
		return nil
	}
	note := obs.Runtime.Note
	if note == "" {
		note = "driver reported no runtime provenance"
	}
	return fmt.Errorf("runtime provenance unavailable: %s", note)
}

// domXSSHarnessMessages returns the sink-hook reports whose console call the
// engine traced back to the exact installed init script. Page-authored console
// text that merely imitates the prefix is absent from Runtime.Reports.
func domXSSHarnessMessages(rt browser.RuntimeObservations) []browser.ConsoleMessage {
	out := make([]browser.ConsoleMessage, 0, len(rt.Reports))
	for _, report := range rt.Reports {
		out = append(out, browser.ConsoleMessage{Type: "log", Text: report.Text})
	}
	for _, compilation := range rt.Compilations {
		if compilation.Location.FrameID != rt.MainFrameID || rt.MainFrameID == "" {
			continue
		}
		if compilation.Kind != string(detection.DOMSinkEval) && compilation.Kind != string(detection.DOMSinkFunction) {
			continue
		}
		raw, err := json.Marshal(domXSSSinkReport{Sink: compilation.Kind, Value: compilation.SourceExcerpt})
		if err == nil {
			out = append(out, browser.ConsoleMessage{Type: "log", Text: domXSSConsolePrefix + string(raw)})
		}
	}
	return out
}

// domXSSAttributionNotes states what a confirmed DOM-XSS verdict does and does
// not establish. Execution is proven by the engine; the sink label is the
// first hooked sink that received the canary, and the source delivery is the
// scanner's own, so both caveats are recorded instead of implied.
func domXSSAttributionNotes(source detection.DOMXSSSource, sink detection.DOMXSSSink, observed []detection.DOMXSSSink) string {
	var notes string
	switch {
	case len(observed) > 1:
		notes += fmt.Sprintf("; sink attribution is ambiguous: %d hooked sinks received the payload (%s), execution is proven but not tied to %s", len(observed), joinSinks(observed), sink)
	case len(observed) == 0:
		notes += fmt.Sprintf("; no hooked sink reported the payload in this run, execution is proven but not tied to %s", sink)
	default:
		notes += fmt.Sprintf("; execution is proven by the engine, the sink label (%s) is the hooked sink that received the payload and is not proven to be the executing code path", sink)
	}
	if source == detection.DOMSourcePostMessage {
		notes += "; the sender is a scanner-created sandboxed child frame, so a handler that trusts a specific event.source or origin may not be attacker-deliverable, confirm delivery manually"
	}
	return notes
}

func joinSinks(sinks []detection.DOMXSSSink) string {
	names := make([]string, 0, len(sinks))
	for _, sink := range sinks {
		names = append(names, string(sink))
	}
	return strings.Join(names, ", ")
}

// domXSSObservation is everything one probe navigation observed. Runtime is
// the engine-attributed execution record (paused V8 position plus verified
// harness reports); Console and PageErrors are page-controlled text, kept as
// evidence only and never as a verdict or reachability authority.
type domXSSObservation struct {
	Console    []browser.ConsoleMessage
	PageErrors []string
	HTML       string
	Screenshot []byte
	Runtime    browser.RuntimeObservations
	// Dialogs are the page's own alert/confirm/prompt messages. A dialog that
	// carries the scan marker is the one observation that proves CANDIDATE CODE
	// RAN: a page cannot raise one by echoing text, and the marker is random per
	// scan. It is how the AngularJS sandbox-escape shape is confirmed — that
	// shape exists to EXECUTE code rather than merely compile an expression.
	Dialogs []string
	// SettleBusy records that the network-quiet settle hit its hard bound with
	// requests still in flight. The observation is still taken (bounded, never
	// unbounded), but a negative must say so: async-driven sinks may simply not
	// have run yet.
	SettleBusy bool
}

// openObservedPage opens a fresh page, installs the sink-hook harness BEFORE
// any navigation and starts engine-level runtime provenance for the same
// script. Provenance failure is an error, never a silent downgrade: a probe
// that cannot attribute execution must surface as an errored test case, not as
// a negative "not reachable" or "not vulnerable" result.
func (e *domXSSExecutor) openObservedPage(ctx context.Context, bctx *browser.Context, marker string) (*browser.Page, error) {
	page, err := bctx.NewPage(ctx)
	if err != nil {
		return nil, err
	}
	script := domXSSHarnessScript(marker)
	if err := page.AddInitScript(ctx, script); err != nil {
		page.Close()
		return nil, err
	}
	if err := page.EnableRuntimeProvenance(marker, script); err != nil {
		page.Close()
		return nil, fmt.Errorf("enable runtime provenance: %w", err)
	}
	return page, nil
}

func observePage(ctx context.Context, page *browser.Page, quiet time.Duration) (domXSSObservation, error) {
	settled, err := settleDOMXSSObservation(ctx, page, quiet)
	if err != nil {
		return domXSSObservation{}, err
	}
	html, _ := page.Content(ctx)
	shot, _ := page.Screenshot(ctx, browser.ScreenshotOptions{})
	return domXSSObservation{Console: page.ConsoleMessages(), PageErrors: page.PageErrors(), Dialogs: page.DialogMessages(), HTML: html, Screenshot: shot, Runtime: page.RuntimeObservations(), SettleBusy: !settled}, nil
}

// navigateSource performs ONE phase's navigation for source, injecting
// value via that source's own mechanism, and returns the page's
// observations plus the URL actually navigated to (used for the
// TestCase's own URL field and, for verification, the Finding's "verified
// URL"). marker installs the sink-hook harness (see domXSSHarnessScript);
// value is this phase's canary or real payload.
//
// Hash and Query both encode value directly into the navigation URL (the
// SAME single-navigation mechanism, just a different URL part — see
// domXSSHashURL/domXSSQueryURL). WindowName and PostMessage are
// mechanically different (see navigateWithWindowName/
// navigateWithPostMessage's own doc comments) — this is exactly the "only
// the source-side injection mechanism is new per source" boundary
// docs/dom-xss.md describes; the sink-hook harness and the phase-2
// verification signal are identical for all four.
func (e *domXSSExecutor) navigateSource(ctx context.Context, bctx *browser.Context, source detection.DOMXSSSource, ep *domain.Endpoint, queryParam, marker, value string) (obs domXSSObservation, navURL string, err error) {
	obs, navURL, _, err = e.navigateSourceWithActivation(ctx, bctx, source, ep, queryParam, marker, value, domXSSActivateNone, false)
	return obs, navURL, err
}

// navigateSourceWithActivation is navigateSource plus the one bounded
// activation step a sink may need (see domXSSActivation), and a phase-one
// probe mode for the hash source: when the page reaches no hooked sink from
// the fragment carried by the navigation itself, the engine re-issues that
// same fragment as a real hash change, because a hashchange-driven page has
// not run its handler yet. activated reports whether a step actually ran, so
// verification repeats only the delivery phase one needed.
func (e *domXSSExecutor) navigateSourceWithActivation(ctx context.Context, bctx *browser.Context, source detection.DOMXSSSource, ep *domain.Endpoint, queryParam, marker, value string, act domXSSActivation, probeHashChange bool) (obs domXSSObservation, navURL string, activated bool, err error) {
	switch source {
	case detection.DOMSourceQuery:
		navURL = domXSSQueryURL(ep.URL, queryParam, value)
		obs, activated, err = e.navigate(ctx, bctx, navURL, marker, value, act, false)
	case detection.DOMSourceWindowName:
		navURL = ep.URL
		obs, err = e.navigateWithWindowName(ctx, bctx, navURL, marker, value, act)
	case detection.DOMSourcePostMessage:
		navURL = ep.URL
		obs, err = e.navigateWithPostMessage(ctx, bctx, navURL, marker, value, act)
	case detection.DOMSourceReferrer:
		navURL = ep.URL
		obs, err = e.navigateWithReferrer(ctx, bctx, navURL, marker, value, act)
	case detection.DOMSourceLocalStorage, detection.DOMSourceSessionStorage:
		navURL = ep.URL
		obs, err = e.navigateWithStorage(ctx, bctx, source, navURL, queryParam, marker, value, act)
	default: // detection.DOMSourceHash
		navURL = domXSSHashURL(ep.URL, value)
		if queryParam != "" {
			if routeURL := domXSSFragmentRouteURL(ep.URL, queryParam, value); routeURL != "" {
				navURL = routeURL
			}
		}
		obs, activated, err = e.navigate(ctx, bctx, navURL, marker, value, act, probeHashChange)
	}
	return obs, navURL, activated, err
}

// navigateNamedDOMXSSExpression delivers a candidate whose sink compiles a
// query parameter NAME (see detection.DOMXSSShapeNeedsParameterName). The
// ordinary parameter keeps a fixed benign value so the page still renders its
// vulnerable binding, and the expression rides as the last parameter name.
func (e *domXSSExecutor) navigateNamedDOMXSSExpression(ctx context.Context, bctx *browser.Context, ep *domain.Endpoint, selector, expr, marker string) (domXSSObservation, string, error) {
	navURL := domXSSQueryNameURL(ep.URL, selector, domXSSNamedExpressionAnchorValue, expr)
	obs, _, err := e.navigate(ctx, bctx, navURL, marker, "", domXSSActivateNone, false)
	return obs, navURL, err
}

// sessionStatePathFor returns the scan's saved authenticated session
// state path, if any, best-effort (an unreadable/absent session simply
// means an unauthenticated probe, never a fatal error here).
func (e *domXSSExecutor) sessionStatePathFor(ctx context.Context, scanID domain.ID) string {
	sess, err := e.store.Sessions().GetByScan(ctx, scanID)
	if err != nil || sess == nil {
		return ""
	}
	return sess.StatePath
}

// domXSSURLSourceObservationWindow gives hash/query-driven pages a short
// post-load settling window. Hash-router pages get a larger bounded window:
// the route handler commonly starts an API request after load, and the result
// may not reach a sink until that request completes.
const (
	domXSSURLSourceObservationWindow     = 250 * time.Millisecond
	domXSSFragmentRouteObservationWindow = time.Second
)

// domXSSNetworkSettleBudget is how much time one observation may spend waiting
// for in-flight network work BEYOND its own quiet window. quiet plus this
// budget is the hard ceiling; a request that never finishes cannot hold a DOM
// probe past it.
const domXSSNetworkSettleBudget = 1250 * time.Millisecond

func domXSSURLSourceObservationDelay(navURL string) time.Duration {
	if i := strings.IndexByte(navURL, '#'); i >= 0 {
		fragment := navURL[i+1:]
		if strings.HasPrefix(fragment, "/") && strings.Contains(fragment, "?") {
			return domXSSFragmentRouteObservationWindow
		}
	}
	return domXSSURLSourceObservationWindow
}

// settleDOMXSSObservation gives asynchronous work the page itself started time
// to finish before a sink observation is read back. The measured shape is an
// XHR whose response is later written into an HTML sink: reading the page at
// the load event would report "no sink reachable" while the response is still
// in flight.
//
// quiet is the trailing period with no in-flight request that counts as
// settled (the URL sources' existing fixed window, so a synchronous page keeps
// paying exactly what it paid before). The hard ceiling is quiet +
// domXSSNetworkSettleBudget, after which the observation is taken anyway and
// the caller is told the page was still busy. A page with no async activity
// pays quiet, never the ceiling.
//
// Sources run in separate DOM-XSS jobs on the browser worker group, so the
// wait overlaps across sources; within one source the per-selector
// navigations were already sequential.
func settleDOMXSSObservation(ctx context.Context, page *browser.Page, quiet time.Duration) (bool, error) {
	if quiet <= 0 {
		quiet = domXSSURLSourceObservationWindow
	}
	settled, err := page.WaitNetworkIdle(ctx, quiet, quiet+domXSSNetworkSettleBudget)
	if err == nil {
		return settled, nil
	}
	if !errors.Is(err, browser.ErrNetworkIdleUnsupported) {
		return false, err
	}
	// The driver cannot observe in-flight requests (test fakes, or a driver
	// without CDP). Fall back to the same fixed bounded settle the probe used
	// before network-quiet support: nothing is known about async work, and the
	// caller is told the quiet period was not observed.
	timer := time.NewTimer(quiet)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	case <-timer.C:
		return false, nil
	}
}

// navigate opens a fresh page in bctx, installs the init-script harness
// BEFORE navigating (see domXSSHarnessScript's doc comment), navigates to
// navURL, allows a bounded post-load observation window for hash/query SPA
// work, and returns the page's observations. One page per navigation, never
// reused — mirrors BrowserVerifier.Verify's own discipline of never
// attributing a signal to the wrong navigation.
//
// probeHashChange (hash source, phase one only) re-issues the fragment as a
// real hash change when the page's own load-time scripts reached no hooked
// sink; a hashchange-driven page has not run its handler with the fragment the
// URL already carried. act applies the same bounded activation unconditionally
// during verification. The observation is retaken after any activation, and
// activated reports whether one happened.
func (e *domXSSExecutor) navigate(ctx context.Context, bctx *browser.Context, navURL, marker, value string, act domXSSActivation, probeHashChange bool) (domXSSObservation, bool, error) {
	page, err := e.openObservedPage(ctx, bctx, marker)
	if err != nil {
		return domXSSObservation{}, false, err
	}
	defer page.Close()
	if _, err := page.Navigate(ctx, navURL, browser.NavOptions{Limiter: e.limiter, WaitUntil: browser.WaitLoad}); err != nil {
		return domXSSObservation{}, false, err
	}
	// The quiet duration is the URL source's existing fixed observation
	// window; network-quiet can only extend it, up to the hard bound.
	obs, err := observePage(ctx, page, domXSSURLSourceObservationDelay(navURL))
	if err != nil {
		return domXSSObservation{}, false, err
	}
	if probeHashChange && act == domXSSActivateNone && len(parseDOMXSSReachability(domXSSHarnessMessages(obs.Runtime), marker)) == 0 {
		act = domXSSActivateHashChange
	}
	if act == domXSSActivateNone {
		return obs, false, nil
	}
	applied, err := e.applyDOMXSSActivation(ctx, page, act, marker, value)
	if err != nil {
		return domXSSObservation{}, false, err
	}
	if !applied {
		return obs, false, nil
	}
	// A dispatched hash-change activation is followed by the page's own
	// handler: jQuery parses the fragment into markup, and the element it
	// creates only errors after its request round trip. Wait for the marker's
	// own execution signal (bounded) before the post-activation observation,
	// so a slow-but-successful execution is not read as a negative.
	if _, err := awaitDOMXSSExecutionSignal(ctx, page, marker, 0); err != nil {
		return domXSSObservation{}, false, err
	}
	post, err := observePage(ctx, page, domXSSURLSourceObservationDelay(navURL))
	if err != nil {
		return domXSSObservation{}, false, err
	}
	return post, true, nil
}

// navigateWithWindowName implements the ONE genuinely different mechanical
// step window.name needs versus Hash/Query (see
// detection.DOMSourceWindowName's doc comment): window.name PERSISTS
// across a same-tab navigation, even cross-origin, in real browsers —
// unlike Hash/Query it cannot be set by simply encoding it into the URL
// being navigated to. Sequence (same page/tab throughout, never a new
// one — this is load-bearing, since window.name is a property of the TAB,
// not the document):
//  1. install the sink-hook harness (BEFORE any navigation, so it is
//     already in place for every navigation this page makes — Playwright's
//     AddInitScript re-runs it on every subsequent navigation, including
//     step 3's);
//  2. navigate to a neutral page first (about:blank — the simplest choice
//     given browser.Page's existing Navigate; about: URLs are never
//     subject to the scope gate at all, see browser.isNetworkURL, so this
//     cannot leak a real request anywhere);
//  3. set window.name via Evaluate;
//  4. THEN navigate (same page) to targetURL — window.name is still set,
//     exactly reproducing the real-world legacy attack (an attacker page
//     sets window.name on a tab it controls, then redirects that SAME tab
//     to the victim page).
func (e *domXSSExecutor) navigateWithWindowName(ctx context.Context, bctx *browser.Context, targetURL, marker, value string, act domXSSActivation) (domXSSObservation, error) {
	page, err := e.openObservedPage(ctx, bctx, marker)
	if err != nil {
		return domXSSObservation{}, err
	}
	defer page.Close()
	if _, err := page.Navigate(ctx, "about:blank", browser.NavOptions{Limiter: e.limiter, WaitUntil: browser.WaitLoad}); err != nil {
		return domXSSObservation{}, err
	}
	if _, err := evaluateDOMXSSScript(ctx, page, setWindowNameScript(value), domXSSEvaluateBound); err != nil {
		return domXSSObservation{}, err
	}
	if _, err := page.Navigate(ctx, targetURL, browser.NavOptions{Limiter: e.limiter, WaitUntil: browser.WaitLoad}); err != nil {
		return domXSSObservation{}, err
	}
	if err := e.finishSourceNavigation(ctx, page, act, marker, value); err != nil {
		return domXSSObservation{}, err
	}
	return observePage(ctx, page, domXSSURLSourceObservationWindow)
}

// setWindowNameScript builds the Evaluate script that sets window.name to
// value, JS-string-literal-quoted via goQuoteJS (the exact same escaping
// helper the harness itself uses) — no URL percent-encoding is involved at
// all here, unlike Hash/Query: the value becomes a JS string directly,
// never travels through a URL.
func setWindowNameScript(value string) string {
	return "window.name = " + goQuoteJS(value) + ";"
}

// navigateWithPostMessage implements the postMessage source using an
// opaque-origin sandboxed frame as the sender. It first navigates the page
// to the in-scope target (the ordinary browser.Manager AllowRequest route
// gates this request and every target subresource), then creates a local
// srcdoc iframe with sandbox="allow-scripts" but without
// "allow-same-origin". That sender has the opaque serialized origin
// "null"; it sends to its parent, so the target observes event.origin ===
// "null" and event.source !== window. No attacker host or other network
// URL is navigated.
//
// AddInitScript installs the sink harness before the target's own scripts.
// The srcdoc sender posts only after it loads, and a short Promise delay
// lets the target's asynchronous message handler finish before observations
// are read back. Since the target itself remains the top-level document,
// existing Page console/error/hook observations and DOM evidence still
// describe the target page directly.
//
// A document with no attachable root (no body and no documentElement — a
// body-less/plugin/XML-ish response) reports errDOMXSSSourceNotApplicable
// instead of a Playwright TypeError: nothing could ever receive this
// delivery there, so the source is NOT APPLICABLE for the endpoint, not
// broken. Any genuine evaluation failure still propagates as an error.
func (e *domXSSExecutor) navigateWithPostMessage(ctx context.Context, bctx *browser.Context, targetURL, marker, value string, act domXSSActivation) (domXSSObservation, error) {
	page, err := e.openObservedPage(ctx, bctx, marker)
	if err != nil {
		return domXSSObservation{}, err
	}
	defer page.Close()
	if _, err := page.Navigate(ctx, targetURL, browser.NavOptions{Limiter: e.limiter, WaitUntil: browser.WaitLoad}); err != nil {
		return domXSSObservation{}, err
	}
	// The script's own fallback settles first in every normal case. The
	// per-call deadline is the second layer: a page that replaced the timer
	// functions the fallback depends on, or blocked the main thread, still
	// cannot hold this worker past domXSSPostMessageProbeBound.
	status, err := evaluateDOMXSSScript(ctx, page, postMessageScript(value), domXSSPostMessageProbeBound)
	if errors.Is(err, errDOMXSSEvaluateDeadline) {
		return domXSSObservation{}, errDOMXSSPostMessageIndeterminate
	}
	if err != nil {
		return domXSSObservation{}, err
	}
	outcome, ok := status.(string)
	if !ok {
		// The script's every path resolves a status string, so anything else
		// means the probe's result cannot be trusted as delivery.
		return domXSSObservation{}, fmt.Errorf("postMessage probe returned %T (%v) instead of a probe outcome: %w", status, status, errDOMXSSPostMessageIndeterminate)
	}
	switch outcome {
	case domXSSPostMessageNoRoot:
		return domXSSObservation{}, errDOMXSSSourceNotApplicable
	case domXSSPostMessageSent:
		// The sender frame reported load, so the message was posted.
	case domXSSPostMessageIndeterminate:
		return domXSSObservation{}, errDOMXSSPostMessageIndeterminate
	default:
		return domXSSObservation{}, fmt.Errorf("postMessage probe reported unknown outcome %q: %w", outcome, errDOMXSSPostMessageIndeterminate)
	}
	if err := e.finishSourceNavigation(ctx, page, act, marker, value); err != nil {
		return domXSSObservation{}, err
	}
	return observePage(ctx, page, domXSSURLSourceObservationWindow)
}

// postMessageScript creates an opaque-origin sandboxed srcdoc sender and
// posts value to its parent (the already-loaded target page). Omitting
// allow-same-origin is essential: it gives the frame an opaque origin that
// serializes as "null". The parent receives the event from another Window,
// never from its own window object. No network request is made by this
// local sender document.
//
// It attaches to the first real container the document has (body, else
// documentElement — a frameset document has no body but does have a root)
// and resolves domXSSPostMessageNoRoot when neither exists, so a body-less
// response is an explicit NOT APPLICABLE answer rather than a crash. The
// attachment itself is NOT wrapped in try/catch: a genuine failure on an
// attachable document must still surface as an evaluation error.
//
// EVERY path settles. The only delivery signal is the sender frame's own
// load event, and a frame can silently never fire it: the page can strip or
// refuse it (a sanitizer, or an SPA that re-renders its body right after load),
// the document can be replaced mid-probe, or the root can stop accepting
// children. An unsettled promise blocks Page.Evaluate (browser.callCtx only
// returns early on context cancellation, which a scan-level context does not
// supply per call) until the worker pool's whole job deadline fires, freezing
// one browser worker slot — with BrowserConcurrency: 1, the entire browser
// group — for that whole bound. So a hard timer, armed before anything else and
// independent of the job deadline, always settles the probe. If it fires
// without frame-load evidence, the answer is domXSSPostMessageIndeterminate:
// the message may never have been posted, so it must never be reported as
// "sent".
//
// Known limit of that signal (measured, not assumed): a policy that lets the
// frame LOAD but blocks the script inside it is indistinguishable from a
// delivery here, so the probe reports "sent" and the sink observation is a
// negative. Measured on Chromium 1.62 (playwright-go v0.6201.1): a
// "frame-src 'none'" CSP does NOT stop a sandboxed srcdoc sender frame from
// loading and posting, so a frame policy is not by itself a trigger for this
// probe's failure modes.
func postMessageScript(value string) string {
	srcdoc := "<!doctype html><script>parent.postMessage(" + goQuoteJS(value) + ", '*');</script>"
	return fmt.Sprintf(domXSSPostMessageTemplate,
		domXSSPostMessageFallback.Milliseconds(),
		goQuoteJS(domXSSPostMessageSent),
		goQuoteJS(domXSSPostMessageIndeterminate),
		goQuoteJS(domXSSPostMessageNoRoot),
		goQuoteJS(domXSSPostMessageSent),
		goQuoteJS(domXSSPostMessageIndeterminate),
		goQuoteJS(srcdoc),
	)
}

const domXSSPostMessageTemplate = `(() => new Promise((resolve) => {
  // Hard bound, armed before the root check so EVERY path is covered. It is
  // deliberately independent of the worker's job deadline: this is the probe's
  // own settle guarantee, not a scan-level timeout.
  const FALLBACK_MS = %d;
  const sender = document.createElement('iframe');
  let settled = false;
  let frameLoaded = false;
  let fallback = null;
  // One settle gate: every outcome resolves through it, and it removes every
  // trace of the sender first (handlers, timer, DOM node) so a later probe in
  // this same document — or the page's own scripts — never inherits a
  // leftover frame, a live handler, or a pending timer.
  const settle = (outcome) => {
    if (settled) return;
    settled = true;
    if (fallback !== null) { clearTimeout(fallback); fallback = null; }
    sender.onload = null;
    sender.onerror = null;
    if (sender.parentNode) sender.parentNode.removeChild(sender);
    resolve(outcome);
  };
  fallback = setTimeout(() => {
    // No load event means there is no evidence the message was ever posted.
    // Reporting "sent" would fabricate delivery, so the honest answer is the
    // distinct indeterminate outcome.
    settle(frameLoaded ? %s : %s);
  }, FALLBACK_MS);
  const root = document.body || document.documentElement;
  if (!root) { settle(%s); return; }
  sender.setAttribute('sandbox', 'allow-scripts');
  sender.onload = () => {
    frameLoaded = true;
    // Let the target's own asynchronous message handler finish before the
    // caller reads observations back.
    setTimeout(() => settle(%s), 300);
  };
  // A load failure is the same missing evidence as a load that never fires.
  sender.onerror = () => { settle(%s); };
  sender.srcdoc = %s;
  root.appendChild(sender);
}))();`

const (
	// domXSSPostMessageNoRoot is what postMessageScript resolves when the
	// loaded document has no container to attach a sender frame to.
	domXSSPostMessageNoRoot = "indago-domxss-postmessage-no-root"
	// domXSSPostMessageSent is what it resolves after the sender frame
	// loaded and was given time to post.
	domXSSPostMessageSent = "indago-domxss-postmessage-sent"
	// domXSSPostMessageIndeterminate is what it resolves when the fallback
	// bound fired (or the frame reported load failure) without evidence that
	// the sender frame loaded. The message may never have been posted, so
	// this is NOT a delivery: the engine records "could not determine
	// postMessage reachability", never a Confirmed and never a negative.
	domXSSPostMessageIndeterminate = "indago-domxss-postmessage-indeterminate"
)

// domXSSPostMessageFallback bounds how long the sender-frame probe may wait
// for the frame's load event before reporting the indeterminate outcome. The
// srcdoc frame is local (no network) and normally loads in milliseconds, so a
// few seconds is generous; it must never grow to a job-scale timeout, because
// a probe that cannot deliver is wasted scan time, not work in progress.
const domXSSPostMessageFallback = 4 * time.Second

// domXSSPostMessageProbeBound is the scan-side deadline for the ONE Evaluate
// that runs the sender probe. It is the fallback plus a small margin, so the
// script's own (more informative) fallback always reports first, while a page
// that broke the timer functions, or blocked the main thread, still cannot hold
// the browser worker past a few seconds.
const domXSSPostMessageProbeBound = domXSSPostMessageFallback + 2*time.Second

// errDOMXSSSourceNotApplicable reports that a source's injection mechanism
// found nothing it could deliver into — today, a document with no attachable
// root for the postMessage sender. The caller records a skipped/not-applicable
// TestCase: no DOM-XSS coverage was exercised, and this is explicitly not a
// clean negative.
var errDOMXSSSourceNotApplicable = errors.New("dom-xss source not applicable to this document")

// errDOMXSSPostMessageIndeterminate reports that the postMessage sender probe
// could not establish whether the message was posted: its sender frame never
// fired load (or fired onerror) within domXSSPostMessageFallback, which is what
// a stripped or refused sender frame, a document replaced mid-probe, or a root
// that stopped accepting children looks like from inside the page. It is
// deliberately its own outcome: the delivery is unknown, so it must never be
// read as "sent" (which would let an absent sink look like a clean negative) and
// never as a Confirmed execution.
var errDOMXSSPostMessageIndeterminate = errors.New("dom-xss postMessage probe indeterminate: the sender frame never reported load within the probe's bounded fallback, so whether the message was delivered is unknown")

const domXSSStorageObserverPrefix = "__INDAGO_DOMXSS_STORAGE__"

// domXSSStorageKeyLimit bounds candidate attempts separately for each
// storage backend at an endpoint. The discovery TestCase records the
// observed count and any keys skipped beyond this ceiling.
const domXSSStorageKeyLimit = 32

func domXSSStorageObserverScript() string {
	return fmt.Sprintf(`(() => {
  const PREFIX = %s;
  try {
    const proto = Storage.prototype;
    const desc = Object.getOwnPropertyDescriptor(proto, 'getItem');
    if (!desc || typeof desc.value !== 'function') return;
    const nativeGetItem = desc.value;
    Object.defineProperty(proto, 'getItem', {
      configurable: desc.configurable,
      enumerable: desc.enumerable,
      writable: desc.writable,
      value: function (key) {
        let backend = '';
        try {
          if (this === window.localStorage) backend = 'localStorage';
          else if (this === window.sessionStorage) backend = 'sessionStorage';
        } catch (_) {}
        if (!backend || typeof key === 'symbol') return nativeGetItem.apply(this, arguments);
        const keyName = String(key);
        const value = nativeGetItem.call(this, keyName);
        try {
          console.log(PREFIX + JSON.stringify({backend: backend, key: keyName}));
        } catch (_) {}
        return value;
      }
    });
  } catch (_) {}
})();`, goQuoteJS(domXSSStorageObserverPrefix))
}

type domXSSStorageRead struct {
	Backend string `json:"backend"`
	Key     string `json:"key"`
}

func parseDOMXSSStorageReads(messages []browser.ConsoleMessage, source detection.DOMXSSSource) []string {
	seen := make(map[string]bool)
	var keys []string
	for _, message := range messages {
		if !strings.HasPrefix(message.Text, domXSSStorageObserverPrefix) {
			continue
		}
		var read domXSSStorageRead
		if err := json.Unmarshal([]byte(strings.TrimPrefix(message.Text, domXSSStorageObserverPrefix)), &read); err != nil || read.Backend != string(source) || seen[read.Key] {
			continue
		}
		seen[read.Key] = true
		keys = append(keys, read.Key)
	}
	return keys
}

func domXSSStorageKeysScript(source detection.DOMXSSSource) (string, error) {
	storageName := ""
	switch source {
	case detection.DOMSourceLocalStorage:
		storageName = "localStorage"
	case detection.DOMSourceSessionStorage:
		storageName = "sessionStorage"
	default:
		return "", fmt.Errorf("%s is not a storage backend", source)
	}
	return `(() => { const s = ` + storageName + `; const keys = []; for (let i=0; i<s.length; i++) { const key=s.key(i); if (key !== null) keys.push(key); } return JSON.stringify(keys); })()`, nil
}

func readDOMXSSStorageKeys(ctx context.Context, page *browser.Page, source detection.DOMXSSSource) ([]string, error) {
	script, err := domXSSStorageKeysScript(source)
	if err != nil {
		return nil, err
	}
	raw, err := evaluateDOMXSSScript(ctx, page, script, domXSSEvaluateBound)
	if err != nil {
		return nil, fmt.Errorf("enumerate %s keys: %w", source, err)
	}
	encoded, ok := raw.(string)
	if !ok {
		return nil, fmt.Errorf("enumerate %s keys: unexpected browser result %T", source, raw)
	}
	var keys []string
	if err := json.Unmarshal([]byte(encoded), &keys); err != nil {
		return nil, fmt.Errorf("parse %s keys: %w", source, err)
	}
	return keys, nil
}

func uniqueSortedStorageKeys(keys []string) []string {
	seen := make(map[string]bool)
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

// discoverStorageKeys performs an observation-only navigation to the real
// target in the scan's isolated context. It enumerates existing keys (which
// includes localStorage seeded by storage state) and records getItem names
// requested by the page's own scripts. The observer preserves string
// conversion, returns the native method's result unchanged, and writes no
// candidate value during discovery.
func (e *domXSSExecutor) discoverStorageKeys(ctx context.Context, bctx *browser.Context, source detection.DOMXSSSource, targetURL string) ([]string, error) {
	page, err := bctx.NewPage(ctx)
	if err != nil {
		return nil, err
	}
	defer page.Close()
	if err := page.AddInitScript(ctx, domXSSStorageObserverScript()); err != nil {
		return nil, err
	}
	if _, err := page.Navigate(ctx, targetURL, browser.NavOptions{Limiter: e.limiter, WaitUntil: browser.WaitLoad}); err != nil {
		return nil, err
	}
	present, err := readDOMXSSStorageKeys(ctx, page, source)
	if err != nil {
		return nil, err
	}
	observed := parseDOMXSSStorageReads(page.ConsoleMessages(), source)
	return uniqueSortedStorageKeys(append(present, observed...)), nil
}

// domXSSRefererURL builds a synthetic, well-formed absolute URL carrying
// fragmentValue (percent-encoded by jsEncodeURIComponent) as its path —
// the value actually passed as the navigation's Referer override. This
// indirection is load-bearing, discovered empirically against a real
// Chromium: Playwright's/Chromium's Referer override is SILENTLY IGNORED
// unless the given string is itself a well-formed absolute URL (a bare
// canary/payload string like "indago-domxss-canary-abc123" or
// "<img src=x onerror=M>" is rejected outright, and document.referrer
// then reflects whatever the browser's own default referrer computation
// would have produced instead — NOT an error, just quietly wrong). The
// fixed ".invalid" host (RFC 2606 — reserved, never resolved/dereferenced;
// this is a header value only, no network request is ever made to it) is
// an arbitrary, inert placeholder; only the embedded path segment matters.
//
// A second, equally load-bearing consequence of needing an absolute URL:
// the browser's own URL parser ALWAYS percent-encodes "<"/">"/space in the
// path when constructing the Referer header, exactly like it already does
// for a URL fragment (see jsEncodeURIComponent's doc comment on the hash
// source) — there is no way to get a literal, unescaped "<" into a real
// browser's document.referrer at all, a genuine protocol-level
// constraint, not an Indago limitation. So the SAME realistic vulnerable
// pattern the hash source targets applies here too: a page that reads
// document.referrer and explicitly decodeURIComponent's it (or a
// substring of it) before using it as markup is exploitable through this
// vector; a page that uses the raw, still-percent-encoded string is not —
// correctly, not a false negative. See docs/dom-xss.md.
func domXSSRefererURL(fragmentValue string) string {
	return "https://indago-domxss-probe.invalid/" + jsEncodeURIComponent(fragmentValue)
}

// navigateWithReferrer implements the document.referrer source. Unlike
// Hash/Query (encoded into the URL being navigated TO) or WindowName/
// PostMessage (set via a separate Evaluate step), the browser automation
// layer itself exposes a direct mechanism for this: Playwright's own
// Page.Goto accepts a Referer override for a single navigation
// (browser.NavOptions.Referer, newly threaded all the way down to
// pageHandle.Goto — see driver.go/playwright.go). So this is a ONE-STEP
// navigation, not a multi-step sequence like WindowName/Storage: the
// harness is installed first (same discipline as every other source),
// then the single navigation to targetURL carries domXSSRefererURL(value)
// as the Referer HTTP header, which the browser reflects into the loaded
// page's own document.referrer (see domXSSRefererURL's doc comment for
// why the value must be wrapped in a synthetic absolute URL rather than
// passed raw).
func (e *domXSSExecutor) navigateWithReferrer(ctx context.Context, bctx *browser.Context, targetURL, marker, value string, act domXSSActivation) (domXSSObservation, error) {
	page, err := e.openObservedPage(ctx, bctx, marker)
	if err != nil {
		return domXSSObservation{}, err
	}
	defer page.Close()
	if _, err := page.Navigate(ctx, targetURL, browser.NavOptions{Limiter: e.limiter, WaitUntil: browser.WaitLoad, Referer: domXSSRefererURL(value)}); err != nil {
		return domXSSObservation{}, err
	}
	if err := e.finishSourceNavigation(ctx, page, act, marker, value); err != nil {
		return domXSSObservation{}, err
	}
	return observePage(ctx, page, domXSSURLSourceObservationWindow)
}

// navigateWithStorage implements BOTH the localStorage and sessionStorage
// sources — ONE shared sequence parametrized by backend (source), since
// the exploitation pattern and navigation sequencing are identical for
// both (see detection.DOMSourceLocalStorage's doc comment). Unlike
// window.name (tab-scoped — any neutral page works, see
// navigateWithWindowName), localStorage/sessionStorage are ORIGIN-scoped:
// a value written from a page on a DIFFERENT origin would simply not be
// visible to the target. Correct sequencing:
//  1. install the sink-hook harness FIRST (before any navigation at all —
//     Playwright re-runs it on every subsequent navigation this page
//     makes, including step 4's target navigation);
//  2. navigate to a harmless, SAME-ORIGIN page first — this engine uses
//     the target's own origin ROOT (domXSSOriginURL(targetURL)), which is
//     guaranteed same-origin by construction and needs no extra
//     discovery;
//  3. set localStorage/sessionStorage with browser.Page's existing
//     SetLocalStorage/SetSessionStorage methods (no new browser primitive
//     needed) under this exact, previously discovered key;
//  4. THEN navigate (same page) to targetURL — the write from step 3 is
//     now visible since both navigations share the same origin.
func (e *domXSSExecutor) navigateWithStorage(ctx context.Context, bctx *browser.Context, source detection.DOMXSSSource, targetURL, key, marker, value string, act domXSSActivation) (domXSSObservation, error) {
	page, err := e.openObservedPage(ctx, bctx, marker)
	if err != nil {
		return domXSSObservation{}, err
	}
	defer page.Close()
	originURL, err := domXSSOriginURL(targetURL)
	if err != nil {
		return domXSSObservation{}, err
	}
	if _, err := page.Navigate(ctx, originURL, browser.NavOptions{Limiter: e.limiter, WaitUntil: browser.WaitLoad}); err != nil {
		return domXSSObservation{}, err
	}
	if source == detection.DOMSourceSessionStorage {
		err = page.SetSessionStorage(ctx, key, value)
	} else {
		err = page.SetLocalStorage(ctx, key, value)
	}
	if err != nil {
		return domXSSObservation{}, err
	}
	if _, err := page.Navigate(ctx, targetURL, browser.NavOptions{Limiter: e.limiter, WaitUntil: browser.WaitLoad}); err != nil {
		return domXSSObservation{}, err
	}
	if err := e.finishSourceNavigation(ctx, page, act, marker, value); err != nil {
		return domXSSObservation{}, err
	}
	return observePage(ctx, page, domXSSURLSourceObservationWindow)
}

// newTestCase creates and persists a running TestCase for one navigation
// attempt (reachability or verification phase).
func (e *domXSSExecutor) newTestCase(ctx context.Context, job *domain.TestJob, url string) *domain.TestCase {
	now := time.Now()
	tc := &domain.TestCase{
		ID: domain.NewID(), ScanID: job.ScanID, JobID: job.ID, Attempt: job.Attempts,
		VulnClass: domain.VulnDOMXSS, Status: domain.TestCaseRunning,
		Method: string(domain.MethodGET), URL: url,
		StartedAt: &now, CreatedAt: now, UpdatedAt: now,
	}
	if err := e.store.TestCases().Create(ctx, tc); err != nil {
		e.log.Warn("dom-xss: persist test case", "job", job.ID, "err", err)
	}
	return tc
}

// finishTestCase persists tc's outcome. probeErr nil means success (or,
// for the skip path, the caller already set tc.Status to Skipped before
// calling this).
func (e *domXSSExecutor) finishTestCase(ctx context.Context, tc *domain.TestCase, probeErr error, note string) {
	now := time.Now()
	tc.FinishedAt, tc.UpdatedAt = &now, now
	if note != "" {
		tc.Note = note
	}
	switch {
	case tc.Status == domain.TestCaseSkipped:
		// already set by the caller (no browser configured)
	case probeErr == nil:
		tc.Status = domain.TestCaseCompleted
		tc.Outcome = domain.OutcomeSuccess
	case ctx.Err() != nil:
		tc.Status = domain.TestCaseCancelled
		tc.Outcome = domain.OutcomeCancelled
	case browser.IsTimeout(probeErr):
		tc.Status = domain.TestCaseFailed
		tc.Outcome = domain.OutcomeTimeout
		tc.Error = truncate(probeErr.Error(), 1024)
	default:
		tc.Status = domain.TestCaseFailed
		tc.Outcome = domain.OutcomeError
		tc.Error = truncate(probeErr.Error(), 1024)
	}
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	if err := e.store.TestCases().Update(wctx, tc); err != nil {
		e.log.Error("dom-xss: persist test case result", "test_case", tc.ID, "job", tc.JobID, "err", err)
	}
}

// persistDOMXSSEvidence stores the verification phase's screenshot,
// rendered DOM, and browser log as evidence blobs — the SAME shared
// putEvidenceBlob free function verifyExecutor.persistVerificationEvidence
// uses.
func (e *domXSSExecutor) persistDOMXSSEvidence(ctx context.Context, scanID, tcID domain.ID, screenshot []byte, html string, logLines []string) []domain.ID {
	var ids []domain.ID
	note := "test_case=" + string(tcID)
	if len(screenshot) > 0 {
		if id, err := putEvidenceBlob(ctx, e.store, e.evidence, scanID, domain.EvidenceScreenshot, ".png", "image/png", screenshot, note+" screenshot"); err == nil {
			ids = append(ids, id)
		} else {
			e.log.Warn("dom-xss: persist screenshot evidence", "err", err)
		}
	}
	if html != "" {
		if id, err := putEvidenceBlob(ctx, e.store, e.evidence, scanID, domain.EvidenceDOM, ".html", "text/html", []byte(html), note+" rendered DOM"); err == nil {
			ids = append(ids, id)
		} else {
			e.log.Warn("dom-xss: persist DOM evidence", "err", err)
		}
	}
	if len(logLines) > 0 {
		if id, err := putEvidenceBlob(ctx, e.store, e.evidence, scanID, domain.EvidenceBrowserLog, ".log", "text/plain", []byte(joinLines(logLines)), note+" browser log"); err == nil {
			ids = append(ids, id)
		} else {
			e.log.Warn("dom-xss: persist browser log evidence", "err", err)
		}
	}
	return ids
}

// domXSSChildFrameExecution accepts a marker execution that happened in a
// child frame, but only for element.src and only when the main-frame harness
// observed the same marker being assigned to an element URL. That pairing is
// what makes the child exception attributable to the payload instead of to a
// page-authored error.
func domXSSChildFrameExecution(rt browser.RuntimeObservations, marker string) bool {
	if !rt.Available || rt.MainFrameID == "" {
		return false
	}
	sawSrcWrite := false
	for _, report := range rt.Reports {
		if strings.Contains(report.Text, `"sink":"element.src"`) && strings.Contains(report.Text, marker) {
			sawSrcWrite = true
			break
		}
	}
	if !sawSrcWrite {
		return false
	}
	for _, ex := range rt.Exceptions {
		if !ex.MarkerIdentifier || ex.ClassName != "ReferenceError" ||
			!strings.HasPrefix(ex.Description, "ReferenceError: "+marker+" is not defined") {
			continue
		}
		if ex.Location.FrameID != "" && ex.Location.FrameID != rt.MainFrameID {
			return true
		}
	}
	return false
}

// domXSSHasRedirectLink is a narrow, static gate for the client-side redirect
// probe: a link whose onclick both reads a url= value and writes location.
func domXSSHasRedirectLink(html string) bool {
	low := strings.ToLower(html)
	return strings.Contains(low, "onclick") && strings.Contains(low, "url=") && strings.Contains(low, "location")
}

// probeClientOpenRedirect executes the page's own onclick handler with a fake
// location object, so the handler's real regex/assignment runs without a
// navigation. A destination containing the marker on a foreign origin is
// execution of attacker-controlled redirect logic, not a text match.
func (e *domXSSExecutor) probeClientOpenRedirect(ctx context.Context, bctx *browser.Context, job *domain.TestJob, ep *domain.Endpoint, marker string) {
	canary := "https://example.com/indago-redirect-" + marker
	sep := "?"
	if strings.Contains(ep.URL, "?") {
		sep = "&"
	}
	navURL := ep.URL + sep + "url=" + canary
	tc := e.newTestCase(ctx, job, navURL)
	page, err := bctx.NewPage(ctx)
	if err != nil {
		e.finishTestCase(ctx, tc, err, "open-redirect probe: new page")
		return
	}
	defer page.Close()
	if _, err := page.Navigate(ctx, navURL, browser.NavOptions{Limiter: e.limiter, WaitUntil: browser.WaitLoad}); err != nil {
		e.finishTestCase(ctx, tc, err, "open-redirect probe: navigate")
		return
	}
	script := `(() => {
  const link = [...document.querySelectorAll('a[onclick]')].find(a => /url=/.test(a.getAttribute('onclick') || ''));
  if (!link) return {found: false};
  const fake = {href: location.href, toString() { return this.href; }};
  try {
    new Function('location', link.getAttribute('onclick')).call(window, fake);
  } catch (err) {
    return {found: true, error: String(err), target: fake.href};
  }
  return {found: true, target: fake.href};
})()`
	raw, err := page.Evaluate(ctx, script)
	if err != nil {
		e.finishTestCase(ctx, tc, err, "open-redirect probe: evaluate")
		return
	}
	res, _ := raw.(map[string]any)
	found, _ := res["found"].(bool)
	target, _ := res["target"].(string)
	if !found || !strings.Contains(target, "indago-redirect-"+marker) {
		e.finishTestCase(ctx, tc, nil, "open-redirect probe: the page's handlers did not assign the supplied external target")
		return
	}
	html, _ := page.Content(ctx)
	shot, _ := page.Screenshot(ctx, browser.ScreenshotOptions{})
	evIDs := e.persistDOMXSSEvidence(ctx, job.ScanID, tc.ID, shot, html, []string{"open redirect target: " + target})
	detail, _ := json.Marshal(map[string]any{
		"source": "dom_link_onclick", "target": target, "canary": canary,
		"test_case_ids": []domain.ID{tc.ID},
	})
	f := &domain.Finding{
		ID: domain.NewID(), ScanID: job.ScanID, ProjectID: e.projectIDFor(ctx, job.ScanID),
		VulnClass: domain.VulnOpenRedirect, Verdict: domain.VerdictConfirmed,
		Severity: domain.SeverityMedium, Confidence: domain.ConfidenceHigh,
		Title:      "Open redirect: a link on the page sends the user to an attacker-controlled URL",
		Summary:    "The page's own click handler took the url parameter and assigned it to location, so a trusted link can redirect to " + target + ".",
		EndpointID: ep.ID, EvidenceIDs: evIDs,
		Provenance: domain.Provenance{Engine: "dom-open-redirect", DiscoverySource: ep.Source, DetectedAt: time.Now(), VerifiedAt: ptrTime(time.Now())},
		Detail:     detail, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	tc.Status = domain.TestCaseCompleted
	if err := e.store.Findings().Create(ctx, f); err != nil {
		e.finishTestCase(ctx, tc, err, "open-redirect probe: create finding")
		return
	}
	e.finishTestCase(ctx, tc, nil, "confirmed: the page's onclick assigned the supplied external target to location: "+target)
}

func ptrTime(t time.Time) *time.Time { return &t }

func (e *domXSSExecutor) projectIDFor(ctx context.Context, scanID domain.ID) domain.ID {
	sc, err := e.store.Scans().Get(ctx, scanID)
	if err != nil {
		return ""
	}
	return sc.ProjectID
}

// domXSSCookieWritePattern detects a page that stores its own URL (or a
// source-derived value) in document.cookie. The separate read side is the
// server: a cookie echoed into HTML can execute on the next page load.
func domXSSCookieWritePattern(html string) bool {
	low := strings.ToLower(html)
	return strings.Contains(low, "document.cookie") && strings.Contains(low, "window.location")
}

// probeCookieReflection poisons the page's own cookie with an encoded script
// payload, then loads the origin with that cookie. The server URL-decodes the
// cookie and reflects it into an attribute, so the marker's execution is the
// proof; nothing is navigated outside the target origin.
func (e *domXSSExecutor) probeCookieReflection(ctx context.Context, bctx *browser.Context, job *domain.TestJob, ep *domain.Endpoint, marker string) {
	payload := "'><script>" + marker + "</script>"
	sep := "?"
	if strings.Contains(ep.URL, "?") {
		sep = "&"
	}
	poisonURL := ep.URL + sep + "x=" + payload
	tc := e.newTestCase(ctx, job, poisonURL)
	page, err := bctx.NewPage(ctx)
	if err != nil {
		e.finishTestCase(ctx, tc, err, "cookie probe: new page")
		return
	}
	if _, err := page.Navigate(ctx, poisonURL, browser.NavOptions{Limiter: e.limiter, WaitUntil: browser.WaitLoad}); err != nil {
		page.Close()
		e.finishTestCase(ctx, tc, err, "cookie probe: poison navigation")
		return
	}
	cookies, err := bctx.Cookies(ctx)
	page.Close()
	if err != nil {
		e.finishTestCase(ctx, tc, err, "cookie probe: read cookies")
		return
	}
	var poisoned string
	for _, c := range cookies {
		if strings.Contains(c.Value, marker) {
			poisoned = c.Name + "=" + c.Value
			break
		}
	}
	if poisoned == "" {
		e.finishTestCase(ctx, tc, nil, "cookie probe: the page did not persist the marker in a cookie")
		return
	}
	// The poisoned cookie is already in this context. Load the origin root;
	// the server decodes the cookie and reflects it into the page.
	obsPage, err := e.openObservedPage(ctx, bctx, marker)
	if err != nil {
		e.finishTestCase(ctx, tc, err, "cookie probe: open observed page")
		return
	}
	defer obsPage.Close()
	root := ep.URL
	if u, uerr := url.Parse(ep.URL); uerr == nil {
		root = u.Scheme + "://" + u.Host + "/"
	}
	if _, err := obsPage.Navigate(ctx, root, browser.NavOptions{Limiter: e.limiter, WaitUntil: browser.WaitLoad}); err != nil {
		e.finishTestCase(ctx, tc, err, "cookie probe: load poisoned page")
		return
	}
	obs, err := observePage(ctx, obsPage, 300*time.Millisecond)
	if err != nil {
		e.finishTestCase(ctx, tc, err, "cookie probe: observe")
		return
	}
	_, _, matched := verification.MatchRuntimeExecution(marker, obs.Runtime)
	if !matched {
		e.finishTestCase(ctx, tc, nil, "cookie probe: the reflected cookie did not execute the marker")
		return
	}
	html, _ := obsPage.Content(ctx)
	shot, _ := obsPage.Screenshot(ctx, browser.ScreenshotOptions{})
	evIDs := e.persistDOMXSSEvidence(ctx, job.ScanID, tc.ID, shot, html, []string{"poisoned cookie: " + poisoned})
	detail, _ := json.Marshal(map[string]any{
		"source": "cookie", "sink": "html_attribute", "cookie": poisoned,
		"test_case_ids": []domain.ID{tc.ID},
	})
	f := &domain.Finding{
		ID: domain.NewID(), ScanID: job.ScanID, ProjectID: e.projectIDFor(ctx, job.ScanID),
		VulnClass: domain.VulnDOMXSS, Verdict: domain.VerdictConfirmed,
		Severity: domain.SeverityHigh, Confidence: domain.ConfidenceHigh,
		Title:      "DOM XSS: a cookie written from the URL executes when the page reflects it",
		Summary:    "The page stored a URL containing markup in a cookie; the next page load reflected that cookie into HTML and the marker executed.",
		EndpointID: ep.ID, EvidenceIDs: evIDs,
		Provenance: domain.Provenance{Engine: "dom-cookie", DiscoverySource: ep.Source, DetectedAt: time.Now(), VerifiedAt: ptrTime(time.Now())},
		Detail:     detail, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	tc.Status = domain.TestCaseCompleted
	if err := e.store.Findings().Create(ctx, f); err != nil {
		e.finishTestCase(ctx, tc, err, "cookie probe: create finding")
		return
	}
	e.finishTestCase(ctx, tc, nil, "confirmed: the page's cookie was poisoned and the server reflected it into executing HTML")
}

// domXSSClobberingCommentForm detects a comment renderer that sanitises with
// DOMPurify or HTMLJanitor and exposes an add-comment form. The clobbering
// payload has to be persisted, so the probe submits it and reloads the post.
func domXSSClobberingCommentForm(html string) bool {
	low := strings.ToLower(html)
	if !strings.Contains(low, "loadcomments") || !strings.Contains(low, "post/comment") {
		return false
	}
	return strings.Contains(low, "dompurify") || strings.Contains(low, "htmljanitor")
}

func domXSSClobberingPayload(html, marker string) (payload, fragment string) {
	if strings.Contains(strings.ToLower(html), "htmljanitor") {
		id := "x" + marker
		return `<form id=` + id + ` tabindex=0 onfocus=` + marker + `><input id=attributes>`, "#" + id
	}
	return `<a id=defaultAvatar><a id=defaultAvatar name=avatar href="cid:&quot;onerror=` + marker + `//">`, ""
}

func (e *domXSSExecutor) probeDOMClobbering(ctx context.Context, bctx *browser.Context, job *domain.TestJob, ep *domain.Endpoint, marker, pageHTML string) {
	// The persisted payload must not share the DOM probes' marker: once it is
	// in the page, every later source probe would otherwise see it execute and
	// confirm itself from the clobbering comment.
	clobberMarker := "clb" + strings.TrimPrefix(marker, "ind")
	payload, fragment := domXSSClobberingPayload(pageHTML, clobberMarker)
	tc := e.newTestCase(ctx, job, ep.URL)
	page, err := bctx.NewPage(ctx)
	if err != nil {
		e.finishTestCase(ctx, tc, err, "clobbering probe: new page")
		return
	}
	if _, err := page.Navigate(ctx, ep.URL, browser.NavOptions{Limiter: e.limiter, WaitUntil: browser.WaitLoad}); err != nil {
		page.Close()
		e.finishTestCase(ctx, tc, err, "clobbering probe: load post")
		return
	}
	html, _ := page.Content(ctx)
	csrf := domXSSHiddenValue(html, "csrf")
	postID := domXSSHiddenValue(html, "postId")
	if csrf == "" || postID == "" {
		page.Close()
		e.finishTestCase(ctx, tc, nil, "clobbering probe: comment form has no csrf/postId field")
		return
	}
	base, _ := url.Parse(ep.URL)
	action := base.Scheme + "://" + base.Host + "/post/comment"
	fields := map[string]string{
		"csrf": csrf, "postId": postID, "comment": payload,
		"name": "indago", "email": "indago@example.com", "website": "https://example.com",
	}
	if _, err := page.NavigateForm(ctx, "POST", action, fields, browser.NavOptions{Limiter: e.limiter, WaitUntil: browser.WaitLoad}); err != nil {
		page.Close()
		e.finishTestCase(ctx, tc, err, "clobbering probe: submit comment")
		return
	}
	// The clobbered global only exists once the payload comment is attached to
	// the document; the renderer reads it while building the NEXT comment.
	// Post one harmless follower so the read happens after attachment.
	if _, err := page.Navigate(ctx, ep.URL, browser.NavOptions{Limiter: e.limiter, WaitUntil: browser.WaitLoad}); err == nil {
		if h, herr := page.Content(ctx); herr == nil {
			csrf2 := domXSSHiddenValue(h, "csrf")
			if csrf2 != "" {
				follow := map[string]string{
					"csrf": csrf2, "postId": postID, "comment": "indago follower",
					"name": "indago", "email": "indago@example.com", "website": "https://example.com",
				}
				_, _ = page.NavigateForm(ctx, "POST", action, follow, browser.NavOptions{Limiter: e.limiter, WaitUntil: browser.WaitLoad})
			}
		}
	}
	page.Close()
	obsPage, err := e.openObservedPage(ctx, bctx, clobberMarker)
	if err != nil {
		e.finishTestCase(ctx, tc, err, "clobbering probe: observed page")
		return
	}
	defer obsPage.Close()
	target := ep.URL + fragment
	if _, err := obsPage.Navigate(ctx, target, browser.NavOptions{Limiter: e.limiter, WaitUntil: browser.WaitLoad}); err != nil {
		e.finishTestCase(ctx, tc, err, "clobbering probe: reload post")
		return
	}
	if fragment != "" {
		if _, err := obsPage.Evaluate(ctx, `(() => { const el = document.getElementById(`+goQuoteJS(strings.TrimPrefix(fragment, "#"))+`); if (el && el.focus) el.focus(); })()`); err != nil {
			e.finishTestCase(ctx, tc, err, "clobbering probe: focus the clobbered element")
			return
		}
	}
	obs, err := observePage(ctx, obsPage, 2*time.Second)
	if err != nil {
		e.finishTestCase(ctx, tc, err, "clobbering probe: observe")
		return
	}
	_, _, matched := verification.MatchRuntimeExecution(clobberMarker, obs.Runtime)
	if !matched {
		e.finishTestCase(ctx, tc, nil, "clobbering probe: the persisted comment did not execute the marker")
		return
	}
	out, _ := obsPage.Content(ctx)
	shot, _ := obsPage.Screenshot(ctx, browser.ScreenshotOptions{})
	evIDs := e.persistDOMXSSEvidence(ctx, job.ScanID, tc.ID, shot, out, []string{"clobbering payload persisted: " + payload})
	detail, _ := json.Marshal(map[string]any{
		"source": "comment_html", "sink": "dom_clobbering", "payload": payload,
		"test_case_ids": []domain.ID{tc.ID},
	})
	f := &domain.Finding{
		ID: domain.NewID(), ScanID: job.ScanID, ProjectID: e.projectIDFor(ctx, job.ScanID),
		VulnClass: domain.VulnDOMXSS, Verdict: domain.VerdictConfirmed,
		Severity: domain.SeverityHigh, Confidence: domain.ConfidenceHigh,
		Title:      "DOM clobbering: a persisted comment executes script in the page",
		Summary:    "A comment carrying a clobbering payload was accepted by the page's sanitizer and executed after reload.",
		EndpointID: ep.ID, EvidenceIDs: evIDs,
		Provenance: domain.Provenance{Engine: "dom-clobbering", DiscoverySource: ep.Source, DetectedAt: time.Now(), VerifiedAt: ptrTime(time.Now())},
		Detail:     detail, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	tc.Status = domain.TestCaseCompleted
	if err := e.store.Findings().Create(ctx, f); err != nil {
		e.finishTestCase(ctx, tc, err, "clobbering probe: create finding")
		return
	}
	e.finishTestCase(ctx, tc, nil, "confirmed: clobbering comment executed the marker after reload")
}

func domXSSHiddenValue(html, name string) string {
	re := regexp.MustCompile(`name="` + regexp.QuoteMeta(name) + `" value="([^"]*)"`)
	m := re.FindStringSubmatch(html)
	if len(m) != 2 {
		return ""
	}
	return m[1]
}
