package scan

// This file implements the FIRST slice of a DOM-XSS detection engine — see
// docs/dom-xss.md for the full design and its explicit scope boundary.
// Reflected XSS only ever inspects the SERVER's HTTP response body for a
// marker reflection; location.hash (the URL fragment, after "#") is NEVER
// sent to the server by the browser, so that whole pipeline is
// structurally blind to a page's OWN client-side JavaScript doing
// something like
//
//	document.getElementById('x').innerHTML = location.hash.substring(1)
//
// This engine actually renders the page in a real browser, lets its OWN
// JavaScript run, and observes the live DOM/JS runtime — the fundamentally
// new capability. Every navigation it performs goes through the SAME
// scope-enforcing browser.Manager the rest of the product already uses
// (AllowRequest is checked on every request, exactly like discovery and
// Reflected XSS verification).
//
// Scope for this slice (deliberately narrow — see docs/dom-xss.md):
//   - exactly ONE source: location.hash.
//   - exactly ONE sink category: HTML injection (innerHTML/outerHTML/
//     document.write/writeln) — see detection.DOMXSSSink.
//   - ONE (source, sink) pair tested per endpoint per probe pass: if a
//     page's own script reaches more than one hooked sink, only the
//     first (by whichever the page happened to call first) is tested —
//     documented, not silently incomplete.
//
// Two-phase design, mirroring Reflected XSS's reflect-then-verify split:
//  1. REACHABILITY (canary): navigate with a benign, inert canary value
//     (detection.DOMXSSCanary) in location.hash, with an init-script
//     harness (installed via browser.Page.AddInitScript, so it is in
//     place BEFORE the page's own scripts run — see domXSSHarnessScript)
//     that monkey-patches the three sink setters/functions to report (via
//     a uniquely-prefixed console.log, scraped by
//     parseDOMXSSReachability) whenever a value CONTAINING the canary
//     reaches one of them. A canary reaching a hooked sink is a
//     REACHABILITY signal only, not yet a confirmed vulnerability — the
//     canary itself is inert (no "<"/">" at all).
//  2. VERIFICATION (real payload): once a reachable pair is found,
//     construct a real deterministic candidate (detection.DOMXSSPayloadFor
//     — a bare "<img src=x onerror=MARKER>", the SAME markup-breakout
//     idea candidate.go's html_text templates use, adapted for a value
//     assigned WHOLESALE to a sink rather than reflected into existing
//     markup) and navigate again with it in location.hash. Confirmed only
//     when the browser throws "Uncaught ReferenceError: MARKER is not
//     defined" — the EXACT SAME deterministic bare-marker signal
//     Reflected XSS verification already uses (verification.
//     MatchExecutionSignal / verification.Decide), attributed strictly to
//     this navigation.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
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

// domXSSJob is the JobDOMXSS queue payload: which endpoint to probe.
type domXSSJob struct {
	EndpointID domain.ID `json:"endpoint_id"`
}

func parseDOMXSSJob(job *domain.TestJob) (domXSSJob, error) {
	var dj domXSSJob
	if len(job.Payload) == 0 {
		return dj, errors.New("dom-xss job has no payload")
	}
	if err := json.Unmarshal(job.Payload, &dj); err != nil {
		return dj, fmt.Errorf("decode dom-xss job payload: %w", err)
	}
	if dj.EndpointID.Empty() {
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
// GET/HEAD-navigable Endpoint URL (see selectDOMXSSEndpoints). It reuses
// the scan's existing Endpoint registry — never a parallel discovery
// mechanism. Best-effort throughout: a failure here is logged, never
// fatal.
func (c *Controller) enqueueDOMXSSProbes(ctx context.Context, scanID domain.ID) {
	endpoints, err := c.store.Endpoints().ListByScan(ctx, scanID)
	if err != nil {
		c.log.Warn("dom-xss probes: list endpoints", "scan", scanID, "err", err)
		return
	}
	targets := selectDOMXSSEndpoints(endpoints)
	now := time.Now()
	n := 0
	for _, ep := range targets {
		payload, err := json.Marshal(domXSSJob{EndpointID: ep.ID})
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
		c.log.Info("dom-xss probes: enqueued", "scan", scanID, "endpoints", n)
	}
}

// ---------------------------------------------------------------------------
// the init-script harness and its console-message report format
// ---------------------------------------------------------------------------

// domXSSConsolePrefix uniquely tags a sink-reachability report so it can
// be told apart from any console.log the page's own code might emit.
const domXSSConsolePrefix = "__INDAGO_DOMXSS__"

// domXSSSinkReport is the JSON payload the harness logs (after
// domXSSConsolePrefix) each time a value containing the marker reaches a
// hooked sink.
type domXSSSinkReport struct {
	Sink  string `json:"sink"`
	Value string `json:"value"`
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
		sink := detection.DOMXSSSink(rep.Sink)
		if !sink.IsValid() || seen[sink] {
			continue
		}
		seen[sink] = true
		out = append(out, sink)
	}
	return out
}

// goQuoteJS renders s as a JS double-quoted string literal. Go's %q
// produces backslash escapes JS also accepts for every byte that can
// appear in marker/domXSSConsolePrefix (both are plain ASCII
// alphanumeric/underscore by construction — see detection.NewProbe and
// domXSSConsolePrefix).
func goQuoteJS(s string) string { return fmt.Sprintf("%q", s) }

// domXSSHarnessScript builds the init-script harness: monkey-patches
// Element.prototype.innerHTML/outerHTML and document.write/writeln to
// report (via a uniquely-prefixed console.log) whenever a value
// CONTAINING marker reaches one of them. Installed via
// browser.Page.AddInitScript, BEFORE any page script runs: attaching a
// listener AFTER the page has already loaded would miss an onload-style
// handler that already fired (see docs/dom-xss.md).
func domXSSHarnessScript(marker string) string {
	return fmt.Sprintf(domXSSHarnessTemplate, goQuoteJS(marker), goQuoteJS(domXSSConsolePrefix))
}

const domXSSHarnessTemplate = `(() => {
  const MARKER = %s;
  const PREFIX = %s;
  function report(sink, value) {
    try {
      var v = String(value);
      if (v.indexOf(MARKER) === -1) return;
      console.log(PREFIX + JSON.stringify({ sink: sink, value: v.slice(0, 500) }));
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
// XSS one (disjoint tag) and from a different sink or endpoint — the
// three things that together identify "the same underlying DOM-XSS site"
// for this slice's one source.
func domXSSFindingDedupKey(endpointID domain.ID, source detection.DOMXSSSource, sink detection.DOMXSSSink) string {
	return string(endpointID) + "\x00dom_xss\x00" + string(source) + "\x00" + string(sink)
}

func domXSSFindingTitle(ep *domain.Endpoint, source detection.DOMXSSSource, sink detection.DOMXSSSink) string {
	return fmt.Sprintf("DOM XSS candidate: %s reaches %s at %s %s", source, sink, ep.Method, endpointLabel(ep.URL))
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
func upsertDOMXSSFinding(ctx context.Context, st store.Store, scanID domain.ID, ep *domain.Endpoint, cand detection.Candidate, canaryValue string, reachTestCaseID domain.ID) (*domain.Finding, error) {
	source := detection.DOMSourceHash
	sink := detection.DOMXSSSink(cand.Context)
	key := domXSSFindingDedupKey(ep.ID, source, sink)
	now := time.Now()
	reachAttempt := verificationAttempt{
		CandidateValue:   canaryValue,
		VerifyTestCaseID: reachTestCaseID,
		Verdict:          domain.VerdictPending,
		Confidence:       domain.ConfidenceLow,
		Notes:            "reachability probe: a benign canary in location.hash reached this sink — reachability only, not yet a confirmed vulnerability",
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
		Method: ep.Method, ParameterName: string(source), DedupKey: key, Occurrences: 1,
		TestCaseIDs: []domain.ID{reachTestCaseID}, Candidates: []detection.Candidate{cand}, Attempts: []verificationAttempt{reachAttempt},
	}
	f := &domain.Finding{
		ID: domain.NewID(), ScanID: scanID, ProjectID: sc.ProjectID, VulnClass: domain.VulnDOMXSS,
		Verdict: domain.VerdictPending, Severity: domain.SeverityHigh, Confidence: domain.ConfidenceLow,
		Title:      domXSSFindingTitle(ep, source, sink),
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

// domXSSExecutor runs JobDOMXSS jobs: it probes ONE discovered Endpoint
// for the one source/sink-category combination this slice implements,
// through the SAME scope-enforcing browser.Manager the rest of the
// product already uses.
type domXSSExecutor struct {
	store    store.Store
	browser  *browser.Manager // nil: jobs are recorded skipped, never failed (no browser configured for this scan — mirrors verifyExecutor's Stub behavior)
	evidence evidence.Store   // nil: outcomes are recorded without evidence blobs
	scope    domain.Scope
	log      *slog.Logger
	// findingsMu — see newExecutor's doc comment. MUST be the SAME mutex
	// shared with this scan's executor/verifyExecutor.
	findingsMu *sync.Mutex
}

func newDOMXSSExecutor(st store.Store, mgr *browser.Manager, ev evidence.Store, scope domain.Scope, log *slog.Logger, findingsMu *sync.Mutex) *domXSSExecutor {
	if findingsMu == nil {
		findingsMu = &sync.Mutex{}
	}
	return &domXSSExecutor{store: st, browser: mgr, evidence: ev, scope: scope, log: log, findingsMu: findingsMu}
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
		tc := e.newTestCase(ctx, job, ep.URL)
		tc.Status = domain.TestCaseSkipped
		e.finishTestCase(ctx, tc, nil, "dom-xss probe skipped: no browser configured for this scan")
		return nil
	}

	marker := detection.NewProbe(job.ScanID, ep.ID).Token
	sessionStatePath := e.sessionStatePathFor(ctx, job.ScanID)

	bctx, err := e.browser.NewContext(ctx, browser.ContextOptions{AllowRequest: allow, StorageStatePath: sessionStatePath})
	if err != nil {
		tc := e.newTestCase(ctx, job, ep.URL)
		e.finishTestCase(ctx, tc, err, "open browser context")
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	defer bctx.Close()

	// --- Phase 1: reachability ---
	canary := detection.DOMXSSCanary(marker)
	canaryURL := domXSSHashURL(ep.URL, canary)
	console, _, _, _, navErr := e.navigate(ctx, bctx, canaryURL, marker)
	reachTC := e.newTestCase(ctx, job, canaryURL)
	if navErr != nil {
		e.finishTestCase(ctx, reachTC, navErr, "reachability probe")
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return navErr
	}
	reachable := parseDOMXSSReachability(console, marker)
	if len(reachable) == 0 {
		e.finishTestCase(ctx, reachTC, nil, "no HTML-injection sink reachable from location.hash (negative result)")
		return nil
	}
	// Bounded to the FIRST reachable sink (deterministic: whichever the
	// page's own script used first) — see this file's header comment:
	// this slice tests one pair per endpoint, not every reachable sink.
	sink := reachable[0]
	e.finishTestCase(ctx, reachTC, nil, fmt.Sprintf("reachable sink: %s (canary observed in the hooked setter/call)", sink))

	cand, ok := detection.DOMXSSPayloadFor(sink, marker)
	if !ok {
		return nil
	}

	e.findingsMu.Lock()
	finding, err := upsertDOMXSSFinding(ctx, e.store, job.ScanID, ep, cand, canary, reachTC.ID)
	e.findingsMu.Unlock()
	if err != nil {
		e.log.Warn("dom-xss: upsert finding", "job", job.ID, "err", err)
		return nil
	}

	// --- Phase 2: verification (the EXACT SAME deterministic bare-marker
	// signal Reflected XSS verification already uses) ---
	payloadURL := domXSSHashURL(ep.URL, cand.Value)
	console2, pageErrs2, html2, screenshot2, verr := e.navigate(ctx, bctx, payloadURL, marker)
	verifyTC := e.newTestCase(ctx, job, payloadURL)
	if verr != nil {
		e.finishTestCase(ctx, verifyTC, verr, "verification navigation")
		return nil // the finding stays Pending; a later retry can still verify it
	}

	var consoleErrs []string
	for _, cm := range console2 {
		if cm.Type == "error" {
			consoleErrs = append(consoleErrs, cm.Text)
		}
	}
	_, sigText, matched := verification.MatchExecutionSignal(marker, pageErrs2, consoleErrs)
	markerInDOM := strings.Contains(html2, marker)
	verdict, confidence, notes := verification.Decide(matched, markerInDOM)
	if matched && sigText != "" {
		notes = notes + " (" + sigText + ")"
	}

	var evidenceIDs []domain.ID
	if e.evidence != nil {
		logLines := append(append([]string(nil), consoleErrs...), pageErrs2...)
		evidenceIDs = e.persistDOMXSSEvidence(ctx, job.ScanID, verifyTC.ID, screenshot2, html2, logLines)
	}
	verifyTC.EvidenceIDs = evidenceIDs
	e.finishTestCase(ctx, verifyTC, nil, notes)

	e.correlateDOMXSSVerification(ctx, finding.ID, cand, verdict, confidence, notes, verifyTC.ID, evidenceIDs, payloadURL)
	return nil
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

// navigate opens a fresh page in bctx, installs the init-script harness
// BEFORE navigating (see domXSSHarnessScript's doc comment), navigates to
// navURL, waits for load, and returns the page's observations. One page
// per navigation, never reused — mirrors BrowserVerifier.Verify's own
// discipline of never attributing a signal to the wrong navigation (here
// trivially true since every page is brand new, but kept explicit).
func (e *domXSSExecutor) navigate(ctx context.Context, bctx *browser.Context, navURL, marker string) (console []browser.ConsoleMessage, pageErrs []string, html string, screenshot []byte, err error) {
	page, err := bctx.NewPage(ctx)
	if err != nil {
		return nil, nil, "", nil, err
	}
	defer page.Close()
	if err := page.AddInitScript(ctx, domXSSHarnessScript(marker)); err != nil {
		return nil, nil, "", nil, err
	}
	if _, err := page.Navigate(ctx, navURL, browser.NavOptions{WaitUntil: browser.WaitLoad}); err != nil {
		return nil, nil, "", nil, err
	}
	html, _ = page.Content(ctx)
	shot, _ := page.Screenshot(ctx, browser.ScreenshotOptions{})
	return page.ConsoleMessages(), page.PageErrors(), html, shot, nil
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
