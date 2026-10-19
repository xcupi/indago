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
	"log/slog"
	"net/url"
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
	EndpointID domain.ID              `json:"endpoint_id"`
	Source     detection.DOMXSSSource `json:"source"`
}

func parseDOMXSSJob(job *domain.TestJob) (domXSSJob, error) {
	var dj domXSSJob
	if len(job.Payload) == 0 {
		return dj, errors.New("dom-xss job has no payload")
	}
	if err := json.Unmarshal(job.Payload, &dj); err != nil {
		return dj, fmt.Errorf("decode dom-xss job payload: %w", err)
	}
	if dj.EndpointID.Empty() || !dj.Source.IsValid() {
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
// GET/HEAD-navigable Endpoint URL (see selectDOMXSSEndpoints) per implemented
// source. Each source job performs its own query-parameter or storage-key
// selection inside Handle. It reuses the scan's existing Endpoint registry —
// never a parallel discovery mechanism. Best-effort throughout: a failure
// here is logged, never fatal.
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
		for _, source := range detection.DOMXSSSources {
			payload, err := json.Marshal(domXSSJob{EndpointID: ep.ID, Source: source})
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
				c.log.Warn("dom-xss probes: enqueue job", "scan", scanID, "source", source, "err", err)
				continue
			}
			n++
		}
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

// domXSSSinkReport is the JSON payload the harness logs (after
// domXSSConsolePrefix) each time a value containing the marker reaches a
// hooked sink.
type domXSSSinkReport struct {
	Sink      string `json:"sink"`
	Value     string `json:"value"`
	Connected bool   `json:"connected,omitempty"`
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

// goQuoteJS renders s as a JS double-quoted string literal. Go's %q
// produces backslash escapes JS also accepts for every byte that can
// appear in marker/domXSSConsolePrefix (both are plain ASCII
// alphanumeric/underscore by construction — see detection.NewProbe and
// domXSSConsolePrefix).
func goQuoteJS(s string) string { return fmt.Sprintf("%q", s) }

// domXSSHarnessScript builds the init-script harness: monkey-patches
// the implemented HTML and primitive-string timer sinks to
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
  // Capture the natives before any page script runs. A page (many production
  // builds do) that neutralizes console.log or JSON.stringify later must not be
  // able to silence the reports, which would read as "no sink reachable".
  const LOG = (function () { try { return console.log.bind(console); } catch (e) { return function () {}; } })();
  const STRINGIFY = JSON.stringify.bind(JSON);
  const TOSTRING = String;
  function report(sink, value, connected) {
    try {
      var v = TOSTRING(value);
      if (v.indexOf(MARKER) === -1) return;
      LOG(PREFIX + STRINGIFY({ sink: sink, value: v.slice(0, 500), connected: connected === true }));
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
		Method: ep.Method, ParameterName: parameterName, DedupKey: key, Occurrences: 1,
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
	proxyPool  []string
	proxyNext  atomic.Uint64
}

func newDOMXSSExecutor(st store.Store, mgr *browser.Manager, ev evidence.Store, scope domain.Scope, log *slog.Logger, findingsMu *sync.Mutex) *domXSSExecutor {
	if findingsMu == nil {
		findingsMu = &sync.Mutex{}
	}
	return &domXSSExecutor{store: st, browser: mgr, evidence: ev, scope: scope, log: log, findingsMu: findingsMu}
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
		tc := e.newTestCase(ctx, job, ep.URL)
		tc.Status = domain.TestCaseSkipped
		e.finishTestCase(ctx, tc, nil, "dom-xss probe skipped: no browser configured for this scan")
		return nil
	}

	source := dj.Source
	marker := detection.NewProbe(job.ScanID, ep.ID).Token
	sessionStatePath := e.sessionStatePathFor(ctx, job.ScanID)
	proxy := e.nextProxy() // one proxy per job, shared by every per-selector context below
	newContext := func() (*browser.Context, error) {
		return e.browser.NewContext(ctx, browser.ContextOptions{AllowRequest: allow, StorageStatePath: sessionStatePath, ProxyServer: proxy})
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

	var selectors []string
	switch source {
	case detection.DOMSourceQuery:
		selectors, err = e.queryParamNames(ctx, ep.ID)
		if err != nil {
			tc := e.newTestCase(ctx, job, ep.URL)
			e.finishTestCase(ctx, tc, err, "query-string DOM-XSS parameter discovery")
			return err
		}
		if len(selectors) == 0 {
			tc := e.newTestCase(ctx, job, ep.URL)
			tc.Status = domain.TestCaseSkipped
			e.finishTestCase(ctx, tc, nil, "query-string DOM-XSS source not tested: no discovered query parameter on this endpoint")
			return nil
		}
	case detection.DOMSourceLocalStorage, detection.DOMSourceSessionStorage:
		selectors, err = e.discoverStorageKeys(ctx, bctx, source, ep.URL)
		if err != nil {
			tc := e.newTestCase(ctx, job, ep.URL)
			e.finishTestCase(ctx, tc, err, "storage key discovery")
			return err
		}
		discoveryTC := e.newTestCase(ctx, job, ep.URL)
		if len(selectors) == 0 {
			discoveryTC.Status = domain.TestCaseSkipped
			e.finishTestCase(ctx, discoveryTC, nil, fmt.Sprintf("%s source not tested: no storage key was present and no getItem key was observed", source))
			return nil
		}
		skipped := 0
		if len(selectors) > domXSSStorageKeyLimit {
			skipped = len(selectors) - domXSSStorageKeyLimit
			selectors = selectors[:domXSSStorageKeyLimit]
		}
		discoveryNote := fmt.Sprintf("%s key discovery observed %d distinct key(s); deterministic ceiling=%d, testing %d", source, len(selectors)+skipped, domXSSStorageKeyLimit, len(selectors))
		if skipped > 0 {
			discoveryNote += fmt.Sprintf("; skipped %d additional key(s)", skipped)
		}
		e.finishTestCase(ctx, discoveryTC, nil, discoveryNote)
	case detection.DOMSourceHash:
		selectors, err = e.paramNamesAt(ctx, ep.ID, domain.LocationFragment)
		if err != nil {
			tc := e.newTestCase(ctx, job, ep.URL)
			e.finishTestCase(ctx, tc, err, "fragment-route parameter discovery")
			return err
		}
		if len(selectors) == 0 {
			// No route parameter: keep the whole-fragment probe for plain hashes.
			selectors = []string{""}
		}
	default:
		selectors = []string{""}
	}

	// Every selector gets a context of its own. Origin storage, cookies and
	// service state written while probing one selector (for example a storage
	// key's payload) must never be visible to the next selector's attempt, or
	// execution caused by the first is attributed to the second.
	for _, selector := range selectors {
		if err := e.probeSelectorInFreshContext(ctx, newContext, job, ep, source, selector, marker); err != nil {
			return err
		}
	}
	return nil
}

func (e *domXSSExecutor) probeSelectorInFreshContext(ctx context.Context, newContext func() (*browser.Context, error), job *domain.TestJob, ep *domain.Endpoint, source detection.DOMXSSSource, selector, marker string) error {
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
	return e.probeDOMXSSCandidate(ctx, sctx, job, ep, source, selector, marker)
}

// queryParamNames returns every distinct discovered LocationQuery parameter
// for endpointID in lexicographic name order. Sorting makes probe ordering
// deterministic even when a store implementation does not preserve row order.
func (e *domXSSExecutor) queryParamNames(ctx context.Context, endpointID domain.ID) ([]string, error) {
	return e.paramNamesAt(ctx, endpointID, domain.LocationQuery)
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
	case detection.DOMSourceLocalStorage, detection.DOMSourceSessionStorage:
		return fmt.Sprintf("%s key %q", source, selector)
	default:
		return string(source)
	}
}

func domXSSCandidateForSelector(cand detection.Candidate, source detection.DOMXSSSource, selector string) detection.Candidate {
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

func (e *domXSSExecutor) probeDOMXSSCandidate(ctx context.Context, bctx *browser.Context, job *domain.TestJob, ep *domain.Endpoint, source detection.DOMXSSSource, selector, marker string) error {
	label := domXSSSelectorLabel(source, selector)
	canary := detection.DOMXSSCanary(marker)

	// --- Phase 1: reachability ---
	obs1, canaryNavURL, navErr := e.navigateSource(ctx, bctx, source, ep, selector, marker, canary)
	reachTC := e.newTestCase(ctx, job, canaryNavURL)
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
	if len(reachable) == 0 {
		e.finishTestCase(ctx, reachTC, nil, fmt.Sprintf("no implemented DOM-XSS sink reachable from %s (negative result)", label))
		return nil
	}
	// Bounded to the FIRST reachable sink (deterministic: whichever the
	// page's own script used first) — see this file's header comment.
	sink := reachable[0]
	e.finishTestCase(ctx, reachTC, nil, fmt.Sprintf("reachable sink: %s from %s (canary observed in the hooked setter/call)", sink, label))

	cand, ok := detection.DOMXSSPayloadFor(source, sink, marker)
	if !ok {
		return nil
	}
	cand = domXSSCandidateForSelector(cand, source, selector)

	e.findingsMu.Lock()
	finding, err := upsertDOMXSSFinding(ctx, e.store, job.ScanID, ep, cand, canary, reachTC.ID)
	e.findingsMu.Unlock()
	if err != nil {
		e.log.Warn("dom-xss: upsert finding", "job", job.ID, "err", err)
		return nil
	}

	// --- Phase 2: verification ---
	// Execution is attributed by the browser engine (the paused instruction
	// is the bare marker identifier, in the main frame), never by matching
	// page-controlled error or console text.
	obs2, payloadNavURL, verr := e.navigateSource(ctx, bctx, source, ep, selector, marker, cand.Value)
	verifyTC := e.newTestCase(ctx, job, payloadNavURL)
	if verr == nil {
		verr = requireDOMXSSProvenance(obs2)
	}
	if verr != nil {
		e.finishTestCase(ctx, verifyTC, verr, "verification navigation for "+label)
		return nil // the finding stays Pending; a later retry can still verify it
	}

	harness2 := domXSSHarnessMessages(obs2.Runtime)
	var consoleErrs []string
	for _, cm := range obs2.Console {
		if cm.Type == "error" {
			consoleErrs = append(consoleErrs, cm.Text)
		}
	}
	_, sigText, matched := verification.MatchRuntimeExecution(marker, obs2.Runtime)
	fragmentNotInserted := sink == detection.DOMSinkCreateContextualFragment && !hasConnectedDOMXSSFragment(harness2, marker)
	if fragmentNotInserted {
		matched = false
	}
	markerInDOM := strings.Contains(obs2.HTML, marker)
	verdict, confidence, notes := verification.DecideWithProvenance(marker, matched, markerInDOM, obs2.Runtime)
	if fragmentNotInserted {
		notes += "; target insertion of the parsed fragment was not observed; detached-fragment runtime errors alone do not confirm this sink"
	}
	if matched && sigText != "" {
		notes = notes + " (" + sigText + ")"
	}
	if matched {
		notes += domXSSAttributionNotes(source, sink, parseDOMXSSReachability(harness2, marker))
	}
	if source == detection.DOMSourceLocalStorage || source == detection.DOMSourceSessionStorage {
		notes += "; attacker-relevant ability to write or poison this storage key is not established by this isolated probe and requires manual exploitability review unless the target flow demonstrates it"
	}

	var evidenceIDs []domain.ID
	if e.evidence != nil {
		logLines := append(append([]string(nil), consoleErrs...), obs2.PageErrors...)
		for _, message := range harness2 {
			logLines = append(logLines, message.Text)
		}
		if raw, err := json.Marshal(obs2.Runtime); err == nil {
			logLines = append(logLines, "__INDAGO_RUNTIME_PROVENANCE__"+string(raw))
		}
		evidenceIDs = e.persistDOMXSSEvidence(ctx, job.ScanID, verifyTC.ID, obs2.Screenshot, obs2.HTML, logLines)
	}
	verifyTC.EvidenceIDs = evidenceIDs
	e.finishTestCase(ctx, verifyTC, nil, notes)

	e.correlateDOMXSSVerification(ctx, finding.ID, cand, verdict, confidence, notes, verifyTC.ID, evidenceIDs, payloadNavURL)
	return nil
}

// requireDOMXSSProvenance turns missing engine-level provenance into a visible
// probe error. Without it the attempt can be neither a trustworthy negative nor
// a trustworthy positive, so it must not be recorded as either.
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

func observePage(ctx context.Context, page *browser.Page) domXSSObservation {
	html, _ := page.Content(ctx)
	shot, _ := page.Screenshot(ctx, browser.ScreenshotOptions{})
	return domXSSObservation{Console: page.ConsoleMessages(), PageErrors: page.PageErrors(), HTML: html, Screenshot: shot, Runtime: page.RuntimeObservations()}
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
	switch source {
	case detection.DOMSourceQuery:
		navURL = domXSSQueryURL(ep.URL, queryParam, value)
		obs, err = e.navigate(ctx, bctx, navURL, marker)
	case detection.DOMSourceWindowName:
		navURL = ep.URL
		obs, err = e.navigateWithWindowName(ctx, bctx, navURL, marker, value)
	case detection.DOMSourcePostMessage:
		navURL = ep.URL
		obs, err = e.navigateWithPostMessage(ctx, bctx, navURL, marker, value)
	case detection.DOMSourceReferrer:
		navURL = ep.URL
		obs, err = e.navigateWithReferrer(ctx, bctx, navURL, marker, value)
	case detection.DOMSourceLocalStorage, detection.DOMSourceSessionStorage:
		navURL = ep.URL
		obs, err = e.navigateWithStorage(ctx, bctx, source, navURL, queryParam, marker, value)
	default: // detection.DOMSourceHash
		navURL = domXSSHashURL(ep.URL, value)
		if queryParam != "" {
			if routeURL := domXSSFragmentRouteURL(ep.URL, queryParam, value); routeURL != "" {
				navURL = routeURL
			}
		}
		obs, err = e.navigate(ctx, bctx, navURL, marker)
	}
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

func domXSSURLSourceObservationDelay(navURL string) time.Duration {
	if i := strings.IndexByte(navURL, '#'); i >= 0 {
		fragment := navURL[i+1:]
		if strings.HasPrefix(fragment, "/") && strings.Contains(fragment, "?") {
			return domXSSFragmentRouteObservationWindow
		}
	}
	return domXSSURLSourceObservationWindow
}

func waitForDOMXSSURLSourceObservationWindow(ctx context.Context, navURL string) error {
	timer := time.NewTimer(domXSSURLSourceObservationDelay(navURL))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// navigate opens a fresh page in bctx, installs the init-script harness
// BEFORE navigating (see domXSSHarnessScript's doc comment), navigates to
// navURL, allows a bounded post-load observation window for hash/query SPA
// work, and returns the page's observations. One page per navigation, never
// reused — mirrors BrowserVerifier.Verify's own discipline of never
// attributing a signal to the wrong navigation.
func (e *domXSSExecutor) navigate(ctx context.Context, bctx *browser.Context, navURL, marker string) (domXSSObservation, error) {
	page, err := e.openObservedPage(ctx, bctx, marker)
	if err != nil {
		return domXSSObservation{}, err
	}
	defer page.Close()
	if _, err := page.Navigate(ctx, navURL, browser.NavOptions{Limiter: e.limiter, WaitUntil: browser.WaitLoad}); err != nil {
		return domXSSObservation{}, err
	}
	if err := waitForDOMXSSURLSourceObservationWindow(ctx, navURL); err != nil {
		return domXSSObservation{}, err
	}
	return observePage(ctx, page), nil
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
func (e *domXSSExecutor) navigateWithWindowName(ctx context.Context, bctx *browser.Context, targetURL, marker, value string) (domXSSObservation, error) {
	page, err := e.openObservedPage(ctx, bctx, marker)
	if err != nil {
		return domXSSObservation{}, err
	}
	defer page.Close()
	if _, err := page.Navigate(ctx, "about:blank", browser.NavOptions{Limiter: e.limiter, WaitUntil: browser.WaitLoad}); err != nil {
		return domXSSObservation{}, err
	}
	if _, err := page.Evaluate(ctx, setWindowNameScript(value)); err != nil {
		return domXSSObservation{}, err
	}
	if _, err := page.Navigate(ctx, targetURL, browser.NavOptions{Limiter: e.limiter, WaitUntil: browser.WaitLoad}); err != nil {
		return domXSSObservation{}, err
	}
	return observePage(ctx, page), nil
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
func (e *domXSSExecutor) navigateWithPostMessage(ctx context.Context, bctx *browser.Context, targetURL, marker, value string) (domXSSObservation, error) {
	page, err := e.openObservedPage(ctx, bctx, marker)
	if err != nil {
		return domXSSObservation{}, err
	}
	defer page.Close()
	if _, err := page.Navigate(ctx, targetURL, browser.NavOptions{Limiter: e.limiter, WaitUntil: browser.WaitLoad}); err != nil {
		return domXSSObservation{}, err
	}
	if _, err := page.Evaluate(ctx, postMessageScript(value)); err != nil {
		return domXSSObservation{}, err
	}
	return observePage(ctx, page), nil
}

// postMessageScript creates an opaque-origin sandboxed srcdoc sender and
// posts value to its parent (the already-loaded target page). Omitting
// allow-same-origin is essential: it gives the frame an opaque origin that
// serializes as "null". The parent receives the event from another Window,
// never from its own window object. No network request is made by this
// local sender document.
func postMessageScript(value string) string {
	srcdoc := "<!doctype html><script>parent.postMessage(" + goQuoteJS(value) + ", '*');</script>"
	return "(() => new Promise((resolve) => { const sender = document.createElement('iframe'); sender.setAttribute('sandbox', 'allow-scripts'); sender.onload = () => setTimeout(resolve, 300); sender.srcdoc = " + goQuoteJS(srcdoc) + "; document.body.appendChild(sender); }))();"
}

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
	raw, err := page.Evaluate(ctx, script)
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
func (e *domXSSExecutor) navigateWithReferrer(ctx context.Context, bctx *browser.Context, targetURL, marker, value string) (domXSSObservation, error) {
	page, err := e.openObservedPage(ctx, bctx, marker)
	if err != nil {
		return domXSSObservation{}, err
	}
	defer page.Close()
	if _, err := page.Navigate(ctx, targetURL, browser.NavOptions{Limiter: e.limiter, WaitUntil: browser.WaitLoad, Referer: domXSSRefererURL(value)}); err != nil {
		return domXSSObservation{}, err
	}
	return observePage(ctx, page), nil
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
func (e *domXSSExecutor) navigateWithStorage(ctx context.Context, bctx *browser.Context, source detection.DOMXSSSource, targetURL, key, marker, value string) (domXSSObservation, error) {
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
	return observePage(ctx, page), nil
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
