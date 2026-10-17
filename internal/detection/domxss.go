package detection

// This file is the (currently single-source, single-sink-category)
// DOM-XSS candidate model — see docs/dom-xss.md for the full design and
// the explicit scope boundary of this first slice. Unlike Reflected XSS, a
// DOM-XSS "site" is identified by (client-side source, HTML-injection
// sink) at one Endpoint, not a server-side parameter/injection point —
// there is no HTTP request/response cycle to inspect at all. That is the
// whole point of this engine: location.hash (the URL fragment) is NEVER
// sent to the server by the browser, so Indago's entire server-response-
// based Reflected XSS pipeline is structurally blind to it.
//
// The two genuinely new, minimal domain concepts this needs are
// DOMXSSSource and DOMXSSSink below. Everything else deliberately REUSES
// the existing Candidate shape (see DOMXSSPayloadFor's doc comment for the
// field repurposing this implies) rather than inventing a parallel type,
// so every existing presentation surface that already renders a
// Candidate's Category/Context/Value/Rationale (CLI, web API, markdown/
// HTML reports) renders a DOM-XSS candidate too, with no new plumbing.
//
// PLANNING ONLY here, same purity contract as candidate.go: no network, no
// browser, no LLM. Reachability PROBING and verification — which DO need a
// real browser to observe whether a value actually reaches a sink — live
// in internal/scan/domxss.go, the same separation Reflected XSS already
// has between detection (pure) and verification (browser-backed).

// DOMXSSSource identifies a client-side-only input this engine reads as a
// candidate DOM-XSS source. Exactly one for this first slice — see
// docs/dom-xss.md "out of scope" for what is deliberately NOT implemented
// yet (postMessage, document.referrer, window.name, localStorage/
// sessionStorage, query-string-read-by-JS).
type DOMXSSSource string

// DOMSourceHash is the URL fragment (everything after "#"), read via
// location.hash. It is never sent to the server by the browser.
const DOMSourceHash DOMXSSSource = "location.hash"

// DOMXSSSink identifies an HTML-injection sink this engine hooks. Exactly
// these three for this first slice (document.writeln shares
// document.write's hook and is reported under the same sink name) — see
// docs/dom-xss.md for what is deliberately NOT implemented yet
// (eval/Function, location/src assignment sinks).
type DOMXSSSink string

const (
	DOMSinkInnerHTML     DOMXSSSink = "innerHTML"
	DOMSinkOuterHTML     DOMXSSSink = "outerHTML"
	DOMSinkDocumentWrite DOMXSSSink = "document.write"
)

// IsValid reports whether sink is one of this slice's three implemented
// HTML-injection sinks.
func (s DOMXSSSink) IsValid() bool {
	switch s {
	case DOMSinkInnerHTML, DOMSinkOuterHTML, DOMSinkDocumentWrite:
		return true
	default:
		return false
	}
}

// CatDOMXSS is the DOM-XSS engine's Candidate.Category value — distinct
// from every Reflected XSS category (html_text, html_attribute, …) so the
// two engines' candidates are never confused on a shared presentation
// surface.
const CatDOMXSS CandidateCategory = "dom_xss"

// DOMXSSCanary returns the benign, inert REACHABILITY probe value planted
// in location.hash during phase one (see internal/scan/domxss.go): a
// value containing marker as a plain substring, embedded in an otherwise
// harmless string, so a sink hook can detect "a value derived from the
// hash source reached this sink" without the canary itself being a markup
// breakout (AGENTS.md §2.2 — a canary is a detection probe, never a
// payload). marker is the SAME bare-identifier marker DOMXSSPayloadFor
// embeds in the real verification payload, so a single substring check
// covers both phases.
func DOMXSSCanary(marker string) string {
	return "indago-domxss-canary-" + marker
}

// DOMXSSPayloadFor returns the deterministic verification Candidate for a
// REACHABLE (DOMSourceHash, sink) pair found during phase one. Pure,
// deterministic, benign-marker-only — mirrors candidate.go's html_text
// onLoad templates (e.g. "<svg onload=M>" / "<img src=x onerror=M>"),
// adapted for a value assigned WHOLESALE to an HTML-injection sink rather
// than reflected into EXISTING HTML markup: being assigned to
// .innerHTML/.outerHTML, or passed to document.write, is actually a
// SIMPLER context than reflected HTML text, since there is no existing
// tag/attribute context to break out of first — a bare
// "<img src=x onerror=M>" string parses and fires as-is the moment the
// sink sets/writes it.
//
// Field repurposing (documented once here; applies everywhere this
// Candidate is read back by scan/report/web/cli code): Category is always
// CatDOMXSS; Context carries the SINK name (not an HTML/JS parse
// position, as it does for Reflected XSS); ContextSub carries the SOURCE
// name. Location/Parameter/InjectionPointID are left at their zero
// values — a DOM-XSS candidate has no server-side parameter or injection
// point at all.
func DOMXSSPayloadFor(sink DOMXSSSink, marker string) (Candidate, bool) {
	if !sink.IsValid() || marker == "" {
		return Candidate{}, false
	}
	value := "<img src=x onerror=" + marker + ">"
	return Candidate{
		Source:     SourceBuiltin,
		Category:   CatDOMXSS,
		Context:    Context(sink),
		ContextSub: string(DOMSourceHash),
		Value:      value,
		Trigger:    TriggerLoad,
		Rationale: "the location.hash value is assigned wholesale to " + string(sink) +
			"; an <img> with a deliberately-broken src fires its onerror handler the moment the browser parses the injected markup, referencing the benign marker",
		DedupKey: "dom_xss\x00" + string(sink) + "\x00" + value,
	}, true
}
