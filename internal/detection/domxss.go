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
// candidate DOM-XSS source. Four as of this second slice — see
// docs/dom-xss.md "out of scope" for what is deliberately STILL NOT
// implemented (document.referrer, localStorage/sessionStorage).
type DOMXSSSource string

const (
	// DOMSourceHash is the URL fragment (everything after "#"), read via
	// location.hash. It is never sent to the server by the browser.
	DOMSourceHash DOMXSSSource = "location.hash"

	// DOMSourceQuery is the URL query string, read via location.search or
	// URLSearchParams. This is DELIBERATELY NOT the same thing as Indago's
	// existing Reflected-XSS query-parameter testing: that pipeline probes
	// whether the SERVER reflects a query parameter back into the HTTP
	// response body. This source probes whether the PAGE'S OWN CLIENT-SIDE
	// JavaScript re-reads the raw query string and feeds it into a
	// dangerous sink, independent of whatever the server did with it — a
	// page can encode a parameter safely server-side while its own JS
	// still unsafely re-reads the same raw value and gets popped. See
	// docs/dom-xss.md's "Query-string source vs. Reflected XSS" section;
	// the two detections are intentionally never deduplicated against each
	// other, even when they share an endpoint and parameter name.
	DOMSourceQuery DOMXSSSource = "location.search"

	// DOMSourceWindowName is window.name — it PERSISTS across a same-tab
	// navigation, even cross-origin, in real browsers. Probing it needs a
	// different navigation sequence than Hash/Query (see
	// navigateWithWindowName in internal/scan/domxss.go): navigate to a
	// neutral page first, set window.name there, THEN navigate (same
	// page) to the target.
	DOMSourceWindowName DOMXSSSource = "window.name"

	// DOMSourcePostMessage is the message payload a page's own
	// `window.addEventListener('message', ...)` handler receives. The
	// realistic vulnerable pattern is a listener that uses event.data in a
	// dangerous sink without validating event.origin/event.source — which
	// means ANY other page/frame/popup that holds a reference to this
	// window can reach it. See docs/dom-xss.md's "postMessage testing
	// methodology" section for how this is probed without a second
	// controlled origin.
	DOMSourcePostMessage DOMXSSSource = "postMessage"
)

// IsValid reports whether source is one of this engine's implemented
// client-side sources.
func (s DOMXSSSource) IsValid() bool {
	switch s {
	case DOMSourceHash, DOMSourceQuery, DOMSourceWindowName, DOMSourcePostMessage:
		return true
	default:
		return false
	}
}

// DOMXSSSources lists every implemented source, in the fixed order the
// engine probes them in for a given endpoint (see
// internal/scan/domxss.go's domXSSSourcesFor).
var DOMXSSSources = []DOMXSSSource{DOMSourceHash, DOMSourceQuery, DOMSourceWindowName, DOMSourcePostMessage}

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
// REACHABLE (source, sink) pair found during phase one. Pure,
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
// name — this is how an operator tells a hash-sourced finding apart from
// a query/window.name/postMessage-sourced one on every existing
// presentation surface, with no new fields. Location/Parameter/
// InjectionPointID are left at their zero values — a DOM-XSS candidate
// has no server-side parameter or injection point at all.
func DOMXSSPayloadFor(source DOMXSSSource, sink DOMXSSSink, marker string) (Candidate, bool) {
	if !sink.IsValid() || !source.IsValid() || marker == "" {
		return Candidate{}, false
	}
	value := "<img src=x onerror=" + marker + ">"
	return Candidate{
		Source:     SourceBuiltin,
		Category:   CatDOMXSS,
		Context:    Context(sink),
		ContextSub: string(source),
		Value:      value,
		Trigger:    TriggerLoad,
		Rationale:  domXSSRationale(source, sink),
		DedupKey:   "dom_xss\x00" + string(source) + "\x00" + string(sink) + "\x00" + value,
	}, true
}

// domXSSRationale explains, per source, how the verification candidate's
// value is expected to reach sink — each source has a genuinely different
// client-side read, worth spelling out distinctly rather than a single
// generic sentence.
func domXSSRationale(source DOMXSSSource, sink DOMXSSSink) string {
	var how string
	switch source {
	case DOMSourceQuery:
		how = "the location.search (query string) value, read via URLSearchParams or location.search itself,"
	case DOMSourceWindowName:
		how = "the window.name value (set before, and persisting across, the navigation that loaded this page)"
	case DOMSourcePostMessage:
		how = "a postMessage value received by this page's own window message-event listener, which did not validate event.origin/event.source,"
	default: // DOMSourceHash
		how = "the location.hash value"
	}
	return how + " is assigned wholesale to " + string(sink) +
		"; an <img> with a deliberately-broken src fires its onerror handler the moment the browser parses the injected markup, referencing the benign marker"
}
