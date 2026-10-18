package detection

// This file is the pure seven-source DOM-XSS candidate model. HTML sinks
// receive the unchanged marker image; primitive-string timers receive only a
// bare marker JavaScript expression. See docs/dom-xss.md for bounded coverage.
// A DOM-XSS site is identified by (client-side source, sink) at an Endpoint,
// not a server-side injection point. In particular, fragments never reach the
// server-response-based Reflected XSS pipeline.
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
// candidate DOM-XSS source. Seven sources are implemented; see
// docs/dom-xss.md for the exact query/storage selector coverage and the
// sink categories deliberately left out of scope.
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
	// dangerous sink without validating event.origin/event.source. The
	// browser probe sends from an allow-scripts sandboxed srcdoc iframe
	// (opaque origin, serialized as "null"), not from the target window
	// itself; see docs/dom-xss.md's "postMessage testing methodology".
	DOMSourcePostMessage DOMXSSSource = "postMessage"

	// DOMSourceReferrer is document.referrer, the HTTP Referer header
	// value the browser sets automatically on a real navigation. Unlike
	// Hash/Query it is set via the navigation's Referer HEADER, not
	// encoded into the URL — see navigateWithReferrer in
	// internal/scan/domxss.go, which drives the navigation with an
	// explicit referer override (browser.NavOptions.Referer).
	DOMSourceReferrer DOMXSSSource = "document.referrer"

	// DOMSourceLocalStorage and DOMSourceSessionStorage are
	// window.localStorage/window.sessionStorage. Unlike every other
	// source, these are ORIGIN-scoped, not window/tab-scoped — a value
	// written to storage is only visible to a page on the SAME ORIGIN
	// that wrote it. Probing them needs a same-origin pre-navigation
	// before the write (see navigateWithStorage in
	// internal/scan/domxss.go), unlike window.name (tab-scoped, any
	// neutral page works) or Hash/Query (no storage at all). They share
	// one navigation helper parametrized by backend, not two
	// near-duplicate code paths — the sequencing and exploitation shape
	// are identical, only the JS object (localStorage vs sessionStorage)
	// differs.
	DOMSourceLocalStorage   DOMXSSSource = "localStorage"
	DOMSourceSessionStorage DOMXSSSource = "sessionStorage"
)

// IsValid reports whether source is one of this engine's implemented
// client-side sources.
func (s DOMXSSSource) IsValid() bool {
	switch s {
	case DOMSourceHash, DOMSourceQuery, DOMSourceWindowName, DOMSourcePostMessage,
		DOMSourceReferrer, DOMSourceLocalStorage, DOMSourceSessionStorage:
		return true
	default:
		return false
	}
}

// DOMXSSSources lists every implemented source, in the fixed order the
// engine probes them in for a given endpoint (see
// internal/scan/domxss.go's domXSSSourcesFor).
var DOMXSSSources = []DOMXSSSource{
	DOMSourceHash, DOMSourceQuery, DOMSourceWindowName, DOMSourcePostMessage,
	DOMSourceReferrer, DOMSourceLocalStorage, DOMSourceSessionStorage,
}

// DOMXSSSink identifies the bounded HTML and primitive-string timer sinks.
// document.writeln shares document.write's identity. eval/Function and
// location/src assignment remain excluded; see docs/dom-xss.md.
type DOMXSSSink string

const (
	DOMSinkInnerHTML                DOMXSSSink = "innerHTML"
	DOMSinkOuterHTML                DOMXSSSink = "outerHTML"
	DOMSinkDocumentWrite            DOMXSSSink = "document.write"
	DOMSinkInsertAdjacentHTML       DOMXSSSink = "insertAdjacentHTML"
	DOMSinkCreateContextualFragment DOMXSSSink = "Range.createContextualFragment"
	DOMSinkSetTimeout               DOMXSSSink = "setTimeout"
	DOMSinkSetInterval              DOMXSSSink = "setInterval"
)

// IsValid reports whether sink is one of this engine's implemented sinks.
func (s DOMXSSSink) IsValid() bool {
	switch s {
	case DOMSinkInnerHTML, DOMSinkOuterHTML, DOMSinkDocumentWrite, DOMSinkInsertAdjacentHTML, DOMSinkCreateContextualFragment, DOMSinkSetTimeout, DOMSinkSetInterval:
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
// Primitive-string timer candidates instead contain ONLY the bare marker
// expression: native timers evaluate JavaScript, not HTML. No string-literal
// breakout is attempted. Invalid/non-identifier markers are rejected.
//
// Field repurposing (documented once here; applies everywhere this
// Candidate is read back by scan/report/web/cli code): Category is always
// CatDOMXSS; Context carries the SINK name (not an HTML/JS parse
// position, as it does for Reflected XSS); ContextSub carries the SOURCE
// name — this is how an operator tells a hash-sourced finding apart from
// a query/window.name/postMessage-sourced one on every existing
// presentation surface, with no new fields. For query and storage sources,
// scan code fills Candidate.Parameter with the tested query name or storage
// key (and query candidates set LocationQuery); storage backend remains the
// source in ContextSub. Other sources leave Location/Parameter/
// InjectionPointID at zero values because they have no named selector.
func DOMXSSPayloadFor(source DOMXSSSource, sink DOMXSSSink, marker string) (Candidate, bool) {
	if !sink.IsValid() || !source.IsValid() || !validDOMXSSMarker(marker) {
		return Candidate{}, false
	}
	value := "<img src=x onerror=" + marker + ">"
	if sink == DOMSinkSetTimeout || sink == DOMSinkSetInterval {
		value = marker // A timer evaluates JavaScript, not HTML.
	}
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

// validDOMXSSMarker accepts only a bare ASCII identifier, never supplied code,
// literals, keywords or the commonly defined undefined/NaN/Infinity globals.
func validDOMXSSMarker(marker string) bool {
	if marker == "" {
		return false
	}
	for i := 0; i < len(marker); i++ {
		c := marker[i]
		if c == '_' || c == '$' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || i > 0 && c >= '0' && c <= '9' {
			continue
		}
		return false
	}
	switch marker {
	case "await", "break", "case", "catch", "class", "const", "continue", "debugger", "default", "delete", "do", "else", "enum", "export", "extends", "false", "finally", "for", "function", "if", "implements", "import", "in", "instanceof", "interface", "let", "new", "null", "package", "private", "protected", "public", "return", "static", "super", "switch", "this", "throw", "true", "try", "typeof", "var", "void", "while", "with", "yield", "undefined", "NaN", "Infinity":
		return false
	}
	return true
}

// domXSSRationale explains, per source, how the verification candidate's
// value is expected to reach sink — each source has a genuinely different
// client-side read, worth spelling out distinctly rather than a single
// generic sentence.
func domXSSRationale(source DOMXSSSource, sink DOMXSSSink) string {
	var how string
	storageControlCaveat := ""
	switch source {
	case DOMSourceQuery:
		how = "the location.search (query string) value, read via URLSearchParams or location.search itself,"
	case DOMSourceWindowName:
		how = "the window.name value (set before, and persisting across, the navigation that loaded this page)"
	case DOMSourcePostMessage:
		how = "a postMessage value received by this page's own window message-event listener, which did not validate event.origin/event.source,"
	case DOMSourceReferrer:
		how = "the document.referrer value (the HTTP Referer header of the navigation that loaded this page)"
	case DOMSourceLocalStorage:
		how = "the localStorage key read by this page's own client-side JavaScript (the candidate is written only in Indago's isolated browser context)"
		storageControlCaveat = "; this reachability does not establish that an attacker can write or poison the key—manual exploitability review is required unless an attacker-relevant application flow demonstrates that control"
	case DOMSourceSessionStorage:
		how = "the sessionStorage key read by this page's own client-side JavaScript (the candidate is written only in Indago's isolated browser context)"
		storageControlCaveat = "; this reachability does not establish that an attacker can write or poison the key—manual exploitability review is required unless an attacker-relevant application flow demonstrates that control"
	default: // DOMSourceHash
		how = "the location.hash value"
	}
	if sink == DOMSinkSetTimeout || sink == DOMSinkSetInterval {
		return how + " reaches the primitive-string handler of native " + string(sink) + "; the browser alone schedules and evaluates the benign bare marker expression, subject to native delay, cancellation, CSP and Trusted Types; confirmation requires the exact marker-specific page error within the bounded observation window" + storageControlCaveat
	}
	if sink == DOMSinkCreateContextualFragment {
		return how + " is parsed by " + string(sink) + "; confirmation additionally requires observed target insertion of a returned node and the marker-specific browser runtime signal; Indago never inserts the fragment" + storageControlCaveat
	}
	return how + " is assigned wholesale to " + string(sink) +
		"; an <img> with a deliberately-broken src fires its onerror handler the moment the browser parses the injected markup, referencing the benign marker" + storageControlCaveat
}
