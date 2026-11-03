package detection

// This file is the pure seven-source DOM-XSS candidate model. HTML sinks
// receive an ordered, bounded set of shapes: wholesale markup insertion
// (query-sourced document.write keeps its benign script body, because a
// decodeURI reader preserves reserved characters) and — for a value injected
// inside a quoted attribute — an attribute-breakout image whose broken src
// fires onerror. Primitive-string timers receive a bare marker expression.
// The two jQuery sinks are attribute/selector calls, not HTML parses from the
// start: a jQuery href write receives a javascript: URL (activated by one
// deterministic engine click) and a jQuery selector call receives markup that
// jQuery's own parser turns into elements. See docs/dom-xss.md for bounded
// coverage.
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

// DOMXSSSink identifies the bounded HTML, primitive-string timer and jQuery
// sinks. document.writeln shares document.write's identity. The jQuery sinks
// are the instrumented call paths, never a source-text search for "$(":
// jQuery.attr is an attribute WRITE (only href is observed) and
// jQuery.selector is a value handed to jQuery's own factory/selector parser.
// eval/Function, location/src assignment and every other jQuery method remain
// excluded; see docs/dom-xss.md.
type DOMXSSSink string

const (
	DOMSinkInnerHTML                DOMXSSSink = "innerHTML"
	DOMSinkOuterHTML                DOMXSSSink = "outerHTML"
	DOMSinkDocumentWrite            DOMXSSSink = "document.write"
	DOMSinkInsertAdjacentHTML       DOMXSSSink = "insertAdjacentHTML"
	DOMSinkCreateContextualFragment DOMXSSSink = "Range.createContextualFragment"
	DOMSinkSetTimeout               DOMXSSSink = "setTimeout"
	DOMSinkSetInterval              DOMXSSSink = "setInterval"
	// DOMSinkJQueryAttr is jQuery's Element attribute writer used for an
	// <a href> (jQuery.fn.attr("href", value)). A javascript: URL written
	// there executes only when the link is activated, so verification
	// performs one deterministic click on the exact element the harness
	// tagged. Only the href attribute of a real element is observed.
	DOMSinkJQueryAttr DOMXSSSink = "jQuery.attr"
	// DOMSinkJQuerySelector is a value handed to jQuery's factory/selector
	// call (jQuery(...)/$(...)). jQuery decides between a CSS selector and
	// HTML; a value that turns the call into markup is parsed and created.
	// Verification issues the hash change a hashchange-driven page needs,
	// then requires the same marker execution signal.
	DOMSinkJQuerySelector DOMXSSSink = "jQuery.selector"
)

// IsValid reports whether sink is one of this engine's implemented sinks.
func (s DOMXSSSink) IsValid() bool {
	switch s {
	case DOMSinkInnerHTML, DOMSinkOuterHTML, DOMSinkDocumentWrite, DOMSinkInsertAdjacentHTML, DOMSinkCreateContextualFragment, DOMSinkSetTimeout, DOMSinkSetInterval, DOMSinkJQueryAttr, DOMSinkJQuerySelector:
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

// DOMXSS candidate SHAPES. A shape is one deterministic way of turning the
// same benign marker into an executing position; each shape is an independent
// Candidate with its own DedupKey, verified by its own navigation. Only
// shapes that can be overlaid on the SAME (source, sink) sit here — a shape
// never changes the source or the sink.
const (
	// domXSSShapeMarkup is the original wholesale-insertion shape: markup
	// handed to a sink that parses it as HTML from the start.
	domXSSShapeMarkup = "markup"
	// domXSSShapeAttributeBreakout is for values that reach an HTML sink
	// inside an ALREADY-OPEN quoted attribute (for example a page that does
	// document.write('<img src="/t.gif?q='+value+'">')). No standalone tag
	// can execute there: the markup stays part of the attribute value. This
	// shape closes the enclosing double-quoted attribute and tag first, then
	// injects an image whose deliberately-broken src fires onerror. Measured
	// against current Chromium: an inline <svg onload=…> does NOT fire when
	// written/assigned this way, while <img onerror=…> does.
	domXSSShapeAttributeBreakout = "attr_breakout"
	// domXSSShapeTimerExpression is the only shape a primitive-string timer
	// can evaluate: a bare JavaScript expression.
	domXSSShapeTimerExpression = "timer_expression"
	// domXSSShapeJQueryJavascriptURL is the only shape a jQuery href
	// attribute write can execute: a javascript: URL whose body is the bare
	// marker identifier. It is inert until the link is activated, so the
	// engine performs exactly one click on the element it located.
	domXSSShapeJQueryJavascriptURL = "jquery_javascript_url"
)

// DOMXSSPayloadFor returns the PRIMARY (first) verification Candidate for a
// REACHABLE (source, sink) pair. It is the wholesale-markup shape, or the
// query-sourced document.write script body, or the bare marker expression for
// primitive-string timers. Verification code must use DOMXSSPayloadsFor so a
// value that lands inside an attribute still gets its breakout attempt; this
// function stays as the single-shape view for callers that only need one
// representative candidate.
//
// Primitive-string timer candidates contain ONLY the bare marker expression:
// native timers evaluate JavaScript, not HTML. No string-literal breakout is
// attempted. Invalid/non-identifier markers are rejected.
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
	cands := DOMXSSPayloadsFor(source, sink, marker)
	if len(cands) == 0 {
		return Candidate{}, false
	}
	return cands[0], true
}

// DOMXSSPayloadsFor returns the ordered, bounded verification Candidate set
// for a REACHABLE (source, sink) pair. Ordered most-specific-first and fully
// deterministic: HTML sinks get the wholesale-markup shape and then the
// attribute-breakout shape; primitive-string timers get exactly one shape.
// One candidate per (source, sink, shape), enforced by the shape component of
// DedupKey. Callers try them in order and stop at the first Confirmed
// execution — a reflection alone never confirms any shape.
func DOMXSSPayloadsFor(source DOMXSSSource, sink DOMXSSSink, marker string) []Candidate {
	if !sink.IsValid() || !source.IsValid() || !validDOMXSSMarker(marker) {
		return nil
	}
	if sink == DOMSinkSetTimeout || sink == DOMSinkSetInterval {
		// A timer evaluates JavaScript, not HTML.
		return []Candidate{domXSSPayloadCandidate(source, sink, domXSSShapeTimerExpression, marker, domXSSRationale(source, sink))}
	}
	if sink == DOMSinkJQueryAttr {
		// An href write only executes a javascript: URL, and only when the
		// link is activated. No markup shape belongs here: the page writes
		// the exact value we supply as the attribute value.
		return []Candidate{domXSSPayloadCandidate(source, sink, domXSSShapeJQueryJavascriptURL, "javascript:"+marker, domXSSJQueryAttrRationale(source, sink))}
	}
	if sink == DOMSinkJQuerySelector {
		// jQuery decides selector vs HTML itself. Markup is the shape that
		// makes its own parser create an element whose onerror references
		// the bare marker.
		return []Candidate{domXSSPayloadCandidate(source, sink, domXSSShapeMarkup, "<img src=x onerror="+marker+">", domXSSJQuerySelectorRationale(source, sink))}
	}
	value := "<img src=x onerror=" + marker + ">"
	if source == DOMSourceQuery && sink == DOMSinkDocumentWrite {
		// A query payload may be read via decodeURI(location.href), which
		// intentionally leaves escaped reserved slashes such as %2F intact.
		// Use a script body (no attribute equals sign) and let the query URL
		// builder keep its closing-tag slash literal for that reader.
		value = "<script>" + marker + "</script>"
	}
	return []Candidate{
		domXSSPayloadCandidate(source, sink, domXSSShapeMarkup, value, domXSSRationale(source, sink)),
		domXSSPayloadCandidate(source, sink, domXSSShapeAttributeBreakout, `"><img src=y onerror=`+marker+">", domXSSAttributeBreakoutRationale(source, sink)),
	}
}

// domXSSPayloadCandidate builds one shape's Candidate. DedupKey names the
// shape explicitly (not just its value), so "one candidate per (source, sink,
// shape)" holds by construction even if two shapes ever shared a value.
func domXSSPayloadCandidate(source DOMXSSSource, sink DOMXSSSink, shape, value, rationale string) Candidate {
	return Candidate{
		Source:     SourceBuiltin,
		Category:   CatDOMXSS,
		Context:    Context(sink),
		ContextSub: string(source),
		Value:      value,
		Trigger:    TriggerLoad,
		Rationale:  rationale,
		DedupKey:   "dom_xss\x00" + string(source) + "\x00" + string(sink) + "\x00" + shape + "\x00" + value,
	}
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

// domXSSSourceRoute describes, per source, how a verification value reaches
// the page and the exploitability caveat that applies to it.
func domXSSSourceRoute(source DOMXSSSource) (how, storageControlCaveat string) {
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
	return how, storageControlCaveat
}

// domXSSRationale explains, per source, how the verification candidate's
// value is expected to reach sink — each source has a genuinely different
// client-side read, worth spelling out distinctly rather than a single
// generic sentence.
func domXSSRationale(source DOMXSSSource, sink DOMXSSSink) string {
	how, storageControlCaveat := domXSSSourceRoute(source)
	if sink == DOMSinkSetTimeout || sink == DOMSinkSetInterval {
		return how + " reaches the primitive-string handler of native " + string(sink) + "; the browser alone schedules and evaluates the benign bare marker expression, subject to native delay, cancellation, CSP and Trusted Types; confirmation requires the exact marker-specific page error within the bounded observation window" + storageControlCaveat
	}
	if source == DOMSourceQuery && sink == DOMSinkDocumentWrite {
		return how + " reaches " + string(sink) + "; the verification uses a benign script element containing only the marker because decodeURI preserves encoded reserved slashes and document.write may wrap the value inside option/select markup" + storageControlCaveat
	}
	if sink == DOMSinkCreateContextualFragment {
		return how + " is parsed by " + string(sink) + "; confirmation additionally requires observed target insertion of a returned node and the marker-specific browser runtime signal; Indago never inserts the fragment" + storageControlCaveat
	}
	return how + " is assigned wholesale to " + string(sink) +
		"; an <img> with a deliberately-broken src fires its onerror handler the moment the browser parses the injected markup, referencing the benign marker" + storageControlCaveat
}

// domXSSAttributeBreakoutRationale explains the second, attribute-context
// shape: the same source reaches the same sink, but the page places the value
// inside a quoted HTML attribute (or an equivalent document.write template),
// where no standalone tag can execute. It states explicitly that confirmation
// still comes from the browser's marker-specific execution signal.
func domXSSAttributeBreakoutRationale(source DOMXSSSource, sink DOMXSSSink) string {
	how, storageControlCaveat := domXSSSourceRoute(source)
	return how + " reaches " + string(sink) + " inside an already-open quoted HTML attribute (for example an img src or document.write template, where the value cannot start its own tag); this shape first closes that attribute and the enclosing tag, then injects an <img> whose deliberately-broken src fires onerror referencing the benign marker; confirmation still requires the browser's own marker-specific execution signal, never the reflection alone" + storageControlCaveat
}

// domXSSJQueryAttrRationale explains the javascript: URL shape for a jQuery
// href attribute write. The value is inert until the link is activated, so the
// engine's one deterministic click is part of verification; the verdict is
// still the marker-specific browser execution signal, never the attribute
// value itself.
func domXSSJQueryAttrRationale(source DOMXSSSource, sink DOMXSSSink) string {
	how, storageControlCaveat := domXSSSourceRoute(source)
	return how + " is written by jQuery through " + string(sink) + " into the href attribute of an anchor element; only a javascript: URL executes from that position, and only after the link is activated, so verification performs one deterministic activation click on the exact element the harness located and then requires the browser's own marker-specific execution signal (the bare marker identifier evaluated by the javascript: URL), never the attribute value or a reflection alone" + storageControlCaveat
}

// domXSSJQuerySelectorRationale explains the markup shape for a value handed
// to jQuery's factory/selector call. jQuery itself decides selector vs HTML;
// a hashchange-driven page needs the engine's bounded hash-change activation
// before its own handler runs. The verdict is the marker-specific browser
// execution signal.
func domXSSJQuerySelectorRationale(source DOMXSSSource, sink DOMXSSSink) string {
	how, storageControlCaveat := domXSSSourceRoute(source)
	return how + " is handed to jQuery's factory/selector call through " + string(sink) + "; jQuery parses a value that turns that call into markup and creates an element whose deliberately-broken src fires onerror referencing the benign marker, so a hashchange-driven page needs the engine's one bounded hash-change activation before its own handler runs; confirmation still requires the browser's own marker-specific execution signal, never the reflection alone" + storageControlCaveat
}
