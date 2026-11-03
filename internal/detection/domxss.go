package detection

import (
	"fmt"
	"strconv"
	"strings"
)

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
	// DOMSinkAngularExpression is AngularJS's text-node interpolation: a
	// value placed where Angular compiles a {{...}} expression, which Angular
	// evaluates and writes back into the text node. It is NOT an HTML sink
	// (nothing is parsed as markup) and NOT a JavaScript-identifier sink: an
	// unknown identifier inside an Angular expression resolves to undefined
	// rather than throwing, so confirmation comes from the evaluated RESULT
	// appearing in rendered text, never from a ReferenceError. Only the
	// classic double-brace interpolation is covered; attribute-expression
	// injection (ng-focus="…" and friends), sandbox escapes and $eval/ng-bind-html
	// chains are out of scope (see docs/dom-xss.md).
	DOMSinkAngularExpression DOMXSSSink = "angular_expression"
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
	case DOMSinkInnerHTML, DOMSinkOuterHTML, DOMSinkDocumentWrite, DOMSinkInsertAdjacentHTML, DOMSinkCreateContextualFragment, DOMSinkSetTimeout, DOMSinkSetInterval, DOMSinkJQueryAttr, DOMSinkJQuerySelector, DOMSinkAngularExpression:
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
	// domXSSShapeAngularInterpolation is the only shape Angular's text-node
	// compiler accepts: a double-brace interpolation. The expression has no
	// side effect at all — it concatenates two string literals into the
	// benign marker identifier — so compiling it is the test, not a payload.
	domXSSShapeAngularInterpolation = "angular_interpolation"
)

// domXSSAngularInterpolation builds the {{...}} candidate for marker. The
// marker is split in half and reassembled by the expression itself:
//
//	marker = "MARKERTOKEN"  ->  {{'MARKER' + 'TOKEN' + ($id ? '' : '')}}
//
// This is the marker-specificity property the sink relies on: the candidate
// bytes never contain the contiguous marker, so the contiguous marker
// appearing in a rendered text node can only be the RESULT of Angular
// evaluating the expression. A page that merely echoes the source (server
// side or via textContent/innerHTML) keeps the literal, quotes and braces
// included, and therefore cannot produce it.
//
// The trailing ($id ? … : …) reads Angular's always-present per-scope $id and
// appends the empty string either way, so the result is still exactly the
// marker. It is there because an expression made only of string literals is
// compile-time-constant: Angular can fold it without its dynamic evaluator,
// which would let a CSP that forbids eval still render the result. Referencing
// a scope value forces Angular's real expression compiler to run at execution
// time — so a document whose CSP refuses dynamic evaluation genuinely blocks
// this candidate, which is what makes the csp_blocked outcome observable
// instead of silently Confirmed. It is a scope property read, not a sandbox
// escape and not a side effect.
//
// The result is a text node, not a ReferenceError: Angular resolves an
// unknown identifier to undefined instead of throwing, so a bare identifier
// would render as "undefined" — indistinguishable from ordinary text — and
// could never be a marker-specific signal. A short marker is refused because
// splitting it would produce meaningless fragments.
func domXSSAngularInterpolation(marker string) (string, bool) {
	if marker == "" {
		return "", false
	}
	if len(marker) < 4 {
		return "", false
	}
	cut := len(marker) / 2
	return "{{'" + marker[:cut] + "' + '" + marker[cut:] + "' + ($id ? '' : '')}}", true
}

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
	if sink == DOMSinkAngularExpression {
		// Angular evaluates the interpolation expression and writes the
		// result into the text node; the split-literal construction is what
		// makes the observed result marker-specific.
		value, ok := domXSSAngularInterpolation(marker)
		if !ok {
			return nil
		}
		return []Candidate{domXSSPayloadCandidate(source, sink, domXSSShapeAngularInterpolation, value, domXSSAngularRationale(source, sink))}
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

// ---------------------------------------------------------------------------
// Bounded static data-flow approximation: source -> variable -> argument -> sink
// ---------------------------------------------------------------------------
//
// Reachability is decided by the browser, not here: the init-script harness
// reports whenever a hooked sink receives a value containing the probe marker,
// so a value that travels through a local variable, a function argument or
// string concatenation is observed exactly like an inline one. This pass is a
// second, purely textual opinion used for DIAGNOSTICS: after a page reported no
// sink, it separates "the analysed inline scripts contain no tainted path"
// from "there is a path this bounded analysis cannot resolve", so an unknown is
// never reported as a negative.
//
// It is not a JavaScript interpreter and never produces a verdict. The
// supported flow shapes, and the point where support stops, are:
//
//	1. a source read bound to a local variable (var/let/const, plain
//	   assignment), including URLSearchParams(...).get(name) and the
//	   location.search / location.hash / window.name / document.referrer /
//	   localStorage / sessionStorage / event.data idioms;
//	2. exactly ONE user-defined function boundary (DOMXSSStaticMaxDepth = 1):
//	   a tainted argument reaching a parameter, or a function returning a
//	   tainted value;
//	3. `+` concatenation and template-literal interpolation of those.
//
// Everything else is reported as an explicit unresolved flow rather than
// silently guessed: a dynamically computed callee
// (window['docu'+'ment']['write'](x)), eval/Function fed with tainted data, a
// tainted value crossing a second user-defined function, a tainted value handed
// to a function whose body is not in the analysed inline scripts, a tainted
// value written through a computed property, and any script this pass could not
// tokenize or parse. Escaping/sanitisation is NOT modelled: a value passed
// through .replace()/encodeURIComponent() still counts as tainted here, so a
// tainted path is a structural statement about where the value came from, never
// a claim that the sink executes. The browser's marker execution remains the
// only confirmation signal (AGENTS.md §2.6 / §3).

// DOMXSSFlowOutcome classifies one static analysis run over a page's inline
// scripts.
type DOMXSSFlowOutcome string

const (
	// DOMXSSFlowTainted means a value derived from the analysed source reaches
	// an implemented sink call through one of the supported flow shapes. It is
	// NOT a confirmation: the value may still be escaped, the sink may not
	// execute, and only the browser's marker signal can confirm execution.
	DOMXSSFlowTainted DOMXSSFlowOutcome = "tainted_path"
	// DOMXSSFlowNoTaintedPath means the analysed inline scripts contain no
	// supported tainted path into an implemented sink. External scripts are not
	// analysed (see DOMXSSStaticResult.ExternalScripts), so this is never a
	// statement about the whole page.
	DOMXSSFlowNoTaintedPath DOMXSSFlowOutcome = "no_tainted_path"
	// DOMXSSFlowUnresolved means the pass met a construct it cannot resolve, or
	// could not tokenize/parse part of the page. The honest reading is "flow
	// unknown", never "reachable" or "not reachable".
	DOMXSSFlowUnresolved DOMXSSFlowOutcome = "unresolved_flow"
)

// DOMXSSStaticMaxDepth is the number of user-defined function boundaries a
// tainted value may cross. One is enough for the class this engine targets (a
// value handed to a single helper that writes it into a sink) and is the hard
// bound: passing tainted data into a second user-defined function is reported
// as DOMXSSFlowUnresolved rather than followed.
const DOMXSSStaticMaxDepth = 1

// DOMXSSFlowSite is one sink call the static pass proved reachable from the
// analysed source.
type DOMXSSFlowSite struct {
	Sink DOMXSSSink
	// Line is the 1-based line in the analysed page where the sink call or
	// assignment appears.
	Line int
	// Hops is the number of user-defined function boundaries the tainted value
	// crossed before reaching the sink (0..DOMXSSStaticMaxDepth).
	Hops int
	// Chain is the short, human-readable provenance of the value: source read,
	// variable/argument names, then the sink. Evidence for the operator, not a
	// proof.
	Chain []string
}

// DOMXSSUnresolvedFlow is one construct the bounded pass could not resolve. It
// exists so an unknown is recorded explicitly instead of being folded into a
// negative.
type DOMXSSUnresolvedFlow struct {
	Line   int
	Reason string
	Detail string
}

// DOMXSSStaticResult is the bounded static analysis of one page for one
// (source, selector) pair.
type DOMXSSStaticResult struct {
	Outcome DOMXSSFlowOutcome
	Sites   []DOMXSSFlowSite
	// Unresolved lists every construct that defeated the pass. It is populated
	// even when Outcome is DOMXSSFlowTainted: sites prove what the pass could
	// see, Unresolved says what it could not.
	Unresolved []DOMXSSUnresolvedFlow
	// ExternalScripts counts <script src=...> elements, whose bodies are not
	// part of the page HTML and therefore not analysed.
	ExternalScripts int
	Notes           []string
}

// DOMXSSStaticReachability runs the bounded static pass over pageHTML for one
// client-side source and its selector (a query/fragment-route parameter name, a
// storage key, or "" where the source has no selector).
//
// The result is advisory only. It never confirms or rejects a finding; the
// browser's own marker signal is the only verdict authority.
func DOMXSSStaticReachability(pageHTML string, source DOMXSSSource, selector string) DOMXSSStaticResult {
	res := DOMXSSStaticResult{}
	if !source.IsValid() {
		res.Outcome = DOMXSSFlowUnresolved
		res.Notes = append(res.Notes, "unsupported DOM-XSS source "+string(source))
		return res
	}

	scripts, external := dxsInlineScripts(pageHTML)
	res.ExternalScripts = external
	if external > 0 {
		res.Notes = append(res.Notes, fmt.Sprintf("%d external <script src=...> element(s) were not analysed; this pass only sees inline script bodies", external))
	}

	in := &dxsInterp{
		source:    source,
		selector:  selector,
		env:       &dxsEnv{},
		funcs:     map[string]*dxsFunc{},
		active:    map[*dxsFunc]int{},
		siteSeen:  map[string]bool{},
		unresSeen: map[string]bool{},
		budget:    dxsAnalysisBudget,
	}
	in.env.push()

	var gaps []DOMXSSUnresolvedFlow
	for _, script := range scripts {
		toks, err := dxsTokenize(script.body, script.line)
		if err != nil {
			gaps = append(gaps, DOMXSSUnresolvedFlow{Line: script.line, Reason: "unparsed script", Detail: "the inline script could not be tokenized: " + err.Error()})
			continue
		}
		p := &dxsParser{toks: toks}
		prog := p.parseProgram()
		for _, g := range p.gaps {
			gaps = append(gaps, DOMXSSUnresolvedFlow{Line: g.line, Reason: "unparsed script", Detail: g.msg})
		}
		dxsCollectFuncs(prog, in.funcs)
		in.execStmt(prog)
	}

	res.Sites = in.sites
	res.Unresolved = in.unresolved
	res.Unresolved = append(res.Unresolved, gaps...)
	if in.exhausted {
		res.Unresolved = append(res.Unresolved, DOMXSSUnresolvedFlow{Reason: "analysis budget exhausted", Detail: fmt.Sprintf("the pass stopped after %d evaluation steps; the remainder of the inline scripts was not analysed", dxsAnalysisBudget)})
	}
	res.Unresolved = dxsLimitUnresolved(res.Unresolved, &res.Notes)

	switch {
	case len(res.Sites) > 0:
		res.Outcome = DOMXSSFlowTainted
	case len(res.Unresolved) > 0:
		res.Outcome = DOMXSSFlowUnresolved
	default:
		res.Outcome = DOMXSSFlowNoTaintedPath
	}
	return res
}

// dxsLimitUnresolved bounds the diagnostic list so one messy page cannot flood
// a report, and says so in Notes.
func dxsLimitUnresolved(in []DOMXSSUnresolvedFlow, notes *[]string) []DOMXSSUnresolvedFlow {
	const limit = 16
	if len(in) <= limit {
		return in
	}
	*notes = append(*notes, fmt.Sprintf("%d unresolved-flow entries were found; only the first %d are recorded", len(in), limit))
	return in[:limit]
}

// ---------------------------------------------------------------------------
// Inline <script> extraction
// ---------------------------------------------------------------------------

type dxsScript struct {
	body string
	line int // 1-based line of the first body character in the page
}

// dxsInlineScripts returns the bodies of executable inline <script> elements
// and counts <script src=...> elements. It is an HTML fragment scanner, not a
// parser: it only needs the script boundaries, and it deliberately skips
// non-JavaScript type attributes so a data block is not fed to the tokenizer.
func dxsInlineScripts(html string) ([]dxsScript, int) {
	var out []dxsScript
	external := 0
	for i := 0; i < len(html); {
		rel := dxsIndexFold(html, "<script", i)
		if rel < 0 {
			break
		}
		start := rel
		after := start + len("<script")
		if after < len(html) {
			c := html[after]
			if !(c == '>' || c == '/' || c == ' ' || c == '	' || c == '\n' || c == '\r') {
				i = after
				continue
			}
		}
		gt := strings.IndexByte(html[after:], '>')
		if gt < 0 {
			break
		}
		attrs := strings.ToLower(html[after : after+gt])
		bodyStart := after + gt + 1
		end := dxsIndexFold(html, "</script", bodyStart)
		if end >= 0 {
			end -= bodyStart
		}
		if end < 0 {
			break // an unterminated script element is malformed HTML: no body to analyse
		}
		body := html[bodyStart : bodyStart+end]
		if dxsHasAttr(attrs, "src") {
			external++
		} else if dxsIsJavaScriptType(attrs) {
			line := 1 + strings.Count(html[:bodyStart], "\n")
			out = append(out, dxsScript{body: body, line: line})
		}
		i = bodyStart + end + len("</script")
	}
	return out, external
}

// dxsIndexFold finds sub in s starting at from, comparing ASCII case
// insensitively WITHOUT rewriting the string: strings.ToLower can change byte
// length on non-ASCII input and would misalign every later index.
func dxsIndexFold(s, sub string, from int) int {
	n := len(sub)
	if n == 0 {
		return from
	}
	for i := from; i+n <= len(s); i++ {
		ok := true
		for j := 0; j < n; j++ {
			a, b := s[i+j], sub[j]
			if a >= 'A' && a <= 'Z' {
				a += 'a' - 'A'
			}
			if b >= 'A' && b <= 'Z' {
				b += 'a' - 'A'
			}
			if a != b {
				ok = false
				break
			}
		}
		if ok {
			return i
		}
	}
	return -1
}

// dxsHasAttr reports whether an attribute list contains name as an attribute
// (not as a substring of another attribute's value).
func dxsHasAttr(attrs, name string) bool {
	for _, field := range strings.FieldsFunc(attrs, func(r rune) bool { return r == ' ' || r == '	' || r == '\n' || r == '\r' }) {
		if field == name || strings.HasPrefix(field, name+"=") {
			return true
		}
	}
	return false
}

// dxsIsJavaScriptType accepts an absent type and the JavaScript MIME types. A
// script with a data type (application/json, text/template) is not executable
// code and is skipped.
func dxsIsJavaScriptType(attrs string) bool {
	typ := ""
	for _, field := range strings.Fields(attrs) {
		if strings.HasPrefix(field, "type=") {
			typ = strings.Trim(strings.TrimPrefix(field, "type="), `"'`)
		}
	}
	switch typ {
	case "", "text/javascript", "application/javascript", "application/x-javascript", "text/ecmascript", "application/ecmascript", "module":
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// Tokenizer (bounded JavaScript lexer)
// ---------------------------------------------------------------------------

type dxsTokKind uint8

const (
	dxsTokEOF dxsTokKind = iota
	dxsTokIdent
	dxsTokNumber
	dxsTokString
	dxsTokPunct
	dxsTokRegex
	dxsTokTemplateStart
	dxsTokTemplateText
	dxsTokTemplateExprStart
	dxsTokTemplateExprEnd
	dxsTokTemplateEnd
)

type dxsTok struct {
	kind dxsTokKind
	text string
	line int
}

type dxsTmplCtx struct {
	inExpr bool
	braces int
}

type dxsScanner struct {
	src  string
	i    int
	line int
	toks []dxsTok
	tmpl []dxsTmplCtx
	prev dxsTok
}

// dxsAnalysisBudget bounds one page's evaluation so a pathological script
// cannot hold a scan worker. Exhausting it is reported as unresolved, never as
// a negative.
const dxsAnalysisBudget = 200000

var dxsPuncts = []string{
	">>>=", "===", "!==", "**=", "<<=", ">>=", "&&=", "||=", "??=", "...",
	">>>", "==", "!=", "<=", ">=", "&&", "||", "??", "?.", "**", "++", "--",
	"+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<", ">>", "=>", "??",
}

func dxsTokenize(src string, baseLine int) ([]dxsTok, error) {
	s := &dxsScanner{src: src, line: baseLine}
	if err := s.run(); err != nil {
		return s.toks, err
	}
	return s.toks, nil
}

func (s *dxsScanner) emit(kind dxsTokKind, text string) {
	t := dxsTok{kind: kind, text: text, line: s.line}
	s.toks = append(s.toks, t)
	s.prev = t
}

func (s *dxsScanner) run() error {
	for s.i < len(s.src) {
		if n := len(s.tmpl); n > 0 && !s.tmpl[n-1].inExpr {
			if err := s.templateText(); err != nil {
				return err
			}
			continue
		}
		c := s.src[s.i]
		switch {
		case c == '\n':
			s.line++
			s.i++
		case c == ' ' || c == '	' || c == '\r' || c == '\f' || c == '\v':
			s.i++
		case c == '/' && s.i+1 < len(s.src) && s.src[s.i+1] == '/':
			for s.i < len(s.src) && s.src[s.i] != '\n' {
				s.i++
			}
		case c == '/' && s.i+1 < len(s.src) && s.src[s.i+1] == '*':
			s.i += 2
			for s.i+1 < len(s.src) && !(s.src[s.i] == '*' && s.src[s.i+1] == '/') {
				if s.src[s.i] == '\n' {
					s.line++
				}
				s.i++
			}
			if s.i+1 >= len(s.src) {
				return fmt.Errorf("unterminated block comment")
			}
			s.i += 2
		case c == '\'' || c == '"':
			if err := s.stringLit(c); err != nil {
				return err
			}
		case c == '`':
			s.i++
			s.emit(dxsTokTemplateStart, "`")
			s.tmpl = append(s.tmpl, dxsTmplCtx{})
		case c == '}' && len(s.tmpl) > 0:
			top := &s.tmpl[len(s.tmpl)-1]
			if top.inExpr && top.braces == 0 {
				s.i++
				s.emit(dxsTokTemplateExprEnd, "}")
				top.inExpr = false
				continue
			}
			if top.inExpr {
				top.braces--
			}
			s.i++
			s.emit(dxsTokPunct, "}")
		case c == '{' && len(s.tmpl) > 0:
			top := &s.tmpl[len(s.tmpl)-1]
			if top.inExpr {
				top.braces++
			}
			s.i++
			s.emit(dxsTokPunct, "{")
		case dxsIdentStart(c):
			start := s.i
			for s.i < len(s.src) && dxsIdentPart(s.src[s.i]) {
				s.i++
			}
			s.emit(dxsTokIdent, s.src[start:s.i])
		case c >= '0' && c <= '9' || c == '.' && s.i+1 < len(s.src) && s.src[s.i+1] >= '0' && s.src[s.i+1] <= '9':
			start := s.i
			s.i++
			for s.i < len(s.src) {
				d := s.src[s.i]
				if d >= '0' && d <= '9' || d == '.' || d == 'x' || d == 'X' || d == 'e' || d == 'E' || d == '_' ||
					(d == '+' || d == '-') && s.i > start && (s.src[s.i-1] == 'e' || s.src[s.i-1] == 'E') {
					s.i++
					continue
				}
				break
			}
			s.emit(dxsTokNumber, s.src[start:s.i])
		case c == '/' && s.regexAllowed():
			if err := s.regexLit(); err != nil {
				return err
			}
		default:
			op := ""
			for _, cand := range dxsPuncts {
				if strings.HasPrefix(s.src[s.i:], cand) {
					op = cand
					break
				}
			}
			if op == "" {
				op = string(c)
			}
			s.i += len(op)
			s.emit(dxsTokPunct, op)
		}
	}
	return nil
}

func dxsIdentStart(c byte) bool {
	return c == '_' || c == '$' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= 0x80
}

func dxsIdentPart(c byte) bool {
	return dxsIdentStart(c) || c >= '0' && c <= '9'
}

func (s *dxsScanner) stringLit(quote byte) error {
	s.i++
	var b strings.Builder
	for s.i < len(s.src) {
		c := s.src[s.i]
		switch {
		case c == '\\':
			if s.i+1 >= len(s.src) {
				s.i++
				continue
			}
			b.WriteByte(dxsUnescapeByte(s.src[s.i+1]))
			s.i += 2
		case c == quote:
			s.i++
			s.emit(dxsTokString, b.String())
			return nil
		case c == '\n':
			return fmt.Errorf("unterminated string literal at line %d", s.line)
		default:
			b.WriteByte(c)
			s.i++
		}
	}
	return fmt.Errorf("unterminated string literal at line %d", s.line)
}

func dxsUnescapeByte(c byte) byte {
	switch c {
	case 'n':
		return '\n'
	case 'r':
		return '\r'
	case 't':
		return '	'
	case 'b':
		return '\b'
	case 'f':
		return '\f'
	default:
		return c
	}
}

// regexAllowed is the standard lexer heuristic: a slash starts a regular
// expression unless the previous token can end an expression.
func (s *dxsScanner) regexAllowed() bool {
	switch s.prev.kind {
	case dxsTokEOF:
		return true
	case dxsTokPunct:
		switch s.prev.text {
		case ")", "]", "}", "++", "--":
			return false
		}
		return true
	case dxsTokIdent:
		switch s.prev.text {
		case "return", "typeof", "instanceof", "in", "of", "new", "delete", "void", "throw", "case", "do", "else", "yield", "await":
			return true
		}
		return false
	}
	return false
}

func (s *dxsScanner) regexLit() error {
	start := s.i
	s.i++
	inClass := false
	for s.i < len(s.src) {
		c := s.src[s.i]
		switch {
		case c == '\\':
			s.i += 2
			continue
		case c == '[':
			inClass = true
		case c == ']':
			inClass = false
		case c == '/' && !inClass:
			s.i++
			for s.i < len(s.src) && dxsIdentPart(s.src[s.i]) {
				s.i++
			}
			s.emit(dxsTokRegex, s.src[start:s.i])
			return nil
		case c == '\n':
			return fmt.Errorf("unterminated regular expression at line %d", s.line)
		}
		s.i++
	}
	return fmt.Errorf("unterminated regular expression at line %d", s.line)
}

func (s *dxsScanner) templateText() error {
	start := s.i
	for s.i < len(s.src) {
		switch {
		case s.src[s.i] == '\\':
			s.i += 2
			continue
		case s.src[s.i] == '`':
			if s.i > start {
				s.emit(dxsTokTemplateText, s.src[start:s.i])
			}
			s.i++
			s.emit(dxsTokTemplateEnd, "`")
			s.tmpl = s.tmpl[:len(s.tmpl)-1]
			return nil
		case s.src[s.i] == '$' && s.i+1 < len(s.src) && s.src[s.i+1] == '{':
			if s.i > start {
				s.emit(dxsTokTemplateText, s.src[start:s.i])
			}
			s.i += 2
			s.emit(dxsTokTemplateExprStart, "${")
			s.tmpl[len(s.tmpl)-1].inExpr = true
			return nil
		case s.src[s.i] == '\n':
			s.line++
		}
		s.i++
	}
	return fmt.Errorf("unterminated template literal at line %d", s.line)
}

// ---------------------------------------------------------------------------
// Bounded syntax tree
// ---------------------------------------------------------------------------
//
// The tree is intentionally small: it models expressions, variable bindings,
// blocks, if/loop/try bodies and function literals, which is everything the
// taint pass needs. Object/array literals keep statically named properties so a
// tainted value stored as { q: x }.q is followed without tainting the whole
// object.

type dxsExprKind uint8

const (
	dxsExprIdent dxsExprKind = iota
	dxsExprString
	dxsExprNumber
	dxsExprTemplate
	dxsExprArray
	dxsExprObject
	dxsExprMember // obj.text (computed=false) or obj[kids[0]] (computed=true)
	dxsExprCall   // obj(args...), isNew for `new obj(...)`
	dxsExprBinary
	dxsExprUnary
	dxsExprAssign // kids[0] = target, kids[1] = value; text is the operator
	dxsExprCond   // kids[0] ? kids[1] : kids[2]
	dxsExprSeq
	dxsExprFunc
)

type dxsExpr struct {
	kind     dxsExprKind
	line     int
	text     string // identifier name, string literal value, operator, member name
	kids     []*dxsExpr
	names    []string // object literal property names, parallel to kids
	obj      *dxsExpr
	args     []*dxsExpr
	computed bool
	isNew    bool
	fn       *dxsFunc
}

type dxsStmtKind uint8

const (
	dxsStmtBlock dxsStmtKind = iota
	dxsStmtVar
	dxsStmtExpr
	dxsStmtIf
	dxsStmtLoop
	dxsStmtReturn
	dxsStmtFuncDecl
	dxsStmtTry
	dxsStmtEmpty
)

// dxsStmt uses one struct for every statement kind. Field meaning per kind:
//
//	Block    stmts
//	Var      names[i] = exprs[i] (either may be nil for a bare declaration)
//	Expr     exprs[0]
//	If       exprs[0] = condition, block = then, elseStmt = else
//	Loop     stmts = initializer statements, exprs = condition/update, block = body
//	Return   exprs[0] (optional)
//	FuncDecl names[0] = function name, fn = body
//	Try      stmts = [body, catch, finally], names[0] = catch parameter
type dxsStmt struct {
	kind     dxsStmtKind
	line     int
	stmts    []*dxsStmt
	names    []string
	exprs    []*dxsExpr
	block    *dxsStmt
	elseStmt *dxsStmt
	fn       *dxsFunc
}

type dxsFunc struct {
	params []string
	body   *dxsStmt
	line   int
}

type dxsParseGap struct {
	line int
	msg  string
}

type dxsParser struct {
	toks []dxsTok
	pos  int
	gaps []dxsParseGap
}

func (p *dxsParser) peek() dxsTok {
	if p.pos >= len(p.toks) {
		return dxsTok{kind: dxsTokEOF}
	}
	return p.toks[p.pos]
}

func (p *dxsParser) next() dxsTok {
	t := p.peek()
	if p.pos < len(p.toks) {
		p.pos++
	}
	return t
}

func (p *dxsParser) eof() bool { return p.pos >= len(p.toks) || p.peek().kind == dxsTokEOF }

func (p *dxsParser) is(s string) bool {
	t := p.peek()
	return t.kind == dxsTokPunct && t.text == s
}

func (p *dxsParser) isIdent(s string) bool {
	t := p.peek()
	return t.kind == dxsTokIdent && t.text == s
}

func (p *dxsParser) gap(t dxsTok, msg string) {
	if len(p.gaps) < 32 {
		p.gaps = append(p.gaps, dxsParseGap{line: t.line, msg: msg})
	}
}

func (p *dxsParser) parseProgram() *dxsStmt {
	blk := &dxsStmt{kind: dxsStmtBlock}
	for !p.eof() {
		before := p.pos
		if st := p.parseStatement(); st != nil {
			blk.stmts = append(blk.stmts, st)
		}
		if p.pos == before {
			p.next()
		}
	}
	return blk
}

func (p *dxsParser) parseBlock() *dxsStmt {
	st := &dxsStmt{kind: dxsStmtBlock, line: p.peek().line}
	if !p.is("{") {
		return st
	}
	p.next()
	for !p.eof() && !p.is("}") {
		before := p.pos
		if s := p.parseStatement(); s != nil {
			st.stmts = append(st.stmts, s)
		}
		if p.pos == before {
			p.next()
		}
	}
	if p.is("}") {
		p.next()
	}
	return st
}

func (p *dxsParser) parseStatement() *dxsStmt {
	t := p.peek()
	if t.kind == dxsTokEOF {
		return nil
	}
	if t.kind == dxsTokPunct {
		switch t.text {
		case ";":
			p.next()
			return &dxsStmt{kind: dxsStmtEmpty, line: t.line}
		case "{":
			return p.parseBlock()
		}
	}
	if t.kind == dxsTokIdent {
		switch t.text {
		case "var", "let", "const":
			return p.parseVarStmt(true)
		case "function":
			return p.parseFuncDecl()
		case "if":
			return p.parseIf()
		case "for", "while":
			return p.parseLoop()
		case "do":
			return p.parseDo()
		case "return":
			p.next()
			st := &dxsStmt{kind: dxsStmtReturn, line: t.line}
			if !p.is(";") && !p.is("}") && !p.eof() {
				st.exprs = []*dxsExpr{p.parseExpr()}
			}
			p.endStatement()
			return st
		case "try":
			return p.parseTry()
		case "switch":
			return p.parseSwitch()
		case "break", "continue", "debugger":
			p.next()
			p.endStatement()
			return &dxsStmt{kind: dxsStmtEmpty, line: t.line}
		case "case", "default":
			p.skipUntilPunct(":")
			return &dxsStmt{kind: dxsStmtEmpty, line: t.line}
		}
		if p.pos+1 < len(p.toks) && p.toks[p.pos+1].kind == dxsTokPunct && p.toks[p.pos+1].text == ":" {
			p.next()
			p.next()
			return p.parseStatement()
		}
	}
	line := t.line
	x := p.parseExpr()
	p.endStatement()
	if x == nil {
		return nil
	}
	return &dxsStmt{kind: dxsStmtExpr, line: line, exprs: []*dxsExpr{x}}
}

// endStatement consumes a statement terminator, or records a gap and skips to
// a boundary so the rest of the script is still analysed.
func (p *dxsParser) endStatement() {
	if p.is(";") {
		p.next()
		return
	}
	if p.eof() || p.is("}") {
		return
	}
	p.gap(p.peek(), "unparsed statement tail near "+strconv.Quote(p.peek().text))
	for !p.eof() && !p.is(";") && !p.is("}") {
		p.next()
	}
	if p.is(";") {
		p.next()
	}
}

func (p *dxsParser) parseVarStmt(semi bool) *dxsStmt {
	st := &dxsStmt{kind: dxsStmtVar, line: p.peek().line}
	p.next() // var / let / const
	for !p.eof() {
		if p.peek().kind == dxsTokIdent {
			name := p.next().text
			var v *dxsExpr
			if p.is("=") {
				p.next()
				v = p.parseAssign()
			}
			st.names = append(st.names, name)
			st.exprs = append(st.exprs, v)
		} else if p.is("{") || p.is("[") {
			names := p.parsePattern()
			var v *dxsExpr
			if p.is("=") {
				p.next()
				v = p.parseAssign()
			}
			for _, n := range names {
				st.names = append(st.names, n)
				st.exprs = append(st.exprs, v)
			}
		} else {
			break
		}
		if p.is(",") {
			p.next()
			continue
		}
		break
	}
	if semi {
		p.endStatement()
	}
	return st
}

// parsePattern skips a destructuring pattern and returns the names it binds.
func (p *dxsParser) parsePattern() []string {
	var names []string
	open := p.peek().text
	close := "}"
	if open == "[" {
		close = "]"
	}
	depth := 0
	for !p.eof() {
		t := p.next()
		switch {
		case t.kind == dxsTokPunct && t.text == open:
			depth++
		case t.kind == dxsTokPunct && t.text == close:
			depth--
			if depth == 0 {
				return names
			}
		case t.kind == dxsTokIdent && depth > 0:
			nxt := p.peek()
			if nxt.kind == dxsTokPunct && nxt.text == ":" {
				continue // property key, not a binding
			}
			names = append(names, t.text)
		}
	}
	return names
}

func (p *dxsParser) parseFuncDecl() *dxsStmt {
	line := p.peek().line
	p.next() // function
	name := ""
	if p.peek().kind == dxsTokIdent {
		name = p.next().text
	}
	fn := p.parseFuncRest(line)
	return &dxsStmt{kind: dxsStmtFuncDecl, line: line, names: []string{name}, fn: fn}
}

func (p *dxsParser) parseFuncRest(line int) *dxsFunc {
	fn := &dxsFunc{line: line}
	if p.is("(") {
		p.next()
		for !p.eof() && !p.is(")") {
			switch {
			case p.is("..."):
				p.next()
			case p.peek().kind == dxsTokIdent:
				fn.params = append(fn.params, p.next().text)
				if p.is("=") {
					p.next()
					p.parseAssign()
				}
			case p.is("{") || p.is("["):
				fn.params = append(fn.params, p.parsePattern()...)
			default:
				p.next()
			}
			if p.is(",") {
				p.next()
			}
		}
		if p.is(")") {
			p.next()
		}
	}
	switch {
	case p.is("{"):
		fn.body = p.parseBlock()
	case p.is("=>"):
		p.next()
		fn.body = p.parseArrowBody()
	default:
		p.gap(p.peek(), "function without a body")
	}
	return fn
}

func (p *dxsParser) parseArrowBody() *dxsStmt {
	if p.is("{") {
		return p.parseBlock()
	}
	line := p.peek().line
	return &dxsStmt{kind: dxsStmtBlock, line: line, stmts: []*dxsStmt{{kind: dxsStmtReturn, line: line, exprs: []*dxsExpr{p.parseAssign()}}}}
}

func (p *dxsParser) parseIf() *dxsStmt {
	st := &dxsStmt{kind: dxsStmtIf, line: p.peek().line}
	p.next() // if
	if p.is("(") {
		p.next()
		st.exprs = []*dxsExpr{p.parseExpr()}
		if p.is(")") {
			p.next()
		}
	}
	st.block = p.parseStatement()
	if p.isIdent("else") {
		p.next()
		st.elseStmt = p.parseStatement()
	}
	return st
}

func (p *dxsParser) parseLoop() *dxsStmt {
	st := &dxsStmt{kind: dxsStmtLoop, line: p.peek().line}
	p.next() // for / while
	if p.is("(") {
		p.next()
		if p.peek().kind == dxsTokIdent && (p.peek().text == "var" || p.peek().text == "let" || p.peek().text == "const") {
			st.stmts = append(st.stmts, p.parseVarStmt(false))
			if p.isIdent("of") || p.isIdent("in") {
				p.next()
				st.exprs = append(st.exprs, p.parseExpr())
			}
		} else if !p.is(";") {
			st.exprs = append(st.exprs, p.parseExpr())
		}
		if p.is(";") {
			p.next()
			if !p.is(";") && !p.is(")") {
				st.exprs = append(st.exprs, p.parseExpr())
			}
			if p.is(";") {
				p.next()
			}
			if !p.is(")") {
				st.exprs = append(st.exprs, p.parseExpr())
			}
		}
		if p.is(")") {
			p.next()
		}
	}
	st.block = p.parseStatement()
	return st
}

func (p *dxsParser) parseDo() *dxsStmt {
	st := &dxsStmt{kind: dxsStmtLoop, line: p.peek().line}
	p.next() // do
	st.block = p.parseStatement()
	if p.isIdent("while") {
		p.next()
		if p.is("(") {
			p.next()
			st.exprs = []*dxsExpr{p.parseExpr()}
			if p.is(")") {
				p.next()
			}
		}
	}
	p.endStatement()
	return st
}

func (p *dxsParser) parseTry() *dxsStmt {
	st := &dxsStmt{kind: dxsStmtTry, line: p.peek().line}
	p.next() // try
	st.stmts = append(st.stmts, p.parseBlock())
	if p.isIdent("catch") {
		p.next()
		catchParam := ""
		if p.is("(") {
			p.next()
			if p.peek().kind == dxsTokIdent {
				catchParam = p.next().text
			}
			if p.is(")") {
				p.next()
			}
		}
		st.names = []string{catchParam}
		st.stmts = append(st.stmts, p.parseBlock())
	} else {
		st.names = []string{""}
		st.stmts = append(st.stmts, nil)
	}
	if p.isIdent("finally") {
		p.next()
		st.stmts = append(st.stmts, p.parseBlock())
	} else {
		st.stmts = append(st.stmts, nil)
	}
	return st
}

func (p *dxsParser) parseSwitch() *dxsStmt {
	st := &dxsStmt{kind: dxsStmtBlock, line: p.peek().line}
	p.next() // switch
	if p.is("(") {
		p.next()
		p.parseExpr()
		if p.is(")") {
			p.next()
		}
	}
	if !p.is("{") {
		return st
	}
	p.next()
	for !p.eof() && !p.is("}") {
		if p.isIdent("case") || p.isIdent("default") {
			p.skipUntilPunct(":")
			continue
		}
		before := p.pos
		if s := p.parseStatement(); s != nil {
			st.stmts = append(st.stmts, s)
		}
		if p.pos == before {
			p.next()
		}
	}
	if p.is("}") {
		p.next()
	}
	return st
}

func (p *dxsParser) skipUntilPunct(target string) {
	for !p.eof() {
		t := p.next()
		if t.kind == dxsTokPunct && t.text == target {
			return
		}
	}
}

func (p *dxsParser) parseExpr() *dxsExpr {
	first := p.parseAssign()
	if first == nil || !p.is(",") {
		return first
	}
	seq := &dxsExpr{kind: dxsExprSeq, line: first.line, kids: []*dxsExpr{first}}
	for p.is(",") {
		p.next()
		if x := p.parseAssign(); x != nil {
			seq.kids = append(seq.kids, x)
		}
	}
	return seq
}

func (p *dxsParser) parseAssign() *dxsExpr {
	left := p.parseConditional()
	if left == nil {
		return nil
	}
	if left.kind == dxsExprIdent && p.is("=>") {
		p.next()
		fn := &dxsFunc{line: left.line, params: []string{left.text}, body: p.parseArrowBody()}
		return &dxsExpr{kind: dxsExprFunc, line: left.line, fn: fn}
	}
	t := p.peek()
	if t.kind == dxsTokPunct {
		switch t.text {
		case "=", "+=", "-=", "*=", "/=", "%=", "&&=", "||=", "??=":
			p.next()
			right := p.parseAssign()
			return &dxsExpr{kind: dxsExprAssign, line: left.line, text: t.text, kids: []*dxsExpr{left, right}}
		}
	}
	return left
}

func (p *dxsParser) parseConditional() *dxsExpr {
	cond := p.parseBinary(0)
	if cond == nil || !p.is("?") {
		return cond
	}
	p.next()
	then := p.parseAssign()
	if p.is(":") {
		p.next()
	}
	els := p.parseAssign()
	return &dxsExpr{kind: dxsExprCond, line: cond.line, kids: []*dxsExpr{cond, then, els}}
}

func dxsPrec(op string) int {
	switch op {
	case "||", "??":
		return 1
	case "&&":
		return 2
	case "|":
		return 3
	case "^":
		return 4
	case "&":
		return 5
	case "==", "!=", "===", "!==":
		return 6
	case "<", ">", "<=", ">=", "in", "instanceof":
		return 7
	case "<<", ">>", ">>>":
		return 8
	case "+", "-":
		return 9
	case "*", "/", "%":
		return 10
	case "**":
		return 11
	}
	return 0
}

func (p *dxsParser) parseBinary(min int) *dxsExpr {
	left := p.parseUnary()
	if left == nil {
		return nil
	}
	for {
		t := p.peek()
		op := ""
		if t.kind == dxsTokPunct || (t.kind == dxsTokIdent && (t.text == "in" || t.text == "instanceof")) {
			op = t.text
		}
		prec := dxsPrec(op)
		if prec == 0 || prec <= min {
			break
		}
		p.next()
		right := p.parseBinary(prec)
		left = &dxsExpr{kind: dxsExprBinary, line: left.line, text: op, kids: []*dxsExpr{left, right}}
	}
	return left
}

func (p *dxsParser) parseUnary() *dxsExpr {
	t := p.peek()
	if t.kind == dxsTokPunct {
		switch t.text {
		case "!", "-", "+", "~", "++", "--":
			p.next()
			return &dxsExpr{kind: dxsExprUnary, line: t.line, text: t.text, kids: []*dxsExpr{p.parseUnary()}}
		}
	}
	if t.kind == dxsTokIdent {
		switch t.text {
		case "typeof", "void", "delete", "await", "yield":
			p.next()
			return &dxsExpr{kind: dxsExprUnary, line: t.line, text: t.text, kids: []*dxsExpr{p.parseUnary()}}
		}
	}
	return p.parsePostfix()
}

func (p *dxsParser) parsePostfix() *dxsExpr {
	x := p.parsePrimary()
	for x != nil {
		t := p.peek()
		if t.kind == dxsTokPunct {
			switch t.text {
			case ".", "?.":
				p.next()
				if p.peek().kind == dxsTokIdent {
					x = &dxsExpr{kind: dxsExprMember, line: x.line, text: p.next().text, obj: x}
					continue
				}
				if p.is("(") {
					x = &dxsExpr{kind: dxsExprCall, line: x.line, obj: x, args: p.parseArgs()}
					continue
				}
			case "[":
				p.next()
				key := p.parseExpr()
				if p.is("]") {
					p.next()
				}
				x = &dxsExpr{kind: dxsExprMember, line: x.line, obj: x, kids: []*dxsExpr{key}, computed: true}
				continue
			case "(":
				x = &dxsExpr{kind: dxsExprCall, line: x.line, obj: x, args: p.parseArgs()}
				continue
			case "++", "--":
				p.next()
				continue
			}
		}
		if t.kind == dxsTokTemplateStart {
			tmpl := p.parseTemplate()
			if tmpl != nil {
				x = &dxsExpr{kind: dxsExprCall, line: x.line, obj: x, args: []*dxsExpr{tmpl}}
			}
			continue
		}
		break
	}
	return x
}

func (p *dxsParser) parseArgs() []*dxsExpr {
	var out []*dxsExpr
	if !p.is("(") {
		return out
	}
	p.next()
	for !p.eof() && !p.is(")") {
		before := p.pos
		if x := p.parseAssign(); x != nil {
			out = append(out, x)
		}
		if p.pos == before {
			p.next()
		}
		if p.is(",") {
			p.next()
			continue
		}
		break
	}
	if p.is(")") {
		p.next()
	}
	return out
}

func (p *dxsParser) parseTemplate() *dxsExpr {
	if p.peek().kind != dxsTokTemplateStart {
		return nil
	}
	start := p.peek()
	p.next()
	tmpl := &dxsExpr{kind: dxsExprTemplate, line: start.line}
	for !p.eof() {
		t := p.peek()
		switch t.kind {
		case dxsTokTemplateText:
			p.next()
		case dxsTokTemplateExprStart:
			p.next()
			if x := p.parseExpr(); x != nil {
				tmpl.kids = append(tmpl.kids, x)
			}
			if p.peek().kind == dxsTokTemplateExprEnd {
				p.next()
			}
		case dxsTokTemplateEnd:
			p.next()
			return tmpl
		default:
			// Malformed interpolation: stop rather than spin.
			p.gap(t, "unterminated template interpolation")
			return tmpl
		}
	}
	return tmpl
}

func (p *dxsParser) parsePrimary() *dxsExpr {
	t := p.peek()
	switch t.kind {
	case dxsTokIdent:
		switch t.text {
		case "function":
			p.next()
			fn := p.parseFuncRest(t.line)
			return &dxsExpr{kind: dxsExprFunc, line: t.line, fn: fn}
		case "new":
			return p.parseNew()
		}
		p.next()
		return &dxsExpr{kind: dxsExprIdent, line: t.line, text: t.text}
	case dxsTokString:
		p.next()
		return &dxsExpr{kind: dxsExprString, line: t.line, text: t.text}
	case dxsTokNumber, dxsTokRegex:
		p.next()
		return &dxsExpr{kind: dxsExprNumber, line: t.line, text: t.text}
	case dxsTokTemplateStart:
		return p.parseTemplate()
	case dxsTokPunct:
		switch t.text {
		case "(":
			save := p.pos
			if fn := p.tryArrow(); fn != nil {
				return &dxsExpr{kind: dxsExprFunc, line: t.line, fn: fn}
			}
			p.pos = save
			p.next()
			x := p.parseExpr()
			if p.is(")") {
				p.next()
			}
			return x
		case "[":
			return p.parseArray()
		case "{":
			return p.parseObject()
		case "...":
			p.next()
			return p.parseAssign()
		}
	}
	p.gap(t, "unparseable expression starting at "+strconv.Quote(t.text))
	return nil
}

func (p *dxsParser) tryArrow() *dxsFunc {
	if !p.is("(") {
		return nil
	}
	save := p.pos
	fn := &dxsFunc{line: p.peek().line}
	p.next()
	for !p.eof() && !p.is(")") {
		switch {
		case p.is("..."):
			p.next()
		case p.peek().kind == dxsTokIdent:
			fn.params = append(fn.params, p.next().text)
			if p.is("=") {
				p.next()
				p.parseAssign()
			}
		case p.is("{") || p.is("["):
			fn.params = append(fn.params, p.parsePattern()...)
		default:
			p.pos = save
			return nil
		}
		if p.is(",") {
			p.next()
		}
	}
	if !p.is(")") {
		p.pos = save
		return nil
	}
	p.next()
	if !p.is("=>") {
		p.pos = save
		return nil
	}
	p.next()
	fn.body = p.parseArrowBody()
	return fn
}

func (p *dxsParser) parseNew() *dxsExpr {
	line := p.peek().line
	p.next() // new
	callee := p.parsePrimary()
	for callee != nil {
		switch {
		case p.is(".") || p.is("?."):
			p.next()
			if p.peek().kind == dxsTokIdent {
				callee = &dxsExpr{kind: dxsExprMember, line: callee.line, text: p.next().text, obj: callee}
				continue
			}
		case p.is("["):
			p.next()
			key := p.parseExpr()
			if p.is("]") {
				p.next()
			}
			callee = &dxsExpr{kind: dxsExprMember, line: callee.line, obj: callee, kids: []*dxsExpr{key}, computed: true}
			continue
		}
		break
	}
	var args []*dxsExpr
	if p.is("(") {
		args = p.parseArgs()
	}
	return &dxsExpr{kind: dxsExprCall, line: line, obj: callee, args: args, isNew: true}
}

func (p *dxsParser) parseArray() *dxsExpr {
	arr := &dxsExpr{kind: dxsExprArray, line: p.peek().line}
	p.next() // [
	idx := 0
	for !p.eof() && !p.is("]") {
		before := p.pos
		if p.is(",") {
			p.next()
			idx++
			continue
		}
		if x := p.parseAssign(); x != nil {
			arr.kids = append(arr.kids, x)
			arr.names = append(arr.names, strconv.Itoa(idx))
		}
		if p.pos == before {
			p.next()
		}
		idx++
		if p.is(",") {
			p.next()
		}
	}
	if p.is("]") {
		p.next()
	}
	return arr
}

func (p *dxsParser) parseObject() *dxsExpr {
	obj := &dxsExpr{kind: dxsExprObject, line: p.peek().line}
	p.next() // {
	for !p.eof() && !p.is("}") {
		before := p.pos
		if p.is(",") {
			p.next()
			continue
		}
		if p.is("...") {
			p.next()
			obj.kids = append(obj.kids, p.parseAssign())
			obj.names = append(obj.names, "")
			if p.is(",") {
				p.next()
			}
			continue
		}
		t := p.peek()
		key := ""
		switch t.kind {
		case dxsTokIdent, dxsTokString, dxsTokNumber:
			key = t.text
			p.next()
		default:
			p.next()
			continue
		}
		switch {
		case p.is(":"):
			p.next()
			obj.names = append(obj.names, key)
			obj.kids = append(obj.kids, p.parseAssign())
		case p.is("("):
			p.parseFuncRest(t.line) // method shorthand: body not modelled
			obj.names = append(obj.names, key)
			obj.kids = append(obj.kids, nil)
		default:
			obj.names = append(obj.names, key)
			obj.kids = append(obj.kids, &dxsExpr{kind: dxsExprIdent, line: t.line, text: key})
		}
		if p.pos == before {
			p.next()
		}
		if p.is(",") {
			p.next()
		}
	}
	if p.is("}") {
		p.next()
	}
	return obj
}

// dxsCollectFuncs records every named function declaration so a call can be
// resolved regardless of declaration order (declarations are hoisted in JS).
func dxsCollectFuncs(st *dxsStmt, out map[string]*dxsFunc) {
	if st == nil {
		return
	}
	if st.kind == dxsStmtFuncDecl && st.fn != nil && len(st.names) == 1 && st.names[0] != "" {
		if _, exists := out[st.names[0]]; !exists {
			out[st.names[0]] = st.fn
		}
	}
	for _, s := range st.stmts {
		dxsCollectFuncs(s, out)
	}
	dxsCollectFuncs(st.block, out)
	dxsCollectFuncs(st.elseStmt, out)
	for _, e := range st.exprs {
		dxsCollectFuncsExpr(e, out)
	}
}

func dxsCollectFuncsExpr(e *dxsExpr, out map[string]*dxsFunc) {
	if e == nil {
		return
	}
	if e.kind == dxsExprFunc && e.fn != nil {
		dxsCollectFuncs(e.fn.body, out)
	}
	for _, k := range e.kids {
		dxsCollectFuncsExpr(k, out)
	}
	dxsCollectFuncsExpr(e.obj, out)
	for _, a := range e.args {
		dxsCollectFuncsExpr(a, out)
	}
}

// ---------------------------------------------------------------------------
// Abstract taint evaluation
// ---------------------------------------------------------------------------

type dxsTaintKind uint8

const (
	dxsTaintValue dxsTaintKind = iota
	// dxsTaintSearchParams is a URLSearchParams built from a source-carrying
	// string: .get(name) is selector-aware, so a page reading a DIFFERENT
	// parameter than the one under test stays negative.
	dxsTaintSearchParams
	// dxsTaintMessageEvent is a message-event object: only .data carries the
	// payload, .origin/.source do not.
	dxsTaintMessageEvent
	// dxsTaintObject is a statically shaped object/array literal. Its `on` flag
	// stays false (the object itself is not a string), so only a tainted
	// property read is followed.
	dxsTaintObject
)

type dxsTaint struct {
	on    bool
	hops  int
	kind  dxsTaintKind
	props map[string]dxsTaint
	chain []string
}

const dxsChainLimit = 8

func (t dxsTaint) with(step string) dxsTaint {
	if step == "" || !t.on {
		return t
	}
	if n := len(t.chain); n > 0 && t.chain[n-1] == step {
		return t
	}
	c := make([]string, 0, len(t.chain)+1)
	c = append(c, t.chain...)
	c = append(c, step)
	if len(c) > dxsChainLimit {
		c = c[len(c)-dxsChainLimit:]
	}
	t.chain = c
	return t
}

// withHop records one crossed user-defined function boundary.
func (t dxsTaint) withHop(label string) dxsTaint {
	if !t.on {
		return t
	}
	if label == "" {
		label = "function call"
	}
	t.hops++
	return t.with(label)
}

// withReturnHop counts the boundary only when the value was read inside the
// callee; a parameter that already crossed the boundary on the way in is not
// charged twice.
func (t dxsTaint) withReturnHop(label string) dxsTaint {
	if !t.on {
		return t
	}
	if t.hops == 0 {
		return t.withHop(label)
	}
	return t.with(label)
}

func dxsOr(a, b dxsTaint) dxsTaint {
	if a.on {
		return a
	}
	return b
}

func dxsFirstTainted(args []dxsTaint) dxsTaint {
	for _, a := range args {
		if a.on {
			return a
		}
	}
	return dxsTaint{}
}

type dxsEnv struct {
	scopes []map[string]dxsTaint
}

func (e *dxsEnv) push() { e.scopes = append(e.scopes, map[string]dxsTaint{}) }

func (e *dxsEnv) pop() {
	if len(e.scopes) > 1 {
		e.scopes = e.scopes[:len(e.scopes)-1]
	}
}

func (e *dxsEnv) clone() *dxsEnv {
	out := &dxsEnv{scopes: make([]map[string]dxsTaint, len(e.scopes))}
	for i, sc := range e.scopes {
		cp := make(map[string]dxsTaint, len(sc))
		for k, v := range sc {
			cp[k] = v
		}
		out.scopes[i] = cp
	}
	return out
}

func (e *dxsEnv) declare(name string, t dxsTaint) {
	if len(e.scopes) == 0 {
		e.push()
	}
	e.scopes[len(e.scopes)-1][name] = t
}

func (e *dxsEnv) lookup(name string) dxsTaint {
	for i := len(e.scopes) - 1; i >= 0; i-- {
		if t, ok := e.scopes[i][name]; ok {
			return t
		}
	}
	return dxsTaint{}
}

// assign writes to the nearest scope that already declares the name, so an
// assignment inside an if-block is visible after the block (a may-taint
// approximation, not lexical scoping).
func (e *dxsEnv) assign(name string, t dxsTaint) {
	for i := len(e.scopes) - 1; i >= 0; i-- {
		if _, ok := e.scopes[i][name]; ok {
			e.scopes[i][name] = t
			return
		}
	}
	e.declare(name, t)
}

// mergeTop folds a child block's assignments into its parent for names the
// parent already declared.
func (e *dxsEnv) mergeTop() {
	if len(e.scopes) < 2 {
		return
	}
	top := e.scopes[len(e.scopes)-1]
	parent := e.scopes[len(e.scopes)-2]
	for name, t := range top {
		if _, ok := parent[name]; ok {
			parent[name] = dxsOr(parent[name], t)
		}
	}
}

type dxsInterp struct {
	source   DOMXSSSource
	selector string
	env      *dxsEnv
	funcs    map[string]*dxsFunc
	active   map[*dxsFunc]int
	ret      dxsTaint

	budget    int
	exhausted bool

	sites      []DOMXSSFlowSite
	siteSeen   map[string]bool
	unresolved []DOMXSSUnresolvedFlow
	unresSeen  map[string]bool
}

func (in *dxsInterp) tick() bool {
	in.budget--
	if in.budget <= 0 {
		in.exhausted = true
		return false
	}
	return true
}

func (in *dxsInterp) recordSite(sink DOMXSSSink, t dxsTaint, line int) {
	key := string(sink) + "\x00" + strconv.Itoa(line)
	if in.siteSeen[key] {
		return
	}
	in.siteSeen[key] = true
	chain := make([]string, 0, len(t.chain)+1)
	chain = append(chain, t.chain...)
	chain = append(chain, string(sink))
	in.sites = append(in.sites, DOMXSSFlowSite{Sink: sink, Line: line, Hops: t.hops, Chain: chain})
}

func (in *dxsInterp) addUnresolved(line int, reason, detail string) {
	key := reason + "\x00" + detail + "\x00" + strconv.Itoa(line)
	if in.unresSeen[key] {
		return
	}
	in.unresSeen[key] = true
	in.unresolved = append(in.unresolved, DOMXSSUnresolvedFlow{Line: line, Reason: reason, Detail: detail})
}

func (in *dxsInterp) execStmt(st *dxsStmt) {
	if st == nil || in.exhausted || !in.tick() {
		return
	}
	switch st.kind {
	case dxsStmtBlock:
		in.execBlock(st, false)
	case dxsStmtVar:
		for i, name := range st.names {
			var t dxsTaint
			if i < len(st.exprs) && st.exprs[i] != nil {
				t = in.evalExpr(st.exprs[i]).with(name)
				if st.exprs[i].kind == dxsExprFunc && st.exprs[i].fn != nil {
					in.funcs[name] = st.exprs[i].fn
				}
			}
			in.env.declare(name, t)
		}
	case dxsStmtExpr:
		for _, e := range st.exprs {
			in.evalExpr(e)
		}
	case dxsStmtIf:
		if len(st.exprs) > 0 {
			in.evalExpr(st.exprs[0])
		}
		in.execBranch(st.block)
		in.execBranch(st.elseStmt)
	case dxsStmtLoop:
		for _, s := range st.stmts {
			in.execStmt(s)
		}
		for _, e := range st.exprs {
			in.evalExpr(e)
		}
		in.execBranch(st.block)
	case dxsStmtReturn:
		if len(st.exprs) > 0 {
			in.ret = dxsOr(in.ret, in.evalExpr(st.exprs[0]))
		}
	case dxsStmtFuncDecl:
		if st.fn != nil && len(st.names) == 1 && st.names[0] != "" {
			in.funcs[st.names[0]] = st.fn
		}
	case dxsStmtTry:
		if len(st.stmts) > 0 {
			in.execBranch(st.stmts[0])
		}
		if len(st.stmts) > 1 && st.stmts[1] != nil {
			in.env.push()
			if len(st.names) > 0 && st.names[0] != "" {
				in.env.declare(st.names[0], dxsTaint{})
			}
			in.execBlock(st.stmts[1], false)
			in.env.pop()
		}
		if len(st.stmts) > 2 {
			in.execBranch(st.stmts[2])
		}
	}
}

func (in *dxsInterp) execBranch(st *dxsStmt) {
	if st == nil {
		return
	}
	in.execBlock(st, true)
}

func (in *dxsInterp) execBlock(st *dxsStmt, merge bool) {
	if st == nil {
		return
	}
	in.env.push()
	for _, s := range st.stmts {
		in.execStmt(s)
	}
	if merge {
		in.env.mergeTop()
	}
	in.env.pop()
}

func (in *dxsInterp) evalExpr(e *dxsExpr) dxsTaint {
	if e == nil || in.exhausted || !in.tick() {
		return dxsTaint{}
	}
	switch e.kind {
	case dxsExprIdent:
		return in.env.lookup(e.text)
	case dxsExprString, dxsExprNumber:
		return dxsTaint{}
	case dxsExprTemplate:
		var out dxsTaint
		for _, k := range e.kids {
			out = dxsOr(out, in.evalExpr(k))
		}
		return out.with("template literal")
	case dxsExprArray:
		props := map[string]dxsTaint{}
		for i, k := range e.kids {
			if i < len(e.names) {
				props[e.names[i]] = in.evalExpr(k)
			}
		}
		return dxsTaint{kind: dxsTaintObject, props: props}
	case dxsExprObject:
		props := map[string]dxsTaint{}
		for i, k := range e.kids {
			if i < len(e.names) && e.names[i] != "" && k != nil {
				props[e.names[i]] = in.evalExpr(k)
			} else if i < len(e.names) && e.names[i] == "" && k != nil {
				// Spread: merge statically known properties of the source object.
				spread := in.evalExpr(k)
				for pn, pv := range spread.props {
					props[pn] = pv
				}
			}
		}
		return dxsTaint{kind: dxsTaintObject, props: props}
	case dxsExprMember:
		return in.evalMember(e)
	case dxsExprCall:
		return in.evalCall(e)
	case dxsExprBinary:
		if len(e.kids) != 2 {
			return dxsTaint{}
		}
		left := in.evalExpr(e.kids[0])
		right := in.evalExpr(e.kids[1])
		switch e.text {
		case "+", "||", "&&", "??":
			return dxsOr(left, right)
		}
		return dxsTaint{}
	case dxsExprUnary:
		return dxsTaint{}
	case dxsExprAssign:
		return in.evalAssign(e)
	case dxsExprCond:
		if len(e.kids) != 3 {
			return dxsTaint{}
		}
		in.evalExpr(e.kids[0])
		return dxsOr(in.evalExpr(e.kids[1]), in.evalExpr(e.kids[2]))
	case dxsExprSeq:
		var last dxsTaint
		for _, k := range e.kids {
			last = in.evalExpr(k)
		}
		return last
	case dxsExprFunc:
		return dxsTaint{}
	}
	return dxsTaint{}
}

func (in *dxsInterp) evalAssign(e *dxsExpr) dxsTaint {
	var val dxsTaint
	if len(e.kids) > 1 {
		val = in.evalExpr(e.kids[1])
	}
	target := e.kids[0]
	if target == nil {
		return val
	}
	if e.text == "+=" {
		val = dxsOr(val, in.env.lookup(dxsAssignedName(target)))
	}
	switch target.kind {
	case dxsExprIdent:
		if len(e.kids) > 1 && e.kids[1] != nil && e.kids[1].kind == dxsExprFunc && e.kids[1].fn != nil {
			in.funcs[target.text] = e.kids[1].fn
		}
		val = val.with(target.text)
		in.env.assign(target.text, val)
		return val
	case dxsExprMember:
		name, ok := dxsMemberName(target)
		if !ok {
			if val.on {
				in.addUnresolved(e.line, "dynamic property write", "a value derived from "+string(in.source)+" is written through a computed property name, so a later read of it cannot be resolved")
			}
			return val
		}
		if sink, isSink := dxsSinkForAssignment(name); isSink && val.on {
			in.recordSite(sink, val, e.line)
		}
		if (name == "onmessage" || name == "onmessageerror") && len(e.kids) > 1 && e.kids[1] != nil && e.kids[1].kind == dxsExprFunc {
			in.callFunc(e.kids[1].fn, []dxsTaint{dxsMessageEventTaint()}, "onmessage")
		}
		return val
	}
	return val
}

func dxsAssignedName(e *dxsExpr) string {
	if e != nil && e.kind == dxsExprIdent {
		return e.text
	}
	return ""
}

func (in *dxsInterp) evalMember(e *dxsExpr) dxsTaint {
	if path, ok := dxsStaticPath(e); ok {
		if t, ok := in.sourceTaint(path); ok {
			return t
		}
	}
	name, nameOK := dxsMemberName(e)
	recv := in.evalExpr(e.obj)
	if !nameOK {
		if recv.on {
			in.addUnresolved(e.line, "dynamic property read", "a value derived from "+string(in.source)+" is read through a computed property name, so the resulting value cannot be followed")
		}
		return dxsTaint{}
	}
	if recv.kind == dxsTaintObject {
		return recv.props[name]
	}
	if recv.on && recv.kind == dxsTaintMessageEvent && name == "data" {
		return dxsTaint{on: true, hops: recv.hops, chain: recv.chain}.with("event.data")
	}
	return dxsTaint{}
}

func (in *dxsInterp) evalCall(e *dxsExpr) dxsTaint {
	args := make([]dxsTaint, len(e.args))
	for i, a := range e.args {
		args[i] = in.evalExpr(a)
	}
	callee := e.obj
	if callee == nil {
		return dxsTaint{}
	}

	path, pathOK := dxsStaticPath(callee)
	name, nameOK := dxsMemberName(callee)
	var recv dxsTaint
	recvPath := ""
	if callee.kind == dxsExprMember {
		recv = in.evalExpr(callee.obj)
		recvPath, _ = dxsStaticPath(callee.obj)
	}
	tainted := dxsFirstTainted(args)

	// A computed callee hides which sink is being called. When a value derived
	// from the source is involved this is an explicit unknown; calls whose sink
	// can still be identified by method name are decided below.
	if callee.kind == dxsExprMember && !pathOK {
		nameIdentified := nameOK && (name == "insertAdjacentHTML" || name == "createContextualFragment" || name == "attr")
		if !nameIdentified && tainted.on {
			in.addUnresolved(e.line, "dynamic property access", "a call carrying a value derived from "+string(in.source)+" uses a computed member expression as its callee (for example window['docu'+'ment']['write'](x)), so the called sink cannot be named statically")
			return dxsTaint{}
		}
	}

	if e.isNew {
		switch {
		case path == "URLSearchParams":
			return in.searchParamsTaint(args)
		case path == "Function":
			if tainted.on {
				in.addUnresolved(e.line, "dynamic code evaluation", "new Function receives a value derived from "+string(in.source)+", so the executed code cannot be analysed")
			}
			return dxsTaint{}
		}
		if fn, ok := in.funcs[path]; ok {
			return in.callFunc(fn, args, path)
		}
		return dxsTaint{}
	}

	switch path {
	case "document.write", "document.writeln", "window.document.write", "window.document.writeln":
		if tainted.on {
			in.recordSite(DOMSinkDocumentWrite, tainted, e.line)
		}
		return dxsTaint{}
	case "setTimeout", "window.setTimeout":
		if len(args) > 0 && args[0].on && e.args[0].kind != dxsExprFunc {
			in.recordSite(DOMSinkSetTimeout, args[0], e.line)
		}
		return dxsTaint{}
	case "setInterval", "window.setInterval":
		if len(args) > 0 && args[0].on && e.args[0].kind != dxsExprFunc {
			in.recordSite(DOMSinkSetInterval, args[0], e.line)
		}
		return dxsTaint{}
	case "jQuery", "$", "window.jQuery":
		if len(args) > 0 && args[0].on {
			in.recordSite(DOMSinkJQuerySelector, args[0], e.line)
		}
		return dxsTaint{}
	case "eval", "window.eval":
		if tainted.on {
			in.addUnresolved(e.line, "dynamic code evaluation", "eval receives a value derived from "+string(in.source)+", so the executed code cannot be analysed")
		}
		return dxsTaint{}
	case "URLSearchParams":
		return in.searchParamsTaint(args)
	}

	if nameOK {
		switch name {
		case "insertAdjacentHTML":
			if len(args) > 1 && args[1].on {
				in.recordSite(DOMSinkInsertAdjacentHTML, args[1], e.line)
			}
			return dxsTaint{}
		case "createContextualFragment":
			if len(args) > 0 && args[0].on {
				in.recordSite(DOMSinkCreateContextualFragment, args[0], e.line)
			}
			return dxsTaint{}
		case "attr":
			if len(e.args) >= 2 {
				if attr, ok := dxsStringLiteral(e.args[0]); ok && attr == "href" && args[1].on {
					in.recordSite(DOMSinkJQueryAttr, args[1], e.line)
				}
			}
			return dxsTaint{}
		}
	}

	if nameOK && name == "get" && recv.on && recv.kind == dxsTaintSearchParams {
		if len(e.args) > 0 {
			key, ok := dxsStringLiteral(e.args[0])
			if !ok {
				in.addUnresolved(e.line, "dynamic selector", "URLSearchParams.get receives a name that is not a string literal, so the selected parameter cannot be compared with the parameter under test")
				return dxsTaint{}
			}
			if in.selector == "" || in.selector == key {
				return dxsTaint{on: true, hops: recv.hops, chain: recv.chain}.with("URLSearchParams.get(" + key + ")")
			}
		}
		return dxsTaint{}
	}

	if nameOK && name == "getItem" && dxsStorageBackend(recvPath) == in.source {
		if len(e.args) > 0 {
			key, ok := dxsStringLiteral(e.args[0])
			if !ok {
				in.addUnresolved(e.line, "dynamic selector", "storage getItem receives a key that is not a string literal, so it cannot be compared with the storage key under test")
				return dxsTaint{}
			}
			if in.selector == "" || in.selector == key {
				return dxsTaint{on: true, chain: []string{recvPath + ".getItem(" + key + ")"}}
			}
		}
		return dxsTaint{}
	}

	if nameOK && name == "addEventListener" && len(e.args) >= 2 && e.args[1] != nil && e.args[1].kind == dxsExprFunc {
		if ev, ok := dxsStringLiteral(e.args[0]); ok && ev == "message" {
			in.callFunc(e.args[1].fn, []dxsTaint{dxsMessageEventTaint()}, "message handler")
			return dxsTaint{}
		}
	}

	if nameOK && recv.on && dxsStringMethodPropagates(name) {
		return dxsTaint{on: true, hops: recv.hops, chain: recv.chain}.with("." + name + "()")
	}

	if callee.kind == dxsExprIdent {
		if fn, ok := in.funcs[callee.text]; ok {
			return in.callFunc(fn, args, callee.text)
		}
		if dxsGlobalPreserving(callee.text) {
			return tainted
		}
		if dxsKnownNonDOMGlobal(callee.text) {
			return dxsTaint{}
		}
		if tainted.on {
			in.addUnresolved(e.line, "external function", "a value derived from "+string(in.source)+" is passed to "+callee.text+"(), whose body is not in the analysed inline scripts")
		}
		return dxsTaint{}
	}
	return dxsTaint{}
}

// searchParamsTaint models URLSearchParams built from a source-carrying value.
func (in *dxsInterp) searchParamsTaint(args []dxsTaint) dxsTaint {
	if in.source != DOMSourceQuery && in.source != DOMSourceHash {
		return dxsTaint{}
	}
	if len(args) == 0 {
		// new URLSearchParams() reads the current query string implicitly.
		if in.source == DOMSourceQuery {
			return dxsTaint{on: true, kind: dxsTaintSearchParams, chain: []string{"URLSearchParams()"}}
		}
		return dxsTaint{}
	}
	if args[0].on {
		return dxsTaint{on: true, hops: args[0].hops, kind: dxsTaintSearchParams, chain: args[0].chain}.with("URLSearchParams")
	}
	return dxsTaint{}
}

// callFunc evaluates one user-defined function body with tainted parameters.
// The depth bound is enforced here: an argument that already crossed one
// boundary is not followed into a second, it is reported as unresolved.
func (in *dxsInterp) callFunc(fn *dxsFunc, args []dxsTaint, label string) dxsTaint {
	if fn == nil || in.exhausted || !in.tick() {
		return dxsTaint{}
	}
	if in.active[fn] > 0 {
		in.addUnresolved(fn.line, "recursive call", "function "+label+" calls itself; the bounded pass does not unroll recursion")
		return dxsTaint{}
	}
	for _, a := range args {
		if a.on && a.hops >= DOMXSSStaticMaxDepth {
			in.addUnresolved(fn.line, "flow depth", "a value derived from "+string(in.source)+" is passed through more than "+strconv.Itoa(DOMXSSStaticMaxDepth)+" user-defined function boundary; the supported depth is "+strconv.Itoa(DOMXSSStaticMaxDepth))
			return dxsTaint{}
		}
	}
	in.active[fn]++
	oldEnv := in.env
	in.env = oldEnv.clone()
	in.env.push()
	for i, p := range fn.params {
		if i < len(args) {
			in.env.declare(p, args[i].withHop(label))
		}
	}
	oldRet := in.ret
	in.ret = dxsTaint{}
	in.execStmt(fn.body)
	ret := in.ret
	in.ret = oldRet
	in.env = oldEnv
	in.active[fn]--
	return ret.withReturnHop(label)
}

// ---------------------------------------------------------------------------
// Source and sink recognition
// ---------------------------------------------------------------------------

// dxsStaticPath renders a statically resolvable member chain ("a.b.c"),
// including computed accesses with literal string/number keys. It returns false
// for anything dynamic, including a call in the middle of the chain.
func dxsStaticPath(e *dxsExpr) (string, bool) {
	if e == nil {
		return "", false
	}
	switch e.kind {
	case dxsExprIdent:
		return e.text, true
	case dxsExprMember:
		base, ok := dxsStaticPath(e.obj)
		if !ok {
			return "", false
		}
		name, ok := dxsMemberName(e)
		if !ok {
			return "", false
		}
		return base + "." + name, true
	}
	return "", false
}

func dxsMemberName(e *dxsExpr) (string, bool) {
	if e == nil || e.kind != dxsExprMember {
		return "", false
	}
	if !e.computed {
		if e.text == "" {
			return "", false
		}
		return e.text, true
	}
	if len(e.kids) == 1 && e.kids[0] != nil {
		switch e.kids[0].kind {
		case dxsExprString, dxsExprNumber:
			if e.kids[0].text != "" {
				return e.kids[0].text, true
			}
		}
	}
	return "", false
}

func dxsStringLiteral(e *dxsExpr) (string, bool) {
	if e == nil || e.kind != dxsExprString {
		return "", false
	}
	return e.text, true
}

func dxsMessageEventTaint() dxsTaint {
	return dxsTaint{on: true, kind: dxsTaintMessageEvent, chain: []string{"message event"}}
}

func dxsSinkForAssignment(name string) (DOMXSSSink, bool) {
	switch name {
	case "innerHTML":
		return DOMSinkInnerHTML, true
	case "outerHTML":
		return DOMSinkOuterHTML, true
	}
	return "", false
}

// dxsSourceTaint answers "does this statically named value carry THIS source?".
// Every other source is deliberately untainted: a query probe must not be
// credited by a hash read, and a storage key must match its selector.
func (in *dxsInterp) sourceTaint(path string) (dxsTaint, bool) {
	t := dxsTaint{on: true, chain: []string{path}}
	switch in.source {
	case DOMSourceQuery:
		switch path {
		case "location.search", "window.location.search", "document.location.search":
			return t, true
		}
		if dxsIsFullURLPath(path) {
			return t.with("query in URL"), true
		}
	case DOMSourceHash:
		switch path {
		case "location.hash", "window.location.hash", "document.location.hash":
			return t, true
		}
		if dxsIsFullURLPath(path) {
			return t.with("fragment in URL"), true
		}
	case DOMSourceWindowName:
		if path == "window.name" {
			return t, true
		}
	case DOMSourceReferrer:
		if path == "document.referrer" || path == "window.document.referrer" {
			return t, true
		}
	case DOMSourceLocalStorage, DOMSourceSessionStorage:
		backend := "localStorage"
		if in.source == DOMSourceSessionStorage {
			backend = "sessionStorage"
		}
		for _, prefix := range []string{backend + ".", "window." + backend + "."} {
			if !strings.HasPrefix(path, prefix) {
				continue
			}
			key := strings.TrimPrefix(path, prefix)
			switch key {
			case "getItem", "setItem", "removeItem", "clear", "key", "length":
				return dxsTaint{}, false
			}
			if in.selector == "" || in.selector == key {
				return dxsTaint{on: true, chain: []string{path}}, true
			}
		}
	}
	return dxsTaint{}, false
}

func dxsIsFullURLPath(path string) bool {
	switch path {
	case "location.href", "window.location.href", "document.location.href", "document.URL", "window.document.URL":
		return true
	}
	return false
}

func dxsStorageBackend(path string) DOMXSSSource {
	switch path {
	case "localStorage", "window.localStorage":
		return DOMSourceLocalStorage
	case "sessionStorage", "window.sessionStorage":
		return DOMSourceSessionStorage
	}
	return ""
}

// dxsStringMethodPropagates lists the String/Array methods whose result is
// still derived from their receiver. Escaping behaviour is deliberately NOT
// modelled (see this section's header comment).
func dxsStringMethodPropagates(name string) bool {
	switch name {
	case "slice", "substring", "substr", "trim", "trimStart", "trimEnd",
		"toLowerCase", "toUpperCase", "replace", "replaceAll", "split", "concat",
		"padStart", "padEnd", "repeat", "normalize", "toString", "valueOf",
		"charAt", "at", "join", "flat":
		return true
	}
	return false
}

func dxsGlobalPreserving(name string) bool {
	switch name {
	case "String", "decodeURI", "decodeURIComponent", "encodeURI", "encodeURIComponent", "escape", "unescape":
		return true
	}
	return false
}

// dxsKnownNonDOMGlobal lists globals that cannot carry a value into an
// implemented DOM sink by being called. Without it every alert()/fetch() call
// with a tainted argument would be reported as unresolved noise.
func dxsKnownNonDOMGlobal(name string) bool {
	switch name {
	case "alert", "confirm", "prompt", "parseInt", "parseFloat", "isNaN", "isFinite",
		"Number", "Boolean", "BigInt", "Symbol", "Object", "Array", "JSON", "Math",
		"Date", "RegExp", "Error", "TypeError", "RangeError", "Promise", "Map", "Set",
		"WeakMap", "WeakSet", "Reflect", "Proxy", "Intl", "fetch", "XMLHttpRequest",
		"WebSocket", "URL", "Blob", "File", "FormData", "Headers", "Request", "Response",
		"clearTimeout", "clearInterval", "queueMicrotask", "requestAnimationFrame",
		"structuredClone", "btoa", "atob", "history", "navigator", "console", "location",
		"require", "define":
		return true
	}
	return false
}
// domXSSAngularRationale explains the interpolation shape. Two things must be
// unambiguous to an operator reading a report: (1) what was evaluated, and
// (2) why the observation is marker-specific rather than a reflection match.
// Sandbox escape is deliberately absent — the first Angular labs differ only
// in what the page permits AFTER compilation, so proving compilation is the
// honest, bounded claim this engine makes.
func domXSSAngularRationale(source DOMXSSSource, sink DOMXSSSink) string {
	how, storageControlCaveat := domXSSSourceRoute(source)
	return how + " is placed where AngularJS compiles a text-node interpolation: Angular's interpolate service evaluates the {{...}} expression and writes the RESULT back into that text node through the DOM's own text API. " +
		"The candidate's only effect is to concatenate two string literals into the benign marker identifier, so compiling it is the detection signal and no sandbox escape, alert, cookie or network call is attempted. " +
		"The candidate bytes never contain the marker contiguously ('MARK' + 'ER'), so observing the contiguous marker in rendered text cannot come from a page that merely echoes the source — it is the expression's evaluated result. " +
		"Confirmation therefore requires that observed text result; a document whose Content-Security-Policy refuses dynamic evaluation is recorded as a distinct csp_blocked outcome, never as a rejection and never as a confirmation." + storageControlCaveat
}
