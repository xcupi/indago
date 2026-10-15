package detection

// This file is the OPT-IN WAF/filter-bypass candidate generator.
//
// Everything here deliberately reshapes a canonical breakout to survive
// common, naive content filters (case-sensitive string/regex matching,
// literal-space-only tokenizing, single-layer URL decoding) — WHILE STILL
// embedding nothing but the same benign marker as every other candidate
// (TestEvasionCandidatesAreBenignMarkers enforces this exactly like
// TestPlanCandidatesAreBenignMarkers does for the canonical set: no alert/
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
	default:
		return nil
	}
}

// evasionTpl builds a load-trigger evasion template tagged with technique.
// All current techniques reshape a LOAD-trigger canonical breakout (never an
// interaction-only one) because only a load-trigger candidate can ever be
// Confirmed by the passive verifier — an evasion variant of an
// interaction-only shape would be untestable the same way the canonical one
// already is.
func evasionTpl(value, needs string, priority int, why, technique string) candTemplate {
	return candTemplate{value: value, needs: needs, priority: priority, rationale: why, trigger: TriggerLoad, technique: technique}
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
