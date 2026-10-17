package detection

// This file plans BOUNDED, multi-parameter (combined) candidates: see
// docs/reflection-candidates.md "Combined (multi-parameter) candidates".
//
// Deliberately narrow, matching the single-param planner's own boundaries:
//   - PAIR only, never a triple+. One combined Candidate = exactly two
//     parameter slots (Value/ValueB).
//   - Exactly two context categories: CtxHTMLAttrValue and CtxJSString — the
//     two most common "a single parameter cannot both close AND add" cases.
//     Every other context returns (nil, false): no generic/unknown combined
//     template, unlike the single-param planner's unknownTemplates.
//   - PURE and DETERMINISTIC: no network, no re-detection of reflection —
//     callers (internal/scan/combined.go) pass in only what the EXISTING
//     per-parameter reflection/context analysis already recorded (a site's
//     Context + ContextSub). This file never re-probes a target.
//   - Each combined template is a natural two-parameter DECOMPOSITION of the
//     matching single-parameter template already defined above
//     (htmlAttrTemplates' onload breakout / jsTemplates' string-escape
//     breakout) — never a new, unrelated payload shape.
//   - BENIGN MARKER ONLY: the marker appears in exactly one half (the
//     "breakout" half); the other ("closer") half carries no executable
//     reference at all, matching AGENTS.md's "detection probe, not a
//     weapon" rule the single-param templates already follow.

// PlanCombinedCandidate builds the combined (two-parameter) candidate for a
// pair of reflection sites sharing the same classified Context, given the
// FIRST site's own ContextSub (the quote/sub-kind the existing context
// analyzer already recorded for it — "double_quoted"/"single_quoted"/
// "unquoted" for CtxHTMLAttrValue, "double_quoted"/"single_quoted"/
// "template_literal" for CtxJSString). marker is the benign sentinel to
// embed (the SAME probe token the first site's own injection point already
// uses — see internal/scan/combined.go).
//
// Returns (nil, false) when ctx is not one of the two supported categories,
// or subA names a sub-kind this piece has no combined template for (e.g. a
// JS template literal, which has no closing-quote character to split on).
// The returned Candidate has Value/ValueB/Combined/Category/Context/
// Trigger/Priority/Rationale/DedupKey set; the caller fills in the
// provenance fields (ScanID, Parameter(B), Location(B), InjectionPoint(B)ID)
// it already knows from the two sites being paired.
func PlanCombinedCandidate(ctx Context, subA, marker string) (*Candidate, bool) {
	switch ctx {
	case CtxHTMLAttrValue:
		return combinedHTMLAttr(subA, marker)
	case CtxJSString:
		return combinedJSString(subA, marker)
	default:
		return nil, false
	}
}

// combinedHTMLAttr splits the SAME breakout as htmlAttrTemplates' onload
// template (q+"><svg onload=M>", see candidate.go) across two parameters:
// the FIRST ("closer") supplies only the attribute/tag-closing sequence —
// its own quote (if any) plus ">" — carrying no executable reference at
// all; the SECOND ("breakout"), reflecting afterward in the same response,
// supplies an entirely new <svg onload> element referencing the marker,
// needing "<" and ">" but no quote of its own.
//
// This is the realistic "needs two parameters" case the product spec
// describes: a site that filters "<"/">" (and any space, defeating the
// onmouseover/autofocus handler siblings too) from the FIRST parameter's
// value whenever it co-occurs with a quote — but not a bare quote alone —
// while a DIFFERENT, more lenient filter on the SECOND parameter strips any
// quote character unconditionally but leaves "<"/">" untouched, defeats
// either parameter's own complete single-parameter template while the pair
// still completes the identical breakout, because neither half needs what
// the OTHER half's filter blocks.
func combinedHTMLAttr(subA, marker string) (*Candidate, bool) {
	q := quoteCharFor(subA)
	valueA := q + ">"
	valueB := "<svg onload=" + marker + ">"
	cand := &Candidate{
		Source: SourceBuiltin, Category: CatHTMLAttr, Context: CtxHTMLAttrValue,
		Value: valueA, ValueB: valueB, Combined: true,
		Trigger:   TriggerLoad,
		Priority:  70,
		Rationale: "combined (2 parameters): the first parameter closes the attribute and the tag (needs only its own quote, if any, plus \">\"); the second, reflecting afterward in the same response, supplies a brand-new <svg onload> element referencing the marker (needs \"<\" and \">\" but no quote of its own) — the same breakout as the single-parameter html_attribute onload template (see candidate.go), split across two parameters that together complete it even when neither alone can",
	}
	cand.DedupKey = combinedDedupKey(cand)
	return cand, true
}

// combinedJSString splits the SAME breakout as jsTemplates' string-escape
// template (";M// / ';M//, see candidate.go) across two parameters: the
// FIRST ("closer") supplies only its own quote character plus a statement
// terminator, carrying no executable reference; the SECOND ("breakout"),
// reflecting afterward as the next piece of code, supplies a bare marker
// reference plus a line comment that swallows whatever static text follows
// it, needing no quote character of its own. Assumes (like every built-in
// candidate is a "worth trying", not guaranteed, shape) the two sites are
// reached as sequential code in the same script — the same kind of
// adjacency assumption the single-parameter templates already make about
// their own surrounding markup.
//
// Template-literal JS strings have no closing-quote character to split on,
// so this returns (nil, false) for subA=="template_literal".
func combinedJSString(subA, marker string) (*Candidate, bool) {
	var valueA string
	switch subA {
	case "double_quoted":
		valueA = `";`
	case "single_quoted":
		valueA = `';`
	default:
		return nil, false
	}
	valueB := marker + "//"
	cand := &Candidate{
		Source: SourceBuiltin, Category: CatJS, Context: CtxJSString,
		Value: valueA, ValueB: valueB, Combined: true,
		Trigger:   TriggerLoad,
		Priority:  65,
		Rationale: "combined (2 parameters): the first parameter closes its JS string and terminates the statement (needs only its own quote character); the second, reflecting afterward as the next code, supplies a bare marker reference plus a line comment swallowing the rest (needs nothing) — the same breakout as the single-parameter js_string escape template (see candidate.go), split across two parameters that together complete it even when neither alone can",
	}
	cand.DedupKey = combinedDedupKey(cand)
	return cand, true
}

// combinedDedupKey mirrors the single-param planner's own
// "category\x00value" dedup key (see PlanCandidates), with a disjoint
// "combined\x00" prefix so a combined candidate's key can never collide
// with a single-parameter one, plus ValueB so the two halves together
// identify this exact combined breakout.
func combinedDedupKey(c *Candidate) string {
	return "combined\x00" + string(c.Category) + "\x00" + c.Value + "\x00" + c.ValueB
}

// quoteCharFor returns the literal quote character a "double_quoted"/
// "single_quoted"/"unquoted" ContextSub implies — "" for unquoted (and for
// any other/unrecognized sub, conservatively treated as needing none).
func quoteCharFor(sub string) string {
	switch sub {
	case "double_quoted":
		return `"`
	case "single_quoted":
		return `'`
	default:
		return ""
	}
}
