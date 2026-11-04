package detection

import (
	"fmt"
	"sort"
	"strings"

	"github.com/indago/indago/internal/domain"
)

// This file is the deterministic CANDIDATE PLANNER for Reflected XSS. Given a
// ReflectionReport whose sites have been context-classified, it produces an
// ordered, deduplicated set of candidate test cases — the breakouts a later,
// separately-gated execution phase would try at each site.
//
// Boundaries (all enforced by tests):
//
//   - PLANNING ONLY. It builds candidate data; it performs no HTTP, no browser
//     execution, and makes no XSS verdict. Execution/verification are later
//     phases, and the executor's state-changing safeguards are unchanged.
//   - DETERMINISTIC & PURE. Bytes/report in, candidates out. No network, clock,
//     randomness, or other modules (a test enforces the imports).
//   - DETECTION PROBES, NOT WEAPONS. Each candidate embeds a benign, unique
//     marker (an identifier/element a later verifier can observe) — never alert/
//     cookie/network payloads, and never obfuscated/WAF-evasion variants. The
//     built-in set is intentionally small.
//   - EXTENSIBLE WITHOUT DOMAIN CHANGES. Candidates live in the engine-specific
//     ReflectionReport (persisted via TestCase.Detail), so future sources (e.g.
//     Source=="llm", advisory only) append here without touching the TestCase
//     model.

// CandidateCategory is the coarse family a candidate belongs to.
type CandidateCategory string

const (
	CatHTMLText CandidateCategory = "html_text"
	CatHTMLAttr CandidateCategory = "html_attribute"
	CatJS       CandidateCategory = "javascript" // JS string or code
	CatURL      CandidateCategory = "url"
	CatCSS      CandidateCategory = "css"
	CatUnknown  CandidateCategory = "unknown_mixed"
)

// Candidate triggers (see Candidate.Trigger).
const (
	TriggerLoad        = "load"
	TriggerInteraction = "interaction"
	TriggerNone        = "none"
)

// Candidate sources.
const (
	SourceBuiltin = "builtin"
	SourceLLM     = "llm" // reserved; advisory only, never authoritative
)

// Candidate is one planned breakout for one reflection site. It is serializable
// and self-describing: it carries enough provenance to be acted on later without
// the surrounding report.
type Candidate struct {
	Source   string            `json:"source"`
	Category CandidateCategory `json:"category"`

	// Provenance — scan, parameter, injection point, and the exact site.
	ScanID           domain.ID            `json:"scan_id,omitempty"`
	InjectionPointID domain.ID            `json:"injection_point_id,omitempty"`
	Parameter        string               `json:"parameter,omitempty"`
	Location         domain.ParamLocation `json:"location,omitempty"`
	SiteIndex        int                  `json:"site_index"`
	Offset           int                  `json:"offset"`
	Context          Context              `json:"context"`
	ContextSub       string               `json:"context_sub,omitempty"`

	// Value is the string to inject (benign marker embedded). It is a detection
	// probe, not an exploit.
	Value string `json:"value"`
	// Transformation is what the site is expected to do to the characters this
	// candidate depends on: "raw" (survive) or an encoding (html/url/js/stripped/
	// mixed) that neutralizes them. Derived from the reflection encoding analysis.
	Transformation string `json:"transformation"`
	// Delimiter names the attribute quote style this candidate closes:
	// "double" or "single" for a quoted-attribute breakout, empty for every
	// candidate that does not close a quote. It is set on the variants planned
	// when the analyser could NOT prove the site's delimiter (see
	// breakoutQuotes), so a report can say which style a given attempt assumed
	// — and therefore which style actually fired when one confirms.
	Delimiter string `json:"delimiter,omitempty"`
	// Trigger is how this breakout could ever produce an execution signal:
	// TriggerLoad fires on page load (what the passive browser verifier can
	// observe), TriggerInteraction needs a user action (hover, click,
	// navigation) the verifier deliberately never simulates, and TriggerNone is
	// a markup-injection probe that carries no executable reference at all.
	// Only TriggerLoad candidates can ever be Confirmed by verification; the
	// others document reflection behaviour and end Rejected/unconfirmed.
	Trigger string `json:"trigger,omitempty"`
	// Technique names the WAF/filter-bypass shape this candidate uses (e.g.
	// "case_variation", "alt_separator", "double_url_encoding"), empty for
	// every canonical (non-evasion) candidate. Only ever set when the scan
	// opted in via PlanOptions.EnableEvasion — see evasion.go. Kept distinct
	// from Rationale so a report can filter/group on it directly.
	Technique string `json:"technique,omitempty"`
	// Variation names the mechanism a VARIATION PACK variant uses (e.g.
	// "img_error", "inline_script", "entity_colon"), empty for every canonical
	// and every evasion candidate. Only ever set when the variation packs ran
	// (PlanOptions.EnableVariationPacks, or the same operator opt-in that
	// enables evasion — see variation.go). Distinct from Technique because a
	// variation is an alternative MECHANISM, not a filter bypass.
	Variation string `json:"variation,omitempty"`
	// Priority orders execution: higher first. Candidates whose required
	// characters the site neutralizes are deprioritized, not hidden.
	Priority  int    `json:"priority"`
	Rationale string `json:"rationale"`
	// DedupKey collapses identical candidates arising from multiple sites.
	DedupKey string `json:"dedup_key"`

	// Combined marks a BOUNDED, multi-parameter (two-parameter, never a
	// triple+) candidate — see docs/reflection-candidates.md "Combined
	// (multi-parameter) candidates" and combined.go. Everything above
	// (Parameter, Location, InjectionPointID, Value) describes the FIRST
	// ("closer") half; these four describe the SECOND ("breakout") half.
	// Empty/false for every ordinary single-parameter candidate produced by
	// PlanCandidates — this never changes what any existing field means.
	Combined          bool                 `json:"combined,omitempty"`
	ParameterB        string               `json:"parameter_b,omitempty"`
	LocationB         domain.ParamLocation `json:"location_b,omitempty"`
	InjectionPointBID domain.ID            `json:"injection_point_b_id,omitempty"`
	ValueB            string               `json:"value_b,omitempty"`
}

// CandidatePlan is the ordered, deduplicated candidate set for one reflection
// report (one injection-point test).
type CandidatePlan struct {
	Source     string      `json:"source"`
	Marker     string      `json:"marker"`
	Generated  int         `json:"generated"` // total built before deduplication
	Candidates []Candidate `json:"candidates,omitempty"`
	// Profile/Limit/Dropped record the selection policy applied (profile.go):
	// the profile name, its per-injection-point cap, and how many deduplicated
	// candidates it left unsent — so a bounded plan is never mistaken for the
	// complete built-in set.
	Profile CandidateProfile `json:"profile,omitempty"`
	Limit   int              `json:"limit,omitempty"`
	Dropped int              `json:"dropped,omitempty"`
	// VariationCapped records how many DISTINCT variation-pack candidates the
	// hard per-injection-point cap (MaxVariationCandidatesPerInjectionPoint)
	// left unsent. Zero when the packs did not run or nothing was capped.
	VariationCapped int `json:"variation_capped,omitempty"`
}

// PlanOptions configures planning.
type PlanOptions struct {
	// Marker is the benign sentinel embedded in candidate values. Empty defaults
	// to the report's probe token (deterministic, unique, identifier-safe).
	Marker string
	// Provenance stamped onto every candidate.
	ScanID           domain.ID
	InjectionPointID domain.ID
	// Profile selects which of the planned candidates are kept (and how many).
	// The zero value keeps every candidate, as before profiles existed.
	Profile ProfileSpec
	// EnableEvasion additionally plans WAF/filter-bypass variants (see
	// evasion.go) for the contexts that have them, ON TOP OF the canonical
	// candidates — it never replaces or hides them. Defaults to false
	// (conservative by design, AGENTS.md §2.3): an operator opts in per scan.
	EnableEvasion bool
	// EnableVariationPacks additionally plans mechanism-distinct variation
	// packs (see variation.go) per reflection context, ON TOP OF the canonical
	// candidates. Defaults to false, so the default plan is byte-identical to
	// before the packs existed. The existing per-scan evasion opt-in also
	// enables them (EnableEvasion is the operator gate already wired end to
	// end); this field exists so a future dedicated flag, or a direct planner
	// caller, can ask for the packs alone.
	EnableVariationPacks bool
}

// PlanCandidates builds the candidate plan for rep and stores it in rep.Plan. It
// is a pure function of rep + opts. Sites that are not reflected, or whose
// context yields nothing worth trying, contribute no candidates.
func PlanCandidates(rep *ReflectionReport, opts PlanOptions) *CandidatePlan {
	if rep == nil {
		return nil
	}
	marker := opts.Marker
	if marker == "" {
		marker = rep.Probe.Token
	}
	plan := &CandidatePlan{Source: SourceBuiltin, Marker: marker}

	// Build per site, keeping the best instance of each dedup key.
	best := map[string]Candidate{}
	for i := range rep.Locations {
		loc := rep.Locations[i]
		if loc.Context == nil {
			continue
		}
		tpls := templatesFor(*loc.Context, marker)
		// A RAW QUERY-STRING injection point that lands in a URL inside an
		// HTML attribute (the canonical <link rel="canonical" href="...">
		// class) needs the attribute-breakout shapes too. templatesFor's URL
		// branch deliberately plans none of them for a named parameter: a URL
		// component the page itself navigates rarely yields load-time
		// execution, and the canonical-link vector is an interaction
		// candidate. A raw query blob, though, is exactly the shape that
		// closes the attribute and injects a new element, so without these a
		// raw-query finding could never be browser-confirmed at all. Gated to
		// LocationRawQuery so every named-parameter plan is byte-identical to
		// before this capability existed. The href shape is the click-class
		// sibling: a new accesskey/onclick pair on the element itself, which
		// the verifier's single click activation can fire.
		if rep.Location == domain.LocationRawQuery && categoryOf(loc.Context.Context) == CatURL {
			tpls = append(tpls, htmlAttrTemplates(*loc.Context, marker)...)
			tpls = append(tpls, urlHrefBreakoutTemplates(*loc.Context, marker)...)
		}
		if opts.EnableEvasion {
			tpls = append(tpls, evasionTemplatesFor(*loc.Context, marker)...)
		}
		// Variation packs are opt-in extra probing: a variant whose required
		// canary characters the site provably neutralizes is not planned at
		// all (unlike a canonical candidate, which is only deprioritized).
		if opts.EnableVariationPacks || opts.EnableEvasion {
			for _, tpl := range variationTemplatesFor(*loc.Context, marker) {
				if ok, _ := survives(loc, tpl.needs); !ok {
					continue
				}
				tpls = append(tpls, tpl)
			}
		}
		for _, tpl := range tpls {
			// A strict template is only plannable when the delimiter it must
			// insert arrives raw; otherwise the request could never break out,
			// so it is dropped rather than sent (see urlHrefBreakoutTemplates).
			if tpl.strict && !strictSurvives(loc, tpl.needs) {
				continue
			}
			plan.Generated++
			c := Candidate{
				Source:           SourceBuiltin,
				Category:         categoryOf(loc.Context.Context),
				ScanID:           opts.ScanID,
				InjectionPointID: opts.InjectionPointID,
				Parameter:        rep.Parameter,
				Location:         rep.Location,
				SiteIndex:        i,
				Offset:           loc.Offset,
				Context:          loc.Context.Context,
				ContextSub:       loc.Context.Sub,
				Value:            tpl.value,
				Delimiter:        tpl.delimiter,
				Trigger:          tpl.trigger,
				Technique:        tpl.technique,
				Variation:        tpl.variation,
				Rationale:        tpl.rationale,
			}
			c.Transformation, c.Priority = transform(loc, tpl, &c)
			c.DedupKey = string(c.Category) + "\x00" + c.Value
			if cur, ok := best[c.DedupKey]; !ok || better(c, cur) {
				best[c.DedupKey] = c
			}
		}
	}

	plan.Candidates = make([]Candidate, 0, len(best))
	for _, c := range best {
		plan.Candidates = append(plan.Candidates, c)
	}
	sort.Slice(plan.Candidates, func(i, j int) bool {
		return lessCandidate(plan.Candidates[i], plan.Candidates[j])
	})
	// Hard cap on variation-pack candidates per injection point. Applied in
	// plan order (highest priority first), so a page that reflects into many
	// contexts keeps the most likely mechanisms and drops the tail — it can
	// never grow the plan without bound with the response.
	if opts.EnableVariationPacks || opts.EnableEvasion {
		kept := plan.Candidates[:0]
		n := 0
		for _, c := range plan.Candidates {
			if c.Variation != "" {
				if n >= MaxVariationCandidatesPerInjectionPoint {
					plan.VariationCapped++
					continue
				}
				n++
			}
			kept = append(kept, c)
		}
		plan.Candidates = kept
	}
	if opts.Profile != (ProfileSpec{}) {
		plan.Candidates, plan.Dropped = opts.Profile.Select(plan.Candidates)
		plan.Profile, plan.Limit = opts.Profile.Name, opts.Profile.MaxPerInjectionPoint
	}
	rep.Plan = plan
	return plan
}

// better reports whether candidate a should win a dedup tie over b: higher
// priority, then earlier site, then lower offset (all deterministic).
func better(a, b Candidate) bool {
	if a.Priority != b.Priority {
		return a.Priority > b.Priority
	}
	if a.SiteIndex != b.SiteIndex {
		return a.SiteIndex < b.SiteIndex
	}
	return a.Offset < b.Offset
}

// lessCandidate is the deterministic final ordering: priority desc, then a
// stable key (category, value, site).
func lessCandidate(a, b Candidate) bool {
	if a.Priority != b.Priority {
		return a.Priority > b.Priority
	}
	if a.Category != b.Category {
		return a.Category < b.Category
	}
	if a.Value != b.Value {
		return a.Value < b.Value
	}
	return a.SiteIndex < b.SiteIndex
}

func categoryOf(ctx Context) CandidateCategory {
	switch ctx {
	case CtxHTMLText, CtxHTMLComment:
		return CatHTMLText
	case CtxHTMLAttrValue, CtxHTMLAttrName, CtxHTMLTagName:
		return CatHTMLAttr
	case CtxJSString, CtxJSCode, CtxJSRegex, CtxJSComment:
		return CatJS
	case CtxURL:
		return CatURL
	case CtxCSS:
		return CatCSS
	default:
		return CatUnknown
	}
}

// ---------------------------------------------------------------------------
// built-in candidate templates (small, canonical, benign)
// ---------------------------------------------------------------------------

// candTemplate is a context-specific breakout shape before transformation-aware
// prioritization. needs lists the canary metacharacters (<,>,",') it depends on.
type candTemplate struct {
	value     string
	needs     string
	priority  int
	rationale string
	trigger   string // TriggerLoad / TriggerInteraction / TriggerNone
	technique string // "" for every canonical template; see evasion.go
	variation string // "" for every canonical/evasion template; see variation.go
	// delimiter is the attribute quote style the shape closes ("double" or
	// "single"), empty when it closes no quote. Copied into Candidate.Delimiter
	// so a plan (and a report) can say which style an attempt assumed.
	delimiter string
	// strict marks a template whose `needs` are DELIMITERS the breakout must
	// receive literally, with no entity-decoding exemption (see
	// strictSurvives). A template that closes an attribute value with a quote
	// cannot use an HTML-encoded quote: the browser decodes it into the
	// attribute VALUE, where it is an ordinary character, never a delimiter.
	// Such a template is not planned at all when the site provably encodes its
	// delimiter, rather than being sent as a request that cannot break out.
	// False for every pre-existing template, so their behaviour is unchanged.
	strict bool
}

// templatesFor returns the built-in candidates for a site's context.
func templatesFor(a ContextAnalysis, m string) []candTemplate {
	switch categoryOf(a.Context) {
	case CatHTMLText:
		return htmlTextTemplates(a, m)
	case CatHTMLAttr:
		return htmlAttrTemplates(a, m)
	case CatJS:
		return jsTemplates(a, m)
	case CatURL:
		// A URL component nested inside an HTML attribute is still inside that
		// attribute: the closing quote alone ends it, so the attribute layer is
		// plannable even when < and > are encoded. urlTemplates' own output
		// stays first (it is the most specific to the URL layer); the link
		// templates only ever add to it. See linkAttributeTemplates.
		return append(urlTemplates(a, m), linkAttributeTemplates(a, m)...)
	case CatCSS:
		return cssTemplates(a, m)
	default:
		return unknownTemplates(m)
	}
}

// Template constructors: the trigger is part of each built-in's definition, so
// a profile can select on it (see profile.go).
func onLoad(value, needs string, priority int, why string) candTemplate {
	return candTemplate{value: value, needs: needs, priority: priority, rationale: why, trigger: TriggerLoad}
}
func onInteraction(value, needs string, priority int, why string) candTemplate {
	return candTemplate{value: value, needs: needs, priority: priority, rationale: why, trigger: TriggerInteraction}
}

// onInteractionStrict is onInteraction for a shape whose `needs` are attribute
// DELIMITERS: it is dropped entirely when the site encodes them (see
// strictSurvives), never merely deprioritized.
func onInteractionStrict(value, needs string, priority int, why string) candTemplate {
	return candTemplate{value: value, needs: needs, priority: priority, rationale: why, trigger: TriggerInteraction, strict: true}
}
func markupProbe(value, needs string, priority int, why string) candTemplate {
	return candTemplate{value: value, needs: needs, priority: priority, rationale: why, trigger: TriggerNone}
}

func htmlTextTemplates(a ContextAnalysis, m string) []candTemplate {
	// In RCDATA/RAWTEXT (title/textarea/iframe/xmp/…) or a comment, markup is not
	// parsed until the construct closes, so the breakout must close it first.
	prefix := closingPrefix(a)
	return []candTemplate{
		onLoad(prefix+"<svg onload="+m+">", "<>", 90,
			prefixReason(prefix, "inject an <svg> element whose onload handler references the benign marker")),
		// img onerror is a second, independent auto-firing vector: a filter
		// that specifically blocks "svg" (but not "img") still misses this one.
		// Not evasion — both are standard, unobfuscated constructs; this is
		// coverage of a second real-world auto-trigger, same as the planner
		// already tries two shapes elsewhere.
		onLoad(prefix+"<img src=x onerror="+m+">", "<>", 88,
			prefixReason(prefix, "inject an <img> with a deliberately-broken src so its onerror handler (fires automatically, no interaction) references the marker")),
		// <details open ontoggle=> is a third independent auto-firing vector:
		// the toggle event fires once when the element is parsed with open
		// already present (no click needed), so a filter that blocks "svg"
		// and "img" but not "details" still misses this one. Also useful
		// against filters that specifically pattern-match "on load"/"on
		// error" strings but not "ontoggle".
		onLoad(prefix+"<details open ontoggle="+m+">", "<>", 80,
			prefixReason(prefix, "inject a <details open> element whose ontoggle handler fires as soon as it is parsed (open already set), referencing the marker")),
		// <body onpageshow=> exploits the HTML parser's own merge behavior: a
		// second <body> start tag does not open a new element — the parser
		// copies any attributes not already present onto the page's REAL
		// <body>, including event-handler attributes, so this works even
		// deep inside existing body content with no need to open a fresh
		// element. pageshow fires once after the initial load too, not only
		// on a back/forward-cache restore.
		onLoad(prefix+"<body onpageshow="+m+">", "<>", 76,
			prefixReason(prefix, "inject a body start tag whose onpageshow attribute the parser merges onto the page's existing <body> element, firing on load")),
		// <svg><animate onbegin=> auto-fires when the animation begins
		// (default begin="0s", i.e. immediately) — a fourth independent
		// vector for a filter that blocks onload/onerror/ontoggle/onpageshow
		// specifically but not onbegin.
		onLoad(prefix+"<svg><animate onbegin="+m+">", "<>", 72,
			prefixReason(prefix, "inject an SVG <animate> element whose onbegin handler fires as soon as the (default, immediate) animation begins")),
		markupProbe(prefix+"<"+m+"x>", "<>", 60,
			prefixReason(prefix, "inject a marker element to detect raw markup injection without script")),
	}
}

// breakoutQuotes returns the quoted attribute delimiters a quote-closing
// breakout may use at this site.
//
// The list is ONE style when the analyser PROVED the site's delimiter
// (ContextAnalysis.QuoteProven: the reflection came back raw, so the quote
// bytes around the site are the template's own) — that is the pre-existing
// behaviour, byte for byte.
//
// It is BOTH styles when the delimiter is not proven: the target rewrote the
// value (encoded/transformed/stripped/unknown), so the quote in force while the
// probe was parsed is a product of that rewrite applied to OUR payload, not
// proof of the delimiter the next payload will meet. A single-style plan then
// guesses, and a wrong guess can never close the attribute — exactly the
// measured live-lab failure. Both variants are planned instead; the per-variant
// strict guard still drops any style whose quote the site provably encodes, so
// a site that encodes both still plans neither.
//
// A site inside an attribute value for which no delimiter was established at
// all (Quote == "") is unproven too, and gets both. An unquoted value, an
// attribute-name/tag-name position, or any position outside an attribute yields
// no styles: a quote cannot close a value that has no delimiter.
func breakoutQuotes(a ContextAnalysis) []string {
	switch a.Quote {
	case "double", "single":
		if a.QuoteProven {
			return []string{a.Quote}
		}
		return []string{"double", "single"}
	case "":
		if inAttributeValue(a) {
			return []string{"double", "single"}
		}
	}
	return nil
}

// inAttributeValue reports whether the site sits inside an HTML attribute
// value, either as the innermost context or as an enclosing layer of the chain
// (a URL/CSS/JS site nested in an attribute keeps the attribute in the chain).
func inAttributeValue(a ContextAnalysis) bool {
	if a.Context == CtxHTMLAttrValue {
		return true
	}
	for _, c := range a.Chain {
		if c == CtxHTMLAttrValue {
			return true
		}
	}
	return false
}

// htmlAttrTemplates expands the in-tag attribute breakouts over every quote
// style the site's evidence supports: one style when the delimiter is proven,
// both when it is not (see breakoutQuotes). Each variant carries its style in
// Candidate.Delimiter and says so in its rationale, so a report can state which
// one fired. Unquoted/attribute-name positions keep the unquoted shapes.
func htmlAttrTemplates(a ContextAnalysis, m string) []candTemplate {
	styles := breakoutQuotes(a)
	if len(styles) == 0 {
		return htmlAttributeShapes("", m)
	}
	out := make([]candTemplate, 0, len(styles)*3)
	for _, style := range styles {
		shapes := htmlAttributeShapes(quoteByte(style), m)
		for i := range shapes {
			shapes[i].delimiter = style
		}
		out = append(out, shapes...)
	}
	return out
}

// quoteByte maps an analyser quote style to the delimiter byte a candidate must
// send. "" for anything that is not a quoted style.
func quoteByte(style string) string {
	switch style {
	case "double":
		return `"`
	case "single":
		return `'`
	}
	return ""
}

// htmlAttributeShapes builds the canonical in-tag breakouts for ONE attribute
// delimiter byte. q == "" means an unquoted value / attribute-name position.
func htmlAttributeShapes(q, m string) []candTemplate {
	var needs string
	if q != "" {
		needs = q
	}

	// Staying inside the tag and adding an event-handler attribute needs only the
	// delimiter (not <,>), so it survives when < and > are encoded.
	handler := q + " onmouseover=" + m
	handlerRationale := "close the attribute and add an onmouseover handler referencing the marker, without needing < or >"
	// autofocus+onfocus is the LOAD-TRIGGER sibling of onmouseover: a focusable
	// element with the autofocus attribute fires onfocus automatically when the
	// page loads — no click/hover needed — so, unlike onmouseover, this one CAN
	// be Confirmed by the passive verifier. Same shape (new attribute inside the
	// tag), same character requirement.
	autofocusHandler := q + " autofocus onfocus=" + m
	autofocusRationale := "close the attribute and add an autofocus element whose onfocus handler (fires automatically on page load) references the marker, without needing < or >"
	if q == "" {
		handler = " onmouseover=" + m + " "
		handlerRationale = "add a new event-handler attribute (unquoted value ends at whitespace)"
		autofocusHandler = " autofocus onfocus=" + m + " "
		autofocusRationale = "add a new autofocus/onfocus attribute pair (fires automatically on page load; unquoted value ends at whitespace)"
	} else {
		handler += " x=" + q // swallow the original closing quote
		autofocusHandler += " x=" + q
		handlerRationale = delimiterNote(handlerRationale, q)
		autofocusRationale = delimiterNote(autofocusRationale, q)
	}

	shapes := []candTemplate{
		onLoad(q+"><svg onload="+m+">", needs+"<>", 90,
			delimiterNote("break out of the attribute and tag, then inject an <svg> element with an onload handler", q)),
		onLoad(autofocusHandler, needs, 87, autofocusRationale),
		// onmouseover needs a hover the passive verifier never simulates, so this
		// documents attribute injection but cannot itself be Confirmed.
		onInteraction(handler, needs, 85, handlerRationale),
	}
	return shapes
}

// delimiterNote appends the provenance sentence that names the quote style a
// variant assumes. It is only reached for quote-closing variants, so a report
// reading a candidate can always tell which delimiter that attempt tried.
func delimiterNote(rationale, q string) string {
	if q == "" {
		return rationale
	}
	return rationale + " (this variant closes the " + quoteWord(q) + " attribute delimiter)"
}

func jsTemplates(a ContextAnalysis, m string) []candTemplate {
	switch {
	case a.Context == CtxJSString && a.Sub == "single_quoted":
		return []candTemplate{
			onLoad("';"+m+"//", "'", 90, "close the single-quoted JS string and start a statement that references the marker"),
			// A reader that backslash-escapes the quote defeats the shape above
			// (the injected quote comes back as \', so the string never closes).
			// The HTML tokenizer, though, ends the <script> ELEMENT at a literal
			// </script> regardless of the JS string state, and a fresh script
			// block whose whole body is the marker then runs. This needs no
			// quote at all — only < and > — so it survives a quote-and-backslash
			// escaping reader.
			onLoad("</script><script>"+m+"</script>", "<>", 88,
				"end the script element with a literal </script> (the HTML tokenizer does not track JS string state) and open a fresh script block whose whole body is the marker, so no quote is needed at all"),
			// When < and > are HTML-encoded, the remaining route is the escape
			// rule itself: a leading backslash consumes the backslash the reader
			// inserts before the escaped quote, leaving that quote raw and
			// closing the string. The probe canary has no backslash, so the
			// planner cannot tell whether the reader escapes backslash too —
			// this shape is planned anyway (never dropped) and simply fails
			// against a reader that does.
			onLoad(`\';`+m+"//", "'", 86,
				"lead with a backslash so the reader's own quote escaping consumes it (\\' becomes \\\\'), leaving the closing quote raw; works when the reader escapes the quote but not the backslash"),
		}
	case a.Context == CtxJSString && a.Sub == "double_quoted":
		return []candTemplate{onLoad(`";`+m+"//", `"`, 90, "close the double-quoted JS string and start a statement that references the marker")}
	case a.Context == CtxJSString && a.Sub == "template_literal":
		// Substitution is the one shape a template literal cannot take away
		// from us: it executes without needing any quote, angle bracket or
		// backtick, so it is the only route when the reader escapes those
		// characters — the literal cannot then be closed, and the script
		// element cannot be ended either. It does depend on the server
		// leaving '$', '{' and '}' unescaped, which the probe canary
		// (<>"') cannot observe, so the planner neither claims nor denies
		// that they survive: it plans the shape at full priority and sends
		// it regardless. A reader that escapes those characters too (or
		// escapes the whole opener) keeps it inert text, and the attempt is
		// then recorded as reflected-but-not-executed.
		return []candTemplate{onLoad("${"+m+"}", "", 85,
			"interpolate the marker as ${MARKER}: substitution executes inside the template literal without needing any quote, angle bracket or backtick, so it is the only route when the reader escapes those characters (the literal cannot then be closed and the script element cannot be ended); it depends on the server leaving '$', '{' and '}' unescaped, which the probe canary cannot observe, so it is planned at full priority regardless")}
	case a.Context == CtxJSComment:
		// Escaping a comment needs a newline (line) or the close sequence (block).
		if a.Sub == "block" {
			return []candTemplate{onLoad("*/"+m+"/*", "", 35, "close the block comment, reference the marker, reopen a comment")}
		}
		return []candTemplate{onLoad("\n"+m, "", 20, "inside a line comment; a newline is required to escape it and may be stripped")}
	case a.Context == CtxJSRegex:
		return []candTemplate{onLoad("/;"+m+"//", "", 40, "terminate the regular-expression literal, then reference the marker")}
	default: // js_code / template expression
		return []candTemplate{
			onLoad(m, "", 95, "already a JavaScript code position: the marker is a direct code reference"),
			onLoad(";"+m+";", "", 70, "introduce the marker as its own statement"),
		}
	}
}

func urlTemplates(a ContextAnalysis, m string) []candTemplate {
	switch a.Sub {
	case "start", "relative_first_segment":
		// Runs only when the link is activated; the verifier never clicks.
		return []candTemplate{onInteraction("javascript:"+m, "", 90,
			"inject a javascript: scheme so the marker runs when the link is activated/navigated")}
	case "data_uri":
		return []candTemplate{onInteraction("data:text/html,<svg onload="+m+">", "<>", 55,
			"a data: URI whose HTML body contains a marker handler (depends on the sink)")}
	default:
		// query/path/fragment/host: reflection inside a URL component rarely yields
		// script execution. Plan nothing rather than noise.
		return nil
	}
}

// linkAttributeTemplates covers a value reflected inside a URL component of a
// <link> element's attribute — the canonical-link position. The analyzer's
// innermost context there is the URL (chain [html_attr_value, url]), and
// urlTemplates deliberately plans nothing for a query/path/fragment component.
// That is right for a URL the page itself navigates; a <link> is metadata
// instead: it has no rendered box, the page never navigates its href, and no
// load-time event fires on it, so neither a javascript: URL nor a tag-injection
// shape can execute there.
//
// The value is still inside an HTML attribute, though, so the closing quote
// alone ends it and an attribute-only injection IS plannable: a new attribute
// pair on the link element itself. That is the reported canonical-link vector
// (accesskey plus onclick). It only runs after an operator keypress that the
// passive verifier never simulates, so it is an interaction candidate: it
// documents the position — and, because it reflects, still produces a finding —
// but it can never be Confirmed by the verifier.
func linkAttributeTemplates(a ContextAnalysis, m string) []candTemplate {
	if a.Element != "link" || a.Attribute == "" {
		return nil
	}
	var q, needs string
	switch a.Quote {
	case "double":
		q, needs = `"`, `"`
	case "single":
		q, needs = `'`, `'`
	case "unquoted":
		q, needs = "", ""
	default:
		// No attribute delimiter was established, so this is not an attribute
		// injection position at all.
		return nil
	}
	return []candTemplate{onInteraction(q+" accesskey=x onclick="+m+" y="+q, needs, 60,
		"close the link's href attribute and add an accesskey/onclick pair on the link element itself (the canonical-link vector); it needs only the quote, so encoding < and > does not stop it, but it executes only after an activation keypress that the passive verifier never simulates, so it documents the position and is never Confirmed")}
}

// urlHrefBreakoutTemplates covers a URL reflection nested inside an element's
// href attribute when the injection point is the RAW QUERY STRING — the
// canonical-link class, where the page reflects the whole query blob into
// <link rel="canonical" href="…">.
//
// linkAttributeTemplates already covers a <link> element at every location, but
// it is deliberately element-gated (an anchor's href is navigated by the page
// itself, so adding shapes there would send a new request at every reflected
// anchor). This shape is the general href-position sibling the raw-query vector
// needs: it closes the attribute value with the site's OWN delimiter and adds
// an accesskey/onclick pair carrying nothing but the benign marker, so the one
// click activation browser verification performs can fire it.
//
// It is quote-aware (the delimiter comes from the analysed bytes, never assumed
// to be a double quote) and strict: the closing delimiter must arrive RAW. An
// HTML-encoded quote is decoded by the browser into the attribute VALUE, where
// it is an ordinary character and can never terminate the attribute, so a site
// that provably encodes its delimiter does not get this shape planned at all —
// the shape is dropped, not merely deprioritized (see strictSurvives).
//
// When the analyser could NOT prove the delimiter, ONE shape per quote style is
// planned (see breakoutQuotes) instead of guessing: each variant closes its own
// style, records it in Candidate.Delimiter, and names it in the rationale, so a
// report can say which style fired. The strict guard is applied per variant, so
// a style whose quote the site encodes is still dropped.
func urlHrefBreakoutTemplates(a ContextAnalysis, m string) []candTemplate {
	if a.Attribute != "href" || len(a.Chain) < 2 || a.Chain[0] != CtxHTMLAttrValue {
		return nil
	}
	styles := breakoutQuotes(a)
	out := make([]candTemplate, 0, len(styles))
	for _, style := range styles {
		q := quoteByte(style)
		tpl := onInteractionStrict(q+"accesskey='x' onclick="+m+" x="+q, q, 78,
			delimiterNote("close the href attribute value and add an accesskey/onclick pair on the element itself: accesskey names the element ('x') and onclick carries the benign marker as its whole body, so the single click activation browser verification performs dispatches it; it needs only the attribute's own quote, which encoding < and > does not affect, and the shape is only planned when that quote arrives raw", style))
		tpl.delimiter = style
		out = append(out, tpl)
	}
	return out
}

func cssTemplates(a ContextAnalysis, m string) []candTemplate {
	// Modern CSS cannot execute JavaScript; the only route to XSS is breaking
	// out of CSS back into HTML markup. There are two distinct ways in: a
	// <style> element's raw-text body, and — just as validly, and previously
	// missed entirely — the style="" ATTRIBUTE value, which is still an
	// ordinary HTML attribute: closing its quote and the tag reaches markup
	// regardless of whether the CSS before the quote is well-formed. The
	// browser's HTML parser finds the attribute's end by the quote character
	// alone; it never validates the CSS inside first.
	switch a.ConstructKind {
	case "style_body":
		return []candTemplate{onLoad("</style><svg onload="+m+">", "<>", 80,
			"break out of the <style> element into HTML and inject a marker handler")}
	case "attribute_value":
		var q, needs string
		switch a.Quote {
		case "double":
			q, needs = `"`, `"`
		case "single":
			q, needs = `'`, `'`
		}
		return []candTemplate{onLoad(q+"><svg onload="+m+">", needs+"<>", 80,
			"break out of the style attribute's quote and the tag, then inject a marker element — the CSS content before the quote never needs to be valid")}
	default:
		return nil
	}
}

func unknownTemplates(m string) []candTemplate {
	return []candTemplate{
		onLoad("<svg onload="+m+">", "<>", 30, "context could not be determined; generic markup/script probe"),
		markupProbe("<"+m+"x>", "<>", 25, "context could not be determined; generic markup-injection probe"),
	}
}

func prefixReason(prefix, base string) string {
	if prefix == "" {
		return base
	}
	return "close the enclosing construct (" + prefix + ") then " + base
}

// closingPrefix is the sequence an HTML-text breakout needs to close the
// enclosing construct first: "-->" inside a comment, and the matching end tag
// inside an RCDATA/RAWTEXT element (title, textarea, iframe, xmp, noscript…).
// Plain element content needs nothing. Shared by the canonical set and the
// variation packs so the two can never drift.
func closingPrefix(a ContextAnalysis) string {
	switch {
	case a.Context == CtxHTMLComment:
		return "-->"
	case a.Sub == "rcdata" || a.Sub == "rawtext" || a.Sub == "rawtext_noscript":
		if a.Element != "" {
			return "</" + a.Element + ">"
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// transformation-aware prioritization
// ---------------------------------------------------------------------------

// transform determines the expected transformation of a candidate's required
// characters at its site and adjusts the priority accordingly. A candidate whose
// required canary characters all survive keeps its template priority; one whose
// characters the site neutralizes is annotated and deprioritized, not dropped.
func transform(loc ReflectionLocation, tpl candTemplate, c *Candidate) (string, int) {
	survive, form := survives(loc, tpl.needs)
	if survive {
		return "raw", tpl.priority
	}
	c.Rationale = tpl.rationale + fmt.Sprintf(" (the site encodes/strips the characters this breakout needs: %s)", form)
	return form, neutralizedPriority(form)
}

// survives reports whether every canary metacharacter the candidate needs would
// reach the browser intact at this site, using the per-character encoding the
// reflection step recorded. A template that needs no canary character (needs=="")
// trivially survives. HTML entity-encoding does NOT neutralize a character the
// browser decodes before use — inside an event-handler, style, srcdoc, or URL
// attribute (an embedded sub-language), the chain is deeper than the attribute
// value, so &quot;/&lt; are decoded back before the inner parser sees them.
func survives(loc ReflectionLocation, needs string) (bool, string) {
	a := loc.Context
	entityDecoded := a != nil && len(a.Chain) >= 2 && a.Chain[0] == CtxHTMLAttrValue
	for _, ch := range needs {
		form := charForm(loc, string(ch))
		switch {
		case form == EncNone:
			continue
		case form == EncHTML && entityDecoded:
			continue // the browser decodes the entity back before using the value
		default:
			return false, form
		}
	}
	return true, EncNone
}

// strictSurvives is survives WITHOUT the attribute-sub-language entity
// exemption. A shape that closes an attribute value depends on the delimiter
// itself arriving raw: an HTML-encoded quote is decoded by the browser into the
// attribute VALUE, where it is an ordinary character, so it can never end the
// attribute — no matter that an event-handler body's entities would be decoded.
// Used only by strict templates; the canonical set keeps survives' behaviour
// unchanged.
func strictSurvives(loc ReflectionLocation, needs string) bool {
	for _, ch := range needs {
		if charForm(loc, string(ch)) != EncNone {
			return false
		}
	}
	return true
}

// charForm returns how a canary character came back at this site, from the
// per-character encoding analysis (falling back to the site's overall encoding,
// then to EncNone when nothing was recorded).
func charForm(loc ReflectionLocation, ch string) string {
	if f, ok := loc.PerChar[ch]; ok {
		return f
	}
	if loc.Encoding != "" {
		return loc.Encoding
	}
	return EncNone
}

func neutralizedPriority(form string) int {
	switch form {
	case EncStripped:
		return 1
	case EncHTML, EncJS, EncMixed:
		return 5
	default: // url, unknown
		return 8
	}
}

// Summary returns the distinct categories present, in priority order, for logs.
func (p *CandidatePlan) Summary() string {
	if p == nil || len(p.Candidates) == 0 {
		return "no candidates"
	}
	var cats []string
	seen := map[CandidateCategory]bool{}
	for _, c := range p.Candidates {
		if !seen[c.Category] {
			seen[c.Category] = true
			cats = append(cats, string(c.Category))
		}
	}
	return fmt.Sprintf("%d candidate(s): %s", len(p.Candidates), strings.Join(cats, ", "))
}
