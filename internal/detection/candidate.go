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
	// Priority orders execution: higher first. Candidates whose required
	// characters the site neutralizes are deprioritized, not hidden.
	Priority  int    `json:"priority"`
	Rationale string `json:"rationale"`
	// DedupKey collapses identical candidates arising from multiple sites.
	DedupKey string `json:"dedup_key"`
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
		if opts.EnableEvasion {
			tpls = append(tpls, evasionTemplatesFor(*loc.Context, marker)...)
		}
		for _, tpl := range tpls {
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
				Trigger:          tpl.trigger,
				Technique:        tpl.technique,
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
		return urlTemplates(a, m)
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
func markupProbe(value, needs string, priority int, why string) candTemplate {
	return candTemplate{value: value, needs: needs, priority: priority, rationale: why, trigger: TriggerNone}
}

func htmlTextTemplates(a ContextAnalysis, m string) []candTemplate {
	// In RCDATA/RAWTEXT (title/textarea/iframe/xmp/…) or a comment, markup is not
	// parsed until the construct closes, so the breakout must close it first.
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
		onLoad(prefix+"<svg onload="+m+">", "<>", 90,
			prefixReason(prefix, "inject an <svg> element whose onload handler references the benign marker")),
		// img onerror is a second, independent auto-firing vector: a filter
		// that specifically blocks "svg" (but not "img") still misses this one.
		// Not evasion — both are standard, unobfuscated constructs; this is
		// coverage of a second real-world auto-trigger, same as the planner
		// already tries two shapes elsewhere.
		onLoad(prefix+"<img src=x onerror="+m+">", "<>", 88,
			prefixReason(prefix, "inject an <img> with a deliberately-broken src so its onerror handler (fires automatically, no interaction) references the marker")),
		markupProbe(prefix+"<"+m+"x>", "<>", 60,
			prefixReason(prefix, "inject a marker element to detect raw markup injection without script")),
	}
}

func htmlAttrTemplates(a ContextAnalysis, m string) []candTemplate {
	var q, needs string
	switch a.Quote {
	case "double":
		q, needs = `"`, `"`
	case "single":
		q, needs = `'`, `'`
	default: // unquoted (or a tag/attr-name position)
		q, needs = "", ""
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
	}

	return []candTemplate{
		onLoad(q+"><svg onload="+m+">", needs+"<>", 90,
			"break out of the attribute and tag, then inject an <svg> element with an onload handler"),
		onLoad(autofocusHandler, needs, 87, autofocusRationale),
		// onmouseover needs a hover the passive verifier never simulates, so this
		// documents attribute injection but cannot itself be Confirmed.
		onInteraction(handler, needs, 85, handlerRationale),
	}
}

func jsTemplates(a ContextAnalysis, m string) []candTemplate {
	switch {
	case a.Context == CtxJSString && a.Sub == "single_quoted":
		return []candTemplate{onLoad("';"+m+"//", "'", 90, "close the single-quoted JS string and start a statement that references the marker")}
	case a.Context == CtxJSString && a.Sub == "double_quoted":
		return []candTemplate{onLoad(`";`+m+"//", `"`, 90, "close the double-quoted JS string and start a statement that references the marker")}
	case a.Context == CtxJSString && a.Sub == "template_literal":
		return []candTemplate{onLoad("${"+m+"}", "", 85, "inject a ${} substitution into the template literal")}
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
