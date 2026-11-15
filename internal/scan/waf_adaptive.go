package scan

// Response-driven WAF & sanitization adaptive evasion analyzer.
//
// This file answers a different question from internal/scan/evasion_escalation.go.
// The escalation pass decides WHEN one bounded, documented filter-bypass pass may
// run: only after every canonical candidate at an in-scope injection point
// completed without a confirmed execution signal, in the deterministic order
// internal/detection/evasion.go documents. This analyzer reads the target's OWN
// response and explains WHAT the filter did — was the probe blocked outright,
// was it reflected but rewritten, which primitive did not survive — and turns
// that evidence into a small, prioritized set of canary shapes worth trying
// next. The two complement each other: escalation owns the "when", this file
// owns the "why" and the "what next".
//
// It is a PURE function of two responses: no network, no browser, no queue, no
// LLM. It sends nothing, stores nothing, and changes no verdict. That keeps it
// usable from an executor, an API response, a report, or a test without
// widening the scan's request budget.
//
// Boundaries (AGENTS.md §2.2, §3):
//
//   - Every suggested payload is a benign canary: markup whose handler is the
//     bare marker token (a JS ReferenceError, never alert/cookie/exfiltration),
//     an arithmetic template expression, or a shell `echo` of the marker.
//     There is no SQL injection shape here, no destructive command, no file or
//     network access, and no proxy/TLS/timing/CAPTCHA technique — those live
//     behind separate operator opt-ins and are deliberately absent.
//   - A rate-limited probe (429/503, or Retry-After on a blocked response)
//     sets BackoffRequired and produces NO tactic: adding bypass requests while
//     the target asks for less traffic would ignore its own backpressure. This
//     mirrors the automatic escalation's 429/503 suppression. A 403 stays
//     eligible, because a filter rejecting the payload is exactly what these
//     shapes exist for.
//   - Nothing is lab- or target-specific. The rules are generic response
//     fingerprints (status codes, vendor headers/bodies) and generic
//     comparisons between the value sent and the value that came back.
//
// Detection is deliberately conservative: a transformation is only reported
// when the probe's own content survived in the response and the primitive is
// missing from the reflection window. Surrounding page markup can therefore
// hide a stripped primitive (a neighbouring tag's '>' looks like a survivor);
// the analyzer errs toward reporting fewer transformations, never more, so a
// suggestion is never justified by a guess.

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

const (
	// adaptationCanary is the fallback marker embedded in a suggested payload
	// when the probe carried no reusable token of its own. Every suggested
	// value is markup/expression/Echo built around this token, never an
	// exploit.
	adaptationCanary = "indago"
	// adaptMarkerPlaceholder is replaced with the per-plan canary when a tactic
	// is materialized, so the shape stays readable in the source table.
	adaptMarkerPlaceholder = "{marker}"
	// adaptBodyScan bounds how much of each body is inspected. A block page and
	// a reflected parameter both live near the top of a response.
	adaptBodyScan = 128 << 10
	// adaptMaxTactics bounds the suggestion list so one response can never turn
	// into a payload spray.
	adaptMaxTactics = 12
	// adaptVendorGeneric labels a block page/header that is recognisably a WAF
	// decision but does not identify its product.
	adaptVendorGeneric = "generic"
)

// Probe families a suggested payload belongs to.
const (
	adaptVectorHTML = "html"
	adaptVectorJS   = "js"
	adaptVectorURL  = "url"
	adaptVectorCMDi = "cmdi"
	adaptVectorSSTI = "ssti"
)

// Stable ids for what the response REMOVED from the probe. They are reported in
// AdaptationPlan.Sanitized and in EvasionTactic.Trigger.
const (
	adaptSanScriptTag      = "script_tag"
	adaptSanEventHandler   = "event_handler:"
	adaptSanQuotes         = "quotes"
	adaptSanAngleBrackets  = "angle_brackets"
	adaptSanSpaces         = "spaces"
	adaptSanTemplatePrefix = "template_delimiter:"
	adaptSanJSScheme       = "javascript_scheme"
)

// Stable ids for what the response REWROTE the probe into. They are reported in
// AdaptationPlan.Escaped.
const (
	adaptEscQuotesBackslash = "quotes:backslash"
	adaptEscQuotesEntity    = "quotes:html_entity"
	adaptEscQuotesPercent   = "quotes:percent_encoded"
	adaptEscAnglesEntity    = "angle_brackets:html_entity"
	adaptEscAnglesPercent   = "angle_brackets:percent_encoded"
	adaptEscAnglesJSEscape  = "angle_brackets:js_escape"
)

// EvasionTactic is one deterministic, prioritized suggestion derived from a
// response. It is DATA: nothing in this package sends it.
type EvasionTactic struct {
	// ID identifies the SHAPE, not this particular response, so a caller can
	// dedupe against shapes it already sent (the same convention
	// detection.Candidate.DedupKey uses for planned candidates).
	ID string `json:"id"`
	// Vector names the probe family the payload belongs to: html, js, url,
	// cmdi or ssti.
	Vector string `json:"vector"`
	// Trigger records the observed signal that selected this shape, e.g.
	// "script_tag", "event_handler:onload", "quotes:backslash", "spaces",
	// "template_delimiter:double_brace" or "waf_block".
	Trigger string `json:"trigger"`
	// Payload is the benign canary to send. It is a detection probe, never an
	// exploit.
	Payload string `json:"payload"`
	// Rationale explains why this shape answers the observed signal, including
	// its preconditions where the shape is only useful in a specific context.
	Rationale string `json:"rationale"`
	// Priority orders suggestions, higher first — the same convention as
	// detection.Candidate.Priority.
	Priority int `json:"priority"`
}

// AdaptationPlan is the pure result of comparing one probe response with its
// baseline. It is advisory data: no field is a verdict.
type AdaptationPlan struct {
	BaselineStatus int  `json:"baseline_status"`
	ProbeStatus    int  `json:"probe_status"`
	StatusChanged  bool `json:"status_changed"`

	// Blocked is true when the response carries a WAF/security block signal:
	// a block status that appears only for this probe, a recognised block page,
	// or a vendor fingerprint combined with either.
	Blocked bool `json:"blocked"`
	// BlockSignal is the stable identifier of that signal, empty when Blocked
	// is false.
	BlockSignal string `json:"block_signal,omitempty"`
	// WAFVendor names the edge/WAF identified by this response, or "generic"
	// for an unidentifiable WAF page/header. Empty when none is identified.
	// A vendor header alone is NOT a block signal (a normal Cloudflare-fronted
	// page carries CF-Ray too).
	WAFVendor string `json:"waf_vendor,omitempty"`

	// BackoffRequired is true when the target answered 429/503 or attached a
	// Retry-After to a failed response. When it is set, Tactics is empty.
	BackoffRequired bool `json:"backoff_required"`
	// RetryAfter is the raw Retry-After header value, and RetryAfterSeconds its
	// delta-seconds form when the header carried an integer (0 for an
	// HTTP-date, which is reported verbatim but not converted, so the analysis
	// stays a pure function of its inputs).
	RetryAfter        string `json:"retry_after,omitempty"`
	RetryAfterSeconds int    `json:"retry_after_seconds,omitempty"`

	// PayloadReflected reports whether the probe's content (or its marker, or
	// its bracket/quote-stripped core) was observed in the response at all.
	// A missing reflection proves nothing about a filter and yields no
	// sanitization advice.
	PayloadReflected bool `json:"payload_reflected"`
	// PayloadIntact reports whether the probe appeared verbatim. When it did,
	// no transformation is reported.
	PayloadIntact bool `json:"payload_intact"`

	// Sanitized lists what the response REMOVED, Escaped what it REWROTE.
	// Both are sorted and deduplicated.
	Sanitized []string `json:"sanitized,omitempty"`
	Escaped   []string `json:"escaped,omitempty"`

	// Tactics is the bounded, prioritized suggestion list. Empty (never
	// unbounded) when nothing can be justified.
	Tactics []EvasionTactic `json:"tactics,omitempty"`
	// Reason is a one-sentence explanation of the overall determination.
	Reason string `json:"reason,omitempty"`
	// Notes carries bounded supporting detail in a deterministic order.
	Notes []string `json:"notes,omitempty"`
}

// adaptBodySignal is one block-page fingerprint. Order matters: the first match
// wins, so vendor-specific pages are listed before the generic fallback.
type adaptBodySignal struct {
	id      string
	vendor  string
	needles []string
}

var adaptBodySignals = []adaptBodySignal{
	{id: "cloudflare_challenge", vendor: "Cloudflare", needles: []string{
		"cf-error-details", "cf_chl_opt", "cf-chl-", "challenge-platform",
		"just a moment...", "attention required! | cloudflare", "cloudflare ray id",
	}},
	{id: "modsecurity", vendor: "ModSecurity", needles: []string{
		"mod_security", "modsecurity", "this error was generated by modsecurity",
	}},
	{id: "aws_waf", vendor: "AWS WAF", needles: []string{
		"aws waf", "x-amzn-waf-action", "request blocked by aws",
	}},
	{id: "akamai", vendor: "Akamai", needles: []string{
		"akamaighost", "reference #18.",
	}},
	{id: "imperva", vendor: "Imperva", needles: []string{
		"incapsula", "_incapsula_resource", "request unsuccessful. incapsula",
	}},
	{id: "wordfence", vendor: "Wordfence", needles: []string{
		"wordfence", "wf-waf", "your access to this site has been limited",
	}},
	{id: "sucuri", vendor: "Sucuri", needles: []string{
		"sucuri_cloudproxy", "sucuri website firewall",
	}},
	// Generic security pages. Kept last and gated on a block status or a status
	// change so an ordinary page that merely mentions "forbidden" is never
	// treated as a filter decision.
	{id: "generic_waf_page", vendor: adaptVendorGeneric, needles: []string{
		"web application firewall", "request blocked", "request rejected",
		"access denied", "not acceptable", "security policy", "blocked by",
		"forbidden",
	}},
}

// adaptHeaderSignal is one edge/WAF header fingerprint.
type adaptHeaderSignal struct {
	vendor           string
	slug             string
	names            []string
	prefixes         []string
	serverSubstrings []string
}

var adaptHeaderSignals = []adaptHeaderSignal{
	{vendor: "Cloudflare", slug: "cloudflare_header", names: []string{"cf-ray", "cf-mitigated"}},
	{vendor: "AWS WAF", slug: "aws_waf_header", names: []string{"x-amzn-waf-action"}},
	{vendor: "Akamai", slug: "akamai_header", prefixes: []string{"x-akamai-"}, serverSubstrings: []string{"akamai"}},
	{vendor: "Imperva", slug: "imperva_header", names: []string{"x-iinfo"}, serverSubstrings: []string{"imperva", "incapsula"}},
	{vendor: "ModSecurity", slug: "modsecurity_header", serverSubstrings: []string{"modsecurity"}},
	{vendor: "Wordfence", slug: "wordfence_header", prefixes: []string{"x-wf-"}, serverSubstrings: []string{"wordfence"}},
	{vendor: "Sucuri", slug: "sucuri_header", prefixes: []string{"x-sucuri-"}, serverSubstrings: []string{"sucuri"}},
	{vendor: adaptVendorGeneric, slug: "waf_header", names: []string{"x-waf", "x-firewall", "x-protected-by"}},
}

// adaptBlockStatuses are the statuses that carry a filter/security decision.
// 503 is deliberately absent: it is backpressure, handled by BackoffRequired.
var adaptBlockStatuses = map[int]string{
	http.StatusForbidden:       "http_403_forbidden",
	http.StatusNotAcceptable:   "http_406_not_acceptable",
	http.StatusTeapot:          "http_418_teapot",
	http.StatusTooManyRequests: "http_429_rate_limited",
	http.StatusNotImplemented:  "http_501_not_implemented",
}

// adaptAnchorStopWords keeps a marker search from latching onto a language
// keyword that appears on every page ("script", "onload", ...). The list only
// affects anchor/marker SELECTION, never a claim about the response.
var adaptAnchorStopWords = map[string]bool{
	"script": true, "style": true, "html": true, "head": true, "body": true,
	"div": true, "span": true, "img": true, "image": true, "svg": true,
	"iframe": true, "frame": true, "input": true, "form": true, "button": true,
	"details": true, "summary": true, "alert": true, "confirm": true,
	"prompt": true, "document": true, "window": true, "function": true,
	"return": true, "var": true, "let": true, "const": true, "true": true,
	"false": true, "null": true, "undefined": true, "this": true,
	"typeof": true, "length": true, "value": true, "name": true, "type": true,
	"text": true, "href": true, "src": true, "onclick": true, "onerror": true,
	"onload": true, "onfocus": true, "ontoggle": true, "onpointerenter": true,
	"onmouseover": true, "onmouseenter": true, "javascript": true,
	"cookie": true, "console": true, "error": true, "string": true,
	"number": true, "object": true, "array": true, "echo": true,
	"printf": true, "whoami": true, "payload": true, "test": true,
	// Common DOM/JS API names: they look like identifiers but every page's own
	// scripts may contain them, so they must never become a reflection anchor.
	"getelementbyid": true, "queryselector": true, "queryselectorall": true,
	"addeventlistener": true, "createelement": true, "innerhtml": true,
	"outerhtml": true, "settimeout": true, "setinterval": true,
	"location": true, "navigator": true, "prototype": true,
	"constructor": true, "action": true, "method": true, "class": true,
	"data": true, "createelementns": true, "insertadjacenthtml": true,
}

// adaptEventHandlerNames is the fixed order handler stripping is reported in.
var adaptEventHandlerNames = []string{
	"onerror", "onload", "onfocus", "ontoggle",
	"onpointerenter", "onmouseover", "onanimationstart", "onpointerdown",
}

// adaptEventHandlerAlternatives are the replacement handlers, best first. Only
// handlers that did NOT appear in the probe are offered, so a suggestion never
// repeats a primitive the response already proved is filtered.
var adaptEventHandlerAlternatives = []struct {
	name     string
	id       string
	priority int
	value    string
	why      string
}{
	{"onfocus", "html_event_handler_onfocus", 58, `<svg tabindex=1 onfocus={marker} autofocus>`,
		"a different event handler on a focusable SVG element: tabindex makes it focusable and autofocus focuses it during page load, so onfocus fires without a click"},
	{"ontoggle", "html_event_handler_ontoggle", 56, `<details open ontoggle={marker}>`,
		"the details element's toggle event fires when its open state is applied at parse time, so this handler needs neither a click nor a hover"},
	{"onpointerenter", "html_event_handler_onpointerenter", 50, `<svg onpointerenter={marker}>`,
		"a pointer event handler from a different family: only useful when the verifier can synthesize the matching interaction, but it survives a filter that blocks only the mouse/error/load handler names"},
	{"onmouseover", "html_event_handler_onmouseover", 48, `<svg onmouseover={marker}>`,
		"the oldest alternative mouse handler — frequently missed by a filter written against onerror/onload, requires a hover"},
}

// adaptTemplateDelimiters are the template-expression delimiter pairs reported.
var adaptTemplateDelimiters = []struct {
	name  string
	open  string
	close string
}{
	{"double_brace", "{{", "}}"},
	{"dollar_brace", "${", "}"},
	{"erb", "<%", "%>"},
	{"hash_brace", "#{", "}"},
	{"star_brace", "*{", "}"},
	{"at_brace", "@{", "}"},
}

// adaptSSTIAlternatives are alternative template families, best first. Each one
// computes arithmetic (7*7 -> 49): harmless, and the computed value is the
// signal, so no marker token is needed.
var adaptSSTIAlternatives = []struct {
	name     string
	id       string
	priority int
	value    string
	why      string
}{
	{"erb", "ssti_erb", 63, "<%= 7*7 %>",
		"ERB/EJS-style expression: a different delimiter family that the same filter may not match, and a server-side evaluation returns 49"},
	{"dollar_brace", "ssti_dollar_brace", 61, "${7*7}",
		"Java/Spring-EL and JavaScript template-literal style expression; evaluates to 49 on a template engine that implements it"},
	{"double_brace", "ssti_double_brace", 59, "{{7*7}}",
		"Jinja/Twig/Handlebars-style expression; evaluates to 49 when that family is the one the target actually renders"},
	{"hash_brace", "ssti_hash_brace", 57, "#{7*7}",
		"Ruby/CoffeeScript-style interpolation; evaluates to 49"},
	{"star_brace", "ssti_star_brace", 55, "*{7*7}",
		"Thymeleaf selection expression; evaluates to 49"},
	{"at_brace", "ssti_at_brace", 53, "@{7*7}",
		"Razor-style expression; evaluates to 49"},
}

// adaptStructuralTokens are the tokens whose survival is scored when choosing
// which occurrence of the marker is the reflection (a page can echo a query
// value in several places). Only tokens present in the probe are scored.
var adaptStructuralTokens = []string{
	"<script", "</script", "<svg", "</svg", "<details", "<img", "<iframe",
	"<body", "<x-", "onerror", "onload", "onfocus", "ontoggle",
	"onpointerenter", "onmouseover", "onanimationstart", "javascript:",
	"{{", "}}", "${", "<%", "%>", "#{", "*{", "@{",
}

// adaptQuoteRules describe how each quote style can be rewritten. Escaped forms
// are checked before the raw character, so a page that also legitimately
// contains a quote in nearby markup cannot mask an escape.
var adaptQuoteRules = []struct {
	raw       string
	backslash []string
	entity    []string
	percent   []string
}{
	{
		raw:       `"`,
		backslash: []string{`\"`, `\x22`, `\u0022`},
		entity:    []string{"&quot;", "&#34;", "&#x22;", "&#034;"},
		percent:   []string{"%22"},
	},
	{
		raw:       `'`,
		backslash: []string{`\'`, `\x27`, `\u0027`},
		entity:    []string{"&#39;", "&#x27;", "&#039;", "&apos;"},
		percent:   []string{"%27"},
	},
}

// AnalyzeResponseAdaptation compares one probe response with its baseline and
// returns a deterministic adaptation plan.
//
// probePayload is the exact value that was sent. baselineStatus/probeStatus are
// the HTTP statuses; a zero baselineStatus means "no baseline available", in
// which case a block status is only believed when the response itself names a
// filter (a vendor fingerprint or an explicit block page). probeHeaders may be
// nil and is matched case-insensitively.
//
// The function is pure: same inputs always produce the same plan, and nothing is
// sent or stored.
func AnalyzeResponseAdaptation(probePayload string, baselineStatus int, baselineBody string, probeStatus int, probeHeaders map[string]string, probeBody string) AdaptationPlan {
	plan := AdaptationPlan{BaselineStatus: baselineStatus, ProbeStatus: probeStatus}
	if probeStatus == 0 {
		plan.Reason = "no probe response to analyse (transport error or timeout); nothing can be inferred about the target's filter"
		return plan
	}

	truncated := len(probeBody) > adaptBodyScan || len(baselineBody) > adaptBodyScan
	lowerProbeBody := adaptLowerBounded(probeBody)
	lowerBaselineBody := adaptLowerBounded(baselineBody)
	headers := adaptLowerHeaders(probeHeaders)

	// --- Block / backpressure classification -----------------------------
	statusSignal := adaptBlockSignal(probeStatus)
	statusChanged := baselineStatus != 0 && probeStatus != baselineStatus
	pageVendor, pageSignal := adaptBodyBlockSignal(lowerProbeBody)
	_, baselinePageSignal := adaptBodyBlockSignal(lowerBaselineBody)
	headerVendor, _ := adaptHeaderVendor(headers)

	// The baseline's headers are not part of this API, so a vendor header can
	// never be shown to be NEW; it labels a block, it does not create one. A
	// block-page fingerprint, by contrast, is compared against the baseline
	// body.
	newPageSignal := pageSignal != "" && pageSignal != baselinePageSignal

	switch {
	case statusSignal != "" && (statusChanged || newPageSignal):
		plan.Blocked = true
	case statusSignal == "" && pageSignal != "" && (statusChanged || headerVendor != ""):
		// A WAF that answers 200 with an interstitial is still a block, but
		// only the page/header must name it: a bare word in an unrelated page
		// is not enough on its own.
		plan.Blocked = true
	}
	plan.StatusChanged = statusChanged

	if plan.Blocked {
		switch {
		case statusSignal != "" && (pageSignal == "" || !newPageSignal):
			plan.BlockSignal = statusSignal
		case pageSignal != "":
			plan.BlockSignal = pageSignal
		default:
			plan.BlockSignal = statusSignal
		}
		plan.WAFVendor = pageVendor
		if plan.WAFVendor == adaptVendorGeneric && headerVendor != "" {
			plan.WAFVendor = headerVendor
		}
	}
	if plan.WAFVendor == "" && headerVendor != "" {
		// Factual edge identification only — a vendor header on its own never
		// sets Blocked.
		plan.WAFVendor = headerVendor
	}

	// --- Rate limiting ----------------------------------------------------
	plan.RetryAfter = adaptHeader(headers, "retry-after")
	retryParsed := false
	if plan.RetryAfter != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(plan.RetryAfter)); err == nil && n >= 0 {
			plan.RetryAfterSeconds = n
			retryParsed = true
		}
	}
	rateStatus := probeStatus == http.StatusTooManyRequests || probeStatus == http.StatusServiceUnavailable
	plan.BackoffRequired = rateStatus ||
		(plan.RetryAfter != "" && probeStatus >= http.StatusBadRequest)

	// --- Reflection and sanitization --------------------------------------
	canary := adaptCanaryToken(probePayload)
	anchor := adaptAnchor(probePayload)
	lowerPayload := strings.ToLower(probePayload)
	plan.PayloadIntact = lowerPayload != "" && strings.Contains(lowerProbeBody, lowerPayload)
	plan.PayloadReflected = plan.PayloadIntact ||
		(anchor != "" && strings.Contains(lowerProbeBody, anchor))

	var sanitized, escaped []string
	if plan.PayloadReflected && !plan.PayloadIntact {
		window := adaptReflectionWindow(lowerProbeBody, lowerPayload, anchor)
		sanitized, escaped = adaptSanitization(lowerPayload, lowerProbeBody, window)
	}
	plan.Sanitized = adaptSortedUnique(sanitized)
	plan.Escaped = adaptSortedUnique(escaped)

	// --- Tactics ----------------------------------------------------------
	if !plan.BackoffRequired {
		var lists [][]EvasionTactic
		if plan.Blocked {
			lists = append(lists, adaptWAFBlockTactics(canary))
		}
		if plan.PayloadReflected && !plan.PayloadIntact {
			lists = append(lists, adaptSanitizationTactics(probePayload, canary, plan.Sanitized, plan.Escaped))
		}
		plan.Tactics = adaptMergeTactics(lists...)
	}

	// --- Explanation ------------------------------------------------------
	if truncated {
		plan.Notes = append(plan.Notes, fmt.Sprintf("only the first %d bytes of each response body were analysed", adaptBodyScan))
	}
	if plan.Blocked && plan.PayloadReflected && !plan.PayloadIntact {
		plan.Notes = append(plan.Notes, "the probe was both blocked and partially reflected; the sanitization signals are the more specific evidence for choosing a shape")
	}
	if plan.RetryAfter != "" && !retryParsed {
		plan.Notes = append(plan.Notes, "Retry-After carried an HTTP-date; it is reported verbatim and not converted to a delta, so the analysis stays a pure function of these inputs")
	}
	if statusSignal != "" && !plan.Blocked {
		plan.Notes = append(plan.Notes, "the probe and the baseline both answered with a block status and no new filter signal, so that status is not evidence about this payload")
	}

	retryDetail := ""
	if plan.RetryAfter != "" {
		retryDetail = fmt.Sprintf(" (Retry-After %s)", plan.RetryAfter)
	}
	switch {
	case probePayload == "":
		plan.Reason = "no probe payload was supplied; only the block and backpressure signals were analysed"
	case plan.BackoffRequired:
		plan.Reason = fmt.Sprintf("HTTP %d is a rate-limit/backpressure answer%s, not a judgement on the payload; back off before sending any further probe and send no evasion shape in the meantime", probeStatus, retryDetail)
	case plan.Blocked:
		filter := "a WAF/security filter"
		if plan.WAFVendor != "" && plan.WAFVendor != adaptVendorGeneric {
			filter = plan.WAFVendor
		}
		plan.Reason = fmt.Sprintf("%s answered the probe with a block signal (%s, HTTP %d); the request SHAPE is what was rejected, so only documented benign-marker shape variations are suggested", filter, plan.BlockSignal, probeStatus)
	case !plan.PayloadReflected:
		plan.Reason = "the payload was not observed in the response, so no transformation can be inferred; a missing reflection may be a blind/stored/unused parameter rather than a filter"
	case plan.PayloadIntact:
		plan.Reason = "the payload survived verbatim: this response shows no rewriting of the probe, so a missing execution signal is a context/verification question, not a filter question"
	default:
		plan.Reason = fmt.Sprintf("the payload was reflected in altered form (%d stripped, %d escaped signal(s)); tactics target only the transformations actually observed", len(plan.Sanitized), len(plan.Escaped))
	}
	return plan
}

// adaptBlockSignal returns the stable id of a block status, or "".
func adaptBlockSignal(status int) string {
	return adaptBlockStatuses[status]
}

// adaptBodyBlockSignal returns the first recognisable WAF page fingerprint.
func adaptBodyBlockSignal(lowerBody string) (vendor, signal string) {
	if lowerBody == "" {
		return "", ""
	}
	for _, sig := range adaptBodySignals {
		for _, needle := range sig.needles {
			if strings.Contains(lowerBody, needle) {
				return sig.vendor, sig.id
			}
		}
	}
	return "", ""
}

// adaptHeaderVendor returns the first recognisable edge/WAF header fingerprint.
func adaptHeaderVendor(headers map[string]string) (vendor, signal string) {
	if len(headers) == 0 {
		return "", ""
	}
	server := strings.ToLower(headers["server"])
	for _, sig := range adaptHeaderSignals {
		for _, name := range sig.names {
			if _, ok := headers[name]; ok {
				return sig.vendor, sig.slug
			}
		}
		for _, prefix := range sig.prefixes {
			if adaptHasHeaderPrefix(headers, prefix) {
				return sig.vendor, sig.slug
			}
		}
		for _, sub := range sig.serverSubstrings {
			if sub != "" && strings.Contains(server, sub) {
				return sig.vendor, sig.slug
			}
		}
	}
	return "", ""
}

func adaptHasHeaderPrefix(headers map[string]string, prefix string) bool {
	for name := range headers {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func adaptHeader(headers map[string]string, name string) string {
	if len(headers) == 0 {
		return ""
	}
	return strings.TrimSpace(headers[strings.ToLower(name)])
}

// adaptLowerHeaders lowercases header NAMES only; values stay verbatim so
// Retry-After can be reported exactly as the target sent it. Names are visited
// in sorted order so a map carrying two spellings of the same header still
// normalizes deterministically.
func adaptLowerHeaders(headers map[string]string) map[string]string {
	if len(headers) == 0 {
		return nil
	}
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make(map[string]string, len(headers))
	for _, name := range names {
		out[strings.ToLower(strings.TrimSpace(name))] = headers[name]
	}
	return out
}

// adaptLowerBounded truncates a body to adaptBodyScan bytes (on a rune
// boundary) and lowercases it for substring matching.
func adaptLowerBounded(body string) string {
	if len(body) > adaptBodyScan {
		cut := adaptBodyScan
		for cut > 0 && body[cut]&0xC0 == 0x80 {
			cut--
		}
		body = body[:cut]
	}
	return strings.ToLower(body)
}

// adaptMarker returns the probe's most distinctive ASCII alphanumeric token,
// preserving its case, or "". Runs that are language keywords are skipped so a
// keyword-only probe cannot masquerade as a reflection anchor.
func adaptMarker(payload string) string {
	best := ""
	for i := 0; i < len(payload); {
		if !adaptIsASCIIAlnum(payload[i]) {
			i++
			continue
		}
		j := i
		for j < len(payload) && adaptIsASCIIAlnum(payload[j]) {
			j++
		}
		run := payload[i:j]
		if len(run) >= 3 && len(run) > len(best) && !adaptAnchorStopWords[strings.ToLower(run)] {
			best = run
		}
		i = j
	}
	return best
}

// adaptAnchor is the lowercase substring used to decide whether the probe's
// content reached the response. It is the marker when the probe has one, else
// the probe with its leading/trailing punctuation (template delimiters, quotes,
// angle brackets) trimmed — the part a filter cannot remove without discarding
// the payload's meaning.
func adaptAnchor(payload string) string {
	if marker := adaptMarker(payload); marker != "" {
		return strings.ToLower(marker)
	}
	trimmed := strings.ToLower(strings.TrimFunc(payload, func(r rune) bool {
		return !adaptIsAlnumRune(r)
	}))
	if len(trimmed) >= 3 {
		return trimmed
	}
	return ""
}

// adaptCanaryToken is the marker suggested payloads embed: the probe's own
// token when it has a clean one, so an operator recognizes the value, else the
// package fallback.
func adaptCanaryToken(payload string) string {
	marker := adaptMarker(payload)
	if len(marker) >= 3 && len(marker) <= 32 {
		return marker
	}
	return adaptationCanary
}

// adaptReflectionWindow returns the slice of the lowercased body around the
// occurrence of anchor that best matches the probe's structure. A page may echo
// the value in several places; scoring occurrences by surviving structural
// tokens picks the one that is actually the reflection.
func adaptReflectionWindow(lowerBody, lowerPayload, anchor string) string {
	if anchor == "" || lowerBody == "" {
		return lowerBody
	}
	margin := len(lowerPayload)
	if margin < 32 {
		margin = 32
	}
	if margin > 512 {
		margin = 512
	}
	var tokens []string
	for _, token := range adaptStructuralTokens {
		if strings.Contains(lowerPayload, token) {
			tokens = append(tokens, token)
		}
	}
	bestStart, bestEnd, bestScore := -1, -1, -1
	for from := 0; from <= len(lowerBody); {
		idx := strings.Index(lowerBody[from:], anchor)
		if idx < 0 {
			break
		}
		idx += from
		start := idx - margin
		if start < 0 {
			start = 0
		}
		end := idx + len(anchor) + margin
		if end > len(lowerBody) {
			end = len(lowerBody)
		}
		score := 0
		for _, token := range tokens {
			if strings.Contains(lowerBody[start:end], token) {
				score++
			}
		}
		if score > bestScore {
			bestStart, bestEnd, bestScore = start, end, score
		}
		from = idx + len(anchor)
	}
	if bestStart < 0 {
		return lowerBody
	}
	return lowerBody[bestStart:bestEnd]
}

// adaptSanitization compares the payload with the reflection window and reports
// what was removed (sanitized) and what was rewritten (escaped).
func adaptSanitization(lowerPayload, lowerBody, window string) (sanitized, escaped []string) {
	bracketsSurvived := adaptAngleBrackets(lowerPayload, window, &sanitized, &escaped)

	if bracketsSurvived {
		if strings.Contains(lowerPayload, "<script") && !strings.Contains(window, "<script") {
			sanitized = append(sanitized, adaptSanScriptTag)
		}
		for _, handler := range adaptEventHandlerNames {
			if strings.Contains(lowerPayload, handler) && !strings.Contains(window, handler) {
				sanitized = append(sanitized, adaptSanEventHandler+handler)
			}
		}
	}

	adaptQuoteEscapes(lowerPayload, window, &sanitized, &escaped)

	// Whitespace: a filter that strips spaces leaves the probe as one contiguous
	// token, so the de-spaced probe is an unambiguous signal.
	if strings.ContainsAny(lowerPayload, " \t") {
		compact := adaptStripWhitespace(lowerPayload)
		if len(compact) >= 6 && strings.Contains(lowerBody, compact) {
			sanitized = append(sanitized, adaptSanSpaces)
		}
	}

	for _, delim := range adaptTemplateDelimiters {
		// Only the OPENING delimiter identifies a template family. Testing the
		// closing one too would make every brace family match "}" and invent
		// transformations the response never performed.
		if !strings.Contains(lowerPayload, delim.open) {
			continue
		}
		if !strings.Contains(window, delim.open) || !strings.Contains(window, delim.close) {
			sanitized = append(sanitized, adaptSanTemplatePrefix+delim.name)
		}
	}

	if strings.Contains(lowerPayload, "javascript:") && !strings.Contains(window, "javascript:") {
		sanitized = append(sanitized, adaptSanJSScheme)
	}
	return sanitized, escaped
}

// adaptAngleBrackets reports how '<'/'>' were treated. It returns true when
// markup still parsed, i.e. when tag/handler checks are meaningful.
func adaptAngleBrackets(lowerPayload, window string, sanitized, escaped *[]string) bool {
	hasLT := strings.Contains(lowerPayload, "<")
	hasGT := strings.Contains(lowerPayload, ">")
	if !hasLT && !hasGT {
		return true
	}
	switch {
	case adaptContainsAny(window, []string{"&lt;", "&gt;", "&#60;", "&#62;", "&#x3c;", "&#x3e;", "&#060;", "&#062;"}):
		*escaped = append(*escaped, adaptEscAnglesEntity)
		return false
	case adaptContainsAny(window, []string{"%3c", "%3e"}):
		*escaped = append(*escaped, adaptEscAnglesPercent)
		return false
	case adaptContainsAny(window, []string{`\x3c`, `\x3e`, `\u003c`, `\u003e`}):
		*escaped = append(*escaped, adaptEscAnglesJSEscape)
		return false
	case hasLT && !strings.Contains(window, "<"):
		*sanitized = append(*sanitized, adaptSanAngleBrackets)
		return false
	case hasGT && !strings.Contains(window, ">"):
		*sanitized = append(*sanitized, adaptSanAngleBrackets)
		return false
	}
	return true
}

// adaptQuoteEscapes reports quote rewriting. Escaped forms win over a raw quote
// found elsewhere in the window, and a raw quote still present in the window is
// treated as survival (conservative: it may belong to neighbouring markup).
func adaptQuoteEscapes(lowerPayload, window string, sanitized, escaped *[]string) {
	for _, rule := range adaptQuoteRules {
		if !strings.Contains(lowerPayload, rule.raw) {
			continue
		}
		switch {
		case adaptContainsAny(window, rule.backslash):
			*escaped = append(*escaped, adaptEscQuotesBackslash)
		case adaptContainsAny(window, rule.entity):
			*escaped = append(*escaped, adaptEscQuotesEntity)
		case adaptContainsAny(window, rule.percent):
			*escaped = append(*escaped, adaptEscQuotesPercent)
		case !strings.Contains(window, rule.raw):
			*sanitized = append(*sanitized, adaptSanQuotes)
		}
	}
}

// adaptWAFBlockTactics are the documented benign-marker shape variations for an
// outright block. They mirror the technique families in
// internal/detection/evasion.go (case variation, alternative separator,
// alternative tag/handler) rather than introducing a new class.
func adaptWAFBlockTactics(canary string) []EvasionTactic {
	return []EvasionTactic{
		adaptNewTactic("html_case_variation", adaptVectorHTML, "waf_block", 54, "<SvG OnLoad={marker}>",
			"mixed-case element and attribute names: a signature written against the lowercase literals \"<svg\"/\"onload\" does not match, while HTML tag and attribute names are case-insensitive", canary),
		adaptNewTactic("html_alt_separator", adaptVectorHTML, "waf_block", 52, "<svg/onload={marker}>",
			"'/' where the markup expects whitespace before an attribute: the HTML tokenizer accepts it as an attribute boundary, so the element still parses", canary),
		adaptNewTactic("html_event_handler_details", adaptVectorHTML, "waf_block", 50, "<details open ontoggle={marker}>",
			"a different element and handler pair: if the filter's rule targets svg/img with onload/onerror, a details element's toggle event is untouched", canary),
	}
}

// adaptSanitizationTactics turns observed transformations into shapes. Every
// rule is keyed on evidence, never on a guess about the target.
func adaptSanitizationTactics(probePayload, canary string, sanitized, escaped []string) []EvasionTactic {
	hasSan := func(id string) bool { return adaptContainsString(sanitized, id) }
	hasEsc := func(id string) bool { return adaptContainsString(escaped, id) }

	var out []EvasionTactic

	if hasSan(adaptSanScriptTag) {
		out = append(out,
			adaptNewTactic("html_event_handler_svg", adaptVectorHTML, adaptSanScriptTag, 62, "<svg onload={marker}>",
				"the response dropped <script> but kept the marker, so elements are not all filtered; an SVG load handler is the smallest shape that still runs on load", canary),
			adaptNewTactic("html_event_handler_details", adaptVectorHTML, adaptSanScriptTag, 60, "<details open ontoggle={marker}>",
				"a non-script element whose toggle event fires when the open state is applied at parse time — no script tag and no user interaction needed", canary),
			adaptNewTactic("html_img_event_handler", adaptVectorHTML, adaptSanScriptTag, 46, "<img src=x onerror={marker}>",
				"the classic non-script element: onerror fires when the deliberately broken image fails to load, covering a filter that blocks only <script>", canary),
		)
	}

	strippedHandlers := adaptPrefixed(sanitized, adaptSanEventHandler)
	if len(strippedHandlers) > 0 {
		offered := 0
		for _, alt := range adaptEventHandlerAlternatives {
			if offered == 3 {
				break
			}
			if adaptContainsString(strippedHandlers, alt.name) {
				continue
			}
			out = append(out, adaptNewTactic(alt.id, adaptVectorHTML, adaptSanEventHandler+strippedHandlers[0], alt.priority, alt.value, alt.why, canary))
			offered++
		}
	}

	if hasSan(adaptSanQuotes) || hasEsc(adaptEscQuotesBackslash) || hasEsc(adaptEscQuotesEntity) || hasEsc(adaptEscQuotesPercent) {
		trigger := adaptSanQuotes
		switch {
		case hasEsc(adaptEscQuotesBackslash):
			trigger = adaptEscQuotesBackslash
		case hasEsc(adaptEscQuotesEntity):
			trigger = adaptEscQuotesEntity
		case hasEsc(adaptEscQuotesPercent):
			trigger = adaptEscQuotesPercent
		}
		out = append(out,
			adaptNewTactic("html_quote_less_handler", adaptVectorHTML, trigger, 57, "{marker} onfocus={marker} autofocus",
				"an unquoted attribute needs no quote to extend: this appends a focus handler to the existing attribute value and autofocus fires it on load; only meaningful when the sink attribute is unquoted", canary),
			adaptNewTactic("js_backtick_breakout", adaptVectorJS, trigger, 51, "`;{marker}//",
				"a backtick-terminated string literal: only useful when the reflection sits inside a JavaScript template literal or a backtick-quoted attribute, where an escaped ' or \" never terminates the value", canary),
			adaptNewTactic("html_entity_breakout", adaptVectorHTML, trigger, 28, "&quot;&gt;&lt;svg onload={marker}&gt;",
				"an entity-encoded breakout: the HTML parser resolves entities AFTER tokenizing an attribute, so this does NOT break out of a server-side attribute; it only helps when the value is later re-inserted through a second HTML parse (e.g. innerHTML)", canary),
		)
	}

	if hasSan(adaptSanSpaces) {
		if adaptLooksLikeCommandPayload(probePayload) {
			out = append(out,
				adaptNewTactic("cmdi_ifs_separator", adaptVectorCMDi, adaptSanSpaces, 61, ";echo${IFS}{marker}",
					"${IFS} expands to the shell's input field separator (space/tab/newline), so a tokenizer that strips literal spaces still splits the arguments; the command only echoes the canary", canary),
				adaptNewTactic("cmdi_tab_separator", adaptVectorCMDi, adaptSanSpaces, 59, ";echo\t{marker}",
					"a literal tab: the shell treats it exactly like a space as an argument separator, while a filter that strips only ' ' leaves it alone; the command only echoes the canary", canary),
			)
		}
		if adaptLooksLikeMarkupPayload(probePayload) {
			out = append(out, adaptNewTactic("html_alt_separator", adaptVectorHTML, adaptSanSpaces, 55, "<svg/onload={marker}>",
				"'/' before the attribute instead of a space: valid HTML attribute separation, so a filter that removes spaces cannot neutralize the tag", canary))
		}
	}

	strippedTemplates := adaptPrefixed(sanitized, adaptSanTemplatePrefix)
	if len(strippedTemplates) > 0 {
		offered := 0
		for _, alt := range adaptSSTIAlternatives {
			if offered == 2 {
				break
			}
			if adaptContainsString(strippedTemplates, alt.name) {
				continue
			}
			out = append(out, adaptNewTactic(alt.id, adaptVectorSSTI, adaptSanTemplatePrefix+strippedTemplates[0], alt.priority, alt.value, alt.why, canary))
			offered++
		}
	}

	if hasSan(adaptSanJSScheme) {
		out = append(out,
			adaptNewTactic("url_scheme_tab", adaptVectorURL, adaptSanJSScheme, 54, "java\tscript:{marker}",
				"a tab inside the scheme: the URL parser strips ASCII tab/newline from the whole URL before parsing it, so this parses identically to javascript:; only meaningful in an href/action-style sink", canary),
			adaptNewTactic("url_scheme_case", adaptVectorURL, adaptSanJSScheme, 52, "JaVaScRiPt:{marker}",
				"mixed-case scheme: URL schemes are case-insensitive to the parser but a literal lowercase signature is not; only meaningful in an href/action-style sink", canary),
		)
	}

	if hasEsc(adaptEscAnglesEntity) || hasEsc(adaptEscAnglesPercent) || hasEsc(adaptEscAnglesJSEscape) || hasSan(adaptSanAngleBrackets) {
		trigger := adaptSanAngleBrackets
		switch {
		case hasEsc(adaptEscAnglesEntity):
			trigger = adaptEscAnglesEntity
		case hasEsc(adaptEscAnglesPercent):
			trigger = adaptEscAnglesPercent
		case hasEsc(adaptEscAnglesJSEscape):
			trigger = adaptEscAnglesJSEscape
		}
		out = append(out, adaptNewTactic("js_string_quote_breakout", adaptVectorJS, trigger, 44, `';{marker}//`,
			"no markup survives, so pivot to the other context a reflection can land in: if the value also sits inside a JavaScript string, a quote terminator plus a comment needs no angle brackets at all", canary))
		if hasSan(adaptSanAngleBrackets) {
			out = append(out, adaptNewTactic("html_entity_breakout", adaptVectorHTML, trigger, 26, "&quot;&gt;&lt;svg onload={marker}&gt;",
				"the raw angle brackets were removed, so an entity-encoded breakout has nothing for a stripper to match; it only materializes through a second HTML parse such as a client-side innerHTML assignment", canary))
		}
	}

	return out
}

// adaptLooksLikeMarkupPayload reports whether a probe is HTML/XML-shaped, which
// is what makes whitespace advice tag-specific. A template expression such as
// "<%= 7*7 %>" also contains '<' but is not markup: only '<' followed by a tag
// character counts.
func adaptLooksLikeMarkupPayload(payload string) bool {
	for i := 0; i+1 < len(payload); i++ {
		if payload[i] != '<' {
			continue
		}
		switch next := payload[i+1]; {
		case next >= 'a' && next <= 'z', next >= 'A' && next <= 'Z', next == '/', next == '!':
			return true
		}
	}
	return false
}

// adaptLooksLikeCommandPayload reports whether a probe is shell-shaped, which
// is what makes the whitespace-stripping advice command-specific. It is a
// shape test on the operator's own probe, not a target-side inference.
func adaptLooksLikeCommandPayload(payload string) bool {
	lower := strings.ToLower(payload)
	if strings.Contains(lower, "echo") {
		return true
	}
	for _, separator := range []string{";", "|", "&&", "$(", "`"} {
		if strings.Contains(payload, separator) {
			return true
		}
	}
	return false
}

func adaptNewTactic(id, vector, trigger string, priority int, value, why, canary string) EvasionTactic {
	return EvasionTactic{
		ID:        id,
		Vector:    vector,
		Trigger:   trigger,
		Priority:  priority,
		Payload:   strings.ReplaceAll(value, adaptMarkerPlaceholder, canary),
		Rationale: why,
	}
}

// adaptMergeTactics deduplicates by shape id (keeping the highest priority
// copy, i.e. the most specific evidence), sorts by priority then id, and caps
// the result. The sort is a total order, so map-free deterministic output never
// depends on insertion order.
func adaptMergeTactics(lists ...[]EvasionTactic) []EvasionTactic {
	byID := make(map[string]EvasionTactic, adaptMaxTactics)
	for _, list := range lists {
		for _, tactic := range list {
			if tactic.ID == "" {
				continue
			}
			if prev, ok := byID[tactic.ID]; ok && prev.Priority >= tactic.Priority {
				continue
			}
			byID[tactic.ID] = tactic
		}
	}
	if len(byID) == 0 {
		return nil
	}
	out := make([]EvasionTactic, 0, len(byID))
	for _, tactic := range byID {
		out = append(out, tactic)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority > out[j].Priority
		}
		return out[i].ID < out[j].ID
	})
	if len(out) > adaptMaxTactics {
		out = out[:adaptMaxTactics]
	}
	return out
}

func adaptStripWhitespace(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\n', '\r', '\v', '\f':
			return -1
		}
		return r
	}, s)
}

func adaptPrefixed(list []string, prefix string) []string {
	var out []string
	for _, item := range list {
		if strings.HasPrefix(item, prefix) {
			out = append(out, strings.TrimPrefix(item, prefix))
		}
	}
	return out
}

func adaptSortedUnique(list []string) []string {
	if len(list) == 0 {
		return nil
	}
	sort.Strings(list)
	out := list[:1]
	for _, item := range list[1:] {
		if item != out[len(out)-1] {
			out = append(out, item)
		}
	}
	return out
}

func adaptContainsString(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

func adaptContainsAny(haystack string, needles []string) bool {
	for _, needle := range needles {
		if strings.Contains(haystack, needle) {
			return true
		}
	}
	return false
}

func adaptIsASCIIAlnum(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

func adaptIsAlnumRune(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
}
