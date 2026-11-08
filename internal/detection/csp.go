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

import "bytes"

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
