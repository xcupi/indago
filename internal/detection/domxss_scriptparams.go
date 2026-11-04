package detection

import "strings"

// This file learns query-parameter NAMES from a page's own JavaScript.
//
// Why it exists: the location.search DOM source tests the names discovery
// found in URLs and forms. A page can read a name that appears in neither —
// `new URLSearchParams(location.search).get('storeId')` against a URL that
// only carries productId — and then the sink behind it is never reached. The
// name is knowable from the page itself, so it is read from there instead of
// guessed.
//
// Scope of the recogniser: LITERALS only. A name is returned only when it
// appears as a string (or a literal regex) in a recognised read shape:
//
//	URLSearchParams(...).get('name') / .getAll('name')      (also `new`,
//	                                                          window.location,
//	                                                          either quote)
//	var p = new URLSearchParams(location.search); p.get('name')
//	location.search.match(/[?&]name=/)                      (regex literal)
//	location.search.split('name=')                          (string literal)
//	location.href.indexOf("name=")                          (also includes,
//	                                                          lastIndexOf,
//	                                                          search)
//	getParameterByName('name')-style helpers               (literal argument)
//
// It is deliberately NOT a JavaScript parser and never guesses: `.get(v)` with
// a variable, `.get(a + b)`, a computed name, a URLSearchParams built from a
// constant or from location.hash, and `Map.get('x')` all yield nothing. The
// result is a candidate list, not evidence: the browser verdict remains the
// only authority (AGENTS.md §2.5/§2.6), and a name is only ever tested against
// the endpoint's own URL, never another host.

// DOMXSSScriptParam is one literal query-parameter name a page's own script
// reads, with the provenance a report needs to say where the name came from.
type DOMXSSScriptParam struct {
	Name string `json:"name"`
	// Script names the source of the literal: DOMXSSScriptInline for an
	// inline <script> body, or the absolute URL of the same-origin external
	// script the literal was read from.
	Script string `json:"script"`
	// Line is the 1-based line of the literal inside that script (inside the
	// page for an inline script).
	Line int `json:"line"`
}

const (
	// DOMXSSScriptInline is the DOMXSSScriptParam.Script value for an inline
	// <script> body.
	DOMXSSScriptInline = "inline"

	// DOMXSSScriptParamLimit bounds how many distinct script-derived names
	// one endpoint may contribute. Names already discovered in a URL or form
	// do not consume this budget; the cap is on EXTRA names, so a script that
	// reads many parameters cannot turn one endpoint into an unbounded number
	// of browser attempts. Twelve is the documented ceiling.
	DOMXSSScriptParamLimit = 12

	// DOMXSSScriptFetchLimit bounds how many same-origin external script
	// files the DOM pass reads for one endpoint, and DOMXSSScriptByteLimit
	// bounds each body it reads. Together with one document load these are
	// the whole discovery cost (see docs/dom-xss.md).
	DOMXSSScriptFetchLimit = 8
	DOMXSSScriptByteLimit  = 256 << 10

	// DOMXSSScriptSrcLimit bounds how many raw <script src> values are
	// extracted from one page before the caller filters them by origin.
	DOMXSSScriptSrcLimit = 64

	// domXSSParamNameMaxLen matches the longest parameter name this pass will
	// carry into a URL.
	domXSSParamNameMaxLen = 64
)

// DOMXSSQueryParamNamesFromHTML returns the distinct literal query-parameter
// names the page's own INLINE scripts read, in document/first-seen order and
// bounded by DOMXSSScriptParamLimit. External scripts are reported separately
// by DOMXSSScriptSrcs because reading their bodies needs the browser/network
// layer; this function stays pure.
func DOMXSSQueryParamNamesFromHTML(pageHTML string) []DOMXSSScriptParam {
	return domXSSQueryParamNamesFromScripts(dxsScriptElements(pageHTML))
}

// DOMXSSQueryParamNamesFromScripts is the same scan over already-extracted
// script elements. The caller (the DOM pass) uses it for external same-origin
// scripts it fetched itself, passing each body with its URL as Script.
func DOMXSSQueryParamNamesFromScripts(scripts []DOMXSSScriptElement) []DOMXSSScriptParam {
	return domXSSQueryParamNamesFromScripts(toDXSScripts(scripts))
}

// DOMXSSScriptElement is one <script> body with the provenance this file's
// API needs. Inline returns DOMXSSQueryParamNamesFromHTML; external bodies are
// read by the caller and passed here.
type DOMXSSScriptElement struct {
	Body string
	// Script is DOMXSSScriptInline or the absolute external URL.
	Script string
	// Line is the 1-based line of the body's first character in the page
	// (ignored/1 for an external body).
	Line int
}

func toDXSScripts(in []DOMXSSScriptElement) []dxsScript {
	out := make([]dxsScript, 0, len(in))
	for _, s := range in {
		line := s.Line
		if line <= 0 {
			line = 1
		}
		out = append(out, dxsScript{body: s.Body, line: line, javaScript: true, label: s.Script})
	}
	return out
}

// DOMXSSScriptSrcs returns the raw src attribute values of the page's
// JavaScript <script src=...> elements, bounded by DOMXSSScriptSrcLimit and
// deduplicated in document order. Values are returned as written (relative,
// protocol-relative, absolute); resolving them and keeping only same-origin
// ones is the caller's job, because that policy belongs with the network
// layer, not this pure package.
func DOMXSSScriptSrcs(pageHTML string) []string {
	var out []string
	seen := make(map[string]bool)
	for _, el := range dxsScriptElements(pageHTML) {
		if el.src == "" || !el.javaScript {
			continue
		}
		if seen[el.src] {
			continue
		}
		seen[el.src] = true
		out = append(out, el.src)
		if len(out) >= DOMXSSScriptSrcLimit {
			break
		}
	}
	return out
}

// DOMXSSMergeScriptParams deduplicates script-derived names in first-seen
// order (keeping the first provenance for a repeated name) and bounds the
// result at limit. The DOM pass uses it after appending external scripts'
// names to the inline ones; limit <= 0 means DOMXSSScriptParamLimit.
func DOMXSSMergeScriptParams(in []DOMXSSScriptParam, limit int) []DOMXSSScriptParam {
	if limit <= 0 {
		limit = DOMXSSScriptParamLimit
	}
	seen := make(map[string]bool, len(in))
	out := make([]DOMXSSScriptParam, 0, len(in))
	for _, p := range in {
		if p.Name == "" || seen[p.Name] {
			continue
		}
		seen[p.Name] = true
		out = append(out, p)
		if len(out) >= limit {
			break
		}
	}
	return out
}

// DOMXSSQueryParamNamesFromScript returns the literal query-parameter names
// one script body reads. Script identifies the body in the returned
// provenance (DOMXSSScriptInline or an external URL). The result is bounded
// by DOMXSSScriptParamLimit and ordered by first occurrence.
func DOMXSSQueryParamNamesFromScript(body, script string) []DOMXSSScriptParam {
	if script == "" {
		script = DOMXSSScriptInline
	}
	return domXSSQueryParamNamesFromScripts([]dxsScript{{body: body, line: 1, javaScript: true, label: script}})
}

func domXSSQueryParamNamesFromScripts(scripts []dxsScript) []DOMXSSScriptParam {
	var out []DOMXSSScriptParam
	seen := make(map[string]bool)
	for _, script := range scripts {
		if !script.javaScript {
			continue
		}
		label := script.label
		if label == "" {
			label = DOMXSSScriptInline
		}
		for _, found := range domXSSNamesInTokens(script.body) {
			if seen[found.Name] {
				continue
			}
			seen[found.Name] = true
			found.Script = label
			if label == DOMXSSScriptInline && found.Line > 0 {
				found.Line += script.line - 1
			}
			out = append(out, found)
			if len(out) >= DOMXSSScriptParamLimit {
				return out
			}
		}
	}
	return out
}

// domXSSNamesInTokens is the recogniser proper: a bounded, token-level scan of
// one JavaScript body. It reuses the DOM-XSS static pass's lexer (strings,
// regexes, templates and comments are tokenized, so a name inside a comment or
// a string that is not a call argument cannot be mistaken for a read), but not
// its parser: a syntax error or an unsupported construct must not discard the
// names that are plainly present.
func domXSSNamesInTokens(body string) []DOMXSSScriptParam {
	toks, _ := dxsTokenize(body, 1) // complete tokens stay usable after a lexer error
	if len(toks) == 0 {
		return nil
	}
	searchVars, paramsVars := domXSSScriptVars(toks)

	var out []DOMXSSScriptParam
	seen := make(map[string]bool)
	add := func(name string, line int) {
		if name == "" || seen[name] || len(out) >= DOMXSSScriptParamLimit {
			return
		}
		seen[name] = true
		out = append(out, DOMXSSScriptParam{Name: name, Line: line})
	}

	for i := 0; i < len(toks); i++ {
		t := toks[i]
		if t.kind != dxsTokIdent {
			continue
		}

		// new URLSearchParams(location.search).get('name') / .getAll('name'),
		// including the parenthesised `(new URLSearchParams(...)).get(...)`.
		if t.text == "URLSearchParams" && i+1 < len(toks) && dspIsPunct(toks[i+1], "(") {
			if end := dspCloseParen(toks, i+1); end >= 0 && dspRangeReadsQuery(toks, i+2, end, searchVars) {
				k := end + 1
				for extra := 0; extra < 2 && k < len(toks) && dspIsPunct(toks[k], ")"); extra++ {
					k++
				}
				if name, line, ok := dspGetCall(toks, k); ok {
					add(name, line)
				}
			}
			continue
		}

		// var p = new URLSearchParams(location.search); p.get('name')
		if paramsVars[t.text] {
			if name, line, ok := dspGetCall(toks, i+1); ok {
				add(name, line)
			}
		}

		// location.search.match(/[?&]name=/) and location.search.split('name=');
		// location.href/document.URL read the query string too.
		if dspIsLocationQueryMember(toks, i) || searchVars[t.text] {
			if name, line, ok := dspLocationMethodArg(toks, i+1); ok {
				add(name, line)
			}
		}

		// getParameterByName('name')-style helpers: the literal argument IS
		// the parameter name.
		if dspHelperIdent(t.text) && i+2 < len(toks) && dspIsPunct(toks[i+1], "(") && toks[i+2].kind == dxsTokString {
			if name, ok := domXSSValidParamName(toks[i+2].text); ok {
				add(name, toks[i+2].line)
			}
		}
	}
	return out
}

// domXSSScriptVars finds, in one bounded pass, the two kinds of local variable
// the recogniser needs:
//
//   - params vars: identifiers assigned `(new) URLSearchParams(<a query
//     reading>)`, so `p.get('name')` is a query read while an unrelated
//     `map.get('name')` is not;
//   - search vars: identifiers assigned a plain dotted path such as
//     `location.search`, `window.location.search` or `document.location.href`,
//     so `var qs = location.search; qs.split('name=')` is followed one level.
func domXSSScriptVars(toks []dxsTok) (search, params map[string]bool) {
	search = make(map[string]bool)
	params = make(map[string]bool)

	for i := 0; i+2 < len(toks); i++ {
		if toks[i].kind != dxsTokIdent || !dspIsPunct(toks[i+1], "=") {
			continue
		}
		// A dotted path only: identifiers joined by '.', ending at a
		// statement boundary. Anything else (a call, a literal, an operator)
		// does not make the variable a plain query-string alias.
		ok, mentionsLocation := true, false
		end := i + 2
		for ; end < len(toks) && end < i+9; end++ {
			tk := toks[end]
			if dspIsPunct(tk, ";") || dspIsPunct(tk, ",") || dspIsPunct(tk, ")") {
				break
			}
			switch {
			case tk.kind == dxsTokIdent:
				switch tk.text {
				case "location", "search", "href", "URL":
					mentionsLocation = true
				}
			case dspIsPunct(tk, "."):
			default:
				ok = false
			}
			if !ok {
				break
			}
		}
		if ok && end > i+2 && mentionsLocation {
			search[toks[i].text] = true
		}
	}

	for i := 0; i < len(toks); i++ {
		t := toks[i]
		if t.kind != dxsTokIdent || t.text != "URLSearchParams" || i+1 >= len(toks) || !dspIsPunct(toks[i+1], "(") {
			continue
		}
		end := dspCloseParen(toks, i+1)
		if end < 0 || !dspRangeReadsQuery(toks, i+2, end, search) {
			continue
		}
		j := i - 1
		if j >= 0 && dspIsIdent(toks[j], "new") {
			j--
		}
		if j >= 1 && dspIsPunct(toks[j], "=") && toks[j-1].kind == dxsTokIdent {
			params[toks[j-1].text] = true
		}
	}

	return search, params
}

// dspRangeReadsQuery reports whether a URLSearchParams argument range reads
// the QUERY string. `location.hash` is explicitly rejected: a name learned
// from a hash-fed parser belongs to the fragment source, and testing it
// against the query would test a name that script does not read there.
func dspRangeReadsQuery(toks []dxsTok, from, to int, searchVars map[string]bool) bool {
	sawHash, sawQuery, sawLocation := false, false, false
	for i := from; i < to && i < len(toks); i++ {
		t := toks[i]
		if t.kind != dxsTokIdent {
			continue
		}
		switch t.text {
		case "hash":
			sawHash = true
		case "search", "href", "URL":
			sawQuery = true
		case "location":
			sawLocation = true
		default:
			if searchVars[t.text] {
				sawQuery = true
			}
		}
	}
	if sawQuery {
		return true
	}
	// A bare `location` is a query read; `location.hash` is not.
	return sawLocation && !sawHash
}

func dspIsLocationQueryMember(toks []dxsTok, i int) bool {
	if i < 2 || toks[i].kind != dxsTokIdent || !dspIsPunct(toks[i-1], ".") || toks[i-2].kind != dxsTokIdent {
		return false
	}
	switch toks[i].text {
	case "search", "href":
		return toks[i-2].text == "location"
	case "URL":
		return toks[i-2].text == "document"
	}
	return false
}

// dspGetCall matches `. get|getAll ( 'literal'` starting at dotIdx and returns
// the literal as a parameter name.
func dspGetCall(toks []dxsTok, dotIdx int) (string, int, bool) {
	if dotIdx+3 >= len(toks) || !dspIsPunct(toks[dotIdx], ".") || toks[dotIdx+1].kind != dxsTokIdent {
		return "", 0, false
	}
	switch toks[dotIdx+1].text {
	case "get", "getAll":
	default:
		return "", 0, false
	}
	if !dspIsPunct(toks[dotIdx+2], "(") || toks[dotIdx+3].kind != dxsTokString {
		return "", 0, false
	}
	// The literal must be the whole argument, not one operand of an
	// expression such as get('a' + suffix).
	if dotIdx+4 < len(toks) && !dspIsPunct(toks[dotIdx+4], ")") && !dspIsPunct(toks[dotIdx+4], ",") {
		return "", 0, false
	}
	name, ok := domXSSValidParamName(toks[dotIdx+3].text)
	return name, toks[dotIdx+3].line, ok
}

// dspLocationMethodArg matches `. method ( 'name=' )` / `. method ( /name=/ )`
// starting at dotIdx for the string/regex methods that read a named query
// parameter.
func dspLocationMethodArg(toks []dxsTok, dotIdx int) (string, int, bool) {
	if dotIdx+3 >= len(toks) || !dspIsPunct(toks[dotIdx], ".") || toks[dotIdx+1].kind != dxsTokIdent {
		return "", 0, false
	}
	switch toks[dotIdx+1].text {
	case "split", "match", "indexOf", "lastIndexOf", "includes", "search":
	default:
		return "", 0, false
	}
	if !dspIsPunct(toks[dotIdx+2], "(") {
		return "", 0, false
	}
	arg := toks[dotIdx+3]
	if arg.kind != dxsTokString && arg.kind != dxsTokRegex {
		return "", 0, false
	}
	if dotIdx+4 < len(toks) && !dspIsPunct(toks[dotIdx+4], ")") && !dspIsPunct(toks[dotIdx+4], ",") {
		return "", 0, false
	}
	name, ok := domXSSNameFromSearchLiteral(arg.text, arg.kind == dxsTokRegex)
	return name, arg.line, ok
}

// domXSSNameFromSearchLiteral extracts a parameter name from a literal that
// names one: 'name=' / '?name=' / '&name=' and the regex equivalents.
func domXSSNameFromSearchLiteral(lit string, isRegex bool) (string, bool) {
	if isRegex {
		return domXSSNameFromRegex(lit)
	}
	s := strings.TrimSpace(lit)
	s = strings.TrimPrefix(s, "?")
	s = strings.TrimPrefix(s, "&")
	if !strings.HasSuffix(s, "=") {
		return "", false
	}
	return domXSSValidParamName(strings.TrimSuffix(s, "="))
}

// domXSSNameFromRegex extracts the name from a regex literal whose text names
// one parameter, e.g. /[?&]name=/ or /\bname=/. Character classes and
// quantifiers are not interpreted: only a plain run of name characters
// immediately before '=' and preceded by a delimiter counts, so a dynamic
// expression such as /([a-z]+)=/ yields nothing.
func domXSSNameFromRegex(lit string) (string, bool) {
	body := lit
	if strings.HasPrefix(body, "/") {
		end := -1
		for i := len(body) - 1; i > 0; i-- {
			if body[i] == '/' && body[i-1] != '\\' {
				end = i
				break
			}
		}
		if end < 0 {
			return "", false
		}
		body = body[1:end]
	}
	for k := 0; k < len(body); k++ {
		if body[k] != '=' {
			continue
		}
		j := k
		for j > 0 && domXSSRegexNameChar(body[j-1]) {
			j--
		}
		if j == k {
			continue
		}
		if j > 0 {
			switch c := body[j-1]; c {
			case '?', '&', ']', ')', '|', '(', '^', '[', '\\':
				// delimiter before the name
			case 'b':
				if j < 2 || body[j-2] != '\\' {
					continue
				}
			default:
				continue
			}
		}
		if name, ok := domXSSValidParamName(body[j:k]); ok {
			return name, true
		}
	}
	return "", false
}

func domXSSRegexNameChar(c byte) bool {
	return c == '_' || c == '-' || c == '.' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// domXSSValidParamName accepts a name that can be carried as a query
// parameter: an identifier-like start, then identifier characters plus the
// dot/hyphen/bracket forms frameworks use (user[name]).
func domXSSValidParamName(name string) (string, bool) {
	if name == "" || len(name) > domXSSParamNameMaxLen {
		return "", false
	}
	start := name[0]
	if !(start == '_' || start >= 'a' && start <= 'z' || start >= 'A' && start <= 'Z') {
		return "", false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c == '_' || c == '-' || c == '.' || c == '[' || c == ']' ||
			c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			continue
		}
		return "", false
	}
	return name, true
}

// dspHelperIdent recognises the conventional "give me a query parameter"
// helper names. It requires both a parameter-ish word AND a query-ish prefix,
// so parseParams(...), getElementById(...) and Map.get(...) are not treated as
// query reads.
func dspHelperIdent(name string) bool {
	l := strings.ToLower(name)
	if strings.Contains(l, "urlsearchparams") || !strings.Contains(l, "param") {
		return false
	}
	return strings.HasPrefix(l, "get") || strings.Contains(l, "query") ||
		strings.Contains(l, "url") || strings.Contains(l, "search")
}

func dspCloseParen(toks []dxsTok, open int) int {
	if open >= len(toks) || !dspIsPunct(toks[open], "(") {
		return -1
	}
	depth := 0
	for i := open; i < len(toks); i++ {
		if toks[i].kind != dxsTokPunct {
			continue
		}
		switch toks[i].text {
		case "(", "[", "{":
			depth++
		case ")", "]", "}":
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func dspIsPunct(t dxsTok, s string) bool { return t.kind == dxsTokPunct && t.text == s }
func dspIsIdent(t dxsTok, s string) bool { return t.kind == dxsTokIdent && t.text == s }
