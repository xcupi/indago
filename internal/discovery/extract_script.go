package discovery

import (
	"regexp"
	"sort"
	"strings"
	"unicode"
)

const (
	// maxScriptParamNames bounds how many script-derived names one page can add.
	maxScriptParamNames = 32
	maxScriptBlocks     = 64
	maxScriptMatches    = 128

	// maxScriptEndpointLiterals bounds how many endpoints one JavaScript asset
	// may contribute. A bundle can contain thousands of path literals (vendor
	// code, source maps, error strings); the cap keeps a single file from
	// flooding the queue.
	maxScriptEndpointLiterals = 32
	// maxScriptEndpointLiteralLen rejects minified blobs and embedded data.
	maxScriptEndpointLiteralLen = 256
)

var (
	scriptBlockRE = regexp.MustCompile(`(?is)<script\b[^>]*>(.*?)</script>`)
	// URL readers supported by this bounded heuristic. `.get()` is only
	// considered on a variable initialized with URLSearchParams.
	scriptParamPatterns = []*regexp.Regexp{
		regexp.MustCompile(`indexOf\(\s*["']([A-Za-z_][A-Za-z0-9_-]{0,31})=["']`),
		regexp.MustCompile(`getParameterByName\(\s*["']([A-Za-z_][A-Za-z0-9_-]{0,31})["']`),
	}
	scriptSearchParamsVarRE     = regexp.MustCompile(`(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:new\s+)?URLSearchParams\s*\(`)
	scriptSearchParamsGetRE     = regexp.MustCompile(`(?:new\s+)?URLSearchParams\s*\([^)]*\)\s*\.\s*get\(\s*["']([A-Za-z_][A-Za-z0-9_-]{0,31})["']\s*\)`)
	scriptSearchParamsGetCallRE = regexp.MustCompile(`\b([A-Za-z_$][A-Za-z0-9_$]*)\s*\.\s*get\(\s*["']([A-Za-z_][A-Za-z0-9_-]{0,31})["']\s*\)`)
)

// ExtractScriptParamNames returns bounded literal candidates from inline
// <script> bodies, sorted and unique (nil when none). It recognizes literal
// URL-read shapes only; matches are discovery input, not evidence that the URL
// controls a sink. The browser verdict still decides.
func ExtractScriptParamNames(body string) []string {
	seen := make(map[string]bool, maxScriptParamNames)
	addMatches := func(pattern *regexp.Regexp, text string) {
		if len(seen) >= maxScriptParamNames {
			return
		}
		for _, m := range pattern.FindAllStringSubmatch(text, maxScriptMatches) {
			seen[m[1]] = true
			if len(seen) >= maxScriptParamNames {
				return
			}
		}
	}

	for _, block := range scriptBlockRE.FindAllStringSubmatch(body, maxScriptBlocks) {
		if len(seen) >= maxScriptParamNames {
			break
		}
		script := block[1]
		for _, pattern := range scriptParamPatterns {
			addMatches(pattern, script)
		}
		addMatches(scriptSearchParamsGetRE, script)

		// Match `.get()` only on identifiers assigned a URLSearchParams instance
		// in this inline script, avoiding unrelated APIs such as Map.get(). Run
		// each regex once per block rather than compiling and rescanning per variable.
		searchParamsVars := make(map[string]struct{})
		for _, variable := range scriptSearchParamsVarRE.FindAllStringSubmatch(script, maxScriptMatches) {
			searchParamsVars[variable[1]] = struct{}{}
		}
		for _, call := range scriptSearchParamsGetCallRE.FindAllStringSubmatch(script, maxScriptMatches) {
			if _, ok := searchParamsVars[call[1]]; !ok {
				continue
			}
			seen[call[2]] = true
			if len(seen) >= maxScriptParamNames {
				break
			}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	names := make([]string, 0, len(seen))
	for n := range seen {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// scriptEndpointLiteralRE finds quoted root-relative paths in JavaScript
// source. It is deliberately syntax-blind: minified bundles, template strings
// and concatenation defeat a parser, while a path literal is recognizable
// without one.
var scriptEndpointLiteralRE = regexp.MustCompile(`["'](/[A-Za-z0-9._~!$&()*+,;=:@%/?-]{1,255})["']`)

// ExtractScriptEndpointLiterals returns the application paths a JavaScript
// asset names as string literals, sorted and unique (nil when none).
//
// This is discovery input, not evidence: a literal may be a dead route, a
// third-party path, or a string that only looks like a path. The collector
// still normalizes, scope-checks and deduplicates every result, and no verdict
// ever comes from here. Only root-relative paths are returned — absolute URLs
// would leave the scanned origin, and protocol-relative ("//cdn/x") values are
// almost always CDN references.
func ExtractScriptEndpointLiterals(body string) []string {
	if body == "" {
		return nil
	}
	seen := make(map[string]struct{}, maxScriptEndpointLiterals)
	out := make([]string, 0, maxScriptEndpointLiterals)
	for _, m := range scriptEndpointLiteralRE.FindAllStringSubmatch(body, maxScriptMatches) {
		literal := m[1]
		if !usableScriptEndpointLiteral(literal) {
			continue
		}
		if _, dup := seen[literal]; dup {
			continue
		}
		seen[literal] = struct{}{}
		out = append(out, literal)
		if len(out) >= maxScriptEndpointLiterals {
			break
		}
	}
	if len(out) == 0 {
		return nil
	}
	sort.Strings(out)
	return out
}

// usableScriptEndpointLiteral rejects values that cannot be an application
// path: template placeholders, escapes, markup, punctuation-only strings, and
// nested references to static assets (the same noise the queue filter drops).
func usableScriptEndpointLiteral(v string) bool {
	if len(v) < 3 || len(v) > maxScriptEndpointLiteralLen {
		return false
	}
	if !strings.HasPrefix(v, "/") || strings.HasPrefix(v, "//") {
		return false
	}
	if strings.ContainsAny(v, "{}\\<>\" ") {
		return false
	}
	if strings.ContainsFunc(v, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return false
	}
	if !strings.ContainsFunc(v, func(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) }) {
		return false
	}
	return !IsStaticAssetPath(v)
}
