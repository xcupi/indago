package discovery

import (
	"regexp"
	"sort"
)

const (
	// maxScriptParamNames bounds how many script-derived names one page can add.
	maxScriptParamNames = 32
	maxScriptBlocks     = 64
	maxScriptMatches    = 128
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
