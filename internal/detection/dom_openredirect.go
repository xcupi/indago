package detection

import (
	"net/url"
	"regexp"
	"strings"
)

const (
	// DOMOpenRedirectCanaryHost is reserved under RFC 2606 (.invalid is never
	// delegated), so a DOM redirect targeting it can never contact a real third
	// party even if a probe were ever followed.
	DOMOpenRedirectCanaryHost = "canary.invalid"

	// domOpenRedirectMarkerPrefix scopes the canary path so a redirect target
	// is attributed to the specific probe marker.
	domOpenRedirectMarkerPrefix = "/indago-redirect-"
)

// DOMOpenRedirectCanaryURL returns the non-resolvable external canary URL
// used to test DOM open-redirect sinks without leaving scope.
func DOMOpenRedirectCanaryURL(marker string) string {
	return "https://" + DOMOpenRedirectCanaryHost + domOpenRedirectMarkerPrefix + marker
}

// DOMOpenRedirectPayloads returns the bounded set of external-canary redirect
// shapes for a DOM source: an explicit HTTPS URL and a protocol-relative URL.
func DOMOpenRedirectPayloads(marker string) []string {
	if !validDOMXSSMarker(marker) {
		return nil
	}
	return []string{
		DOMOpenRedirectCanaryURL(marker),
		"//" + DOMOpenRedirectCanaryHost + domOpenRedirectMarkerPrefix + marker,
	}
}

// IsDOMOpenRedirectTarget reports whether target resolves to the reserved
// canary host and carries marker. A same-origin URL that merely echoes the
// canary inside its own query or fragment (e.g. /login?next=https://canary.invalid/...)
// returns false.
func IsDOMOpenRedirectTarget(target, marker, baseURL string) bool {
	target = strings.TrimSpace(target)
	if target == "" || marker == "" {
		return false
	}
	low := strings.ToLower(target)
	if strings.HasPrefix(low, "javascript:") || strings.HasPrefix(low, "data:") || strings.HasPrefix(low, "vbscript:") {
		return false
	}
	parsed, err := url.Parse(target)
	if err != nil {
		return false
	}
	if !parsed.IsAbs() && strings.HasPrefix(target, "//") {
		if base, berr := url.Parse(baseURL); berr == nil && base.Scheme != "" {
			parsed, err = base.Parse(target)
		} else {
			parsed, err = url.Parse("https:" + target)
		}
		if err != nil {
			return false
		}
	}
	if !parsed.IsAbs() {
		return false
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return false
	}
	if !strings.EqualFold(parsed.Hostname(), DOMOpenRedirectCanaryHost) {
		return false
	}
	return strings.Contains(parsed.Path, marker) || strings.Contains(parsed.RawQuery, marker) || strings.Contains(parsed.Fragment, marker)
}

// DOMOpenRedirectSite describes a statically detected client-side redirect
// surface in a page's HTML or scripts.
type DOMOpenRedirectSite struct {
	Source DOMXSSSource
	Sink   string // e.g. "location.assign", "window.open", "onclick.location"
	Param  string // query parameter name if known
}

var (
	reOnclickAttr       = regexp.MustCompile(`(?is)\bonclick\s*=\s*(?:"([^"]*)"|'([^']*)')`)
	reOnclickLocWrite   = regexp.MustCompile(`(?i)(?:location(?:\.href|\.assign|\.replace)?|window\.open)\b`)
	reOnclickParamRegex = regexp.MustCompile(`(?i)\b([a-zA-Z_][a-zA-Z0-9_]{0,31})\s*=`)
	reWindowOpenCall    = regexp.MustCompile(`(?i)\b(?:window\.)?open\s*\(`)
)

// DOMOpenRedirectOnclickParams extracts query-parameter names referenced inside
// inline onclick handlers that perform a location assignment or window.open.
func DOMOpenRedirectOnclickParams(html string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, m := range reOnclickAttr.FindAllStringSubmatch(html, -1) {
		body := m[1]
		if body == "" {
			body = m[2]
		}
		if !reOnclickLocWrite.MatchString(body) {
			continue
		}
		for _, pm := range reOnclickParamRegex.FindAllStringSubmatch(body, -1) {
			name := pm[1]
			low := strings.ToLower(name)
			// Skip common JS variable names in onclick expressions unless they
			// look like a query parameter match (e.g. /url=(...)/).
			if low == "href" || low == "location" || low == "returnurl" || low == "var" || low == "let" || low == "const" {
				continue
			}
			if _, ok := seen[name]; ok {
				continue
			}
			seen[name] = struct{}{}
			out = append(out, name)
		}
		// Also extract any explicit URLSearchParams/getParameterByName names in the onclick body.
		for _, p := range DOMXSSQueryParamNamesFromScripts([]DOMXSSScriptElement{{Body: body, Script: DOMXSSScriptInline, Line: 1}}) {
			if _, ok := seen[p.Name]; ok {
				continue
			}
			seen[p.Name] = struct{}{}
			out = append(out, p.Name)
		}
	}
	return out
}

// DOMOpenRedirectStaticSites inspects html and same-origin scripts for
// client-side navigation sinks reachable from DOM sources or inline onclick
// handlers.
func DOMOpenRedirectStaticSites(html, pageURL string, scripts []DOMXSSExternalScript) []DOMOpenRedirectSite {
	var sites []DOMOpenRedirectSite
	seen := make(map[string]struct{})
	add := func(src DOMXSSSource, sink, param string) {
		key := string(src) + "|" + sink + "|" + param
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		sites = append(sites, DOMOpenRedirectSite{Source: src, Sink: sink, Param: param})
	}

	// Inline onclick handlers that read a query parameter and assign location.
	for _, param := range DOMOpenRedirectOnclickParams(html) {
		add(DOMSourceQuery, "onclick.location", param)
	}

	// Static taint reachability across the primary DOM sources for navigation sinks.
	sources := []DOMXSSSource{
		DOMSourceQuery,
		DOMSourceHash,
		DOMSourceReferrer,
		DOMSourcePostMessage,
		DOMSourceWindowName,
	}
	for _, src := range sources {
		res := DOMXSSStaticReachabilityWithScripts(html, pageURL, src, "", scripts)
		for _, site := range res.Sites {
			if site.Sink == DOMSinkLocationAssign {
				add(src, string(site.Sink), "")
			}
		}
	}

	// Also detect window.open(...) when a source-tainted script mentions it.
	var scriptBodies []string
	var scriptElems []DOMXSSScriptElement
	for _, s := range scripts {
		if s.Unavailable() {
			continue
		}
		scriptBodies = append(scriptBodies, s.Body)
		scriptElems = append(scriptElems, DOMXSSScriptElement{Body: s.Body, Script: s.URL, Line: 1})
	}
	combined := html + "\n" + strings.Join(scriptBodies, "\n")
	if reWindowOpenCall.MatchString(combined) {
		for _, p := range DOMXSSQueryParamNamesFromHTML(html) {
			add(DOMSourceQuery, "window.open", p.Name)
		}
		for _, p := range DOMXSSQueryParamNamesFromScripts(scriptElems) {
			add(DOMSourceQuery, "window.open", p.Name)
		}
		if strings.Contains(combined, "location.hash") {
			add(DOMSourceHash, "window.open", "")
		}
		if strings.Contains(combined, "postMessage") || strings.Contains(combined, "onmessage") {
			add(DOMSourcePostMessage, "window.open", "")
		}
	}

	return sites
}
