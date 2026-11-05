package accesscontrol

// Path disclosure: where a candidate administrative path may come from.
//
// The engine never guesses a path and never consults a wordlist. Case 19's
// candidates are paths the TARGET ITSELF disclosed:
//
//   - /robots.txt Allow/Disallow directives (consumed by discovery, which
//     registers the disclosed path as an endpoint with SourceRobots; the scan
//     side then probes that endpoint directly — see the panel mode in
//     internal/scan/accesscontrol.go);
//   - a path literal inside a page's OWN inline or same-origin external
//     scripts, which is how an "unpredictable" admin panel (/admin-8f3a2b) is
//     disclosed in practice.
//
// This file implements the second source: it splits one fetched page into the
// script bodies worth reading and reads administrative path literals out of
// them. Everything is deterministic and offline; the scan side does the
// fetching.
//
// The parse is deliberately forgiving: malformed markup still yields whatever
// script elements the HTML5 parser recovered, because a page's own syntax
// errors must not turn into "this page discloses nothing".

import (
	"bytes"
	"fmt"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

const (
	// MaxScriptsPerPage bounds how many same-origin external scripts one page
	// may contribute. The page's own inline scripts are always analysed; this
	// caps the extra files, not the page.
	MaxScriptsPerPage = 8
	// MaxRefsPerScript bounds how many administrative paths are taken from one
	// script body.
	MaxRefsPerScript = 5
	// MaxLiteralLen bounds a string literal we will consider. A path is short;
	// a longer literal is data (a bundle, a template), not a route.
	MaxLiteralLen = 512
	// MaxPathLen bounds an accepted administrative path.
	MaxPathLen = 200
)

// Skip reasons recorded for an external script reference that was not
// analysed. They are stable strings because they are persisted.
const (
	SkipForeignURL  = "not same-origin"
	SkipPageCap     = "per-page script cap reached"
	SkipEmptyURL    = "empty script src"
	SkipUnparseable = "unparseable script src"
)

// Ref is one administrative path a page references, with provenance.
type Ref struct {
	// Path is the absolute path exactly as the page referenced it (a leading
	// "/", optionally a query string). It is never guessed: it is the literal
	// the page's own script contains.
	Path string `json:"path"`
	// Source names what carried the literal: "inline script" for a page's own
	// script body, or the absolute URL of an external script.
	Source string `json:"source"`
}

// Describe renders the provenance for a human-readable reason string.
func (r Ref) Describe() string {
	switch r.Source {
	case "":
		return fmt.Sprintf("%s (referenced by the page itself)", r.Path)
	case "inline script":
		return fmt.Sprintf("%s (referenced by the page's own inline script)", r.Path)
	default:
		return fmt.Sprintf("%s (referenced by %s)", r.Path, r.Source)
	}
}

// Skip records an external script reference that was deliberately not
// analysed, so "no path found" is never confused with "could not look".
type Skip struct {
	URL    string `json:"url"`
	Reason string `json:"reason"`
}

// Scripts is what one fetched HTML page contributes to the analysis.
type Scripts struct {
	// Inline holds the bodies of <script> elements without a src.
	Inline []string
	// External holds absolute, same-origin script URLs, de-duplicated and
	// capped at MaxScriptsPerPage.
	External []string
	// Skipped holds references that were not followed, with the reason.
	Skipped []Skip
}

// ExtractScripts splits one fetched page into the script bodies to analyse:
// its own inline <script> elements, and the same-origin external scripts it
// references. Cross-origin, data: and malformed references are recorded as
// skipped — never fetched, never silently treated as "contains nothing".
func ExtractScripts(pageURL string, body []byte) Scripts {
	var out Scripts
	base, err := url.Parse(strings.TrimSpace(pageURL))
	if err != nil || base.Host == "" {
		return out
	}
	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return out
	}
	seen := make(map[string]bool)
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "script" {
			if src, ok := attrValue(n, "src"); ok {
				src = strings.TrimSpace(src)
				switch {
				case src == "":
					out.Skipped = append(out.Skipped, Skip{URL: src, Reason: SkipEmptyURL})
				case len(out.External) >= MaxScriptsPerPage:
					out.Skipped = append(out.Skipped, Skip{URL: src, Reason: SkipPageCap})
				default:
					resolved, ok := resolveSameOrigin(src, base)
					if !ok {
						out.Skipped = append(out.Skipped, Skip{URL: src, Reason: SkipForeignURL})
					} else if !seen[resolved] {
						seen[resolved] = true
						out.External = append(out.External, resolved)
					}
				}
			} else if text := nodeTextRaw(n); strings.TrimSpace(text) != "" {
				out.Inline = append(out.Inline, text)
			}
			// ElementNode children of a <script> are text; no need to descend.
			return
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return out
}

// RefsFromScript returns the administrative-path literals a script body
// contains: JavaScript string literals that begin with "/" and whose path names
// an administrative area.
//
// String literals are read with a small scanner rather than a regexp so
// comments are skipped and escaped quotes cannot truncate a literal half-way.
// Anything ambiguous — an escape sequence other than \\ \/ \' \" `, or a
// literal longer than MaxLiteralLen — is refused rather than interpreted.
func RefsFromScript(body, source string) []Ref {
	var out []Ref
	seen := make(map[string]bool)
	b := []byte(body)
	for i := 0; i < len(b) && len(out) < MaxRefsPerScript; {
		switch {
		case b[i] == '/' && i+1 < len(b) && b[i+1] == '/':
			for i < len(b) && b[i] != '\n' {
				i++
			}
		case b[i] == '/' && i+1 < len(b) && b[i+1] == '*':
			i += 2
			for i+1 < len(b) && !(b[i] == '*' && b[i+1] == '/') {
				i++
			}
			i += 2
		case b[i] == '\'' || b[i] == '"' || b[i] == '`':
			literal, next, ok := readStringLiteral(b, i)
			i = next
			if !ok {
				continue
			}
			path, ok := AdminPath(literal)
			if !ok || seen[path] {
				continue
			}
			seen[path] = true
			out = append(out, Ref{Path: path, Source: source})
		default:
			i++
		}
	}
	return out
}

// AdminPath canonicalises one candidate string and reports whether it names an
// administrative area on this origin.
//
// Accepted shape: a single-origin absolute path ("/admin-xyz", "/manager/",
// "/panel?view=users"), at most MaxPathLen bytes, containing no whitespace or
// control characters, no quotes/markup, no backslash, no fragment, and no ".."
// segment. "//host/x" is refused: that is a protocol-relative URL, i.e. a
// DIFFERENT origin, not a path on this one.
//
// The administrative test is segment-based (see AdminLikePath). A path whose
// last segment is a static asset (.js, .css, an image, a font, a source map) is
// refused — those are resources a page loads, not an admin console.
func AdminPath(raw string) (string, bool) {
	p := strings.TrimSpace(raw)
	if p == "" || len(p) > MaxPathLen {
		return "", false
	}
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") {
		return "", false
	}
	for _, r := range p {
		if r < 0x21 || r == 0x7f {
			return "", false // whitespace and control characters
		}
		switch r {
		case '\\', '"', '\'', '<', '>', '`', '#':
			return "", false
		}
	}
	if strings.Contains(p, "..") {
		return "", false
	}
	pathPart, query := p, ""
	if i := strings.IndexByte(p, '?'); i >= 0 {
		pathPart, query = p[:i], p[i:]
	}
	if strings.Contains(pathPart, "//") {
		return "", false
	}
	if !adminPathLike(pathPart) {
		return "", false
	}
	pathPart = strings.TrimRight(pathPart, "/")
	if pathPart == "" {
		pathPart = "/"
	}
	if assetPath(pathPart) {
		return "", false
	}
	return pathPart + query, true
}

// PageAnalyzable reports whether a discovered endpoint URL is worth fetching as
// a page that might disclose a route in its scripts. Non-HTTP(S) URLs, static
// assets and script/style files themselves are refused.
func PageAnalyzable(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	return !assetPath(u.Path)
}

// SameOrigin reports whether two URLs share scheme, host and effective port.
// It is stricter than RFC 6265 cookie scoping on purpose: an injected value or
// a disclosed path is never carried across an origin boundary.
func SameOrigin(a, b *url.URL) bool {
	if a == nil || b == nil {
		return false
	}
	if !strings.EqualFold(a.Scheme, b.Scheme) || !strings.EqualFold(a.Hostname(), b.Hostname()) {
		return false
	}
	return effectivePort(a) == effectivePort(b)
}

func effectivePort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	switch strings.ToLower(u.Scheme) {
	case "http":
		return "80"
	case "https":
		return "443"
	}
	return ""
}

var assetExtensions = []string{
	".js", ".mjs", ".cjs", ".css", ".map", ".json", ".xml", ".txt", ".csv",
	".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".bmp",
	".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp4", ".webm", ".mp3", ".pdf", ".zip",
}

func assetPath(path string) bool {
	lower := strings.ToLower(path)
	for _, ext := range assetExtensions {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

// readStringLiteral reads one '…', "…" or `…` literal starting at start and
// returns its unescaped value and the offset just past the closing quote. ok is
// false for an unterminated literal, a literal spanning lines, an escape
// sequence this scanner refuses to interpret, or one longer than
// MaxLiteralLen.
func readStringLiteral(b []byte, start int) (string, int, bool) {
	quote := b[start]
	var sb strings.Builder
	truncated := false
	i := start + 1
	for i < len(b) {
		ch := b[i]
		if ch == '\\' {
			if i+1 >= len(b) {
				return "", len(b), false
			}
			switch esc := b[i+1]; esc {
			case '\\', '/', '\'', '"', '`':
				if !truncated {
					sb.WriteByte(esc)
				}
			default:
				// \u002f, \x2f, \n, line continuations: refuse to guess.
				return "", i + 2, false
			}
			i += 2
			continue
		}
		if ch == quote {
			return sb.String(), i + 1, !truncated
		}
		if ch == '\n' || ch == '\r' {
			return "", i + 1, false
		}
		if sb.Len() >= MaxLiteralLen {
			truncated = true
		} else {
			sb.WriteByte(ch)
		}
		i++
	}
	return "", len(b), false
}

func resolveSameOrigin(raw string, base *url.URL) (string, bool) {
	ref, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || ref.Host == "" && ref.Scheme != "" {
		return "", false
	}
	if ref.Scheme != "" && ref.Scheme != "http" && ref.Scheme != "https" {
		return "", false // data:, blob:, javascript:, …
	}
	resolved := base.ResolveReference(ref)
	if !SameOrigin(base, resolved) {
		return "", false
	}
	return resolved.String(), true
}

func attrValue(n *html.Node, key string) (string, bool) {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, key) {
			return a.Val, true
		}
	}
	return "", false
}

// nodeTextRaw is the unnormalised text of a subtree, used to recover a
// <script> body exactly enough for the literal scanner (which does its own
// whitespace and comment handling).
func nodeTextRaw(n *html.Node) string {
	var sb strings.Builder
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.TextNode {
			sb.WriteString(node.Data)
		}
		for c := node.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return sb.String()
}
