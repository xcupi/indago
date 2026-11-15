package discovery

import (
	"path"
	"strings"
)

// staticAssetExtensions are resource types that have no useful reflection
// surface of their own. Crawlers and browser-network capture see them because
// a page references them, but turning each into a test endpoint only spends
// the scan's request budget on CSS/JS/font/image URLs. Operator-supplied seeds
// are intentionally exempt: if the operator asks to scan one, that is explicit
// intent.
var staticAssetExtensions = map[string]struct{}{
	".css": {}, ".js": {}, ".mjs": {}, ".map": {},
	".png": {}, ".jpg": {}, ".jpeg": {}, ".gif": {}, ".webp": {}, ".avif": {}, ".bmp": {},
	".svg": {}, ".ico": {},
	".woff": {}, ".woff2": {}, ".ttf": {}, ".otf": {}, ".eot": {},
	".mp3": {}, ".mp4": {}, ".webm": {}, ".ogg": {}, ".wav": {}, ".pdf": {},
}

// scriptAssetExtensions are the static resources whose *contents* are still
// worth reading during a crawl. A JavaScript bundle names the endpoints the
// application calls ("/api/v1/users", "/graphql"), so the crawler fetches a
// bounded number of script assets to mine those literals
// (crawlSource.harvestScriptEndpoints) even though the asset itself is never
// registered as a test target. Filtering a URL out of the test queue must not
// blind script-literal extraction; keeping the two decisions separate is what
// makes that possible.
var scriptAssetExtensions = map[string]struct{}{".js": {}, ".mjs": {}}

// IsStaticAssetPath reports whether a URL path names a static resource that
// must not become a test endpoint (or an injection point, or a test job).
func IsStaticAssetPath(p string) bool {
	p = cleanAssetPath(p)
	if p == "" {
		return false
	}
	base := path.Base(p)
	if strings.HasPrefix(base, "favicon") || base == "robots.txt" {
		return true
	}
	_, ok := staticAssetExtensions[path.Ext(base)]
	return ok
}

// IsScriptAssetPath reports whether a URL path names a JavaScript asset whose
// string literals a crawl may read. It is deliberately narrower than
// IsStaticAssetPath: images, fonts and stylesheets have nothing worth fetching.
func IsScriptAssetPath(p string) bool {
	p = cleanAssetPath(p)
	if p == "" {
		return false
	}
	_, ok := scriptAssetExtensions[path.Ext(path.Base(p))]
	return ok
}

// cleanAssetPath lowercases a path and drops its query/fragment, so the
// extension check sees the file name: /assets/app.js?v=2 is still JavaScript.
func cleanAssetPath(p string) string {
	p = strings.ToLower(strings.TrimSpace(p))
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	return p
}
