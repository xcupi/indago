package discovery

import (
	"path"
	"strings"
)

// staticAssetExtensions are resource types that have no useful XSS reflection
// surface of their own. Crawlers and browser-network capture see them because
// a page references them, but turning each into a test endpoint only spends
// the scan's request budget on CSS/JS/font/image URLs. Operator-supplied seeds
// are intentionally exempt: if the operator asks to scan one, that is explicit
// intent.
var staticAssetExtensions = map[string]struct{}{
	".css": {}, ".js": {}, ".mjs": {}, ".map": {},
	".png": {}, ".jpg": {}, ".jpeg": {}, ".gif": {}, ".webp": {}, ".avif": {},
	".svg": {}, ".ico": {}, ".bmp": {},
	".woff": {}, ".woff2": {}, ".ttf": {}, ".otf": {}, ".eot": {},
	".mp3": {}, ".mp4": {}, ".webm": {}, ".ogg": {}, ".wav": {}, ".pdf": {},
}

// IsStaticAssetPath reports whether a URL path names a static resource that
// should not become an XSS test endpoint when static-resource skipping is on.
func IsStaticAssetPath(p string) bool {
	p = strings.ToLower(strings.TrimSpace(p))
	if p == "" {
		return false
	}
	base := path.Base(p)
	if strings.HasPrefix(base, "favicon") || base == "robots.txt" {
		return true
	}
	ext := path.Ext(base)
	_, ok := staticAssetExtensions[ext]
	return ok
}
