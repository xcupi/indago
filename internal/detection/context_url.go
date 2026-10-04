package detection

import (
	"strings"

	"github.com/indago/indago/internal/domain"
)

// URL-valued attributes. The browser resolves these as URLs, so what matters is
// WHERE in the URL the insertion point is (scheme position, host, path, query,
// fragment) and, for javascript: URLs, the JS lexical state of the remainder.
var urlAttributes = map[string]bool{
	"href": true, "src": true, "action": true, "formaction": true, "data": true,
	"poster": true, "cite": true, "background": true, "longdesc": true, "manifest": true,
	"codebase": true, "icon": true, "profile": true, "usemap": true, "xlink:href": true,
	"ping": true,
}

func isURLAttribute(attr string) bool { return urlAttributes[attr] || attr == "srcset" }

// urlFragment classifies the end of a URL attribute value prefix (already
// entity-decoded).
func urlFragment(element, attr, prefix string) fragment {
	if attr == "srcset" {
		return fragment{
			ctx: CtxURL, sub: "srcset_candidates", conf: domain.ConfidenceMedium,
			reason:  "inside a srcset list of image URL candidates (comma-separated, each with an optional descriptor); the exact URL position depends on the preceding candidates",
			signals: []string{"url_attr:srcset"},
		}
	}

	// Browsers strip leading C0 controls/space and delete tab/newline anywhere.
	s := strings.TrimLeft(prefix, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f ")
	s = strings.NewReplacer("\t", "", "\n", "", "\r", "").Replace(s)

	f := fragment{ctx: CtxURL, conf: domain.ConfidenceHigh, signals: []string{"url_attr:" + attr}}
	where := func(sub, reason string) fragment {
		f.sub, f.reason = sub, reason
		return f
	}

	if s == "" {
		return where("start", "at the very start of a URL attribute value: reflected text here chooses the scheme/host of the URL")
	}

	scheme, rest, hasScheme := splitScheme(s)
	if hasScheme {
		f.signals = append(f.signals, "scheme:"+scheme)
		switch scheme {
		case "javascript":
			// The body of a javascript: URL is percent-decoded, then run as script.
			js := jsFragment(percentDecodeLoose(rest))
			inner := js.chain
			if len(inner) == 0 {
				inner = []Context{js.ctx} // an empty chain means "just ctx"
			}
			js.chain = append([]Context{CtxURL}, inner...)
			js.signals = append(f.signals, js.signals...)
			js.reason = "inside a javascript: URL, whose body is percent-decoded and executed as script; " + js.reason
			if js.sub == "" {
				js.sub = "javascript_url"
			}
			return js
		case "data":
			return where("data_uri", "inside a data: URI; how it is interpreted depends on its media type")
		case "mailto", "tel", "sms", "blob", "about":
			return where("opaque_scheme", "inside the opaque part of a "+scheme+": URL")
		}
		return afterAuthority(f, rest, true)
	}
	return afterAuthority(f, s, false)
}

// splitScheme splits "scheme:rest" per the URL grammar.
func splitScheme(s string) (scheme, rest string, ok bool) {
	if s == "" || !isASCIIAlpha(s[0]) {
		return "", "", false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		switch {
		case c == ':':
			return strings.ToLower(s[:i]), s[i+1:], true
		case isASCIIAlpha(c) || c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.':
		default:
			return "", "", false
		}
	}
	return "", "", false
}

// afterAuthority determines the URL component the end of rest falls in.
func afterAuthority(f fragment, rest string, absolute bool) fragment {
	set := func(sub, reason string) fragment {
		f.sub, f.reason = sub, reason
		return f
	}
	if strings.HasPrefix(rest, "//") {
		auth := rest[2:]
		if i := strings.IndexAny(auth, "/?#"); i >= 0 {
			return afterAuthority(f, auth[i:], true)
		}
		return set("host", "in the host (authority) part of a URL: reflected text here can change the destination host")
	}
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		return set("fragment", "in the fragment (#...) part of a URL")
	}
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		return set("query", "in the query string (?...) part of a URL")
	}
	if strings.HasPrefix(rest, "/") || absolute {
		return set("path", "in the path part of a URL")
	}
	if !strings.ContainsAny(rest, "/:") {
		return set("relative_first_segment", "in the first segment of a relative URL (no scheme yet): text that introduces a ':' here would turn the value into a scheme")
	}
	return set("relative_path", "in the path of a relative URL")
}
