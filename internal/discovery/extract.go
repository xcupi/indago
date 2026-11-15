package discovery

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/net/html"

	"github.com/indago/indago/internal/domain"
)

// FormField is a named input discovered within a form.
type FormField struct {
	Name  string
	Type  string
	Value string
}

// Form is a discovered HTML form.
type Form struct {
	Action            string // raw action or handler target ("" means the current page URL)
	ActionFromHandler bool   // target derived from an inline submit handler
	Method            domain.HTTPMethod
	Inputs            []FormField
	// Group identifies the set of fields THIS form submits (see FormGroupKey).
	// Two forms on one page can share an action URL, and their fields must
	// never be merged into one request.
	Group string
}

// URL-bearing attributes by element, used for link extraction.
var urlAttrs = map[string]string{
	"a":      "href",
	"area":   "href",
	"link":   "href",
	"script": "src",
	"img":    "src",
	"iframe": "src",
	"frame":  "src",
	"source": "src",
	"embed":  "src",
	"form":   "action",
}

// ExtractLinks returns the de-duplicated raw URL references found in an HTML
// document (href/src/action attributes). References are NOT resolved or
// normalized — the caller resolves them against the page's base URL.
func ExtractLinks(body string) []string {
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return nil
	}
	var out []string
	seen := make(map[string]struct{})
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" {
			return
		}
		if _, ok := seen[v]; ok {
			return
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			if attrName, ok := urlAttrs[n.Data]; ok {
				if v, present := attrValue(n, attrName); present {
					add(v)
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return out
}

// ExtractForms returns the forms found in an HTML document, each with its action,
// method, and named inputs.
func ExtractForms(body string) []Form {
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return nil
	}
	var forms []Form
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "form" {
			forms = append(forms, parseForm(n))
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return forms
}

func parseForm(form *html.Node) Form {
	f := Form{Method: domain.MethodGET}
	if v, ok := attrValue(form, "action"); ok {
		f.Action = strings.TrimSpace(v)
	}
	if v, ok := attrValue(form, "method"); ok {
		if strings.EqualFold(strings.TrimSpace(v), "post") {
			f.Method = domain.MethodPOST
		}
	}
	handler, hasSubmitHandler := attrValue(form, "onsubmit")
	if f.Action == "" && hasSubmitHandler {
		f.Action = handlerSubmitPath(handler)
		f.ActionFromHandler = f.Action != ""
	}
	seen := make(map[string]struct{})
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			if f.Action == "" && !hasSubmitHandler {
				typ, _ := attrValue(n, "type")
				typ = strings.ToLower(strings.TrimSpace(typ))
				if (n.Data == "button" && (typ == "" || typ == "submit")) || (n.Data == "input" && (typ == "submit" || typ == "image")) {
					onclick, _ := attrValue(n, "onclick")
					f.Action = handlerSubmitPath(onclick)
					f.ActionFromHandler = f.Action != ""
				}
			}
			switch n.Data {
			case "input", "textarea", "select", "button":
				name, _ := attrValue(n, "name")
				name = strings.TrimSpace(name)
				if name != "" {
					if _, dup := seen[name]; !dup {
						seen[name] = struct{}{}
						typ, _ := attrValue(n, "type")
						val, _ := attrValue(n, "value")
						f.Inputs = append(f.Inputs, FormField{Name: name, Type: typ, Value: val})
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	for c := form.FirstChild; c != nil; c = c.NextSibling {
		walk(c)
	}
	if f.ActionFromHandler {
		f.Method = domain.MethodPOST
	}
	f.Group = FormGroupKey(f.Action, f.Method, f.Inputs)
	return f
}

// FormGroupKey derives the stable identity of ONE <form> element's submission:
// exactly which fields travel together. Discovery records it on every
// parameter a form contributes (domain.Parameter.FormGroup), so a request
// built for one field carries that form's fields only.
//
// It is derived from the form's own DECLARED shape — action, method, and the
// set of named fields — not from the page that contained it, so the same form
// rendered on several pages (a login box in a shared header, say) resolves to
// one group and its parameters deduplicate instead of piling up. Including the
// submit buttons is deliberate: a form whose submit control differs is a
// different submission even when the other fields match.
func FormGroupKey(action string, method domain.HTTPMethod, fields []FormField) string {
	names := make([]string, 0, len(fields))
	for _, f := range fields {
		if f.Name != "" {
			names = append(names, f.Name)
		}
	}
	sort.Strings(names)
	h := sha256.New()
	write := func(part string) {
		// Length-prefixed so no two field/action combinations can collide by
		// concatenation ("ab"+"c" vs "a"+"bc").
		h.Write([]byte(strconv.Itoa(len(part))))
		h.Write([]byte{':'})
		h.Write([]byte(part))
	}
	write(string(method))
	write(action)
	for _, name := range names {
		write(name)
	}
	return "fg:" + hex.EncodeToString(h.Sum(nil))[:16]
}

func attrValue(n *html.Node, key string) (string, bool) {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val, true
		}
	}
	return "", false
}

// handlerSubmitPath reads literal paths only; it never executes JavaScript or
// decodes escapes. The last qualifying quoted literal is the submit target.
func handlerSubmitPath(handler string) string {
	var target string
	for i := 0; i < len(handler); i++ {
		quote := handler[i]
		if quote != '\'' && quote != '"' {
			continue
		}
		start := i + 1
		escaped := false
		for i++; i < len(handler); i++ {
			if handler[i] == '\\' {
				escaped = true
				i++
				continue
			}
			if handler[i] == quote {
				break
			}
		}
		if i >= len(handler) {
			break
		}
		literal := handler[start:i]
		if escaped || len(literal) > 512 || !strings.HasPrefix(literal, "/") || strings.HasPrefix(literal, "//") {
			continue
		}
		if strings.ContainsRune(literal, '\\') || strings.ContainsFunc(literal, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
			continue
		}
		// An inline handler is JavaScript too: `replace(/"/g,"")` hides a
		// quote inside the regex and a comma after its flags, so the literal
		// scan reads "/g," as the submit target. Judge it with the same rule
		// the script-literal extractor uses.
		if pathPunctuationArtifact(literal) {
			continue
		}
		target = literal
	}
	return target
}
