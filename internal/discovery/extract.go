package discovery

import (
	"strings"

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
	Action string // raw action attribute ("" means the current page URL)
	Method domain.HTTPMethod
	Inputs []FormField
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
	seen := make(map[string]struct{})
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
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
	return f
}

func attrValue(n *html.Node, key string) (string, bool) {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val, true
		}
	}
	return "", false
}
