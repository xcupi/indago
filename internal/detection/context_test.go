package detection_test

import (
	"encoding/json"
	"html"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
)

var testProbe = detection.NewProbe(domain.ID("scan-ctx"), domain.ID("ip-ctx"))

const htmlCT = "text/html; charset=utf-8"

// siteWith builds a body by substituting the (optionally transformed) probe value
// for {{M}}, runs the real reflection + context pipeline, and returns the first
// site's classification.
func siteWith(t *testing.T, doc, contentType string, transform func(string) string) detection.ContextAnalysis {
	t.Helper()
	if strings.Count(doc, "{{M}}") != 1 {
		t.Fatalf("test document must contain exactly one {{M}}: %q", doc)
	}
	body := []byte(strings.Replace(doc, "{{M}}", transform(testProbe.Value()), 1))
	rep := detection.AnalyzeReflection(testProbe, nil, body)
	if len(rep.Locations) == 0 {
		t.Fatalf("marker token not found in body: %q", body)
	}
	detection.ClassifyContexts(&rep, body, detection.ContextOptions{ContentType: contentType})
	a := rep.Locations[0].Context
	if a == nil {
		t.Fatal("site has no context classification")
	}
	return *a
}

func raw(s string) string { return s }

func site(t *testing.T, doc string) detection.ContextAnalysis {
	return siteWith(t, doc, htmlCT, raw)
}

type ctxCase struct {
	name  string
	doc   string
	ctx   detection.Context
	sub   string // "" = don't check
	chain []detection.Context
	conf  domain.Confidence // "" = don't check
	elem  string
	attr  string
	quote string
}

func runCases(t *testing.T, cases []ctxCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := site(t, c.doc)
			if a.Context != c.ctx {
				t.Fatalf("context = %q (sub %q), want %q\nreason: %s\nsignals: %v", a.Context, a.Sub, c.ctx, a.Reason, a.Signals)
			}
			if c.sub != "" && a.Sub != c.sub {
				t.Errorf("sub = %q, want %q\nreason: %s", a.Sub, c.sub, a.Reason)
			}
			if c.chain != nil && !reflect.DeepEqual(a.Chain, c.chain) {
				t.Errorf("chain = %v, want %v", a.Chain, c.chain)
			}
			if c.conf != "" && a.Confidence != c.conf {
				t.Errorf("confidence = %q, want %q\nreason: %s", a.Confidence, c.conf, a.Reason)
			}
			if c.elem != "" && a.Element != c.elem {
				t.Errorf("element = %q, want %q", a.Element, c.elem)
			}
			if c.attr != "" && a.Attribute != c.attr {
				t.Errorf("attribute = %q, want %q", a.Attribute, c.attr)
			}
			if c.quote != "" && a.Quote != c.quote {
				t.Errorf("quote = %q, want %q", a.Quote, c.quote)
			}
			if a.Reason == "" {
				t.Error("every classification needs a reason")
			}
			if a.Confidence == "" || !a.Confidence.IsValid() {
				t.Errorf("invalid confidence %q", a.Confidence)
			}
		})
	}
}

const (
	hi  = domain.ConfidenceHigh
	med = domain.ConfidenceMedium
	low = domain.ConfidenceLow
)

func TestContextHTMLText(t *testing.T) {
	runCases(t, []ctxCase{
		{name: "paragraph", doc: `<html><body><p>hello {{M}}</p></body></html>`, ctx: detection.CtxHTMLText, sub: "element_content", conf: hi},
		{name: "after a closed comment", doc: `<p>a</p><!-- note --><p>{{M}}</p>`, ctx: detection.CtxHTMLText, sub: "element_content", conf: hi},
		{name: "after a script element", doc: `<script>var a = "x";</script><p>{{M}}</p>`, ctx: detection.CtxHTMLText, sub: "element_content", conf: hi},
		{name: "after a style element", doc: `<style>a{color:red}</style><p>{{M}}</p>`, ctx: detection.CtxHTMLText, sub: "element_content", conf: hi},
		{name: "after a tag with attributes", doc: `<div class="a" id=b data-x='c'>{{M}}</div>`, ctx: detection.CtxHTMLText, sub: "element_content", conf: hi},
		{name: "literal less-than is text", doc: `<p>1 < 2 {{M}}</p>`, ctx: detection.CtxHTMLText, sub: "element_content", conf: hi},
		{name: "title is RCDATA", doc: `<head><title>{{M}}</title></head>`, ctx: detection.CtxHTMLText, sub: "rcdata", conf: hi, elem: "title"},
		{name: "textarea is RCDATA", doc: `<textarea name=q>{{M}}</textarea>`, ctx: detection.CtxHTMLText, sub: "rcdata", conf: hi, elem: "textarea"},
		{name: "iframe content is raw text", doc: `<iframe>{{M}}</iframe>`, ctx: detection.CtxHTMLText, sub: "rawtext", conf: hi},
		{name: "xmp content is raw text", doc: `<xmp>{{M}}</xmp>`, ctx: detection.CtxHTMLText, sub: "rawtext", conf: hi},
	})
}

func TestContextHTMLComment(t *testing.T) {
	runCases(t, []ctxCase{
		{name: "comment", doc: `<p>a</p><!-- user said: {{M}} -->`, ctx: detection.CtxHTMLComment, sub: "comment", conf: hi},
		{name: "comment closed with --!>", doc: `<!-- a --!><p>{{M}}</p>`, ctx: detection.CtxHTMLText, sub: "element_content"},
		{name: "abrupt comment <!-->", doc: `<!--><p>{{M}}</p>`, ctx: detection.CtxHTMLText, sub: "element_content"},
		{name: "processing instruction is a bogus comment", doc: `<?xml version="1.0" {{M}}?>`, ctx: detection.CtxHTMLComment, sub: "bogus_comment", conf: med},
		{name: "doctype", doc: `<!DOCTYPE {{M}}>`, ctx: detection.CtxUnknown, sub: "doctype", conf: med},
	})
}

func TestContextHTMLAttributeValue(t *testing.T) {
	runCases(t, []ctxCase{
		{name: "double quoted", doc: `<input value="{{M}}">`, ctx: detection.CtxHTMLAttrValue, sub: "double_quoted",
			chain: []detection.Context{detection.CtxHTMLAttrValue}, conf: hi, elem: "input", attr: "value", quote: "double"},
		{name: "single quoted", doc: `<input value='{{M}}'>`, ctx: detection.CtxHTMLAttrValue, sub: "single_quoted", conf: hi, quote: "single"},
		{name: "unquoted", doc: `<input value=abc{{M}}>`, ctx: detection.CtxHTMLAttrValue, sub: "unquoted", conf: hi, quote: "unquoted"},
		{name: "unquoted right after the equals sign", doc: `<input value={{M}}>`, ctx: detection.CtxHTMLAttrValue, sub: "unquoted", conf: hi, quote: "unquoted"},
		{name: "middle of a class list", doc: `<div class="a b {{M}} c">`, ctx: detection.CtxHTMLAttrValue, attr: "class", conf: hi},
		{name: "data attribute", doc: `<div data-user="{{M}}" id=x>`, ctx: detection.CtxHTMLAttrValue, attr: "data-user", conf: hi},
		{name: "attribute names are case-insensitive", doc: `<DIV CLASS="{{M}}">`, ctx: detection.CtxHTMLAttrValue, elem: "div", attr: "class"},
		{name: "second attribute", doc: `<a title="t" id="{{M}}">`, ctx: detection.CtxHTMLAttrValue, attr: "id"},
		{name: "equals sign inside a quoted value is not special", doc: `<a title="a=b" id="{{M}}">`, ctx: detection.CtxHTMLAttrValue, attr: "id"},
		{name: "> inside a quoted value does not end the tag", doc: `<a title="a>b" id="{{M}}">`, ctx: detection.CtxHTMLAttrValue, attr: "id"},
	})
}

func TestContextHTMLTagAndAttributeName(t *testing.T) {
	runCases(t, []ctxCase{
		{name: "tag name start", doc: `<{{M}}>`, ctx: detection.CtxHTMLTagName, sub: "tag_name_start", conf: hi},
		{name: "end tag name start", doc: `<div></{{M}}>`, ctx: detection.CtxHTMLTagName, sub: "end_tag_name_start", conf: hi},
		{name: "inside a tag name", doc: `<di{{M}}>`, ctx: detection.CtxHTMLTagName, sub: "tag_name", conf: hi},
		{name: "new attribute", doc: `<div {{M}}>`, ctx: detection.CtxHTMLAttrName, sub: "new_attribute", conf: hi, elem: "div"},
		{name: "new attribute after another", doc: `<div id=a {{M}}>`, ctx: detection.CtxHTMLAttrName, sub: "new_attribute", conf: hi},
		{name: "inside an attribute name", doc: `<div da{{M}}>`, ctx: detection.CtxHTMLAttrName, sub: "within_name", conf: hi},
		{name: "missing whitespace after a quoted value", doc: `<div class="a"{{M}}>`, ctx: detection.CtxHTMLAttrName, sub: "missing_whitespace", conf: med},
		{name: "after a slash", doc: `<br/{{M}}>`, ctx: detection.CtxHTMLAttrName, sub: "after_slash", conf: med},
	})
}

func TestContextJavaScript(t *testing.T) {
	js := func(name, script string, ctx detection.Context, sub string) ctxCase {
		return ctxCase{name: name, doc: `<html><script>` + script + `</script></html>`, ctx: ctx, sub: sub, conf: hi, elem: "script"}
	}
	runCases(t, []ctxCase{
		js("double-quoted string", `var a = "{{M}}";`, detection.CtxJSString, "double_quoted"),
		js("single-quoted string", `var a = '{{M}}';`, detection.CtxJSString, "single_quoted"),
		js("code position", `var a = {{M}};`, detection.CtxJSCode, ""),
		js("start of script", `{{M}}`, detection.CtxJSCode, ""),
		js("call argument", `render(1, {{M}});`, detection.CtxJSCode, ""),
		js("template literal text", "var a = `hello {{M}}`;", detection.CtxJSString, "template_literal"),
		js("template expression", "var a = `x ${ {{M}} }`;", detection.CtxJSCode, "template_expression"),
		js("template after a closed expression", "var a = `${b} {{M}}`;", detection.CtxJSString, "template_literal"),
		js("line comment", "// todo {{M}}\nvar a;", detection.CtxJSComment, "line"),
		js("block comment", "/* {{M}} */ var a;", detection.CtxJSComment, "block"),
		js("code after a line comment", "// c\nvar a = {{M}};", detection.CtxJSCode, ""),
		js("regex literal", `var r = /ab{{M}}/;`, detection.CtxJSRegex, "body"),
		js("regex character class", `var r = /[a-z{{M}}]/;`, detection.CtxJSRegex, "character_class"),
		js("regex after return", `function f(){ return /{{M}}/.test(s) }`, detection.CtxJSRegex, "body"),
		// A '/' after an identifier is division, so the string quote after it is real.
		js("division after an identifier", `var x = a / b; var s = "{{M}}";`, detection.CtxJSString, "double_quoted"),
		// A quote inside a regex literal must not open a string.
		js("quote inside a regex literal", `var r = /"/; var s = "{{M}}";`, detection.CtxJSString, "double_quoted"),
		js("quote inside a line comment", "// it's\nvar s = '{{M}}';", detection.CtxJSString, "single_quoted"),
		js("escaped quote does not end the string", `var s = "a\"b{{M}}";`, detection.CtxJSString, "double_quoted"),
		js("other quote inside a string", `var s = "it's {{M}}";`, detection.CtxJSString, "double_quoted"),
		js("string closed, then code", `var s = "done"; var t = {{M}};`, detection.CtxJSCode, ""),
		js("nested template", "var a = `a ${ `b ${c}` } {{M}}`;", detection.CtxJSString, "template_literal"),
		js("object literal braces", `var o = { a: 1, b: {{M}} };`, detection.CtxJSCode, ""),
	})

	t.Run("pending escape is reported", func(t *testing.T) {
		a := site(t, `<script>var s = "a\{{M}}";</script>`)
		if a.Context != detection.CtxJSString || !hasSignal(a, "pending_escape") {
			t.Fatalf("context=%q signals=%v", a.Context, a.Signals)
		}
	})
	t.Run("end of script ends JS state", func(t *testing.T) {
		a := site(t, `<script>var s = "unterminated</script><p>{{M}}</p>`)
		if a.Context != detection.CtxHTMLText {
			t.Fatalf("</script> ends the script even inside a JS string; got %q", a.Context)
		}
	})
	t.Run("case-insensitive end tag", func(t *testing.T) {
		a := site(t, `<SCRIPT>var a;</ScRiPt><p>{{M}}</p>`)
		if a.Context != detection.CtxHTMLText {
			t.Fatalf("got %q", a.Context)
		}
	})
}

func TestContextJavaScriptScriptTypes(t *testing.T) {
	for _, typ := range []string{`text/javascript`, `module`, `application/javascript`, `text/ecmascript`} {
		t.Run("executed "+typ, func(t *testing.T) {
			a := site(t, `<script type="`+typ+`">var a = "{{M}}";</script>`)
			if a.Context != detection.CtxJSString {
				t.Fatalf("type %q is JavaScript; got %q", typ, a.Context)
			}
		})
	}
	for _, typ := range []string{`application/json`, `application/ld+json`, `importmap`, `text/template`, `text/x-handlebars-template`} {
		t.Run("inert "+typ, func(t *testing.T) {
			a := site(t, `<script type="`+typ+`">{"a":"{{M}}"}</script>`)
			if a.Context != detection.CtxUnknown || a.Sub != "script_data_block" || a.Confidence != med {
				t.Fatalf("type %q is not executed; got %q/%q conf %q", typ, a.Context, a.Sub, a.Confidence)
			}
			if len(a.Alternatives) == 0 || a.Alternatives[0].Context != detection.CtxJSCode {
				t.Fatalf("the alternative reading (evaluated as code) should be listed: %+v", a.Alternatives)
			}
		})
	}
}

func TestContextEventHandlerAttributes(t *testing.T) {
	chain := func(inner detection.Context) []detection.Context {
		return []detection.Context{detection.CtxHTMLAttrValue, inner}
	}
	runCases(t, []ctxCase{
		{name: "string in a handler", doc: `<button onclick="go('{{M}}')">`, ctx: detection.CtxJSString, sub: "single_quoted",
			chain: chain(detection.CtxJSString), conf: hi, elem: "button", attr: "onclick", quote: "double"},
		{name: "code in a handler", doc: `<img src=x onerror="f({{M}})">`, ctx: detection.CtxJSCode, chain: chain(detection.CtxJSCode), attr: "onerror", conf: hi},
		{name: "handler with single-quoted attribute", doc: `<a onmouseover='x="{{M}}"'>`, ctx: detection.CtxJSString, sub: "double_quoted", quote: "single"},
		{name: "unquoted handler", doc: `<a onclick=alert({{M}})>`, ctx: detection.CtxJSCode, quote: "unquoted"},
		// The browser decodes entities BEFORE running the handler: &quot; opens a JS string.
		{name: "entity-decoded quote opens a JS string", doc: `<a onclick="x=&quot;{{M}}">`, ctx: detection.CtxJSString, sub: "double_quoted", chain: chain(detection.CtxJSString)},
		{name: "entity-encoded apostrophe", doc: `<a onclick="go(&#39;{{M}}')">`, ctx: detection.CtxJSString, sub: "single_quoted"},
	})
}

func TestContextURLs(t *testing.T) {
	url := func(name, doc, sub string) ctxCase {
		return ctxCase{name: name, doc: doc, ctx: detection.CtxURL, sub: sub, conf: hi,
			chain: []detection.Context{detection.CtxHTMLAttrValue, detection.CtxURL}}
	}
	runCases(t, []ctxCase{
		url("start of an href", `<a href="{{M}}">x</a>`, "start"),
		url("leading whitespace is stripped by browsers", `<a href="  {{M}}">`, "start"),
		url("query string", `<a href="/search?q={{M}}">`, "query"),
		url("query after other params", `<a href="/s?a=1&b={{M}}">`, "query"),
		url("path", `<a href="/users/{{M}}/profile">`, "path"),
		url("absolute path", `<a href="https://example.com/a/{{M}}">`, "path"),
		url("fragment", `<a href="/page#{{M}}">`, "fragment"),
		url("host", `<a href="https://{{M}}">`, "host"),
		url("scheme-relative host", `<a href="//{{M}}">`, "host"),
		url("host with userinfo and port", `<a href="http://example.com:8080{{M}}">`, "host"),
		url("relative first segment", `<img src="x{{M}}">`, "relative_first_segment"),
		url("relative path", `<img src="img/{{M}}">`, "relative_path"),
		url("form action", `<form action="{{M}}">`, "start"),
		url("script src", `<script src="//cdn.example/{{M}}"></script>`, "path"),
		url("iframe src", `<iframe src="{{M}}"></iframe>`, "start"),
		url("data URI", `<object data="data:text/html,{{M}}">`, "data_uri"),
		url("mailto is opaque", `<a href="mailto:{{M}}">`, "opaque_scheme"),
		{name: "srcset is medium confidence", doc: `<img srcset="a.png 1x, {{M}} 2x">`, ctx: detection.CtxURL, sub: "srcset_candidates", conf: med},
	})

	chain3 := func(inner detection.Context) []detection.Context {
		return []detection.Context{detection.CtxHTMLAttrValue, detection.CtxURL, inner}
	}
	runCases(t, []ctxCase{
		{name: "javascript: URL string", doc: `<a href="javascript:go('{{M}}')">`, ctx: detection.CtxJSString, sub: "single_quoted", chain: chain3(detection.CtxJSString), conf: hi},
		{name: "javascript: URL code", doc: `<a href="javascript:{{M}}">`, ctx: detection.CtxJSCode, chain: chain3(detection.CtxJSCode), conf: hi},
		// The body of a javascript: URL is percent-decoded before it runs.
		{name: "javascript: URL percent-decoded quote", doc: `<a href="javascript:go(%27{{M}}">`, ctx: detection.CtxJSString, sub: "single_quoted"},
		{name: "javascript: scheme is case-insensitive", doc: `<a href="JaVaScRiPt:x='{{M}}'">`, ctx: detection.CtxJSString},
	})
}

func TestContextCSS(t *testing.T) {
	style := func(name, css string, sub string) ctxCase {
		return ctxCase{name: name, doc: `<style>` + css + `</style>`, ctx: detection.CtxCSS, sub: sub, conf: hi, elem: "style"}
	}
	runCases(t, []ctxCase{
		style("declaration value", `body { color: {{M}}; }`, "value"),
		style("value after a colon, before a semicolon", `a { margin: 0 {{M}} 0; }`, "value"),
		style("selector", `{{M}} { color: red }`, "selector"),
		style("selector after another rule", `a{b:c} .x > {{M}} {}`, "selector"),
		style("property name", `.a { {{M}}: red }`, "property"),
		style("property after a declaration", `.a { color: red; {{M}} }`, "property"),
		style("quoted string value", `.a { content: "{{M}}"; }`, "string"),
		style("single-quoted string", `.a { content: '{{M}}'; }`, "string"),
		style("unquoted url()", `.a { background: url({{M}}) }`, "url_unquoted"),
		style("quoted url()", `.a { background: url("{{M}}") }`, "url_string"),
		style("url() with whitespace", `.a { background: url( {{M}}) }`, "url_unquoted"),
		style("comment", `/* {{M}} */ a{}`, "comment"),
		style("at-rule prelude", `@media {{M}} { a{} }`, "at_rule"),
		style("selector inside @media", `@media screen { {{M}} { color: red } }`, "selector"),
		style("declarations inside @media rule", `@media screen { a { color: {{M}} } }`, "value"),
		style("after the block closes", `a { color: red } {{M}} { }`, "selector"),
		style("semicolon inside url() does not end the declaration", `a { background: url(data:image/png;base64,AAA) {{M}} }`, "value"),
	})

	t.Run("style attribute", func(t *testing.T) {
		a := site(t, `<div style="color: {{M}}">`)
		if a.Context != detection.CtxCSS || a.Sub != "value" || a.Element != "div" || a.Attribute != "style" ||
			!reflect.DeepEqual(a.Chain, []detection.Context{detection.CtxHTMLAttrValue, detection.CtxCSS}) {
			t.Fatalf("got %+v", a)
		}
	})
	t.Run("style attribute property position", func(t *testing.T) {
		if a := site(t, `<div style="{{M}}">`); a.Context != detection.CtxCSS || a.Sub != "property" {
			t.Fatalf("got %q/%q", a.Context, a.Sub)
		}
		if a := site(t, `<div style="color:red; {{M}}">`); a.Context != detection.CtxCSS || a.Sub != "property" {
			t.Fatalf("got %q/%q", a.Context, a.Sub)
		}
	})
	t.Run("style attribute url", func(t *testing.T) {
		if a := site(t, `<div style="background: url('{{M}}')">`); a.Context != detection.CtxCSS || a.Sub != "url_string" {
			t.Fatalf("got %q/%q", a.Context, a.Sub)
		}
	})
	t.Run("entity-decoded style attribute", func(t *testing.T) {
		if a := site(t, `<div style="content: &quot;{{M}}">`); a.Context != detection.CtxCSS || a.Sub != "string" {
			t.Fatalf("got %q/%q", a.Context, a.Sub)
		}
	})
}

// --- ambiguity and uncertainty ---

func TestContextAmbiguousRegexVersusDivision(t *testing.T) {
	for _, doc := range []string{
		`<script>if (ok) /{{M}}/.test(s)</script>`,        // after ')': regex or division?
		`<script>function f(){} /{{M}}/.test(s)</script>`, // after '}': block (regex) or object literal (division)?
		`<script>i++ /{{M}}/ 2</script>`,                  // after '++'
	} {
		a := site(t, doc)
		if a.Context != detection.CtxMixed || a.Confidence != low || a.Sub != "regex_or_division" {
			t.Fatalf("%q: context=%q sub=%q conf=%q, want mixed/regex_or_division/low\nreason: %s", doc, a.Context, a.Sub, a.Confidence, a.Reason)
		}
		if len(a.Alternatives) != 2 {
			t.Fatalf("%q: want both readings listed, got %+v", doc, a.Alternatives)
		}
		kinds := map[detection.Context]bool{a.Alternatives[0].Context: true, a.Alternatives[1].Context: true}
		if !kinds[detection.CtxJSRegex] || !kinds[detection.CtxJSCode] {
			t.Fatalf("%q: alternatives should be regex and code, got %+v", doc, a.Alternatives)
		}
		if !hasSignal(a, "js_slash_ambiguity") {
			t.Fatalf("missing ambiguity signal: %v", a.Signals)
		}
	}
}

func TestContextAmbiguityDoesNotFireWhenBothReadingsAgree(t *testing.T) {
	// The marker is inside a string; whether the earlier '/' is regex or division
	// does not change that, so there is no ambiguity to report.
	a := site(t, `<script>if (ok) /x/.test(s); var q = "{{M}}";</script>`)
	if a.Context != detection.CtxJSString || a.Confidence != hi {
		t.Fatalf("got %q conf %q (alts %+v)", a.Context, a.Confidence, a.Alternatives)
	}
}

func TestContextConfidenceReducers(t *testing.T) {
	t.Run("noscript is parsed differently with scripting off", func(t *testing.T) {
		a := site(t, `<noscript><p>{{M}}</p></noscript>`)
		if a.Context != detection.CtxHTMLText || a.Sub != "rawtext_noscript" || a.Confidence != med || len(a.Alternatives) == 0 {
			t.Fatalf("got %+v", a)
		}
	})
	t.Run("foreign content", func(t *testing.T) {
		a := site(t, `<svg><script>var a = {{M}};</script></svg>`)
		if a.Context != detection.CtxHTMLText || a.Confidence != med || !hasSignal(a, "foreign_content") {
			t.Fatalf("got %+v", a)
		}
		if len(a.Alternatives) == 0 || a.Alternatives[0].Context != detection.CtxJSCode {
			t.Fatalf("the executable-script reading should be listed: %+v", a.Alternatives)
		}
	})
	t.Run("foreign content ends at the closing tag", func(t *testing.T) {
		a := site(t, `<svg><circle/></svg><p>{{M}}</p>`)
		if a.Confidence != hi || hasSignal(a, "foreign_content") {
			t.Fatalf("got %+v", a)
		}
	})
	t.Run("earlier markup irregularities", func(t *testing.T) {
		a := site(t, `<div a"b=c><p>{{M}}</p></div>`)
		if a.Confidence != med || !hasSignalPrefix(a, "tokenizer_anomalies:") {
			t.Fatalf("got conf %q signals %v", a.Confidence, a.Signals)
		}
	})
	t.Run("srcdoc is nested HTML", func(t *testing.T) {
		a := site(t, `<iframe srcdoc="&lt;p&gt;{{M}}">`)
		if a.Context != detection.CtxHTMLText || a.Confidence != med || !hasSignal(a, "nested_html") {
			t.Fatalf("got %+v", a)
		}
		if !reflect.DeepEqual(a.Chain, []detection.Context{detection.CtxHTMLAttrValue, detection.CtxHTMLText}) {
			t.Fatalf("chain = %v", a.Chain)
		}
	})
	t.Run("unterminated JS string earlier lowers confidence", func(t *testing.T) {
		a := site(t, "<script>var a = 'oops\nvar b = \"{{M}}\";</script>")
		if a.Context != detection.CtxJSString || a.Confidence != med || !hasSignal(a, "js_error_recovery") {
			t.Fatalf("got %q conf %q signals %v", a.Context, a.Confidence, a.Signals)
		}
	})
	t.Run("after-markup-declaration is unknown", func(t *testing.T) {
		a := site(t, `<!{{M}}>`)
		if a.Context != detection.CtxUnknown || a.Confidence != low {
			t.Fatalf("got %q conf %q", a.Context, a.Confidence)
		}
	})
}

// --- content types ---

func TestContextContentTypes(t *testing.T) {
	cases := []struct {
		name, ct, doc string
		ctx           detection.Context
		sub           string
		conf          domain.Confidence
	}{
		{"json is not markup", "application/json", `{"q":"{{M}}"}`, detection.CtxUnknown, "non_html_response", hi},
		{"json with charset", "application/json; charset=utf-8", `{"q":"{{M}}"}`, detection.CtxUnknown, "non_html_response", hi},
		{"plain text is not markup", "text/plain", `<script>{{M}}</script>`, detection.CtxUnknown, "non_html_response", hi},
		{"image is not markup", "image/png", `{{M}}`, detection.CtxUnknown, "non_html_response", hi},
		{"javascript response", "text/javascript", `var a = "{{M}}";`, detection.CtxJSString, "double_quoted", hi},
		{"javascript response code", "application/javascript", `callback({{M}})`, detection.CtxJSCode, "", hi},
		{"css response", "text/css", `a { color: {{M}} }`, detection.CtxCSS, "value", hi},
		{"html is high confidence", "text/html", `<p>{{M}}</p>`, detection.CtxHTMLText, "element_content", hi},
		{"xhtml is parsed as html", "application/xhtml+xml", `<p>{{M}}</p>`, detection.CtxHTMLText, "element_content", hi},
		{"missing content type is capped", "", `<p>{{M}}</p>`, detection.CtxHTMLText, "element_content", med},
		{"svg is an approximation", "image/svg+xml", `<svg><text>{{M}}</text></svg>`, detection.CtxHTMLText, "", med},
		{"xml is an approximation", "text/xml", `<a>{{M}}</a>`, detection.CtxHTMLText, "", med},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := siteWith(t, c.doc, c.ct, raw)
			if a.Context != c.ctx || (c.sub != "" && a.Sub != c.sub) || a.Confidence != c.conf {
				t.Fatalf("got %q/%q conf %q, want %q/%q conf %q\nreason: %s", a.Context, a.Sub, a.Confidence, c.ctx, c.sub, c.conf, a.Reason)
			}
		})
	}
}

// --- raw vs encoded / transformed ---

func TestContextRawVersusEncoded(t *testing.T) {
	htmlEnc := html.EscapeString
	urlEnc := url.QueryEscape

	t.Run("raw in text", func(t *testing.T) {
		a := siteWith(t, `<p>{{M}}</p>`, htmlCT, raw)
		if a.Form != detection.FormRaw || a.Context != detection.CtxHTMLText {
			t.Fatalf("form=%q ctx=%q", a.Form, a.Context)
		}
		// A raw '<' in text opens markup only if followed by a letter/!/?//; '<>' does not.
		if a.Straddles {
			t.Fatalf("the canary stays in text; got straddle to %q", a.ContextAtTail)
		}
	})
	t.Run("html-encoded in text", func(t *testing.T) {
		a := siteWith(t, `<p>{{M}}</p>`, htmlCT, htmlEnc)
		if a.Form != detection.FormEncoded || a.Context != detection.CtxHTMLText || a.Straddles {
			t.Fatalf("form=%q ctx=%q straddles=%v", a.Form, a.Context, a.Straddles)
		}
	})
	t.Run("html-encoded in attribute", func(t *testing.T) {
		a := siteWith(t, `<input value="{{M}}">`, htmlCT, htmlEnc)
		if a.Form != detection.FormEncoded || a.Context != detection.CtxHTMLAttrValue || a.Straddles {
			t.Fatalf("form=%q ctx=%q straddles=%v tail=%q", a.Form, a.Context, a.Straddles, a.ContextAtTail)
		}
	})
	t.Run("raw in attribute changes the parse context", func(t *testing.T) {
		a := siteWith(t, `<input value="{{M}}">`, htmlCT, raw)
		if a.Form != detection.FormRaw || a.Context != detection.CtxHTMLAttrValue {
			t.Fatalf("form=%q ctx=%q", a.Form, a.Context)
		}
		if !a.Straddles || a.ContextAtTail == "" || a.ContextAtTail == "html_attr_value:double_quoted" {
			t.Fatalf("a raw '\"' in the canary closes the attribute; straddles=%v tail=%q", a.Straddles, a.ContextAtTail)
		}
	})
	t.Run("raw in single-quoted JS string", func(t *testing.T) {
		a := siteWith(t, `<script>var a = '{{M}}';</script>`, htmlCT, raw)
		if !a.Straddles || a.Context != detection.CtxJSString {
			t.Fatalf("a raw ' closes the string; straddles=%v ctx=%q tail=%q", a.Straddles, a.Context, a.ContextAtTail)
		}
	})
	t.Run("js-escaped in JS string", func(t *testing.T) {
		esc := func(v string) string {
			return strings.NewReplacer(`"`, `\"`, `'`, `\'`, `<`, `\x3c`, `>`, `\x3e`).Replace(v)
		}
		a := siteWith(t, `<script>var a = "{{M}}";</script>`, htmlCT, esc)
		if a.Form != detection.FormEncoded || a.Context != detection.CtxJSString || a.Straddles {
			t.Fatalf("form=%q ctx=%q straddles=%v tail=%q", a.Form, a.Context, a.Straddles, a.ContextAtTail)
		}
	})
	t.Run("url-encoded in a query string", func(t *testing.T) {
		enc := func(v string) string {
			return testProbe.Token + urlEnc(testProbe.Canary) + testProbe.Tail
		}
		a := siteWith(t, `<a href="/s?q={{M}}">`, htmlCT, enc)
		if a.Form != detection.FormEncoded || a.Context != detection.CtxURL || a.Sub != "query" {
			t.Fatalf("form=%q ctx=%q sub=%q", a.Form, a.Context, a.Sub)
		}
	})
	t.Run("stripped canary", func(t *testing.T) {
		strip := func(string) string { return testProbe.Token + testProbe.Tail }
		a := siteWith(t, `<p>{{M}}</p>`, htmlCT, strip)
		if a.Form != detection.FormStripped {
			t.Fatalf("form = %q", a.Form)
		}
	})
	t.Run("partially transformed canary", func(t *testing.T) {
		part := func(string) string {
			return testProbe.Token + "&lt;>" + `"` + `\'` + testProbe.Tail
		}
		a := siteWith(t, `<p>{{M}}</p>`, htmlCT, part)
		if a.Form != detection.FormTransformed {
			t.Fatalf("form = %q", a.Form)
		}
	})
	t.Run("encoding does not change the context", func(t *testing.T) {
		r := siteWith(t, `<a title="x {{M}}">`, htmlCT, raw)
		e := siteWith(t, `<a title="x {{M}}">`, htmlCT, htmlEnc)
		if r.Context != e.Context || r.Sub != e.Sub {
			t.Fatalf("raw=%s/%s encoded=%s/%s", r.Context, r.Sub, e.Context, e.Sub)
		}
	})
}

// --- multiple sites are independent; offsets and determinism ---

func TestContextMultipleSitesAreIndependent(t *testing.T) {
	v := testProbe.Value()
	body := []byte(strings.Join([]string{
		`<html><head><title>` + v + `</title></head>`,
		`<body><p>` + v + `</p>`,
		`<input value="` + v + `">`,
		`<a href="/s?q=` + v + `">go</a>`,
		`<script>var s = '` + v + `';</script>`,
		`<div style="color:` + v + `"></div>`,
		`<!-- ` + v + ` -->`,
		`</body></html>`,
	}, "\n"))

	rep := detection.AnalyzeReflection(testProbe, nil, body)
	detection.ClassifyContexts(&rep, body, detection.ContextOptions{ContentType: htmlCT})
	if rep.Count != 7 || len(rep.Locations) != 7 {
		t.Fatalf("expected 7 sites, got count=%d locations=%d", rep.Count, len(rep.Locations))
	}

	want := []struct {
		ctx detection.Context
		sub string
	}{
		{detection.CtxHTMLText, "rcdata"},
		{detection.CtxHTMLText, "element_content"},
		{detection.CtxHTMLAttrValue, "double_quoted"},
		{detection.CtxURL, "query"},
		{detection.CtxJSString, "single_quoted"},
		{detection.CtxCSS, "value"},
		{detection.CtxHTMLComment, "comment"},
	}
	for i, w := range want {
		a := rep.Locations[i].Context
		if a == nil || a.Context != w.ctx || a.Sub != w.sub {
			t.Fatalf("site %d: got %+v, want %s/%s", i, a, w.ctx, w.sub)
		}
	}
}

func TestContextExactOffsets(t *testing.T) {
	v := testProbe.Value()
	body := []byte(`<p>` + v + `</p><input value="` + v + `"><script>x="` + v + `"</script>`)
	rep := detection.AnalyzeReflection(testProbe, nil, body)
	detection.ClassifyContexts(&rep, body, detection.ContextOptions{ContentType: htmlCT})

	if len(rep.Locations) != 3 {
		t.Fatalf("sites = %d", len(rep.Locations))
	}
	for i, loc := range rep.Locations {
		a := loc.Context
		if a.Offset != loc.Offset || string(body[a.Offset:a.TokenEnd]) != testProbe.Token {
			t.Fatalf("site %d: [%d,%d) = %q, want the token", i, a.Offset, a.TokenEnd, body[a.Offset:a.TokenEnd])
		}
		if a.TailOffset != loc.TailOffset || a.TailOffset <= a.TokenEnd ||
			string(body[a.TailOffset:a.TailOffset+len(testProbe.Tail)]) != testProbe.Tail {
			t.Fatalf("site %d: tail offset %d does not address the tail sentinel", i, a.TailOffset)
		}
		if a.ConstructStart > a.Offset {
			t.Fatalf("site %d: construct start %d is after the site %d", i, a.ConstructStart, a.Offset)
		}
	}
	// The attribute-value construct starts right after the opening quote.
	if got := rep.Locations[1].Context.ConstructStart; string(body[got-1]) != `"` {
		t.Fatalf("attribute construct should start after the opening quote, got offset %d", got)
	}
	// The script-body construct starts right after <script>.
	if got := rep.Locations[2].Context.ConstructStart; !strings.HasSuffix(string(body[:got]), "<script>") {
		t.Fatalf("script construct should start after <script>, got %q", body[:got])
	}
}

func TestContextOffsetMismatchIsUnknown(t *testing.T) {
	body := []byte(`<p>` + testProbe.Value() + `</p>`)
	rep := detection.AnalyzeReflection(testProbe, nil, body)
	rep.Locations[0].Offset += 2 // no longer addresses the token
	detection.ClassifyContexts(&rep, body, detection.ContextOptions{ContentType: htmlCT})
	a := rep.Locations[0].Context
	if a.Context != detection.CtxUnknown || a.Confidence != low || !hasSignal(*a, "offset_mismatch") {
		t.Fatalf("got %+v", a)
	}
}

func TestContextDeterministic(t *testing.T) {
	body := []byte(`<div><p>` + testProbe.Value() + `</p><a href="/x?q=` + testProbe.Value() + `">z</a><script>var a = "` + testProbe.Value() + `"</script></div>`)
	run := func() []byte {
		rep := detection.AnalyzeReflection(testProbe, nil, body)
		detection.ClassifyContexts(&rep, body, detection.ContextOptions{ContentType: htmlCT})
		b, err := json.Marshal(rep)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	first := run()
	for i := 0; i < 20; i++ {
		if got := run(); string(got) != string(first) {
			t.Fatalf("run %d differs:\n%s\nvs\n%s", i, got, first)
		}
	}
}

func TestContextClassifyAtEveryOffsetNeverPanics(t *testing.T) {
	// A hostile document exercising every state, including truncation anywhere.
	doc := []byte("<!DOCTYPE html><html a\"b=c><!--x--!><!-->< /><?pi?><![CDATA[x]]><svg><script>`${`${a}`}`/*/*/;/[/]/;'\\\n</script></svg>" +
		"<div on\"x=a onclick='a=&quot;&#x27;\\' style=\"a:url(';\" href=javascript:%zz//%41>" +
		"<style>@media{a{b:url(\"x;\\\"}}</style><textarea></TEXTAREA x><noscript></noscript><script type=module>`\\")
	for off := 0; off <= len(doc); off++ {
		_ = detection.ClassifyAt(doc, off, detection.ContextOptions{ContentType: htmlCT})
	}
	for _, ct := range []string{"", "text/css", "text/javascript", "application/json", "image/svg+xml"} {
		for off := 0; off <= len(doc); off += 7 {
			a := detection.ClassifyAt(doc, off, detection.ContextOptions{ContentType: ct})
			if a.Context == "" || a.Reason == "" || !a.Confidence.IsValid() {
				t.Fatalf("offset %d ct %q: incomplete classification %+v", off, ct, a)
			}
		}
	}
	// Out-of-range offsets are clamped, not a panic.
	_ = detection.ClassifyAt(doc, -5, detection.ContextOptions{})
	_ = detection.ClassifyAt(doc, len(doc)+100, detection.ContextOptions{})
}

func TestContextEveryClassificationIsComplete(t *testing.T) {
	docs := []string{
		`<p>{{M}}</p>`, `<a href="{{M}}">`, `<script>var a = "{{M}}"</script>`, `<style>a{color:{{M}}}</style>`,
		`<div {{M}}>`, `<!-- {{M}} -->`, `<{{M}}>`, `<iframe srcdoc="{{M}}">`, `<a onclick="{{M}}">`,
	}
	for _, d := range docs {
		a := site(t, d)
		if a.Context == "" || a.Reason == "" || len(a.Chain) == 0 || a.Chain[len(a.Chain)-1] != a.Context && a.Context != detection.CtxMixed {
			t.Errorf("%q: incomplete or inconsistent classification: %+v", d, a)
		}
		if a.Form == "" || len(a.Signals) == 0 {
			t.Errorf("%q: missing form/signals: %+v", d, a)
		}
	}
}

// --- purity ---

func TestContextAnalyzerIsPure(t *testing.T) {
	// The analyzer must not be able to touch the network, filesystem, clock, RNG,
	// browser, or any other module. Enforced on its actual imports.
	forbidden := []string{"net", "os", "io/ioutil", "time", "math/rand", "crypto/rand", "syscall", "os/exec", "plugin", "unsafe"}
	files := []string{"context.go", "context_html.go", "context_javascript.go", "context_css.go", "context_url.go", "context_state.go"}
	for _, f := range files {
		for _, imp := range importsOf(t, f) {
			for _, bad := range forbidden {
				if imp == bad || strings.HasPrefix(imp, bad+"/") {
					t.Errorf("%s imports %q: the context analyzer must stay pure", f, imp)
				}
			}
			if strings.HasPrefix(imp, "github.com/") && !strings.HasSuffix(imp, "/internal/domain") {
				t.Errorf("%s imports %q: only the domain model is allowed", f, imp)
			}
		}
	}
}

func hasSignal(a detection.ContextAnalysis, s string) bool {
	for _, x := range a.Signals {
		if x == s {
			return true
		}
	}
	return false
}

func hasSignalPrefix(a detection.ContextAnalysis, p string) bool {
	for _, x := range a.Signals {
		if strings.HasPrefix(x, p) {
			return true
		}
	}
	return false
}
