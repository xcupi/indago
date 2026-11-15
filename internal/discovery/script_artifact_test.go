package discovery

import (
	"testing"

	"github.com/indago/indago/internal/domain"
)

// A quoted path is the only thing the script/handler literal scans can see, so
// JavaScript punctuation that happens to sit between two quotes has to be
// judged on its own. These are the shapes measured against a real SPA (GET /g,
// with source=script_literal): a regex literal's flags plus the comma that ends
// the argument, or a list/statement tail stuck to an otherwise real path.
func TestPathPunctuationArtifact(t *testing.T) {
	cases := []struct {
		path     string
		artifact bool
	}{
		{"/g,", true},
		{"/i,", true},
		{"/m,", true},
		{"/gi,", true},
		{"/gm,", true},
		{"/api/v1/users,", true},
		{"/api/v1/users;", true},
		{"/api/v1/users)", true},

		{"/api/v1/users", false},
		{"/rest/products/search?q=", false},
		// A query may legitimately end with a separator.
		{"/api/users?ids=1,2,", false},
		// Balanced parentheses are a real path shape, not call syntax.
		{"/api/v1/x(my)", false},
		{"/wiki/Foo_(bar)", false},
		// Short routes are kept: only PUNCTUATION is rejected, never a short
		// path that happens to be built from regex-flag letters.
		{"/id", false},
		{"/us", false},
		{"/", false},
		{"", false},
	}
	for _, c := range cases {
		if got := pathPunctuationArtifact(c.path); got != c.artifact {
			t.Errorf("pathPunctuationArtifact(%q) = %v, want %v", c.path, got, c.artifact)
		}
	}
}

// Inline handler targets are read by the same syntax-blind quote scan, so
// `onsubmit="...replace(/"/g,"")"` offers "/g," as a submit target. It must be
// dropped like any other punctuation artifact, while a handler that names a
// real route keeps working.
func TestHandlerSubmitPathDropsPunctuationArtifacts(t *testing.T) {
	for _, handler := range []string{
		`return this.value.replace(/"/g,"")`,
		`return encode(this.value.replace(/"/gi,""))`,
		`return go("/api/x,")`,
		`return go("/api/x;")`,
		`return go("/api/x)")`,
	} {
		if got := handlerSubmitPath(handler); got != "" {
			t.Errorf("handlerSubmitPath(%q) = %q, want no target", handler, got)
		}
	}

	valid := []struct {
		handler string
		want    string
	}{
		{`return clean("/checkout")`, "/checkout"},
		{`go("/api/v1/x(my)")`, "/api/v1/x(my)"},
		{`post("/rest/products/search?q=")`, "/rest/products/search?q="},
	}
	for _, c := range valid {
		if got := handlerSubmitPath(c.handler); got != c.want {
			t.Errorf("handlerSubmitPath(%q) = %q, want %q", c.handler, got, c.want)
		}
	}
}

// The same artifact seen through the form extractor: HTML-escaped quotes decode
// to a regex replace, and the form must keep its (empty, same-page) action
// rather than claim /g, is its submit target.
func TestFormHandlerActionDropsPunctuationArtifact(t *testing.T) {
	forms := ExtractForms(`<html><body>` +
		`<form onsubmit="return this.value.replace(/&quot;/g,&quot;&quot;)"><input name="q"></form>` +
		`</body></html>`)
	if len(forms) != 1 {
		t.Fatalf("expected 1 form, got %d", len(forms))
	}
	if forms[0].Action != "" || forms[0].ActionFromHandler {
		t.Fatalf("regex flags became a form action: action=%q fromHandler=%v", forms[0].Action, forms[0].ActionFromHandler)
	}
	if forms[0].Method != domain.MethodGET {
		t.Fatalf("a form with no usable handler target must keep its declared method, got %s", forms[0].Method)
	}

	forms = ExtractForms(`<html><body>` +
		`<form onsubmit="return submitTo('/checkout')"><input name="q"></form>` +
		`</body></html>`)
	if len(forms) != 1 || forms[0].Action != "/checkout" || !forms[0].ActionFromHandler {
		t.Fatalf("a real handler target was dropped: %+v", forms)
	}
}
