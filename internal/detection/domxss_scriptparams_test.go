package detection_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/indago/indago/internal/detection"
)

func scriptParamNames(t *testing.T, body string) []string {
	t.Helper()
	got := detection.DOMXSSQueryParamNamesFromScript(body, detection.DOMXSSScriptInline)
	names := make([]string, 0, len(got))
	for _, p := range got {
		names = append(names, p.Name)
	}
	return names
}

func TestDOMXSSScriptParamNamesRecognisedShapes(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want []string
	}{
		{
			name: "parenthesised new URLSearchParams window.location any quote",
			body: `var storeId = (new URLSearchParams(window.location.search)).get('storeId');`,
			want: []string{"storeId"},
		},
		{
			name: "new URLSearchParams location.search double quotes",
			body: `const x = new URLSearchParams(location.search).get("productId");`,
			want: []string{"productId"},
		},
		{
			name: "URLSearchParams without new getAll",
			body: `var all = URLSearchParams(location.search).getAll('tag');`,
			want: []string{"tag"},
		},
		{
			name: "variable assigned URLSearchParams",
			body: `const params = new URLSearchParams(window.location.search); var lang = params.get('lang');`,
			want: []string{"lang"},
		},
		{
			name: "search string alias",
			body: `var qs = location.search; qs.split('lang=');`,
			want: []string{"lang"},
		},
		{
			name: "location.search match regex",
			body: `if (location.search.match(/[?&]name=/)) { render(); }`,
			want: []string{"name"},
		},
		{
			name: "location.search split literal",
			body: `var parts = location.search.split('name=');`,
			want: []string{"name"},
		},
		{
			name: "document.location.href indexOf",
			body: `if (document.location.href.indexOf("default=") >= 0) { }`,
			want: []string{"default"},
		},
		{
			name: "getParameterByName helper",
			body: `var id = getParameterByName('id');`,
			want: []string{"id"},
		},
		{
			name: "getQueryParam helper",
			body: `var q = getQueryParam("q");`,
			want: []string{"q"},
		},
		{
			name: "document.URL includes",
			body: `if (document.URL.includes('lang=')) {}`,
			want: []string{"lang"},
		},
		{
			name: "deduplicated first occurrence order",
			body: `var p = new URLSearchParams(location.search); p.get('b'); new URLSearchParams(location.search).get('a'); p.get('b');`,
			want: []string{"b", "a"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := scriptParamNames(t, tc.body)
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("names = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDOMXSSScriptParamNamesLiteralOnly(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"variable argument", `var name = pick(); new URLSearchParams(location.search).get(name);`},
		{"concatenated argument", `new URLSearchParams(location.search).get('a' + suffix);`},
		{"constant URLSearchParams", `new URLSearchParams('a=1&b=2').get('a');`},
		{"hash-fed URLSearchParams", `new URLSearchParams(location.hash.substring(1)).get('q');`},
		{"map get", `const cache = new Map(); cache.get('account');`},
		{"comment only", `// new URLSearchParams(location.search).get('commented');`},
		{"sink write is not a read", `document.write('<select name="storeId">');`},
		{"split without a named literal", `location.search.split('&');`},
		{"dynamic regex", `location.search.match(/([a-z]+)=/);`},
		{"unrelated helper", `getElementById('storeId');`},
		{"object literal not a call", `var o = {get: function(k){}}; o['get']('x');`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := scriptParamNames(t, tc.body); len(got) != 0 {
				t.Fatalf("names = %v, want none", got)
			}
		})
	}
}

func TestDOMXSSScriptParamNamesFromHTMLProvenanceAndLines(t *testing.T) {
	html := `<html><body>
<script src="/app.js"></script>
<script>
// line 4
var storeId = (new URLSearchParams(window.location.search)).get('storeId');
</script>
<script type="text/template">getParameterByName('templateOnly')</script>
<script>
getParameterByName('id');
</script>
</body></html>`
	got := detection.DOMXSSQueryParamNamesFromHTML(html)
	if len(got) != 2 {
		t.Fatalf("names = %+v, want storeId and id", got)
	}
	if got[0].Name != "storeId" || got[0].Script != detection.DOMXSSScriptInline || got[0].Line != 5 {
		t.Fatalf("first name = %+v, want storeId inline at line 5", got[0])
	}
	if got[1].Name != "id" || got[1].Line != 9 {
		t.Fatalf("second name = %+v, want id inline at line 9", got[1])
	}
}

func TestDOMXSSScriptSrcs(t *testing.T) {
	html := `<script src="/app.js"></script>
<SCRIPT SRC='https://cdn.example.net/lib.js?x=1'></SCRIPT>
<script src="/app.js"></script>
<script type="application/json" src="/data.json"></script>
<script src=/relative.js></script>
<script>inline()</script>`
	got := detection.DOMXSSScriptSrcs(html)
	want := []string{"/app.js", "https://cdn.example.net/lib.js?x=1", "/relative.js"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("srcs = %v, want %v", got, want)
	}
}

func TestDOMXSSScriptParamNamesCap(t *testing.T) {
	var body strings.Builder
	for i := 0; i < detection.DOMXSSScriptParamLimit+8; i++ {
		fmt.Fprintf(&body, "new URLSearchParams(location.search).get('p%d');\n", i)
	}
	got := detection.DOMXSSQueryParamNamesFromScript(body.String(), detection.DOMXSSScriptInline)
	if len(got) != detection.DOMXSSScriptParamLimit {
		t.Fatalf("names = %d, want capped at %d", len(got), detection.DOMXSSScriptParamLimit)
	}
	if got[0].Name != "p0" || got[len(got)-1].Name != fmt.Sprintf("p%d", detection.DOMXSSScriptParamLimit-1) {
		t.Fatalf("cap must keep the first %d names in order: %+v", detection.DOMXSSScriptParamLimit, got)
	}
}

// Golden: a page whose scripts do not read a query parameter contributes
// nothing, so every existing plan is byte-for-byte unchanged.
func TestDOMXSSScriptParamNamesGoldenNoReaderPage(t *testing.T) {
	for _, html := range []string{
		``,
		`<html><body><h1>plain</h1></body></html>`,
		`<script>document.addEventListener('click', function () {});</script>`,
		`<script>var m = new Map(); m.get('x'); document.write('<select name="storeId">');</script>`,
		`<script>var x = location.hash.slice(1); document.getElementById('s').innerHTML = x;</script>`,
	} {
		if got := detection.DOMXSSQueryParamNamesFromHTML(html); len(got) != 0 {
			t.Fatalf("%q produced %v, want none", html, got)
		}
	}
}
