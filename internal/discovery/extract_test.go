package discovery_test

import (
	"testing"

	"github.com/indago/indago/internal/discovery"
	"github.com/indago/indago/internal/domain"
)

const sampleHTML = `<!doctype html><html><body>
<a href="/about">About</a>
<a href="https://example.com/contact">Contact</a>
<a href="/about">Dup</a>
<script src="/app.js"></script>
<img src="/logo.png">
<iframe src="/frame.html"></iframe>
<form action="/login" method="POST">
  <input type="text" name="user">
  <input type="password" name="pass">
  <input type="submit" value="Go">
  <button name="action" value="go">Go</button>
</form>
<form action="/search" method="get">
  <input type="text" name="q">
  <input type="hidden" name="src" value="web">
  <input type="text">
</form>
</body></html>`

func TestExtractLinks(t *testing.T) {
	links := discovery.ExtractLinks(sampleHTML)
	want := map[string]bool{
		"/about":                      false,
		"https://example.com/contact": false,
		"/app.js":                     false,
		"/logo.png":                   false,
		"/frame.html":                 false,
		"/login":                      false, // form action is URL-bearing
		"/search":                     false,
	}
	for _, l := range links {
		if _, ok := want[l]; ok {
			want[l] = true
		}
	}
	for l, found := range want {
		if !found {
			t.Errorf("expected link %q not extracted; got %v", l, links)
		}
	}
	// "/about" appears twice but must be de-duplicated.
	count := 0
	for _, l := range links {
		if l == "/about" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("duplicate link not de-duplicated: %d occurrences", count)
	}
}

func TestExtractForms(t *testing.T) {
	forms := discovery.ExtractForms(sampleHTML)
	if len(forms) != 2 {
		t.Fatalf("expected 2 forms, got %d", len(forms))
	}

	var login, search discovery.Form
	for _, f := range forms {
		switch f.Action {
		case "/login":
			login = f
		case "/search":
			search = f
		}
	}

	if login.Method != domain.MethodPOST {
		t.Fatalf("login form method = %s, want POST", login.Method)
	}
	if names := fieldNames(login); !hasAll(names, "user", "pass", "action") {
		t.Fatalf("login fields = %v", names)
	}

	if search.Method != domain.MethodGET {
		t.Fatalf("search form method = %s, want GET", search.Method)
	}
	names := fieldNames(search)
	if !hasAll(names, "q", "src") {
		t.Fatalf("search fields = %v", names)
	}
	// The nameless input must be skipped.
	if len(names) != 2 {
		t.Fatalf("expected 2 named fields in search form, got %d: %v", len(names), names)
	}
}

func fieldNames(f discovery.Form) []string {
	var out []string
	for _, in := range f.Inputs {
		out = append(out, in.Name)
	}
	return out
}

func hasAll(got []string, want ...string) bool {
	set := map[string]bool{}
	for _, g := range got {
		set[g] = true
	}
	for _, w := range want {
		if !set[w] {
			return false
		}
	}
	return true
}
