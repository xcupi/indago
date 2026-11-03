package scan_test

// Three authorized PortSwigger lab shapes, reproduced byte-for-byte on a
// loopback fixture: a reflected value inside a JavaScript STRING under three
// different escaping rules. The escaping IS the subject, so each handler
// implements exactly the documented rule and the test asserts the exact served
// bytes before anything else uses the fixture.
//
//   /lab1  var searchTerms = 'VALUE';  ' -> \' and \ -> \\
//   /lab2  var searchTerms = 'VALUE';  < > " HTML-encoded, ' -> \'
//   /lab3  var searchTerms = `VALUE`;  < > ' " \ and backtick all \uXXXX-escaped
//
// Plus a fully-escaped safe control per context (must stay Rejected) and a
// non-reflecting control (must produce no finding at all). The real-Chromium
// pipeline test that consumes this fixture lives in
// jsstring_contexts_integration_test.go.

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
)

// --- the three lab escaping rules (server side) ---

// labQuoteAndBackslash: backslash is doubled first, then every single quote is
// backslash-escaped. This is lab 1: closing the string needs a backslash the
// server also escapes, so the quote-based breakout cannot work.
func labQuoteAndBackslash(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	return strings.ReplaceAll(v, `'`, `\'`)
}

// labAngleQuotes: angle brackets and double quotes are HTML-encoded; single
// quotes are backslash-escaped. Backslash itself is NOT escaped (lab 2).
func labAngleQuotes(v string) string {
	v = strings.NewReplacer("<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(v)
	return strings.ReplaceAll(v, `'`, `\'`)
}

// labTemplateUnicode: every character that could end or alter the template
// literal (<, >, ', ", \, `) is \uXXXX-escaped (lab 3).
func labTemplateUnicode(v string) string {
	var b strings.Builder
	for _, r := range v {
		switch r {
		case '<', '>', '\'', '"', '\\', '`':
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// --- safe/escaped controls: nothing here can execute ---

// safeJSString escapes the quote AND the backslash, and writes <, > and " as
// JavaScript \u escapes, so neither a quote breakout, a backslash breakout, nor
// a literal </script> can appear in the served script.
func safeJSString(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, `'`, `\'`)
	v = strings.ReplaceAll(v, `"`, `\u0022`)
	v = strings.ReplaceAll(v, "<", `\u003c`)
	v = strings.ReplaceAll(v, ">", `\u003e`)
	return v
}

// safeTemplate additionally escapes the interpolation opener, so a ${...}
// substitution stays literal text.
func safeTemplate(v string) string {
	var b strings.Builder
	for _, r := range v {
		switch r {
		case '<', '>', '\'', '"', '\\', '`', '$', '{', '}':
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// --- fixture ---

func newJSStringLab(t *testing.T) *site {
	t.Helper()
	return newSite(t, func(mux *http.ServeMux, base func() string) {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/" {
				http.NotFound(w, r)
				return
			}
			writeHTML(w, `<a href="/lab1?search=hello">1</a>
<a href="/lab2?search=hello">2</a>
<a href="/lab3?search=hello">3</a>
<a href="/safe-js1?search=hello">s1</a>
<a href="/safe-js2?search=hello">s2</a>
<a href="/safe-template?search=hello">s3</a>
<a href="/noreflect?search=hello">n</a>`)
		})
		inString := func(escape func(string) string) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) {
				writeHTML(w, "<!doctype html><html><body><script>var searchTerms = '"+
					escape(r.URL.Query().Get("search"))+"';</script></body></html>")
			}
		}
		inTemplate := func(escape func(string) string) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) {
				writeHTML(w, "<!doctype html><html><body><script>var searchTerms = `"+
					escape(r.URL.Query().Get("search"))+"`;</script></body></html>")
			}
		}
		mux.HandleFunc("/lab1", inString(labQuoteAndBackslash))
		mux.HandleFunc("/lab2", inString(labAngleQuotes))
		mux.HandleFunc("/lab3", inTemplate(labTemplateUnicode))
		mux.HandleFunc("/safe-js1", inString(safeJSString))
		mux.HandleFunc("/safe-js2", inString(safeJSString))
		mux.HandleFunc("/safe-template", inTemplate(safeTemplate))
		mux.HandleFunc("/noreflect", func(w http.ResponseWriter, r *http.Request) {
			writeHTML(w, "<!doctype html><html><body><p>no reflection here</p></body></html>")
		})
	})
}

// --- assertions on the exact served bytes ---

func TestReflectedJSStringFixturesServeExactEscaping(t *testing.T) {
	lab := newJSStringLab(t)
	p := detection.NewProbe(domain.ID("ps-jsstring-fixture"), domain.ID("ip"))

	// The expected bodies are written out literally (not re-derived through the
	// fixture's own escape helpers), so a change to either side is caught.
	cases := []struct {
		path    string
		sub     string
		want    string
		perChar map[string]string
	}{
		{
			path: "/lab1", sub: "single_quoted",
			want: "<!doctype html><html><body><script>var searchTerms = '" +
				p.Token + "<>\"\\'" + p.Tail + "';</script></body></html>",
			perChar: map[string]string{"<": detection.EncNone, ">": detection.EncNone, `"`: detection.EncNone, `'`: detection.EncJS},
		},
		{
			path: "/lab2", sub: "single_quoted",
			want: "<!doctype html><html><body><script>var searchTerms = '" +
				p.Token + "&lt;&gt;&quot;\\'" + p.Tail + "';</script></body></html>",
			perChar: map[string]string{"<": detection.EncHTML, ">": detection.EncHTML, `"`: detection.EncHTML, `'`: detection.EncJS},
		},
		{
			path: "/lab3", sub: "template_literal",
			want: "<!doctype html><html><body><script>var searchTerms = `" +
				p.Token + `\u003c\u003e\u0022\u0027` + p.Tail + "`;</script></body></html>",
			perChar: map[string]string{"<": detection.EncJS, ">": detection.EncJS, `"`: detection.EncJS, `'`: detection.EncJS},
		},
	}

	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			resp, err := http.Get(lab.URL + tc.path + "?search=" + url.QueryEscape(p.Value()))
			if err != nil {
				t.Fatalf("GET %s: %v", tc.path, err)
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("read %s body: %v", tc.path, err)
			}
			if string(body) != tc.want {
				t.Fatalf("served bytes for %s:\n got %q\nwant %q", tc.path, body, tc.want)
			}

			// And the real analyzer must classify those exact bytes as the lab's
			// context, with the documented per-character transformation.
			rep := detection.AnalyzeReflection(p, nil, body)
			detection.ClassifyContexts(&rep, body, detection.ContextOptions{ContentType: "text/html"})
			if !rep.Reflected || len(rep.Locations) != 1 {
				t.Fatalf("reflection = %v (%d sites), want exactly 1", rep.Reflected, len(rep.Locations))
			}
			loc := rep.Locations[0]
			if loc.Context == nil {
				t.Fatal("no context analysis recorded")
			}
			if loc.Context.Context != detection.CtxJSString || loc.Context.Sub != tc.sub {
				t.Fatalf("context = %s:%s, want js_string:%s", loc.Context.Context, loc.Context.Sub, tc.sub)
			}
			for ch, want := range tc.perChar {
				if got := loc.PerChar[ch]; got != want {
					t.Errorf("per-char %q = %q, want %q", ch, got, want)
				}
			}
		})
	}
}
