package verification_test

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/verification"
)

func verifyReflectedPage(t *testing.T, handler http.HandlerFunc, m, payload string) *verification.Result {
	t.Helper()
	srv := httptest.NewServer(handler)
	defer srv.Close()
	mgr := newManagerOrSkip(t)
	defer mgr.Close()
	res, err := verification.NewBrowserVerifier(mgr, verification.BrowserVerifierConfig{}).Verify(context.Background(), verification.Input{
		Candidate: detection.Candidate{Value: payload}, Marker: m, Method: "GET", URL: queryURL(srv.URL, payload), Scope: openScope(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// requireProvenance keeps the negative tests honest: a broken provenance path
// would also avoid Confirmed, so each one first proves provenance was live.
func requireProvenance(t *testing.T, res *verification.Result) {
	t.Helper()
	if res.Report == nil || !res.Report.Provenance.Available || res.Report.Provenance.MainFrameID == "" {
		t.Fatalf("test is only meaningful with engine provenance available: %+v", res.Report)
	}
}

// An escaped payload plus a page-authored "MARKER is not defined" exception is
// the shape of a forged error: never Confirmed, and not a clean "safe" either.
func TestIntegrationRejectFabricatedMarkerException(t *testing.T) {
	m := marker(t)
	payload := "<img src=x onerror=" + m + ">"
	res := verifyReflectedPage(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<!doctype html><p>%s</p><script>throw new ReferenceError('%s is not defined')</script>`, html.EscapeString(r.URL.Query().Get("q")), m)
	}, m, payload)
	requireProvenance(t, res)
	if res.Verdict != domain.VerdictInconclusive {
		t.Fatalf("a fabricated marker exception must be Inconclusive, got %s: %+v", res.Verdict, res.Report)
	}
}

// Console output is page-controlled text. With an escaped payload the marker is
// in the DOM but nothing executed, so this is the plain Rejected outcome.
func TestIntegrationRejectConsoleOnlyMarker(t *testing.T) {
	m := marker(t)
	payload := "<img src=x onerror=" + m + ">"
	res := verifyReflectedPage(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<!doctype html><p>%s</p><script>console.error('ReferenceError: %s is not defined')</script>`, html.EscapeString(r.URL.Query().Get("q")), m)
	}, m, payload)
	requireProvenance(t, res)
	if res.Verdict != domain.VerdictRejected {
		t.Fatalf("a console-only marker must be Rejected, got %s: %+v", res.Verdict, res.Report)
	}
}

// V8 ends a line at a bare CR; splitting on LF alone did not. Each script below
// throws a forged ReferenceError naming the marker and then places the marker
// identifier exactly where an LF-only reading of the engine's throw position
// lands. Two variants cover the throw keyword and the `new` operand.
func TestIntegrationRejectCarriageReturnLineMappingForgery(t *testing.T) {
	m := marker(t)
	payload := "<img src=x onerror=" + m + ">"
	forged := func(pad int) string {
		return "x=1;\r" + "throw new ReferenceError('" + m + " is not defined');\n" + strings.Repeat(" ", pad) + m + ";"
	}
	res := verifyReflectedPage(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/a.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, forged(0))
		case "/b.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, forged(6))
		default:
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<!doctype html><p>%s</p><script src="/a.js"></script><script src="/b.js"></script>`, html.EscapeString(r.URL.Query().Get("q")))
		}
	}, m, payload)
	requireProvenance(t, res)
	if res.Verdict != domain.VerdictInconclusive {
		t.Fatalf("a CR-shifted forged throw must be Inconclusive, got %s: %+v", res.Verdict, res.Report)
	}
}

// labTemplateValue mirrors the live PortSwigger "template literal with Unicode
// escapes" lab: the characters that could end or alter the template are
// \uXXXX-escaped, while $, { and } are NOT — so a "${...}" in the value is a
// real interpolation and V8 evaluates it while the inline script is parsing.
func labTemplateValue(v string) string {
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

// A value reflected into template-literal TEXT as "${MARKER}" is evaluated by
// the JavaScript engine during the page's own parse. The exception is captured
// by the CDP subscription installed BEFORE navigation, so the attempt must
// Confirm — and a page-level window.onerror handler must not be able to hide it
// (the engine pauses at the throw before the embedder's handler runs).
func TestIntegrationConfirmsExecutableTemplateLiteralDuringParse(t *testing.T) {
	const open = "<!doctype html><script>var message = `0 search results for '"
	const tail = "'`;</script>"
	cases := []struct {
		name string
		page func(v string) string
	}{
		{"plain", func(v string) string { return open + labTemplateValue(v) + tail }},
		{"page swallows with window.onerror", func(v string) string {
			return "<!doctype html><script>window.onerror=function(){return true};</script><script>var message = `0 search results for '" + labTemplateValue(v) + tail
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := marker(t)
			payload := "${" + m + "}"
			res := verifyReflectedPage(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				fmt.Fprint(w, tc.page(r.URL.Query().Get("q")))
			}, m, payload)
			requireProvenance(t, res)
			if res.Verdict != domain.VerdictConfirmed {
				t.Fatalf("a ${MARKER} interpolation threw during parse and must Confirm, got %s: %+v", res.Verdict, res.Report)
			}
			if res.Report.Signal != verification.SignalPageError {
				t.Fatalf("signal = %q, want %q", res.Report.Signal, verification.SignalPageError)
			}
			if !res.Report.MarkerInDOM {
				t.Fatal("the marker should also be reflected in the served document")
			}
			var attributed bool
			for _, ex := range res.Report.Provenance.Exceptions {
				if ex.MarkerIdentifier && ex.ClassName == "ReferenceError" {
					attributed = true
				}
			}
			if !attributed {
				t.Fatalf("no exception was attributed to the marker identifier: %+v", res.Report.Provenance)
			}
		})
	}
}

// The same template-literal shape with the interpolation opener escaped too:
// the marker is reflected (and visible in the served bytes) but is only ever
// template TEXT, so nothing is evaluated and the attempt stays Rejected.
func TestIntegrationTemplateLiteralReflectionOnlyIsRejected(t *testing.T) {
	m := marker(t)
	payload := "${" + m + "}"
	res := verifyReflectedPage(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		v := strings.NewReplacer("$", `\u0024`, "{", `\u007b`, "}", `\u007d`).Replace(labTemplateValue(r.URL.Query().Get("q")))
		fmt.Fprint(w, "<!doctype html><script>var message = `0 search results for '"+v+"'`;</script>")
	}, m, payload)
	requireProvenance(t, res)
	if !res.Report.MarkerInDOM {
		t.Fatal("the fixture must reflect the marker or this is not a Rejected case")
	}
	if res.Verdict != domain.VerdictRejected {
		t.Fatalf("a reflected-but-not-evaluated marker must stay Rejected, got %s: %+v", res.Verdict, res.Report)
	}
}

// A page that serves the same reflection but blocks inline script with CSP
// raises no exception at all: the marker is still in the served bytes, so this
// is Rejected. It is the control that distinguishes "CSP blocked the script"
// from "the script ran and threw" for the same fixture.
func TestIntegrationTemplateLiteralWithCSPBlockedScriptIsNotConfirmed(t *testing.T) {
	m := marker(t)
	payload := "${" + m + "}"
	res := verifyReflectedPage(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "script-src 'none'")
		fmt.Fprint(w, "<!doctype html><script>var message = `0 search results for '"+labTemplateValue(r.URL.Query().Get("q"))+"'`;</script>")
	}, m, payload)
	requireProvenance(t, res)
	if !res.Report.MarkerInDOM {
		t.Fatal("the CSP-blocked page should still reflect the marker")
	}
	if res.Verdict != domain.VerdictRejected {
		t.Fatalf("a CSP-blocked inline script raises nothing and must stay Rejected, got %s: %+v", res.Verdict, res.Report)
	}
}

// Another page error — even another marker-shaped ReferenceError — is not this
// attempt's execution signal and must never confirm it.
func TestIntegrationAnotherMarkersErrorNeverConfirms(t *testing.T) {
	m := marker(t)
	other := "ind" + strings.Repeat("f", 16)
	payload := "<img src=x onerror=" + m + ">"
	res := verifyReflectedPage(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<!doctype html><script>throw new ReferenceError('%s is not defined')</script><p>%s</p>`, other, html.EscapeString(r.URL.Query().Get("q")))
	}, m, payload)
	requireProvenance(t, res)
	if res.Verdict != domain.VerdictRejected {
		t.Fatalf("another identifier's ReferenceError must stay Rejected, got %s: %+v", res.Verdict, res.Report)
	}
}

// Two attempts running at the same time against the same page each carry their
// own marker; neither may confirm the other's candidate, and each report may
// only name its own marker.
func TestIntegrationConcurrentAttemptsKeepTheirOwnMarker(t *testing.T) {
	const open = "<!doctype html><script>var message = `0 search results for '"
	const tail = "'`;</script>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, open+labTemplateValue(r.URL.Query().Get("q"))+tail)
	}))
	defer srv.Close()
	mgr := newManagerOrSkip(t)
	defer mgr.Close()
	v := verification.NewBrowserVerifier(mgr, verification.BrowserVerifierConfig{})

	markers := []string{marker(t), "ind" + strings.Repeat("f", 16)}
	results := make([]*verification.Result, len(markers))
	errs := make([]error, len(markers))
	var wg sync.WaitGroup
	for i, m := range markers {
		wg.Add(1)
		go func(i int, m string) {
			defer wg.Done()
			payload := "${" + m + "}"
			results[i], errs[i] = v.Verify(context.Background(), verification.Input{
				Candidate: detection.Candidate{Value: payload}, Marker: m, Method: "GET",
				URL: queryURL(srv.URL, payload), Scope: openScope(),
			})
		}(i, m)
	}
	wg.Wait()
	for i := range markers {
		if errs[i] != nil {
			t.Fatalf("attempt %d: %v", i, errs[i])
		}
		if results[i].Verdict != domain.VerdictConfirmed {
			t.Fatalf("attempt %d must confirm its own marker, got %s: %+v", i, results[i].Verdict, results[i].Report)
		}
		for _, ex := range results[i].Report.Provenance.Exceptions {
			if strings.Contains(firstLineText(ex.Description), markers[1-i]) {
				t.Fatalf("attempt %d observed the other attempt's marker: %q", i, ex.Description)
			}
		}
	}
}

func firstLineText(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func TestIntegrationConfirmsDespiteErrorAndScriptFlood(t *testing.T) {
	m := marker(t)
	payload := "<img src=x onerror=" + m + ">"
	res := verifyReflectedPage(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		var b strings.Builder
		b.WriteString(`<!doctype html><script>for (let i = 0; i < 300; i++) setTimeout(function () { throw new Error('noise ' + i); }, 0);</script>`)
		for i := 0; i < 300; i++ {
			b.WriteString("<script>0</script>")
		}
		b.WriteString("<p>" + r.URL.Query().Get("q") + "</p>")
		fmt.Fprint(w, b.String())
	}, m, payload)
	requireProvenance(t, res)
	if res.Verdict != domain.VerdictConfirmed {
		t.Fatalf("genuine execution amid 300 unrelated errors and 300 scripts must stay Confirmed, got %s: %+v", res.Verdict, res.Report)
	}
}
