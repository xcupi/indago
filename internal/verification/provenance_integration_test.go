package verification_test

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"strings"
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

// Unrelated page errors and a script flood must not use up the evidence budget:
// the genuine execution is still Confirmed.
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
