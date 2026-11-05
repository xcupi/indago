package scan_test

// The canonical-link lab shape: a reflected value lands inside the single-quoted
// href of a <link rel="canonical"> element in the document head, and the server
// HTML-encodes only the angle brackets. Quotes stay raw, which is exactly what
// makes an attribute-only injection possible while any shape that needs < or >
// is neutralised.
//
// Two routes:
//
//	/canonical?search=VALUE       documented lab escaping: < > encoded
//	/safe-canonical?search=VALUE  control: < > " ' & all encoded
//
// The served bytes are asserted literally (not re-derived through the fixture's
// own escape helper), before anything else uses the fixture. The real-Chromium
// pipeline test that consumes it lives in canonical_link_integration_test.go.

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
)

// labAngleOnly reproduces the lab's server-side escaping: angle brackets are
// HTML-encoded, both quote characters remain raw (so a quote can leave the
// attribute). Ampersands are left alone, as in the documented markup.
func labAngleOnly(v string) string {
	return strings.NewReplacer("<", "&lt;", ">", "&gt;").Replace(v)
}

// safeCanonical escapes every character an attribute breakout would need, so
// nothing can leave the quoted href value.
func safeCanonical(v string) string {
	return strings.NewReplacer(
		"&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;",
	).Replace(v)
}

func canonicalBody(escaped string) string {
	return `<!doctype html><html><head><link rel="canonical" href='https://lab.example/?search=` +
		escaped + `'/></head><body><p>canonical link</p></body></html>`
}

func newCanonicalLinkLab(t *testing.T) *site {
	t.Helper()
	return newSite(t, func(mux *http.ServeMux, _ func() string) {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/" {
				http.NotFound(w, r)
				return
			}
			writeHTML(w, `<a href="/canonical?search=hello">canonical</a>
<a href="/safe-canonical?search=hello">safe canonical</a>`)
		})
		mux.HandleFunc("/canonical", func(w http.ResponseWriter, r *http.Request) {
			writeHTML(w, canonicalBody(labAngleOnly(r.URL.Query().Get("search"))))
		})
		mux.HandleFunc("/safe-canonical", func(w http.ResponseWriter, r *http.Request) {
			writeHTML(w, canonicalBody(safeCanonical(r.URL.Query().Get("search"))))
		})
	})
}

// TestCanonicalLinkServerEscapesExactlyTheAngles asserts the served bytes and
// then the real analyzer/planner output for those exact bytes: the reflection
// must be classified as the link's href attribute, and the plan must already
// contain an attribute-only (no <, no >) breakout — the position the lab's
// accesskey/onclick vector needs.
func TestCanonicalLinkServerEscapesExactlyTheAngles(t *testing.T) {
	lab := newCanonicalLinkLab(t)
	p := detection.NewProbe(domain.ID("ps-canonical-fixture"), domain.ID("ip"))

	// Probe value carries < > " ' so the reflection shows the escaping.
	got := servedBody(t, lab.URL+"/canonical?search="+url.QueryEscape(p.Value()))

	// The escaping under test: angle brackets encoded, quotes raw.
	if !strings.Contains(got, "<link rel=\"canonical\" href='https://lab.example/?search="+p.Token+`&lt;&gt;"'`) {
		t.Fatalf("served bytes must HTML-encode only the angle brackets around the probe; got %q", got)
	}
	// Exact bytes, observed from this fixture (not re-derived through the
	// fixture's own escape helper), so a change to either side is caught.
	if want := `<!doctype html><html><head><link rel="canonical" href='https://lab.example/?search=` +
		p.Token + `&lt;&gt;"'` + p.Tail + `'/></head><body><p>canonical link</p></body></html>`; got != want {
		t.Fatalf("served bytes for /canonical:\n got %q\nwant %q", got, want)
	}
	if strings.Contains(got, "&lt;script") || strings.Contains(got, "%3C") {
		t.Fatalf("fixture must not pre-encode or double-encode the probe: %q", got)
	}

	safe := servedBody(t, lab.URL+"/safe-canonical?search="+url.QueryEscape(p.Value()))
	if !strings.Contains(safe, p.Token+"&lt;&gt;&quot;&#39;"+p.Tail) {
		t.Fatalf("safe control must encode every breakout character; got %q", safe)
	}

	for _, tc := range []struct{ path, body string }{
		{"/canonical", got},
		{"/safe-canonical", safe},
	} {
		rep := detection.AnalyzeReflection(p, nil, []byte(tc.body))
		detection.ClassifyContexts(&rep, []byte(tc.body), detection.ContextOptions{ContentType: "text/html"})
		if !rep.Reflected || len(rep.Locations) != 1 {
			t.Fatalf("%s: reflection = %v (%d sites), want exactly 1", tc.path, rep.Reflected, len(rep.Locations))
		}
		ctx := rep.Locations[0].Context
		if ctx == nil {
			t.Fatalf("%s: no context analysis recorded", tc.path)
		}
		t.Logf("%s: context=%s sub=%s chain=%v element=%s attribute=%s quote=%s straddles=%v",
			tc.path, ctx.Context, ctx.Sub, ctx.Chain, ctx.Element, ctx.Attribute, ctx.Quote, ctx.Straddles)
		// The value is inside the link's href, and the href is a URL: the
		// analyzer's innermost context is the URL query. The HTML attribute
		// layer must still be in the chain, because that is the layer an
		// attribute-only breakout acts on.
		if ctx.Element != "link" || ctx.Attribute != "href" || ctx.Quote != "single" {
			t.Fatalf("%s: enclosing position = element=%q attribute=%q quote=%q, want link/href/single",
				tc.path, ctx.Element, ctx.Attribute, ctx.Quote)
		}
		if ctx.Context != detection.CtxURL && ctx.Context != detection.CtxHTMLAttrValue {
			t.Fatalf("%s: context = %s, want the URL or the attribute layer of the link href", tc.path, ctx.Context)
		}

		plan := detection.PlanCandidates(&rep, detection.PlanOptions{})
		if plan == nil || len(plan.Candidates) == 0 {
			t.Fatalf("%s: no candidate planned for a reflected attribute site", tc.path)
		}
		attributeOnly := 0
		for _, c := range plan.Candidates {
			t.Logf("%s: candidate trigger=%s category=%s value=%q rationale=%s", tc.path, c.Trigger, c.Category, c.Value, c.Rationale)
			if !strings.ContainsAny(c.Value, "<>") {
				attributeOnly++
			}
		}
		// An attribute-only candidate (new attribute inside the tag, no < or >)
		// is what the canonical-link position can execute; < > are encoded, so a
		// tag-injection shape can never reach it here.
		if tc.path == "/canonical" && attributeOnly == 0 {
			t.Fatalf("/canonical: the plan has no attribute-only candidate, so the position is not covered at all")
		}
	}
}

func servedBody(t *testing.T, rawURL string) string {
	t.Helper()
	resp, err := http.Get(rawURL)
	if err != nil {
		t.Fatalf("GET %s: %v", rawURL, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s body: %v", rawURL, err)
	}
	return string(body)
}
