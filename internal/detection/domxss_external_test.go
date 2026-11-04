package detection_test

// Same-origin external script analysis: the sink lives only in /app.js, which
// is the measured lab shape (the served HTML references a script and contains
// no inline document.write at all). These tests pin the three properties the
// pipeline depends on: provenance (the script URL travels with the site), real
// bounds (per page, per file, per scan; skip — never truncate), and a
// content-addressed cache. They are pure: no browser, no network.

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/indago/indago/internal/detection"
)

const extExternalScript = `function trackSearch(query) {
    document.write('<img src="/resources/images/tracker.gif?searchTerms=' + query + '" />');
}
var searchTerms = new URLSearchParams(location.search).get('search');
if (searchTerms) { trackSearch(searchTerms); }
`

// extPage is the measured shape: one same-origin <script src>, no inline sink.
const extPage = `<!doctype html><html><head><title>Search</title>
<script src="/app.js"></script>
</head><body><h1>Search</h1></body></html>`

// countingFetcher records every URL it is asked for and serves from a map.
type countingFetcher struct {
	bodies map[string]string
	errs   map[string]error
	calls  []string
}

func (f *countingFetcher) FetchDOMXSSScript(u string) (string, error) {
	f.calls = append(f.calls, u)
	if err, ok := f.errs[u]; ok {
		return "", err
	}
	if body, ok := f.bodies[u]; ok {
		return body, nil
	}
	return "", errors.New("404 Not Found")
}

func loadPage(t *testing.T, l *detection.DOMXSSScriptLoader, f detection.DOMXSSScriptFetcher, pageURL, html string) []detection.DOMXSSExternalScript {
	t.Helper()
	return l.ScriptsFor(f, pageURL, detection.DOMXSSScriptSrcs(html))
}

// TestDOMXSSExternalScriptSinkProvenance is the headline fixture: the page has
// no inline script at all, and the only sink is inside /app.js. The static pass
// must report document.write reachable AND name the script it came from; the
// base revision returns no_tainted_path here, which is the false negative this
// layer exists to remove.
func TestDOMXSSExternalScriptSinkProvenance(t *testing.T) {
	const pageURL = "http://lab.test/search"
	f := &countingFetcher{bodies: map[string]string{"http://lab.test/app.js": extExternalScript}}
	l := detection.NewDOMXSSScriptLoader()
	scripts := loadPage(t, l, f, pageURL, extPage)

	res := detection.DOMXSSStaticReachabilityWithScripts(extPage, pageURL, detection.DOMSourceQuery, "search", scripts)
	if res.Outcome != detection.DOMXSSFlowTainted {
		t.Fatalf("external-script sink must be reachable, got %s sites=%+v problems=%+v unresolved=%+v",
			res.Outcome, res.Sites, res.ScriptProblems, res.Unresolved)
	}
	var site *detection.DOMXSSFlowSite
	for i := range res.Sites {
		if res.Sites[i].Sink == detection.DOMSinkDocumentWrite {
			site = &res.Sites[i]
		}
	}
	if site == nil {
		t.Fatalf("want a document.write site, got %+v", res.Sites)
	}
	if site.Script != "http://lab.test/app.js" {
		t.Fatalf("site provenance = %q, want the external script URL", site.Script)
	}
	if site.Line < 1 || site.Line > strings.Count(extExternalScript, "\n")+1 {
		t.Fatalf("site line %d is outside the analysed script", site.Line)
	}
	if res.ExternalScripts != 1 || res.AnalysedScripts != 1 || len(res.ScriptProblems) != 0 {
		t.Fatalf("counts: external=%d analysed=%d problems=%+v", res.ExternalScripts, res.AnalysedScripts, res.ScriptProblems)
	}
	if len(f.calls) != 1 || f.calls[0] != "http://lab.test/app.js" {
		t.Fatalf("fetch calls = %v, want exactly the same-origin script", f.calls)
	}
}

// TestDOMXSSExternalScriptCrossScriptFlow keeps document order meaningful: an
// inline script defines the helper, the external script calls it. Both are
// analysed as one program in document order, the way the browser runs them.
func TestDOMXSSExternalScriptCrossScriptFlow(t *testing.T) {
	const pageURL = "http://lab.test/search"
	const html = `<!doctype html><html><head>
<script>function trackSearch(query) { document.write('<b>' + query + '</b>'); }</script>
<script src="/app.js"></script>
</head><body></body></html>`
	const body = `var searchTerms = new URLSearchParams(location.search).get('search');
if (searchTerms) { trackSearch(searchTerms); }`
	f := &countingFetcher{bodies: map[string]string{"http://lab.test/app.js": body}}
	l := detection.NewDOMXSSScriptLoader()

	res := detection.DOMXSSStaticReachabilityWithScripts(html, pageURL, detection.DOMSourceQuery, "search", loadPage(t, l, f, pageURL, html))
	if res.Outcome != detection.DOMXSSFlowTainted {
		t.Fatalf("cross-script flow must be reachable, got %s unresolved=%+v", res.Outcome, res.Unresolved)
	}
	var hasInline, hasExternal bool
	for _, s := range res.Sites {
		switch s.Sink {
		case detection.DOMSinkDocumentWrite:
			hasInline = hasInline || s.Script == ""
			hasExternal = hasExternal || s.Script == "http://lab.test/app.js"
		}
	}
	if !hasExternal {
		t.Fatalf("the site reached through the external call must carry the script URL, got %+v", res.Sites)
	}
}

// TestDOMXSSExternalScriptMissingStaysNegative: a referenced script that cannot
// be read produces NO site (no false positive), and the absence is recorded as
// an unanalysed script instead of being read as a clean negative. Removing the
// reference altogether is the only clean negative.
func TestDOMXSSExternalScriptMissingStaysNegative(t *testing.T) {
	const pageURL = "http://lab.test/search"

	t.Run("reference served 404", func(t *testing.T) {
		f := &countingFetcher{errs: map[string]error{"http://lab.test/app.js": errors.New("404 Not Found")}}
		l := detection.NewDOMXSSScriptLoader()
		scripts := loadPage(t, l, f, pageURL, extPage)
		res := detection.DOMXSSStaticReachabilityWithScripts(extPage, pageURL, detection.DOMSourceQuery, "search", scripts)
		if len(res.Sites) != 0 {
			t.Fatalf("a missing script cannot yield a site: %+v", res.Sites)
		}
		if res.Outcome != detection.DOMXSSFlowUnresolved {
			t.Fatalf("an unreadable script is unresolved, not %s", res.Outcome)
		}
		if len(res.ScriptProblems) != 1 || !strings.Contains(res.ScriptProblems[0].Reason, detection.DOMXSSScriptSkipFetchFailed) {
			t.Fatalf("the failure must be recorded, got %+v", res.ScriptProblems)
		}
	})

	t.Run("no reference at all", func(t *testing.T) {
		const html = `<!doctype html><html><body><h1>Search</h1></body></html>`
		res := detection.DOMXSSStaticReachabilityWithScripts(html, pageURL, detection.DOMSourceQuery, "search", nil)
		if res.Outcome != detection.DOMXSSFlowNoTaintedPath || len(res.Sites) != 0 {
			t.Fatalf("a page with no script is a clean negative, got %s %+v", res.Outcome, res.Sites)
		}
	})
}

// TestDOMXSSExternalScriptTooLargeIsSkipped: an oversized bundle is skipped
// WHOLE. Truncating it would hand the tokenizer half an expression and report
// nonsense, so the body is never analysed and the skip is recorded.
func TestDOMXSSExternalScriptTooLargeIsSkipped(t *testing.T) {
	const pageURL = "http://lab.test/search"
	f := &countingFetcher{errs: map[string]error{"http://lab.test/vendor.js": detection.ErrDOMXSSScriptTooLarge}}
	l := detection.NewDOMXSSScriptLoader()
	html := `<!doctype html><html><head><script src="/vendor.js"></script></head><body></body></html>`
	scripts := loadPage(t, l, f, pageURL, html)

	if len(scripts) != 1 || scripts[0].Body != "" || scripts[0].Err != detection.DOMXSSScriptSkipTooLarge {
		t.Fatalf("oversized script = %+v, want a recorded skip with no body", scripts)
	}
	if st := l.Stats(); st.TooLarge != 1 || st.BytesRead != 0 {
		t.Fatalf("stats = %+v, want one too-large skip and no bytes read", st)
	}
	res := detection.DOMXSSStaticReachabilityWithScripts(html, pageURL, detection.DOMSourceQuery, "search", scripts)
	if res.Outcome != detection.DOMXSSFlowUnresolved || len(res.Sites) != 0 {
		t.Fatalf("skipped script must stay unresolved and produce no site, got %s %+v", res.Outcome, res.Sites)
	}
}

// TestDOMXSSScriptCapsHonoured pins every ceiling with a counting fetcher.
func TestDOMXSSScriptCapsHonoured(t *testing.T) {
	const pageURL = "http://lab.test/search"

	t.Run("max files per page", func(t *testing.T) {
		var html strings.Builder
		f := &countingFetcher{bodies: map[string]string{}}
		html.WriteString(`<!doctype html><html><head>`)
		for i := 0; i < 20; i++ {
			url := "http://lab.test/s" + string(rune('a'+i)) + ".js"
			html.WriteString(`<script src="/s` + string(rune('a'+i)) + `.js"></script>`)
			f.bodies[url] = "var x = 1;"
		}
		html.WriteString(`</head><body></body></html>`)
		scripts := loadPage(t, detection.NewDOMXSSScriptLoader(), f, pageURL, html.String())
		if len(f.calls) != detection.DOMXSSScriptFetchLimit {
			t.Fatalf("fetched %d scripts, cap is %d", len(f.calls), detection.DOMXSSScriptFetchLimit)
		}
		var capped int
		for _, s := range scripts {
			if s.Err == detection.DOMXSSScriptSkipPerPageCap {
				capped++
			}
		}
		if capped != 20-detection.DOMXSSScriptFetchLimit {
			t.Fatalf("recorded %d per-page skips, want %d", capped, 20-detection.DOMXSSScriptFetchLimit)
		}
	})

	t.Run("max bytes per scan", func(t *testing.T) {
		l := detection.NewDOMXSSScriptLoader()
		var fetched int
		f := detection.DOMXSSScriptFetcherFunc(func(u string) (string, error) {
			fetched++
			// Unique content per URL, exactly at the per-file cap, so nothing is
			// deduplicated and the scan budget is the only limit that can bite.
			return strings.Repeat(string(rune('a'+fetched%26)), detection.DOMXSSScriptByteLimit), nil
		})
		pages := (detection.DOMXSSScriptScanByteBudget / detection.DOMXSSScriptByteLimit) + 4
		for i := 0; i < pages; i++ {
			html := `<!doctype html><html><head><script src="/b` + string(rune('a'+i)) + `.js"></script></head><body></body></html>`
			l.ScriptsFor(f, pageURL, detection.DOMXSSScriptSrcs(html))
		}
		st := l.Stats()
		if st.BytesRead > detection.DOMXSSScriptScanByteBudget {
			t.Fatalf("read %d bytes, budget is %d", st.BytesRead, detection.DOMXSSScriptScanByteBudget)
		}
		if st.BudgetRefused == 0 {
			t.Fatalf("the scan budget was never reached: %+v", st)
		}
		if fetched != st.Fetches {
			t.Fatalf("fetcher called %d times but %d fetches recorded", fetched, st.Fetches)
		}
	})
}

// TestDOMXSSScriptHashCache: the same script referenced by two pages is fetched
// once, and identical CONTENT under different URLs reaches the analyser once.
func TestDOMXSSScriptHashCache(t *testing.T) {
	const pageURL = "http://lab.test/search"
	f := &countingFetcher{bodies: map[string]string{"http://lab.test/app.js": extExternalScript}}
	l := detection.NewDOMXSSScriptLoader()

	first := loadPage(t, l, f, pageURL, extPage)
	second := loadPage(t, l, f, pageURL, strings.Replace(extPage, "</head>", `<script src="app.js"></script></head>`, 1))

	if len(f.calls) != 1 {
		t.Fatalf("same script fetched %d times, want 1: %v", len(f.calls), f.calls)
	}
	if st := l.Stats(); st.CacheHits != 1 || st.Fetches != 1 || st.Bodies != 1 {
		t.Fatalf("stats = %+v, want one fetch and one cache hit", st)
	}
	for _, s := range append(first, second...) {
		if s.Body != extExternalScript || s.Hash == "" {
			t.Fatalf("cached entry must still carry body+hash: %+v", s)
		}
	}

	t.Run("identical content at a different URL", func(t *testing.T) {
		f2 := &countingFetcher{bodies: map[string]string{
			"http://lab.test/a.js": extExternalScript,
			"http://lab.test/b.js": extExternalScript,
		}}
		l2 := detection.NewDOMXSSScriptLoader()
		html := `<!doctype html><html><head><script src="/a.js"></script><script src="/b.js"></script></head><body></body></html>`
		scripts := loadPage(t, l2, f2, pageURL, html)
		if st := l2.Stats(); st.HashHits != 1 || st.Bodies != 1 {
			t.Fatalf("stats = %+v, want one hash hit and one distinct body", st)
		}
		res := detection.DOMXSSStaticReachabilityWithScripts(html, pageURL, detection.DOMSourceQuery, "search", scripts)
		if res.AnalysedScripts != 1 {
			t.Fatalf("identical content analysed %d times, want 1", res.AnalysedScripts)
		}
		if len(res.Sites) != 1 || res.Sites[0].Script != "http://lab.test/a.js" {
			t.Fatalf("want one site attributed to the first URL, got %+v", res.Sites)
		}
	})
}

// TestDOMXSSScriptThirdPartyNeverFetched: a CDN reference is not this page's
// script and must never be resolved or fetched, even when a fetcher would serve
// it. It is counted, not analysed.
func TestDOMXSSScriptThirdPartyNeverFetched(t *testing.T) {
	const pageURL = "https://lab.test/search"
	html := `<!doctype html><html><head>
<script src="https://cdn.example.com/lib.js"></script>
<script src="//cdn.example.com/other.js"></script>
<script src="/app.js"></script>
</head><body></body></html>`
	f := &countingFetcher{bodies: map[string]string{"https://lab.test/app.js": extExternalScript}}
	l := detection.NewDOMXSSScriptLoader()
	scripts := loadPage(t, l, f, pageURL, html)

	if len(f.calls) != 1 || f.calls[0] != "https://lab.test/app.js" {
		t.Fatalf("fetcher calls = %v, want only the same-origin script", f.calls)
	}
	if st := l.Stats(); st.Foreign != 2 {
		t.Fatalf("foreign scripts = %d, want 2: %+v", st.Foreign, st)
	}
	res := detection.DOMXSSStaticReachabilityWithScripts(html, pageURL, detection.DOMSourceQuery, "search", scripts)
	if res.ForeignScripts != 2 {
		t.Fatalf("result foreign count = %d, want 2", res.ForeignScripts)
	}
	if res.Outcome != detection.DOMXSSFlowTainted {
		t.Fatalf("the same-origin sink must still be found, got %s", res.Outcome)
	}
}

// TestDOMXSSSameOriginScriptURL pins the origin gate itself.
func TestDOMXSSSameOriginScriptURL(t *testing.T) {
	const base = "https://lab.test/deep/page?x=1"
	cases := []struct {
		raw, want string
		ok        bool
	}{
		{"/app.js", "https://lab.test/app.js", true},
		{"app.js", "https://lab.test/deep/app.js", true},
		{"../js/app.js", "https://lab.test/js/app.js", true},
		{"https://lab.test:443/x.js", "https://lab.test/x.js", true},
		{"//lab.test/x.js", "https://lab.test/x.js", true},
		{"https://cdn.test/x.js", "", false},
		{"http://lab.test/x.js", "", false},
		{"https://lab.test:8443/x.js", "", false},
		{"data:text/javascript,alert(1)", "", false},
		{"javascript:alert(1)", "", false},
		{"blob:https://lab.test/uuid", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		got, ok := detection.DOMXSSSameOriginScriptURL(c.raw, base)
		if got != c.want || ok != c.ok {
			t.Errorf("DOMXSSSameOriginScriptURL(%q) = (%q,%v), want (%q,%v)", c.raw, got, ok, c.want, c.ok)
		}
	}
}

// TestDOMXSSStaticInlineOnlyGolden: for pages with no external script, the
// external-aware entry point must return EXACTLY what the inline-only pass
// returned before this layer existed — same outcome, sites, chains, notes.
func TestDOMXSSStaticInlineOnlyGolden(t *testing.T) {
	pages := []string{
		`<!doctype html><body><p>no script at all</p></body>`,
		`<!doctype html><body><script>document.write('static');</script></body>`,
		`<!doctype html><body><script>var q = new URLSearchParams(location.search).get('q'); document.write('<b>' + q + '</b>');</script></body>`,
		`<!doctype html><body><script>var h = location.hash; document.body.innerHTML = h;</script></body>`,
		`<!doctype html><body><script>var x = "unparsed ((( ;</script></body>`,
	}
	for _, page := range pages {
		for _, src := range []detection.DOMXSSSource{detection.DOMSourceQuery, detection.DOMSourceHash} {
			before := detection.DOMXSSStaticReachability(page, src, "q")
			after := detection.DOMXSSStaticReachabilityWithScripts(page, "https://lab.test/", src, "q", nil)
			if !reflect.DeepEqual(before, after) {
				t.Fatalf("inline-only result changed for %s\nbefore=%+v\nafter =%+v", src, before, after)
			}
		}
	}
}
