package scan

// Unit tests for the DOM-XSS engine's "as unit-testable as it can be"
// pieces: the pure helpers (console-message parsing, harness script
// content, URL/fragment encoding, job payload, endpoint selection) and
// Finding create/absorb/correlate (against store/memory, no browser
// needed). Live browser execution is validated against a disposable lab —
// see docs/dom-xss.md — not here.

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
)

// --- parseDOMXSSReachability: the sink-hook harness's own report format ---

func consoleLog(text string) browser.ConsoleMessage {
	return browser.ConsoleMessage{Type: "log", Text: text}
}

func TestParseDOMXSSReachabilityFindsMatchingSink(t *testing.T) {
	marker := "indabc123"
	msgs := []browser.ConsoleMessage{
		consoleLog("unrelated page log"),
		consoleLog(domXSSConsolePrefix + `{"sink":"innerHTML","value":"hello indabc123 world"}`),
	}
	got := parseDOMXSSReachability(msgs, marker)
	if len(got) != 1 || got[0] != detection.DOMSinkInnerHTML {
		t.Fatalf("got %v, want [innerHTML]", got)
	}
}

func TestParseDOMXSSReachabilityIgnoresMismatchedMarker(t *testing.T) {
	msgs := []browser.ConsoleMessage{
		consoleLog(domXSSConsolePrefix + `{"sink":"innerHTML","value":"some other value"}`),
	}
	if got := parseDOMXSSReachability(msgs, "indabc123"); len(got) != 0 {
		t.Fatalf("got %v, want none (value does not contain the marker)", got)
	}
}

func TestParseDOMXSSReachabilityIgnoresUnknownSink(t *testing.T) {
	marker := "indabc123"
	msgs := []browser.ConsoleMessage{
		consoleLog(domXSSConsolePrefix + `{"sink":"eval","value":"indabc123"}`),
	}
	if got := parseDOMXSSReachability(msgs, marker); len(got) != 0 {
		t.Fatalf("got %v, want none (eval is out of scope for this slice)", got)
	}
}

func TestParseDOMXSSReachabilityIgnoresMalformedJSON(t *testing.T) {
	marker := "indabc123"
	msgs := []browser.ConsoleMessage{
		consoleLog(domXSSConsolePrefix + `not json`),
	}
	if got := parseDOMXSSReachability(msgs, marker); len(got) != 0 {
		t.Fatalf("got %v, want none", got)
	}
}

func TestParseDOMXSSReachabilityIgnoresMessagesWithoutThePrefix(t *testing.T) {
	marker := "indabc123"
	msgs := []browser.ConsoleMessage{
		consoleLog(`{"sink":"innerHTML","value":"indabc123"}`), // no prefix — not ours
	}
	if got := parseDOMXSSReachability(msgs, marker); len(got) != 0 {
		t.Fatalf("got %v, want none (unprefixed messages are not this harness's)", got)
	}
}

func TestParseDOMXSSReachabilityDedupsAndPreservesFirstSeenOrder(t *testing.T) {
	marker := "indabc123"
	msgs := []browser.ConsoleMessage{
		consoleLog(domXSSConsolePrefix + `{"sink":"document.write","value":"indabc123 a"}`),
		consoleLog(domXSSConsolePrefix + `{"sink":"innerHTML","value":"indabc123 b"}`),
		consoleLog(domXSSConsolePrefix + `{"sink":"document.write","value":"indabc123 c"}`), // repeat: deduped
	}
	got := parseDOMXSSReachability(msgs, marker)
	want := []detection.DOMXSSSink{detection.DOMSinkDocumentWrite, detection.DOMSinkInnerHTML}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got %v, want %v (first-seen order, deduped)", got, want)
	}
}

func TestParseDOMXSSReachabilityEmptyMarkerYieldsNothing(t *testing.T) {
	msgs := []browser.ConsoleMessage{
		consoleLog(domXSSConsolePrefix + `{"sink":"innerHTML","value":"anything"}`),
	}
	if got := parseDOMXSSReachability(msgs, ""); got != nil {
		t.Fatalf("got %v, want nil for an empty marker", got)
	}
}

// --- domXSSHarnessScript: the init-script harness content itself ---

func TestDomXSSHarnessScriptContainsMarkerAndHooks(t *testing.T) {
	marker := "indxyzmark1"
	script := domXSSHarnessScript(marker)
	for _, want := range []string{marker, domXSSConsolePrefix, "innerHTML", "outerHTML", "document.write", "document.writeln", "defineProperty"} {
		if !contains(script, want) {
			t.Fatalf("harness script missing %q:\n%s", want, script)
		}
	}
}

func TestDomXSSHarnessScriptIsValidJSStringLiteralQuoting(t *testing.T) {
	// A marker/prefix containing a double quote or backslash would break
	// naive string concatenation; goQuoteJS must escape it correctly.
	// detection.NewProbe/domXSSConsolePrefix never actually produce such
	// characters, but the escaping function itself must still be correct.
	tricky := `weird"marker\with` + "`backtick"
	quoted := goQuoteJS(tricky)
	if quoted[0] != '"' || quoted[len(quoted)-1] != '"' {
		t.Fatalf("goQuoteJS(%q) = %q, want a double-quoted literal", tricky, quoted)
	}
}

// --- URL/fragment helpers ---

func TestJsEncodeURIComponentMatchesJSSemantics(t *testing.T) {
	cases := map[string]string{
		"":            "",
		"abcXYZ019":   "abcXYZ019", // unreserved
		"-_.!~*'()":   "-_.!~*'()", // unreserved per JS encodeURIComponent
		" ":           "%20",       // NOT "+", unlike Go's url.QueryEscape
		"<img src=x>": "%3Cimg%20src%3Dx%3E",
		"a/b":         "a%2Fb",
		"100%":        "100%25",
	}
	for in, want := range cases {
		if got := jsEncodeURIComponent(in); got != want {
			t.Fatalf("jsEncodeURIComponent(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDomXSSHashURLStripsExistingFragmentAndEncodes(t *testing.T) {
	got := domXSSHashURL("https://target.example/page?x=1#old", "<img onerror=M>")
	want := "https://target.example/page?x=1#%3Cimg%20onerror%3DM%3E"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestDomXSSHashURLNoExistingFragment(t *testing.T) {
	got := domXSSHashURL("https://target.example/page", "abc")
	if got != "https://target.example/page#abc" {
		t.Fatalf("got %q", got)
	}
}

// --- domXSSQueryURL: the query-string source's own URL builder ---

func TestDomXSSQueryURLSetsParamPreservesOthersAndFragment(t *testing.T) {
	got := domXSSQueryURL("https://target.example/page?x=1&y=2#frag", "x", "<img onerror=M>")
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("result is not a valid URL: %v (%q)", err, got)
	}
	if u.Query().Get("x") != "<img onerror=M>" {
		t.Fatalf("param x = %q, want the injected value", u.Query().Get("x"))
	}
	if u.Query().Get("y") != "2" {
		t.Fatalf("param y = %q, want untouched (2)", u.Query().Get("y"))
	}
	if u.Fragment != "frag" {
		t.Fatalf("fragment = %q, want preserved (frag)", u.Fragment)
	}
}

func TestDomXSSQueryURLNoExistingQuery(t *testing.T) {
	got := domXSSQueryURL("https://target.example/page", "q", "abc")
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("result is not a valid URL: %v (%q)", err, got)
	}
	if u.Query().Get("q") != "abc" {
		t.Fatalf("param q = %q, want abc", u.Query().Get("q"))
	}
}

func TestDomXSSQueryURLUsesFormEncodingNotJSEncoding(t *testing.T) {
	// Unlike the hash source (jsEncodeURIComponent), the query-string
	// source deliberately uses Go's standard net/url form encoding —
	// URLSearchParams decodes "+" as a space per the WHATWG spec, so a
	// literal space in the raw query string should round-trip as "+",
	// not "%20". See domXSSQueryURL's doc comment.
	got := domXSSQueryURL("https://target.example/page", "q", "a b")
	if !strings.Contains(got, "q=a+b") {
		t.Fatalf("got %q, want a form-encoded space (a+b)", got)
	}
}

// --- window.name / postMessage source-side script builders (pure) ---

func TestSetWindowNameScriptEmbedsValueAsJSStringLiteral(t *testing.T) {
	value := "<img src=x onerror=MARKER>"
	script := setWindowNameScript(value)
	if !strings.Contains(script, "window.name") {
		t.Fatalf("script should set window.name: %q", script)
	}
	if !strings.Contains(script, "MARKER") {
		t.Fatalf("script should embed the value: %q", script)
	}
	// No URL percent-encoding at all — this goes through Evaluate, not a
	// navigation URL (see setWindowNameScript's doc comment).
	if strings.Contains(script, "%3C") || strings.Contains(script, "%20") {
		t.Fatalf("script must not URL-encode the value: %q", script)
	}
}

func TestPostMessageScriptCreatesOpaqueSandboxedSender(t *testing.T) {
	value := "<img src=x onerror=MARKER>"
	script := postMessageScript(value)
	for _, want := range []string{"createElement('iframe')", "setAttribute('sandbox', 'allow-scripts')", "srcdoc", "parent.postMessage", "MARKER", "'*'", "sender.onload", "setTimeout"} {
		if !strings.Contains(script, want) {
			t.Fatalf("script missing %q: %q", want, script)
		}
	}
	if strings.Contains(script, "allow-same-origin") || strings.Contains(script, "window.postMessage") {
		t.Fatalf("sender must have an opaque origin and post to the parent, not self-post: %q", script)
	}
}

// --- piece 3: document.referrer / localStorage / sessionStorage ---

// domXSSOriginURL is the only genuinely new pure helper piece 3 adds (the
// referrer source needs no custom script builder at all — see
// navigateWithReferrer's doc comment — and the storage source reuses the
// EXISTING browser.Page.SetLocalStorage/SetSessionStorage, so there is no
// new storage-side script to unit test either; the sequencing itself is
// validated live, see docs/dom-xss.md).
func TestDomXSSOriginURLDerivesSchemeAndHostOnly(t *testing.T) {
	cases := map[string]string{
		"https://target.example/page?x=1#frag": "https://target.example/",
		"https://target.example:8443/a/b/c":    "https://target.example:8443/",
		"http://127.0.0.1:9000/winname":        "http://127.0.0.1:9000/",
	}
	for in, want := range cases {
		got, err := domXSSOriginURL(in)
		if err != nil {
			t.Fatalf("domXSSOriginURL(%q): %v", in, err)
		}
		if got != want {
			t.Fatalf("domXSSOriginURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDomXSSOriginURLRejectsMalformedOrSchemelessURL(t *testing.T) {
	for _, bad := range []string{"not-a-url-at-all-no-scheme", "/just/a/path", ""} {
		if _, err := domXSSOriginURL(bad); err == nil {
			t.Fatalf("domXSSOriginURL(%q): expected an error, got none", bad)
		}
	}
}

// domXSSRefererURL: Chromium's Referer override is silently ignored
// unless the value is itself a well-formed absolute URL — this helper
// wraps the canary/payload accordingly (see its own doc comment, and the
// live-lab section of docs/dom-xss.md, for the empirical discovery behind
// this).
func TestDomXSSRefererURLIsAWellFormedAbsoluteURLEmbeddingTheValue(t *testing.T) {
	got := domXSSRefererURL("indago-domxss-canary-abc123")
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("domXSSRefererURL produced an invalid URL: %v (%q)", err, got)
	}
	if u.Scheme == "" || u.Host == "" {
		t.Fatalf("domXSSRefererURL must produce an absolute URL, got %q", got)
	}
	if !strings.Contains(got, "indago-domxss-canary-abc123") {
		t.Fatalf("got %q, want it to contain the value", got)
	}
}

func TestDomXSSRefererURLPercentEncodesMarkup(t *testing.T) {
	// A literal "<"/">" can never survive as-is in an HTTP Referer header
	// (the browser's own URL parser always percent-encodes it) — this is
	// the same jsEncodeURIComponent encoder the hash source already uses,
	// reused here rather than reinvented.
	got := domXSSRefererURL("<img src=x onerror=M>")
	if strings.ContainsAny(got, "<>") {
		t.Fatalf("domXSSRefererURL must not contain a literal %q/%q: %q", "<", ">", got)
	}
	if !strings.Contains(got, "MARKER") && !strings.Contains(got, "onerror%3DM") {
		t.Fatalf("got %q, want the percent-encoded payload to still be present", got)
	}
}

// domXSSStorageKey is a fixed, documented convention (there is no
// server-side parameter to derive a key from for this source, same
// boundary Hash/WindowName/PostMessage/Referrer already have) — this test
// exists mainly to pin the exact key name so a future change to it is a
// deliberate, reviewed decision rather than an accidental rename that
// silently breaks every live-lab route tuned to read it.
func TestDomXSSStorageKeyIsStable(t *testing.T) {
	if domXSSStorageKey != "indago_domxss_probe" {
		t.Fatalf("domXSSStorageKey = %q, want the documented stable key name", domXSSStorageKey)
	}
}

// --- domXSSJob now carries a Source; firstQueryParamName ---

func TestParseDOMXSSJobRequiresValidSource(t *testing.T) {
	payload, _ := json.Marshal(domXSSJob{EndpointID: domain.NewID(), Source: detection.DOMSourceHash})
	dj, err := parseDOMXSSJob(&domain.TestJob{Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	if dj.Source != detection.DOMSourceHash {
		t.Fatalf("source = %s, want %s", dj.Source, detection.DOMSourceHash)
	}

	badPayload, _ := json.Marshal(domXSSJob{EndpointID: domain.NewID(), Source: "eval"})
	if _, err := parseDOMXSSJob(&domain.TestJob{Payload: badPayload}); err == nil {
		t.Fatal("expected an error for an invalid/unimplemented source")
	}
}

// --- domXSSNavigable / selectDOMXSSEndpoints ---

func TestDomXSSNavigable(t *testing.T) {
	navigable := []domain.HTTPMethod{domain.MethodGET, domain.MethodHEAD, ""}
	notNavigable := []domain.HTTPMethod{domain.MethodPOST, domain.MethodPUT, domain.MethodPATCH, domain.MethodDELETE}
	for _, m := range navigable {
		if !domXSSNavigable(m) {
			t.Fatalf("%s should be navigable", m)
		}
	}
	for _, m := range notNavigable {
		if domXSSNavigable(m) {
			t.Fatalf("%s should NOT be navigable (would not exercise the real method)", m)
		}
	}
}

func TestSelectDOMXSSEndpointsFiltersAndDedupes(t *testing.T) {
	a := &domain.Endpoint{ID: domain.NewID(), URL: "https://x/a", Method: domain.MethodGET}
	aDup := &domain.Endpoint{ID: domain.NewID(), URL: "https://x/a", Method: domain.MethodGET} // same URL, different endpoint row
	b := &domain.Endpoint{ID: domain.NewID(), URL: "https://x/b", Method: domain.MethodHEAD}
	post := &domain.Endpoint{ID: domain.NewID(), URL: "https://x/c", Method: domain.MethodPOST}

	got := selectDOMXSSEndpoints([]*domain.Endpoint{a, aDup, b, post, nil})
	if len(got) != 2 {
		t.Fatalf("got %d endpoints, want 2 (dedup by URL, POST excluded, nil skipped): %+v", len(got), got)
	}
	if got[0].URL != "https://x/a" || got[1].URL != "https://x/b" {
		t.Fatalf("got %v, want [a, b] in input order", got)
	}
}

// --- parseDOMXSSJob ---

func TestParseDOMXSSJobRoundTrip(t *testing.T) {
	epID := domain.NewID()
	payload, err := json.Marshal(domXSSJob{EndpointID: epID, Source: detection.DOMSourceHash})
	if err != nil {
		t.Fatal(err)
	}
	job := &domain.TestJob{Payload: payload}
	dj, err := parseDOMXSSJob(job)
	if err != nil {
		t.Fatal(err)
	}
	if dj.EndpointID != epID {
		t.Fatalf("got %s, want %s", dj.EndpointID, epID)
	}
	if dj.Source != detection.DOMSourceHash {
		t.Fatalf("source = %s, want %s", dj.Source, detection.DOMSourceHash)
	}
}

func TestParseDOMXSSJobRejectsEmptyOrMissingPayload(t *testing.T) {
	if _, err := parseDOMXSSJob(&domain.TestJob{}); err == nil {
		t.Fatal("expected an error for a job with no payload")
	}
	payload, _ := json.Marshal(domXSSJob{})
	if _, err := parseDOMXSSJob(&domain.TestJob{Payload: payload}); err == nil {
		t.Fatal("expected an error for a job payload with an empty EndpointID and no source")
	}
	// A valid EndpointID but a missing/invalid Source must also be rejected
	// (every job enqueued by enqueueDOMXSSProbes carries one of the four
	// implemented sources — a job without one is malformed).
	missingSource, _ := json.Marshal(domXSSJob{EndpointID: domain.NewID()})
	if _, err := parseDOMXSSJob(&domain.TestJob{Payload: missingSource}); err == nil {
		t.Fatal("expected an error for a job payload with no source")
	}
}

// --- Finding create/absorb/correlate (store/memory, no browser) ---

func domXSSTestEndpoint(t *testing.T, env *scanEnv, url string) *domain.Endpoint {
	t.Helper()
	ep := env.endpoint(url, domain.MethodGET)
	ep.Source = domain.SourceCrawler
	return ep
}

func TestUpsertDOMXSSFindingCreatesPendingFinding(t *testing.T) {
	env := newScanEnv(t)
	ep := domXSSTestEndpoint(t, env, "http://x/page")
	marker := "indhashmarker1"
	cand, ok := detection.DOMXSSPayloadFor(detection.DOMSourceHash, detection.DOMSinkInnerHTML, marker)
	if !ok {
		t.Fatal("expected a candidate")
	}
	canary := detection.DOMXSSCanary(marker)
	reachTC := domain.NewID()

	f, err := upsertDOMXSSFinding(context.Background(), env.st, env.scanID, ep, cand, canary, reachTC)
	if err != nil {
		t.Fatal(err)
	}
	if f.VulnClass != domain.VulnDOMXSS || f.Verdict != domain.VerdictPending {
		t.Fatalf("new dom-xss finding = %+v", f)
	}
	if f.EndpointID != ep.ID {
		t.Fatalf("endpoint id = %s, want %s", f.EndpointID, ep.ID)
	}
	d := decodeFindingDetail(f.Detail)
	if d.Occurrences != 1 || len(d.Attempts) != 1 || d.Attempts[0].Verdict != domain.VerdictPending {
		t.Fatalf("detail = %+v", d)
	}
}

func TestUpsertDOMXSSFindingAbsorbsRepeatReachability(t *testing.T) {
	env := newScanEnv(t)
	ep := domXSSTestEndpoint(t, env, "http://x/page")
	marker := "indhashmarker2"
	cand, _ := detection.DOMXSSPayloadFor(detection.DOMSourceHash, detection.DOMSinkInnerHTML, marker)
	canary := detection.DOMXSSCanary(marker)
	ctx := context.Background()

	first, err := upsertDOMXSSFinding(ctx, env.st, env.scanID, ep, cand, canary, domain.NewID())
	if err != nil {
		t.Fatal(err)
	}
	second, err := upsertDOMXSSFinding(ctx, env.st, env.scanID, ep, cand, canary, domain.NewID())
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != second.ID {
		t.Fatalf("a repeat reachability signal at the same (endpoint, source, sink) must absorb into the SAME finding, got %s and %s", first.ID, second.ID)
	}
	findings, _ := env.st.Findings().ListByScan(ctx, env.scanID)
	if len(findings) != 1 {
		t.Fatalf("expected exactly one dom-xss finding, got %d", len(findings))
	}
	d := decodeFindingDetail(findings[0].Detail)
	if d.Occurrences != 2 || len(d.Attempts) != 2 {
		t.Fatalf("detail = %+v, want occurrences=2 attempts=2", d)
	}
}

func TestUpsertDOMXSSFindingDistinctSinksAreDistinctFindings(t *testing.T) {
	env := newScanEnv(t)
	ep := domXSSTestEndpoint(t, env, "http://x/page")
	marker := "indhashmarker3"
	ctx := context.Background()

	innerHTML, _ := detection.DOMXSSPayloadFor(detection.DOMSourceHash, detection.DOMSinkInnerHTML, marker)
	outerHTML, _ := detection.DOMXSSPayloadFor(detection.DOMSourceHash, detection.DOMSinkOuterHTML, marker)
	canary := detection.DOMXSSCanary(marker)

	if _, err := upsertDOMXSSFinding(ctx, env.st, env.scanID, ep, innerHTML, canary, domain.NewID()); err != nil {
		t.Fatal(err)
	}
	if _, err := upsertDOMXSSFinding(ctx, env.st, env.scanID, ep, outerHTML, canary, domain.NewID()); err != nil {
		t.Fatal(err)
	}
	findings, _ := env.st.Findings().ListByScan(ctx, env.scanID)
	if len(findings) != 2 {
		t.Fatalf("different sinks at the same endpoint must be distinct findings, got %d", len(findings))
	}
}

// correlateDOMXSSVerification: monotonic verdict promotion, sticky confirmed.
func TestCorrelateDOMXSSVerificationPromotesAndStaysConfirmed(t *testing.T) {
	env := newScanEnv(t)
	ep := domXSSTestEndpoint(t, env, "http://x/page")
	marker := "indhashmarker4"
	cand, _ := detection.DOMXSSPayloadFor(detection.DOMSourceHash, detection.DOMSinkInnerHTML, marker)
	canary := detection.DOMXSSCanary(marker)
	ctx := context.Background()

	f, err := upsertDOMXSSFinding(ctx, env.st, env.scanID, ep, cand, canary, domain.NewID())
	if err != nil {
		t.Fatal(err)
	}

	exec := &domXSSExecutor{store: env.st, log: execLog(), findingsMu: &sync.Mutex{}}
	exec.correlateDOMXSSVerification(ctx, f.ID, cand, domain.VerdictConfirmed, domain.ConfidenceHigh, "confirmed note", domain.NewID(), nil, "http://x/page#payload")

	got, err := env.st.Findings().Get(ctx, f.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Verdict != domain.VerdictConfirmed {
		t.Fatalf("verdict = %s, want confirmed", got.Verdict)
	}
	if !contains(got.Title, "DOM XSS:") {
		t.Fatalf("confirmed title should drop 'candidate': %q", got.Title)
	}

	// A later, weaker (Rejected) attempt must NOT downgrade a confirmed finding.
	exec.correlateDOMXSSVerification(ctx, f.ID, cand, domain.VerdictRejected, domain.ConfidenceHigh, "a later rejected attempt", domain.NewID(), nil, "http://x/page#payload2")
	after, err := env.st.Findings().Get(ctx, f.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Verdict != domain.VerdictConfirmed {
		t.Fatalf("confirmed must be sticky, got %s", after.Verdict)
	}
	d := decodeFindingDetail(after.Detail)
	// reachability attempt + 2 verification attempts = 3.
	if len(d.Attempts) != 3 {
		t.Fatalf("attempts = %d, want 3 (evidence is never discarded)", len(d.Attempts))
	}
}

func TestDomXSSFindingDedupKeyDistinctPerEndpointSourceSink(t *testing.T) {
	epA, epB := domain.NewID(), domain.NewID()
	a := domXSSFindingDedupKey(epA, detection.DOMSourceHash, detection.DOMSinkInnerHTML)
	b := domXSSFindingDedupKey(epB, detection.DOMSourceHash, detection.DOMSinkInnerHTML)
	c := domXSSFindingDedupKey(epA, detection.DOMSourceHash, detection.DOMSinkOuterHTML)
	if a == b || a == c || b == c {
		t.Fatalf("dedup keys must differ by endpoint and by sink: %q %q %q", a, b, c)
	}
}

func TestDomXSSFindingDedupKeyNeverCollidesWithReflectedXSS(t *testing.T) {
	ip := domain.NewID()
	reflectedKey := findingDedupKey(ip, candAt(detection.CatHTMLText, detection.CtxHTMLText, "<svg onload=m>"))
	domXSSKey := domXSSFindingDedupKey(ip, detection.DOMSourceHash, detection.DOMSinkInnerHTML)
	if reflectedKey == domXSSKey {
		t.Fatal("a reflected-xss and a dom-xss dedup key must never collide, even sharing the same raw ID")
	}
}

// TestQueryStringDOMXSSFindingDoesNotCollideWithReflectedXSSOnSameParameter
// is the explicit correctness property scope item E calls for: Indago's
// EXISTING Reflected-XSS pipeline tests whether the SERVER reflects a query
// parameter into the HTTP response body; the NEW query-string DOM-XSS
// source (detection.DOMSourceQuery) tests whether the PAGE'S OWN JS re-reads
// that SAME parameter name and feeds it into a sink — a genuinely
// different code path. Both may legitimately fire on the SAME endpoint and
// parameter name ("q"), and must produce TWO DISTINCT findings, never
// merged/deduped against each other.
func TestQueryStringDOMXSSFindingDoesNotCollideWithReflectedXSSOnSameParameter(t *testing.T) {
	env := newScanEnv(t)
	ctx := context.Background()
	ep := domXSSTestEndpoint(t, env, "http://x/search?q=hello")
	param := env.param(ep, "q", domain.LocationQuery, "hello")
	injPoint := env.injection(ep, param)

	// Reflected XSS side: the server echoes "q" into the response body.
	reflectedCand := detection.Candidate{
		Source: detection.SourceBuiltin, Category: detection.CatHTMLText, Context: detection.CtxHTMLText,
		Value: "<svg onload=m1>", DedupKey: "<svg onload=m1>", Priority: 90,
	}
	reflectedFinding, err := upsertPendingFinding(ctx, env.st, env.scanID, ep, injPoint.ID, param, reflectedCand, domain.NewID())
	if err != nil {
		t.Fatal(err)
	}

	// DOM-XSS query-string side: the page's OWN JS re-reads location.search
	// for the SAME parameter name "q" and feeds it into innerHTML —
	// independent of whatever the server did with the parameter.
	marker := "indquerycollide1"
	domCand, ok := detection.DOMXSSPayloadFor(detection.DOMSourceQuery, detection.DOMSinkInnerHTML, marker)
	if !ok {
		t.Fatal("expected a candidate")
	}
	canary := detection.DOMXSSCanary(marker)
	domFinding, err := upsertDOMXSSFinding(ctx, env.st, env.scanID, ep, domCand, canary, domain.NewID())
	if err != nil {
		t.Fatal(err)
	}

	if reflectedFinding.ID == domFinding.ID {
		t.Fatal("the reflected-xss and dom-xss (query source) findings must be DISTINCT Finding rows, even for the same endpoint and parameter name")
	}
	findings, err := env.st.Findings().ListByScan(ctx, env.scanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected exactly 2 distinct findings (reflected + dom-xss query), got %d", len(findings))
	}
	var sawReflected, sawDOMXSS bool
	for _, f := range findings {
		switch f.VulnClass {
		case domain.VulnReflectedXSS:
			sawReflected = true
		case domain.VulnDOMXSS:
			sawDOMXSS = true
			if f.Summary == "" && detection.DOMXSSSource(decodeFindingDetail(f.Detail).ParameterName) != detection.DOMSourceQuery {
				t.Fatalf("dom-xss finding should be labeled with the query source, detail=%+v", decodeFindingDetail(f.Detail))
			}
		}
	}
	if !sawReflected || !sawDOMXSS {
		t.Fatalf("expected one of each vuln class, findings=%+v", findings)
	}
}
