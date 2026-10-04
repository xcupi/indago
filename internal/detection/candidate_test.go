package detection_test

import (
	"encoding/json"
	"go/parser"
	"go/token"
	"html"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
)

var (
	candScan  = domain.ID("scan-cand")
	candIP    = domain.ID("ip-cand")
	candProbe = detection.NewProbe(candScan, candIP)
)

// tok is the benign marker candidate values embed (the probe token by default).
func tok() string { return candProbe.Token }

// planBody runs the real reflection + context + planning pipeline over body and
// returns the report (with rep.Plan populated). Parameter/location provenance is
// stamped as the scan would.
func planBody(t *testing.T, body []byte, ct string) *detection.ReflectionReport {
	t.Helper()
	rep := detection.AnalyzeReflection(candProbe, nil, body)
	rep.Parameter = "q"
	rep.Location = domain.LocationQuery
	detection.ClassifyContexts(&rep, body, detection.ContextOptions{ContentType: ct})
	detection.PlanCandidates(&rep, detection.PlanOptions{ScanID: candScan, InjectionPointID: candIP})
	return &rep
}

// planDoc substitutes transform(probe value) for the single {{M}} in doc.
func planDoc(t *testing.T, doc, ct string, transform func(string) string) *detection.ReflectionReport {
	t.Helper()
	if strings.Count(doc, "{{M}}") != 1 {
		t.Fatalf("doc must contain exactly one {{M}}: %q", doc)
	}
	body := []byte(strings.Replace(doc, "{{M}}", transform(candProbe.Value()), 1))
	return planBody(t, body, ct)
}

func find(p *detection.CandidatePlan, value string) (detection.Candidate, bool) {
	for _, c := range p.Candidates {
		if c.Value == value {
			return c, true
		}
	}
	return detection.Candidate{}, false
}

func mustFind(t *testing.T, p *detection.CandidatePlan, value string) detection.Candidate {
	t.Helper()
	c, ok := find(p, value)
	if !ok {
		t.Fatalf("expected a candidate with value %q; got %v", value, valuesOf(p))
	}
	return c
}

func valuesOf(p *detection.CandidatePlan) []string {
	var out []string
	for _, c := range p.Candidates {
		out = append(out, c.Value)
	}
	return out
}

const candHTML = "text/html; charset=utf-8"

// --- context → candidate selection ---

func TestPlanContextSelection(t *testing.T) {
	m := tok()
	cases := []struct {
		name     string
		doc      string
		ct       string
		cat      detection.CandidateCategory
		expected string // a canonical candidate value that must be present
	}{
		{"html text", `<p>{{M}}</p>`, candHTML, detection.CatHTMLText, "<svg onload=" + m + ">"},
		{"html double-quoted attribute", `<input value="{{M}}">`, candHTML, detection.CatHTMLAttr, `"><svg onload=` + m + ">"},
		{"js double-quoted string", `<script>var a="{{M}}";</script>`, candHTML, detection.CatJS, `";` + m + "//"},
		{"js single-quoted string", `<script>var a='{{M}}';</script>`, candHTML, detection.CatJS, "';" + m + "//"},
		{"js code position", `<script>{{M}}</script>`, candHTML, detection.CatJS, m},
		{"url start", `<a href="{{M}}">x</a>`, candHTML, detection.CatURL, "javascript:" + m},
		{"css style element", `<style>{{M}}</style>`, candHTML, detection.CatCSS, "</style><svg onload=" + m + ">"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := planDoc(t, tc.doc, tc.ct, raw)
			c := mustFind(t, rep.Plan, tc.expected)
			if c.Category != tc.cat {
				t.Fatalf("category = %q, want %q", c.Category, tc.cat)
			}
			if c.Source != detection.SourceBuiltin {
				t.Fatalf("source = %q, want builtin", c.Source)
			}
		})
	}
}

// A URL component that is not a scheme position yields no javascript: candidate:
// the planner declines to plan noise where script execution is not plausible.
func TestPlanDeclinesImplausibleContexts(t *testing.T) {
	rep := planDoc(t, `<a href="/s?x={{M}}">x</a>`, candHTML, raw)
	if _, ok := find(rep.Plan, "javascript:"+tok()); ok {
		t.Fatalf("a query-position URL reflection must not plan a javascript: scheme candidate: %v", valuesOf(rep.Plan))
	}
	// A plain (non-style, non-URL) unknown media still gets generic probes; a URL
	// query position specifically yields nothing.
	if len(rep.Plan.Candidates) != 0 {
		t.Fatalf("query-position URL reflection should yield no candidates; got %v", valuesOf(rep.Plan))
	}
}

// --- transformation-aware selection ---

func TestPlanTransformationAware(t *testing.T) {
	m := tok()
	svg := `"><svg onload=` + m + ">"

	t.Run("raw attribute keeps full priority", func(t *testing.T) {
		rep := planDoc(t, `<input value="{{M}}">`, candHTML, raw)
		c := mustFind(t, rep.Plan, svg)
		if c.Transformation != "raw" || c.Priority < 50 {
			t.Fatalf("raw site: transformation=%q priority=%d", c.Transformation, c.Priority)
		}
	})

	t.Run("html-encoded plain attribute is deprioritized", func(t *testing.T) {
		rep := planDoc(t, `<input value="{{M}}">`, candHTML, html.EscapeString)
		c := mustFind(t, rep.Plan, svg)
		if c.Transformation != detection.EncHTML {
			t.Fatalf("expected html transformation, got %q", c.Transformation)
		}
		rawRep := planDoc(t, `<input value="{{M}}">`, candHTML, raw)
		if rc := mustFind(t, rawRep.Plan, svg); c.Priority >= rc.Priority {
			t.Fatalf("encoded priority %d should be below raw priority %d", c.Priority, rc.Priority)
		}
	})

	// The sharp case: an apostrophe entity-encoded inside an event-handler JS
	// string STILL breaks the string (the browser decodes the attribute before
	// running the JS), but the same encoding inside a <script> string does not.
	t.Run("entity-decoding is context-sensitive", func(t *testing.T) {
		val := "';" + m + "//"
		handler := planDoc(t, `<a onclick="x='{{M}}'">y</a>`, candHTML, html.EscapeString)
		hc := mustFind(t, handler.Plan, val)
		if hc.Category != detection.CatJS || hc.Transformation != "raw" {
			t.Fatalf("event-handler string: category=%q transformation=%q (entity should decode back to a live quote)", hc.Category, hc.Transformation)
		}

		script := planDoc(t, `<script>var a='{{M}}';</script>`, candHTML, html.EscapeString)
		sc := mustFind(t, script.Plan, val)
		if sc.Transformation != detection.EncHTML {
			t.Fatalf("<script> string: transformation=%q (entities are NOT decoded in raw script text)", sc.Transformation)
		}
		if !(hc.Priority > sc.Priority) {
			t.Fatalf("handler-string candidate (%d) should outrank the script-string one (%d)", hc.Priority, sc.Priority)
		}
	})

	// A stripped canary sinks a candidate that depends on those characters to the
	// bottom, but does not remove it.
	t.Run("stripped canary is lowest", func(t *testing.T) {
		strip := func(string) string { return candProbe.Token + candProbe.Tail }
		rep := planDoc(t, `<p>{{M}}</p>`, candHTML, strip)
		c := mustFind(t, rep.Plan, "<svg onload="+m+">")
		if c.Transformation != detection.EncStripped || c.Priority > 5 {
			t.Fatalf("stripped: transformation=%q priority=%d", c.Transformation, c.Priority)
		}
	})
}

// --- ordering ---

func TestPlanOrdering(t *testing.T) {
	v := candProbe.Value()
	// One JS-code site (max priority 95) and one HTML-text site (max 90).
	body := []byte("<script>" + v + "</script><p>" + v + "</p>")
	rep := planBody(t, body, candHTML)

	if len(rep.Plan.Candidates) < 3 {
		t.Fatalf("expected several candidates, got %v", valuesOf(rep.Plan))
	}
	// Priorities must be non-increasing.
	for i := 1; i < len(rep.Plan.Candidates); i++ {
		if rep.Plan.Candidates[i-1].Priority < rep.Plan.Candidates[i].Priority {
			t.Fatalf("candidates not sorted by descending priority: %+v", rep.Plan.Candidates)
		}
	}
	// The top candidate is the direct JS-code reference.
	top := rep.Plan.Candidates[0]
	if top.Value != tok() || top.Category != detection.CatJS {
		t.Fatalf("top candidate = %q (%s), want the JS-code marker", top.Value, top.Category)
	}
}

// --- deduplication ---

func TestPlanDeduplication(t *testing.T) {
	m := tok()
	rawSite := candProbe.Token + candProbe.Canary + candProbe.Tail
	encSite := candProbe.Token + html.EscapeString(candProbe.Canary) + candProbe.Tail
	// Two HTML-text sites producing identical candidate values: one raw (high
	// priority), one html-encoded (low). Dedup must keep one of each value, at the
	// higher priority and earlier site.
	body := []byte("<p>" + rawSite + "</p><div>" + encSite + "</div>")
	rep := planBody(t, body, candHTML)

	if rep.Plan.Generated != 4 {
		t.Fatalf("Generated = %d, want 4 (2 sites × 2 templates)", rep.Plan.Generated)
	}
	if len(rep.Plan.Candidates) != 2 {
		t.Fatalf("after dedup want 2 candidates, got %v", valuesOf(rep.Plan))
	}
	seen := map[string]bool{}
	for _, c := range rep.Plan.Candidates {
		if seen[c.DedupKey] {
			t.Fatalf("duplicate dedup key survived: %q", c.DedupKey)
		}
		seen[c.DedupKey] = true
	}
	svg := mustFind(t, rep.Plan, "<svg onload="+m+">")
	if svg.Priority != 90 || svg.SiteIndex != 0 {
		t.Fatalf("dedup should keep the raw site's instance: priority=%d site=%d", svg.Priority, svg.SiteIndex)
	}
}

// --- unknown / mixed handling ---

func TestPlanUnknownAndMixed(t *testing.T) {
	m := tok()

	t.Run("non-markup response", func(t *testing.T) {
		rep := planDoc(t, `{"q":"{{M}}"}`, "application/json", raw)
		c := mustFind(t, rep.Plan, "<svg onload="+m+">")
		if c.Category != detection.CatUnknown {
			t.Fatalf("category = %q, want unknown_mixed", c.Category)
		}
		for _, c := range rep.Plan.Candidates {
			if c.Priority > 30 {
				t.Fatalf("unknown-context candidate %q has priority %d (should be low)", c.Value, c.Priority)
			}
		}
	})

	t.Run("ambiguous js regex-or-division", func(t *testing.T) {
		// A '/' after ')' is ambiguous: the context analyzer reports mixed.
		body := []byte("<script>a)/" + candProbe.Value() + "</script>")
		rep := planBody(t, body, candHTML)
		if len(rep.Plan.Candidates) == 0 {
			t.Fatal("mixed context should still yield generic candidates")
		}
		for _, c := range rep.Plan.Candidates {
			if c.Category != detection.CatUnknown {
				t.Fatalf("mixed site candidate category = %q, want unknown_mixed", c.Category)
			}
		}
	})
}

// --- deterministic output ---

func TestPlanDeterministic(t *testing.T) {
	v := candProbe.Value()
	body := []byte("<script>var a=\"" + v + "\";</script><p>" + v + "</p><input value=\"" + v + "\"><style>" + v + "</style>")

	first := planBody(t, body, candHTML)
	want, err := json.Marshal(first.Plan)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		got, err := json.Marshal(planBody(t, body, candHTML).Plan)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want) {
			t.Fatalf("plan not deterministic on run %d:\n want %s\n got  %s", i, want, got)
		}
	}
}

// --- provenance & serializability ---

func TestPlanProvenanceAndSerializable(t *testing.T) {
	rep := planDoc(t, `<p>{{M}}</p>`, candHTML, raw)
	if len(rep.Plan.Candidates) == 0 {
		t.Fatal("expected candidates")
	}
	for _, c := range rep.Plan.Candidates {
		if c.ScanID != candScan || c.InjectionPointID != candIP {
			t.Fatalf("provenance not preserved: scan=%q ip=%q", c.ScanID, c.InjectionPointID)
		}
		if c.Parameter != "q" || c.Location != domain.LocationQuery {
			t.Fatalf("parameter provenance not preserved: %q/%q", c.Parameter, c.Location)
		}
		if c.DedupKey == "" || c.Rationale == "" {
			t.Fatalf("candidate metadata incomplete: %+v", c)
		}
	}

	// The plan round-trips through JSON unchanged (persistable in TestCase.Detail).
	blob, err := json.Marshal(rep.Plan)
	if err != nil {
		t.Fatal(err)
	}
	var back detection.CandidatePlan
	if err := json.Unmarshal(blob, &back); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*rep.Plan, back) {
		t.Fatalf("plan did not round-trip:\n orig %+v\n back %+v", *rep.Plan, back)
	}

	// And the whole report (with the plan) round-trips via ParseReflection.
	detail, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := detection.ParseReflection(detail)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Plan == nil || !reflect.DeepEqual(parsed.Plan.Candidates, rep.Plan.Candidates) {
		t.Fatalf("report plan did not survive persistence round-trip")
	}
}

// --- future LLM candidates slot in without TestCase changes ---

func TestPlanSupportsNonBuiltinSource(t *testing.T) {
	// Appending an advisory (e.g. LLM-sourced) candidate is a pure data operation
	// on the same model; no domain/TestCase change is required.
	rep := planDoc(t, `<p>{{M}}</p>`, candHTML, raw)
	rep.Plan.Candidates = append(rep.Plan.Candidates, detection.Candidate{
		Source:   detection.SourceLLM,
		Category: detection.CatHTMLText,
		Value:    "<marker " + tok() + ">",
		DedupKey: "x",
	})
	blob, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := detection.ParseReflection(blob)
	if err != nil {
		t.Fatal(err)
	}
	var llm bool
	for _, c := range parsed.Plan.Candidates {
		if c.Source == detection.SourceLLM {
			llm = true
		}
	}
	if !llm {
		t.Fatal("llm-sourced candidate did not persist")
	}
}

// --- guardrails ---

// No candidate is a weaponized payload: every value embeds the benign marker and
// none carries an exfiltration/sink construct. This keeps the planner on the
// right side of the authorized-use guardrails (detection probes, not exploits).
func TestPlanCandidatesAreBenignMarkers(t *testing.T) {
	v := candProbe.Value()
	body := []byte("<script>var a=\"" + v + "\";</script><p>" + v + "</p><input value=\"" + v +
		"\"><a href=\"" + v + "\">x</a><style>" + v + "</style><a onclick=\"x='" + v + "'\">y</a>")
	rep := planBody(t, body, candHTML)
	if len(rep.Plan.Candidates) == 0 {
		t.Fatal("expected candidates across contexts")
	}

	banned := []string{"alert(", "confirm(", "prompt(", "eval(", "fetch(",
		"document.cookie", ".cookie", "xmlhttprequest", "navigator.", "location=",
		"location.", "window.", "import(", "atob(", "=document"}
	for _, c := range rep.Plan.Candidates {
		if !strings.Contains(c.Value, tok()) {
			t.Fatalf("candidate %q does not embed the benign marker", c.Value)
		}
		low := strings.ToLower(c.Value)
		for _, b := range banned {
			if strings.Contains(low, b) {
				t.Fatalf("candidate %q contains a weaponized construct %q", c.Value, b)
			}
		}
	}
}

func TestPlanNotReflectedYieldsEmptyPlan(t *testing.T) {
	rep := planBody(t, []byte("<p>nothing to see here</p>"), candHTML)
	if rep.Plan == nil {
		t.Fatal("plan should be non-nil even with no reflection")
	}
	if len(rep.Plan.Candidates) != 0 || rep.Plan.Generated != 0 {
		t.Fatalf("expected an empty plan, got %+v", rep.Plan)
	}
	if rep.Plan.Marker != candProbe.Token {
		t.Fatalf("marker = %q, want the probe token", rep.Plan.Marker)
	}
}

// --- purity ---

// The planner, like the rest of the detection analysis layer, must not touch the
// network, filesystem, clock, RNG, or any module beyond the domain model.
func TestPlannerIsPure(t *testing.T) {
	forbidden := []string{"net", "os", "io/ioutil", "time", "math/rand", "crypto/rand", "syscall", "os/exec", "plugin", "unsafe"}
	f, err := parser.ParseFile(token.NewFileSet(), "candidate.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	for _, imp := range f.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			t.Fatal(err)
		}
		for _, bad := range forbidden {
			if p == bad || strings.HasPrefix(p, bad+"/") {
				t.Errorf("candidate.go imports %q: the planner must stay pure", p)
			}
		}
		if strings.HasPrefix(p, "github.com/") && !strings.HasSuffix(p, "/internal/domain") {
			t.Errorf("candidate.go imports %q: only the domain model is allowed", p)
		}
	}
}
