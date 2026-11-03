package detection

// Pack-shape and planning tests for the opt-in variation packs. This file is in
// package detection (not detection_test) so it can assert the pack tables
// themselves — size, mechanism diversity, trigger classes, priorities — and not
// only their deduplicated effect on a plan.

import (
	"encoding/json"
	"html"
	"strings"
	"testing"

	"github.com/indago/indago/internal/domain"
)

var (
	varScan  = domain.ID("scan-variation")
	varIP    = domain.ID("ip-variation")
	varProbe = NewProbe(varScan, varIP)
)

func planVariation(t *testing.T, body []byte, ct string, opts PlanOptions) *ReflectionReport {
	t.Helper()
	rep := AnalyzeReflection(varProbe, nil, body)
	rep.Parameter = "q"
	rep.Location = domain.LocationQuery
	ClassifyContexts(&rep, body, ContextOptions{ContentType: ct})
	opts.ScanID = varScan
	opts.InjectionPointID = varIP
	PlanCandidates(&rep, opts)
	return &rep
}

func classifyOne(t *testing.T, body []byte, ct string) *ContextAnalysis {
	t.Helper()
	rep := AnalyzeReflection(varProbe, nil, body)
	ClassifyContexts(&rep, body, ContextOptions{ContentType: ct})
	if !rep.Reflected || len(rep.Locations) != 1 || rep.Locations[0].Context == nil {
		t.Fatalf("expected exactly 1 classified site; reflected=%v sites=%d", rep.Reflected, len(rep.Locations))
	}
	return rep.Locations[0].Context
}

func variationDocs(t *testing.T) map[string]string {
	t.Helper()
	m := "{{M}}"
	return map[string]string{
		"html":              `<p>` + m + `</p>`,
		"attribute_double":  `<input value="` + m + `">`,
		"attribute_single":  `<input value='` + m + `'>`,
		"attribute_unquote": `<input value=` + m + `>`,
		"js_string_double":  `<script>var a = "` + m + `";</script>`,
		"js_string_single":  `<script>var a = '` + m + `';</script>`,
		"js_template":       "<script>var a = `" + m + "`;</script>",
		"script_block":      `<script type="text/plain">` + m + `</script>`,
		"url_attribute":     `<a href="` + m + `">go</a>`,
	}
}

func docBody(t *testing.T, doc string) []byte {
	t.Helper()
	if strings.Count(doc, "{{M}}") != 1 {
		t.Fatalf("doc must contain exactly one {{M}}: %q", doc)
	}
	return []byte(strings.Replace(doc, "{{M}}", varProbe.Value(), 1))
}

// multiBody substitutes {{M}} in every doc and concatenates them into one body.
func multiBody(t *testing.T, docs map[string]string, keys ...string) []byte {
	t.Helper()
	var b strings.Builder
	for _, k := range keys {
		doc, ok := docs[k]
		if !ok {
			t.Fatalf("unknown doc key %q", k)
		}
		b.WriteString(strings.Replace(doc, "{{M}}", varProbe.Value(), 1))
	}
	return []byte(b.String())
}

// TestVariationPackShapePerContext pins each pack: at most five variants, every
// variant a distinct MECHANISM (not a respelling), priorities strictly
// descending (the pack is ordered by likelihood), and every variant declaring a
// trigger class. Only the url pack is interaction-only; every other pack leads
// with load-trigger variants.
func TestVariationPackShapePerContext(t *testing.T) {
	m := varProbe.Token
	docs := variationDocs(t)

	cases := []struct {
		name        string
		docKey      string
		wantContext Context
		wantSub     string
		wantURL     bool
	}{
		{"html", "html", CtxHTMLText, "", false},
		{"attribute double", "attribute_double", CtxHTMLAttrValue, "", false},
		{"attribute single", "attribute_single", CtxHTMLAttrValue, "", false},
		{"attribute unquoted", "attribute_unquote", CtxHTMLAttrValue, "", false},
		{"js string double", "js_string_double", CtxJSString, "double_quoted", false},
		{"js string single", "js_string_single", CtxJSString, "single_quoted", false},
		{"js template literal", "js_template", CtxJSString, "template_literal", false},
		{"script block", "script_block", CtxUnknown, "script_data_block", false},
		{"url attribute", "url_attribute", CtxURL, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := classifyOne(t, docBody(t, docs[tc.docKey]), "text/html")
			if a.Context != tc.wantContext || (tc.wantSub != "" && a.Sub != tc.wantSub) {
				t.Fatalf("context = %s:%s, want %s:%s", a.Context, a.Sub, tc.wantContext, tc.wantSub)
			}
			pack := variationTemplatesFor(*a, m)
			if len(pack) == 0 {
				t.Fatalf("no variation pack for %s:%s", a.Context, a.Sub)
			}
			if len(pack) > maxVariantsPerContext {
				t.Fatalf("pack has %d variants, max is %d", len(pack), maxVariantsPerContext)
			}

			seenMech := map[string]bool{}
			seenValue := map[string]bool{}
			lastPriority := 1 << 30
			for i, tpl := range pack {
				if tpl.variation == "" {
					t.Fatalf("variant %d has no mechanism name", i)
				}
				if seenMech[tpl.variation] {
					t.Fatalf("mechanism %q appears twice in one pack — variants must differ in mechanism", tpl.variation)
				}
				seenMech[tpl.variation] = true
				if seenValue[tpl.value] {
					t.Fatalf("value %q appears twice in one pack", tpl.value)
				}
				seenValue[tpl.value] = true
				if tpl.priority >= lastPriority {
					t.Fatalf("pack is not ordered by descending priority at %d: %d then %d", i, lastPriority, tpl.priority)
				}
				lastPriority = tpl.priority
				if !strings.Contains(tpl.value, m) {
					t.Fatalf("variant %q does not embed the benign marker", tpl.value)
				}
				switch tpl.trigger {
				case TriggerLoad, TriggerInteraction:
				default:
					t.Fatalf("variant %q has trigger %q, want load or interaction", tpl.value, tpl.trigger)
				}
				if tc.wantURL && tpl.trigger != TriggerInteraction {
					t.Fatalf("url variant %q is %q; a URL needs activation the verifier never simulates", tpl.value, tpl.trigger)
				}
			}
			if !tc.wantURL && pack[0].trigger != TriggerLoad {
				t.Fatalf("pack leads with %q trigger, want load first", pack[0].trigger)
			}
		})
	}
}

// TestVariationPacksOffByDefault proves the default plan is untouched: no
// Variation tag, no cap bookkeeping, and the same candidate count as before the
// packs existed (the frozen golden test in evasion_filter_test.go pins the
// values; this pins the flags).
func TestVariationPacksOffByDefault(t *testing.T) {
	body := docBody(t, variationDocs(t)["html"])
	rep := planVariation(t, body, "text/html", PlanOptions{})
	if rep.Plan.VariationCapped != 0 {
		t.Fatalf("default plan reports %d capped variation candidates", rep.Plan.VariationCapped)
	}
	for _, c := range rep.Plan.Candidates {
		if c.Variation != "" {
			t.Fatalf("default plan contains a variation candidate: %+v", c)
		}
		if c.Technique != "" {
			t.Fatalf("default plan contains an evasion candidate: %+v", c)
		}
	}
	// 6 canonical html-text templates, nothing else.
	if len(rep.Plan.Candidates) != 6 || rep.Plan.Generated != 6 {
		t.Fatalf("default plan = %d/%d candidates, want 6/6", len(rep.Plan.Candidates), rep.Plan.Generated)
	}
}

// TestVariationPacksAreAdditive: enabling the packs never removes a canonical
// candidate, and the pack's genuinely new mechanisms carry the Variation tag.
func TestVariationPacksAreAdditive(t *testing.T) {
	m := varProbe.Token
	docs := variationDocs(t)
	cases := []struct {
		docKey      string
		wantPresent []string // values that must be in the plan (canonical or variation)
		wantTagged  []string // values that must carry a Variation tag
	}{
		{
			docKey: "html",
			wantPresent: []string{
				"<svg onload=" + m + ">", "<img src=x onerror=" + m + ">",
				"<script>" + m + "</script>", "<details open ontoggle=" + m + ">",
				"<svg><script>" + m + "</script></svg>",
			},
			wantTagged: []string{"<script>" + m + "</script>", "<svg><script>" + m + "</script></svg>"},
		},
		{
			docKey: "attribute_double",
			wantPresent: []string{
				`"><svg onload=` + m + `>`, `" autofocus onfocus=` + m + ` x="`,
				`"><script>` + m + `</script>`, `"><img src=x onerror=` + m + `>`,
				`"><details open ontoggle=` + m + `>`,
			},
			wantTagged: []string{
				`"><script>` + m + `</script>`, `"><img src=x onerror=` + m + `>`,
				`"><details open ontoggle=` + m + `>`,
			},
		},
		{
			docKey: "js_string_single",
			wantPresent: []string{
				"';" + m + "//", "</script><script>" + m + "</script>",
				"</script><svg onload=" + m + ">", "</script><img src=x onerror=" + m + ">",
				"</script><details open ontoggle=" + m + ">",
			},
			wantTagged: []string{
				"</script><svg onload=" + m + ">", "</script><img src=x onerror=" + m + ">",
				"</script><details open ontoggle=" + m + ">",
			},
		},
		{
			docKey: "js_template",
			wantPresent: []string{
				"${" + m + "}", "`;" + m + "//", "</script><script>" + m + "</script>",
				"</script><svg onload=" + m + ">", "</script><img src=x onerror=" + m + ">",
			},
			wantTagged: []string{
				"`;" + m + "//", "</script><script>" + m + "</script>",
				"</script><svg onload=" + m + ">", "</script><img src=x onerror=" + m + ">",
			},
		},
		{
			docKey: "script_block",
			wantPresent: []string{
				"</script><svg onload=" + m + ">", "</script><script>" + m + "</script>",
				"</script><img src=x onerror=" + m + ">", "</script><details open ontoggle=" + m + ">",
			},
			wantTagged: []string{
				"</script><svg onload=" + m + ">", "</script><script>" + m + "</script>",
				"</script><img src=x onerror=" + m + ">", "</script><details open ontoggle=" + m + ">",
			},
		},
		{
			docKey: "url_attribute",
			wantPresent: []string{
				"javascript:" + m, "javascript&colon;" + m, "\tjavascript:" + m,
				"data:text/html,<script>" + m + "</script>",
			},
			wantTagged: []string{
				"javascript&colon;" + m, "\tjavascript:" + m, "data:text/html,<script>" + m + "</script>",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.docKey, func(t *testing.T) {
			body := docBody(t, docs[tc.docKey])
			off := planVariation(t, body, "text/html", PlanOptions{})
			on := planVariation(t, body, "text/html", PlanOptions{EnableVariationPacks: true})

			byValue := map[string]Candidate{}
			for _, c := range on.Plan.Candidates {
				byValue[c.Value] = c
			}
			for _, v := range tc.wantPresent {
				if _, ok := byValue[v]; !ok {
					t.Fatalf("value %q missing from the pack-enabled plan: %v", v, planValues(on.Plan))
				}
			}
			for _, v := range tc.wantTagged {
				c, ok := byValue[v]
				if !ok {
					t.Fatalf("tagged value %q missing", v)
				}
				if c.Variation == "" {
					t.Fatalf("value %q is present but not tagged as a variation", v)
				}
			}
			// Additive: every canonical value survives.
			for _, c := range off.Plan.Candidates {
				if _, ok := byValue[c.Value]; !ok {
					t.Fatalf("canonical value %q disappeared when packs were enabled", c.Value)
				}
			}
			// And the tagged candidates all come from the opt-in run only.
			for _, c := range off.Plan.Candidates {
				if c.Variation != "" {
					t.Fatalf("variation candidate in an off plan: %+v", c)
				}
			}
		})
	}
}

func planValues(p *CandidatePlan) []string {
	var out []string
	for _, c := range p.Candidates {
		out = append(out, c.Value)
	}
	return out
}

// TestVariationPacksRespectNeeds: a variant whose required canary characters
// the site proves it neutralizes is not planned at all. Canonical candidates
// keep their older deprioritize-never-drop rule; the packs are opt-in extra
// requests and must not include shapes that cannot work.
func TestVariationPacksRespectNeeds(t *testing.T) {
	t.Run("html text with encoded angle brackets gets no <>/<> variants", func(t *testing.T) {
		doc := `<p>{{M}}</p>`
		body := []byte(strings.Replace(doc, "{{M}}", html.EscapeString(varProbe.Value()), 1))
		rep := planVariation(t, body, "text/html", PlanOptions{EnableVariationPacks: true})
		for _, c := range rep.Plan.Candidates {
			if c.Variation != "" {
				t.Fatalf("planned variation %q although the site encodes its required characters: %+v", c.Value, c)
			}
		}
	})

	t.Run("js string with escaped quote keeps the script-element routes", func(t *testing.T) {
		// The quote is backslash-escaped (EncJS) but < and > are raw.
		body := []byte("<script>var a = '" + strings.ReplaceAll(varProbe.Value(), "'", `\'`) + "';</script>")
		rep := planVariation(t, body, "text/html", PlanOptions{EnableVariationPacks: true})
		var tagged []string
		for _, c := range rep.Plan.Candidates {
			if c.Variation != "" {
				tagged = append(tagged, c.Value)
			}
		}
		for _, v := range tagged {
			if strings.HasPrefix(v, "'") {
				t.Fatalf("planned a quote breakout although the quote is escaped: %q", v)
			}
		}
		var sawScript bool
		for _, v := range tagged {
			if strings.Contains(v, "</script>") {
				sawScript = true
			}
		}
		if !sawScript {
			t.Fatalf("no script-element route survived an escaped quote: %v", tagged)
		}
	})
}

// TestVariationPackCap proves the hard per-injection-point cap is applied in
// plan order and reported, so a response reflecting into many contexts cannot
// grow the opt-in plan without bound.
func TestVariationPackCap(t *testing.T) {
	docs := variationDocs(t)
	body := multiBody(t, docs, "html", "attribute_double", "js_string_single", "url_attribute", "script_block")
	rep := planVariation(t, body, "text/html", PlanOptions{EnableVariationPacks: true})

	tagged := 0
	for _, c := range rep.Plan.Candidates {
		if c.Variation != "" {
			tagged++
		}
	}
	if tagged != MaxVariationCandidatesPerInjectionPoint {
		t.Fatalf("variation candidates = %d, want the cap %d (capped=%d)", tagged, MaxVariationCandidatesPerInjectionPoint, rep.Plan.VariationCapped)
	}
	if rep.Plan.VariationCapped == 0 {
		t.Fatalf("expected a non-zero VariationCapped; plan=%v", planValues(rep.Plan))
	}
	// The cap must never eat a canonical candidate.
	off := planVariation(t, body, "text/html", PlanOptions{})
	inPlan := map[string]bool{}
	for _, c := range rep.Plan.Candidates {
		inPlan[c.Value] = true
	}
	for _, c := range off.Plan.Candidates {
		if !inPlan[c.Value] {
			t.Fatalf("canonical %q was dropped by the variation cap", c.Value)
		}
	}
}

// TestVariationCandidatesAreBenignMarkers is the same guardrail
// TestPlanCandidatesAreBenignMarkers applies to the canonical set: every
// variation variant embeds the benign marker and nothing weaponized.
func TestVariationCandidatesAreBenignMarkers(t *testing.T) {
	docs := variationDocs(t)
	banned := []string{"alert(", "confirm(", "prompt(", "eval(", "fetch(",
		"document.cookie", ".cookie", "xmlhttprequest", "navigator.", "location=",
		"location.", "window.", "import(", "atob(", "=document"}
	seen := 0
	for _, key := range []string{"html", "attribute_double", "attribute_single", "attribute_unquote",
		"js_string_double", "js_string_single", "js_template", "script_block", "url_attribute"} {
		rep := planVariation(t, docBody(t, docs[key]), "text/html", PlanOptions{EnableVariationPacks: true})
		for _, c := range rep.Plan.Candidates {
			if c.Variation == "" {
				continue
			}
			seen++
			if !strings.Contains(c.Value, varProbe.Token) {
				t.Fatalf("%s: variation %q does not embed the benign marker", key, c.Value)
			}
			low := strings.ToLower(c.Value)
			for _, b := range banned {
				if strings.Contains(low, b) {
					t.Fatalf("%s: variation %q contains banned construct %q", key, c.Value, b)
				}
			}
		}
	}
	if seen == 0 {
		t.Fatal("no variation candidates were planned across the six contexts")
	}
}

// TestVariationPacksDeterministic: the packs are literal tables, so twenty
// planning runs must serialize identically.
func TestVariationPacksDeterministic(t *testing.T) {
	docs := variationDocs(t)
	body := multiBody(t, docs, "html", "attribute_double", "js_string_single", "js_template", "url_attribute", "script_block")
	first := planVariation(t, body, "text/html", PlanOptions{EnableVariationPacks: true})
	want, err := json.Marshal(first.Plan)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		got, err := json.Marshal(planVariation(t, body, "text/html", PlanOptions{EnableVariationPacks: true}).Plan)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want) {
			t.Fatalf("variation plan not deterministic on run %d", i)
		}
	}
}

// TestVariationPacksDoNotApplyEverywhere: CSS and generic unknown contexts
// have no mechanism pack; they keep their canonical set. (A comment is
// html_text category and does get the html pack, with its "-->" closer.)
func TestVariationPacksDoNotApplyEverywhere(t *testing.T) {
	cases := []struct {
		doc string
		ct  string
	}{
		{`<style>.a { color: {{M}} }</style>`, "text/html"},
		{`{"q":"{{M}}"}`, "application/json"},
	}
	for _, tc := range cases {
		body := docBody(t, tc.doc)
		rep := planVariation(t, body, tc.ct, PlanOptions{EnableVariationPacks: true})
		for _, c := range rep.Plan.Candidates {
			if c.Variation != "" {
				t.Fatalf("%s: unexpected variation candidate %q for context %s:%s", tc.doc, c.Value, c.Context, c.ContextSub)
			}
		}
	}
}
