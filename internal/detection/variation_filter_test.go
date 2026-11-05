package detection

// "First blocked, later works" fixtures for the variation packs.
//
// Each fixture models one server-side filter that is realistic for its context
// and that blocks the pack's FIRST variant — by rewriting the shape, not by
// returning 403, so the injection point still reflects and the scan still gets
// to try the rest of the pack. The test then proves two things:
//
//  1. the filter really changes/rejects the first variant (it is not a no-op);
//  2. at least one LATER variant passes through byte-identical, and the planner
//     still plans it after the filter has transformed the canary response.
//
// Whether that surviving variant then executes in a browser is proven by the
// real-Chromium integration test (internal/scan, build tag browser_integration);
// this file is the pure half of the same fixture.

import (
	"regexp"
	"strings"
	"testing"
)

// eventAttrRe matches an on*= event-handler attribute with a quoted or
// unquoted value — the shape an "on* stripping" filter removes.
var eventAttrRe = regexp.MustCompile(`(?i)\son[a-z0-9_-]+\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]*)`)

// fixtureStripEvents models a filter that drops event-handler attributes but
// leaves elements and script text alone.
func fixtureStripEvents(v string) string { return eventAttrRe.ReplaceAllString(v, " data-x=1") }

// fixtureDisableTag replaces an opening tag's "<tag" with a text escape, so the
// element is never created while its closing tag (if any) still parses.
func fixtureDisableTag(v, tag string) string {
	return regexp.MustCompile(`(?i)<`+regexp.QuoteMeta(tag)).ReplaceAllString(v, "&lt;"+tag)
}

// fixtureBlockLiteral removes a case-insensitive literal, modelling a filter
// that matches the obvious spelling only.
func fixtureBlockLiteral(v, literal string) string {
	return regexp.MustCompile(`(?i)`+regexp.QuoteMeta(literal)).ReplaceAllString(v, "")
}

// fixtureEscapeJSQuotes models a reader that backslash-escapes quotes (and the
// backslash itself) but leaves markup characters alone.
func fixtureEscapeJSQuotes(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, `'`, `\'`)
	return strings.ReplaceAll(v, `"`, `\"`)
}

// fixtureEscapeTemplate models a reader that neutralises interpolation and
// template syntax with \uXXXX escapes, while leaving angle brackets raw (so a
// literal </script> can still end the element).
func fixtureEscapeTemplate(v string) string {
	var b strings.Builder
	for _, r := range v {
		switch r {
		case '$', '{', '}', '`', '\'', '"', '\\':
			b.WriteString(`\u`)
			const hex = "0123456789abcdef"
			b.WriteRune(rune(hex[(r>>12)&0xf]))
			b.WriteRune(rune(hex[(r>>8)&0xf]))
			b.WriteRune(rune(hex[(r>>4)&0xf]))
			b.WriteRune(rune(hex[r&0xf]))
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

type variationFilterFixture struct {
	name   string
	docKey string
	// filter is the server-side transformation for the filtered route.
	filter func(string) string
	// wantSurvivor is a pack value that must pass the filter unchanged and
	// must still be planned for the filtered canary response.
	wantSurvivor string
	// wantSurvivorMechanism is its Variation tag.
	wantSurvivorMechanism string
}

func TestVariationFirstBlockedLaterSurvives(t *testing.T) {
	m := varProbe.Token
	docs := variationDocs(t)

	fixtures := []variationFilterFixture{
		{
			name:                  "html: event handlers stripped, script element survives",
			docKey:                "html",
			filter:                func(v string) string { return fixtureDisableTag(fixtureStripEvents(v), "svg") },
			wantSurvivorMechanism: "inline_script",
			wantSurvivor:          "<script>" + m + "</script>",
		},
		{
			name:                  "attribute: event handlers and SVG stripped, script breakout survives",
			docKey:                "attribute_double",
			filter:                func(v string) string { return fixtureDisableTag(fixtureStripEvents(v), "svg") },
			wantSurvivorMechanism: "tag_breakout_script",
			wantSurvivor:          `"><script>` + m + `</script>`,
		},
		{
			name:                  "js_string: quotes escaped and script openings blocked, </script> survives",
			docKey:                "js_string_single",
			filter:                func(v string) string { return fixtureDisableTag(fixtureEscapeJSQuotes(v), "script") },
			wantSurvivorMechanism: "script_close_svg",
			wantSurvivor:          "</script><svg onload=" + m + ">",
		},
		{
			name:                  "js_template_literal: interpolation escaped and script openings blocked, </script> survives",
			docKey:                "js_template",
			filter:                func(v string) string { return fixtureDisableTag(fixtureEscapeTemplate(v), "script") },
			wantSurvivorMechanism: "script_close_svg",
			wantSurvivor:          "</script><svg onload=" + m + ">",
		},
		{
			name:                  "script_block: SVG blocked, fresh script block survives",
			docKey:                "script_block",
			filter:                func(v string) string { return fixtureDisableTag(v, "svg") },
			wantSurvivorMechanism: "script_restart",
			wantSurvivor:          "</script><script>" + m + "</script>",
		},
		{
			name:                  "url_attribute: literal javascript: blocked, entity-encoded colon survives",
			docKey:                "url_attribute",
			filter:                func(v string) string { return fixtureBlockLiteral(v, "javascript:") },
			wantSurvivorMechanism: "entity_colon",
			wantSurvivor:          "javascript&colon;" + m,
		},
	}

	for _, f := range fixtures {
		t.Run(f.name, func(t *testing.T) {
			body := docBody(t, docs[f.docKey])
			a := classifyOne(t, body, "text/html")
			pack := variationTemplatesFor(*a, m)
			if len(pack) < 2 {
				t.Fatalf("pack has %d variants; need at least a first and a later one", len(pack))
			}
			first := pack[0]

			// 1. The filter must actually block the first variant.
			if got := f.filter(first.value); got == first.value {
				t.Fatalf("fixture is a no-op for the first variant %q", first.value)
			}
			if !strings.Contains(first.value, m) {
				t.Fatalf("first variant %q does not contain the marker", first.value)
			}

			// 2. The claimed later variant must pass through byte-identical.
			if !strings.Contains(f.wantSurvivor, m) {
				t.Fatalf("fixture's survivor %q does not contain the marker", f.wantSurvivor)
			}
			if got := f.filter(f.wantSurvivor); got != f.wantSurvivor {
				t.Fatalf("filter rewrote the claimed survivor %q -> %q", f.wantSurvivor, got)
			}
			inPack := false
			for _, tpl := range pack {
				if tpl.value == f.wantSurvivor && tpl.variation == f.wantSurvivorMechanism {
					inPack = true
				}
			}
			if !inPack {
				t.Fatalf("claimed survivor %q (%s) is not in the pack", f.wantSurvivor, f.wantSurvivorMechanism)
			}

			// 3. After the filter transforms the CANARY reflection, the planner
			//    must still plan that survivor. This is the property a scan
			//    depends on: the plan is derived from the reflected canary, not
			//    from the blocked candidate.
			filteredDoc := strings.Replace(docs[f.docKey], "{{M}}", f.filter(varProbe.Value()), 1)
			rep := planVariation(t, []byte(filteredDoc), "text/html", PlanOptions{EnableVariationPacks: true})
			found := false
			for _, c := range rep.Plan.Candidates {
				if c.Value == f.wantSurvivor && c.Variation == f.wantSurvivorMechanism {
					found = true
				}
			}
			if !found {
				t.Fatalf("filtered canary plan does not contain the surviving variant %q (%s); plan: %v",
					f.wantSurvivor, f.wantSurvivorMechanism, planValues(rep.Plan))
			}

			// 4. Control: the same filter must not leave the first variant
			//    executable either. The identity check above already proves it
			//    changed; this asserts the changed form no longer contains the
			//    trigger the variant relied on where that is checkable.
			if f.wantSurvivorMechanism == "inline_script" && strings.Contains(f.filter(first.value), "<script") {
				t.Fatalf("first variant %q still contains a live script element after filtering", first.value)
			}
		})
	}
}
