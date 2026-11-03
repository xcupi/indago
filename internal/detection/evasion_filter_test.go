package detection_test

import (
	"io"
	"strings"
	"testing"

	xhtml "golang.org/x/net/html"

	"github.com/indago/indago/internal/detection"
)

// This file pins two properties of the opt-in filter-bypass set that the three
// tag/attribute-allow-list labs depend on:
//
//  1. The CANONICAL (default) candidate set is frozen byte-for-byte: enabling
//     nothing must produce exactly the candidates it produced before these
//     shapes existed. Evasion is additional, never a rewrite.
//  2. Each new evasion shape is proven against a LOCAL reproduction of the
//     lab's WAF: an allow-list of surviving tag names and event-handler
//     attribute names, driven through a real HTML tokenizer. The fixture must
//     REJECT every canonical payload (including an independently executable
//     control such as <svg onload=M>, which a permissive matcher would wrongly
//     admit) and ADMIT exactly the shape the technique claims.

// wafFixture reproduces one lab's tag/attribute allow-list. It is deliberately
// an allow-list, not a deny-list: a tag or on* event attribute that is not
// listed is blocked, exactly how the documented labs behave.
type wafFixture struct {
	name string
	tags map[string]bool
	// events lists the surviving event-handler attribute names (lowercase,
	// with the "on" prefix).
	events map[string]bool
	// customTags admits any custom-element-shaped name (one containing a
	// hyphen) — the "all tags blocked except custom ones" lab.
	customTags bool
}

func (f wafFixture) tagAllowed(name string) bool {
	name = strings.ToLower(name)
	if f.tags[name] {
		return true
	}
	return f.customTags && strings.Contains(name, "-")
}

// allows reports whether the fixture's WAF would let value through to the
// reflecting page. It tokenizes the value with a real HTML tokenizer (the same
// one the context analyzer drives), so the decision follows browser tag/
// attribute splitting rather than a substring guess.
func (f wafFixture) allows(value string) bool {
	z := xhtml.NewTokenizer(strings.NewReader(value))
	for {
		switch tt := z.Next(); tt {
		case xhtml.ErrorToken:
			return z.Err() == io.EOF
		case xhtml.StartTagToken, xhtml.SelfClosingTagToken:
			tok := z.Token()
			if !f.tagAllowed(tok.Data) {
				return false
			}
			for _, a := range tok.Attr {
				key := strings.ToLower(a.Key)
				if strings.HasPrefix(key, "on") && !f.events[key] {
					return false
				}
			}
		case xhtml.EndTagToken:
			if !f.tagAllowed(z.Token().Data) {
				return false
			}
		}
	}
}

// TestEvasionDefaultCandidateSetUnchanged freezes the canonical plan for a
// document that exercises every planning category. If a future change adds,
// removes, reorders, re-prioritizes or retags a default candidate, this fails —
// which is the point: a default scan must stay byte-identical to today.
func TestEvasionDefaultCandidateSetUnchanged(t *testing.T) {
	m := evProbe.Token
	doc := `<p>{{M}}</p>` +
		`<input value="{{M}}">` +
		`<script>var s = '{{M}}';</script>` +
		`<a href="{{M}}">x</a>` +
		`<style>.a { color: {{M}} }</style>` +
		`<title>{{M}}</title>`
	body := []byte(strings.ReplaceAll(doc, "{{M}}", evProbe.Value()))
	rep := planWithEvasion(t, body, false)
	if rep.Plan.Generated != 20 || len(rep.Plan.Candidates) != 20 {
		t.Fatalf("default plan size = %d/%d, want 20/20", len(rep.Plan.Candidates), rep.Plan.Generated)
	}
	want := []string{
		`html_attribute|"><svg onload=` + m + `>|90|load`,
		`html_text|</title><svg onload=` + m + `>|90|load`,
		`html_text|<svg onload=` + m + `>|90|load`,
		`javascript|';` + m + `//|90|load`,
		`url|javascript:` + m + `|90|interaction`,
		`html_text|</title><img src=x onerror=` + m + `>|88|load`,
		`html_text|<img src=x onerror=` + m + `>|88|load`,
		`javascript|</script><script>` + m + `</script>|88|load`,
		`html_attribute|" autofocus onfocus=` + m + ` x="|87|load`,
		`javascript|\';` + m + `//|86|load`,
		`html_attribute|" onmouseover=` + m + ` x="|85|interaction`,
		`css|</style><svg onload=` + m + `>|80|load`,
		`html_text|</title><details open ontoggle=` + m + `>|80|load`,
		`html_text|<details open ontoggle=` + m + `>|80|load`,
		`html_text|</title><body onpageshow=` + m + `>|76|load`,
		`html_text|<body onpageshow=` + m + `>|76|load`,
		`html_text|</title><svg><animate onbegin=` + m + `>|72|load`,
		`html_text|<svg><animate onbegin=` + m + `>|72|load`,
		`html_text|</title><` + m + `x>|60|none`,
		`html_text|<` + m + `x>|60|none`,
	}
	got := make([]string, 0, len(rep.Plan.Candidates))
	for _, c := range rep.Plan.Candidates {
		got = append(got, strings.Join([]string{
			string(c.Category), c.Value, itoa(c.Priority), c.Trigger,
		}, "|"))
		if c.Technique != "" {
			t.Fatalf("default plan contains technique-tagged candidate %q", c.Value)
		}
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("default candidate set changed:\n got:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// TestEvasionFilterFixturesReproduceLabAllowLists proves each new shape against
// a local allow-list reproduction of its lab. Every canonical payload must be
// rejected (including a control that really is executable on an unfiltered
// page), the shape must be admitted, and the OTHER labs' shapes must be
// rejected too — so no fixture is permissive enough to confirm everything.
func TestEvasionFilterFixturesReproduceLabAllowLists(t *testing.T) {
	m := evProbe.Token
	off := planWithEvasion(t, []byte("<p>"+evProbe.Value()+"</p>"), false)
	on := planWithEvasion(t, []byte("<p>"+evProbe.Value()+"</p>"), true)

	cases := []struct {
		name      string
		fixture   wafFixture
		technique string
		value     string
	}{
		{
			name: "lab1 most tags/attributes blocked: body + onresize survive",
			fixture: wafFixture{
				name: "body/onresize", tags: map[string]bool{"body": true},
				events: map[string]bool{"onresize": true},
			},
			technique: "allowlisted_tag_event",
			value:     "<body onresize=" + m + ">",
		},
		{
			name: "lab2 all tags blocked except custom ones",
			fixture: wafFixture{
				name: "custom tags + onfocus", customTags: true,
				events: map[string]bool{"onfocus": true},
			},
			technique: "custom_element_focus",
			value:     "<x-" + m + " autofocus tabindex=1 onfocus=" + m + "></x-" + m + ">",
		},
		{
			name: "lab3 some SVG markup allowed",
			fixture: wafFixture{
				name: "svg subset + onbegin", tags: map[string]bool{"svg": true, "animatetransform": true},
				events: map[string]bool{"onbegin": true},
			},
			technique: "svg_smil_begin",
			value:     "<svg><animatetransform onbegin=" + m + " attributeName=transform></svg>",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The fixture must reject every canonical candidate, otherwise it
			// would prove nothing about the bypass.
			if len(off.Plan.Candidates) == 0 {
				t.Fatal("setup: canonical plan is empty")
			}
			for _, c := range off.Plan.Candidates {
				if tc.fixture.allows(c.Value) {
					t.Fatalf("fixture admits canonical candidate %q — it does not reproduce the lab's filter", c.Value)
				}
			}
			// An independently executable control, deliberately not in any
			// canonical plan for this site: a permissive matcher would let it
			// through (and the unfiltered control page proves it can confirm).
			control := "<svg onload=" + m + ">"
			if tc.fixture.allows(control) {
				t.Fatalf("fixture admits the executable control %q — the allow-list is too permissive", control)
			}

			// The shape itself must be planned only when evasion was opted into,
			// and must be admitted by its lab's allow-list.
			for _, c := range off.Plan.Candidates {
				if c.Technique != "" {
					t.Fatalf("evasion off but got technique-tagged candidate %+v", c)
				}
			}
			var got *detection.Candidate
			for i := range on.Plan.Candidates {
				c := on.Plan.Candidates[i]
				if c.Technique == tc.technique {
					got = &on.Plan.Candidates[i]
					break
				}
			}
			if got == nil {
				t.Fatalf("EnableEvasion=true planned no %q candidate", tc.technique)
			}
			if got.Value != tc.value {
				t.Fatalf("%s value = %q, want %q", tc.technique, got.Value, tc.value)
			}
			if !strings.Contains(got.Value, m) {
				t.Fatalf("%s does not embed the benign marker: %q", tc.technique, got.Value)
			}
			if !tc.fixture.allows(got.Value) {
				t.Fatalf("fixture rejects the shape it is supposed to admit: %q", got.Value)
			}
			// Every OTHER new shape must be rejected by this fixture: the
			// allow-lists are disjoint, so one lab's bypass cannot leak into
			// another's proof.
			for _, other := range cases {
				if other.technique == tc.technique {
					continue
				}
				for i := range on.Plan.Candidates {
					c := on.Plan.Candidates[i]
					if c.Technique != other.technique {
						continue
					}
					if tc.fixture.allows(c.Value) {
						t.Fatalf("fixture for %s wrongly admits %s shape %q", tc.fixture.name, other.technique, c.Value)
					}
				}
			}
		})
	}
}

// TestEvasionNewShapesAreBoundedAndDeterministic keeps the extension small and
// reproducible: exactly three shapes are added, each exactly once in priority
// order, and two planning runs over the same report agree byte-for-byte.
func TestEvasionNewShapesAreBoundedAndDeterministic(t *testing.T) {
	body := []byte("<p>" + evProbe.Value() + "</p>")
	first := planWithEvasion(t, body, true)
	second := planWithEvasion(t, body, true)
	if len(first.Plan.Candidates) != len(second.Plan.Candidates) {
		t.Fatalf("plan size differs between runs: %d vs %d", len(first.Plan.Candidates), len(second.Plan.Candidates))
	}
	for i := range first.Plan.Candidates {
		a, b := first.Plan.Candidates[i], second.Plan.Candidates[i]
		if a.Value != b.Value || a.Priority != b.Priority || a.Technique != b.Technique {
			t.Fatalf("planning is not deterministic at %d: %+v vs %+v", i, a, b)
		}
	}
	counts := map[string]int{}
	for _, c := range first.Plan.Candidates {
		if c.Technique != "" {
			counts[c.Technique]++
		}
	}
	for _, want := range []string{"allowlisted_tag_event", "custom_element_focus", "svg_smil_begin"} {
		if counts[want] != 1 {
			t.Fatalf("technique %q planned %d times, want exactly 1 (all: %v)", want, counts[want], counts)
		}
	}
	// html_text: 6 canonical + 6 pre-existing evasion + 3 new = 15.
	if len(first.Plan.Candidates) != 15 {
		t.Fatalf("html_text plan size = %d, want 15 (bounded extension)", len(first.Plan.Candidates))
	}
}
