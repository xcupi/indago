package detection

// The cheat-sheet library is a data source for the planner, so these tests hold
// it to the same contract as the canonical set: marker-only payloads, honest
// context/trigger declarations, and planning only where it can land.

import (
	"strings"
	"testing"
)

func TestLibraryVectorsAreBenignMarkers(t *testing.T) {
	for _, v := range Library {
		if v.ID == "" || len(v.Contexts) == 0 || v.Build == nil || v.Why == "" {
			t.Fatalf("incomplete library entry: %+v", v)
		}
		if v.Trigger != TriggerLoad && v.Trigger != TriggerInteraction {
			t.Fatalf("%s: trigger = %q, want load or interaction", v.ID, v.Trigger)
		}
		payload := v.Build("MARKER123")
		if !strings.Contains(payload, "MARKER123") {
			t.Fatalf("%s: payload does not carry the marker: %q", v.ID, payload)
		}
		for _, bad := range []string{"alert(", "prompt(", "confirm("} {
			if strings.Contains(strings.ToLower(payload), bad) {
				t.Fatalf("%s: payload must be marker-only, found %q in %q", v.ID, bad, payload)
			}
		}
	}
}

func TestLibraryTemplatesRespectContext(t *testing.T) {
	// details/ontoggle is an element-content vector: it must not be planned at
	// a JS-string or comment site.
	js := libraryTemplatesFor(ContextAnalysis{Context: CtxJSString}, "M")
	if len(js) != 0 {
		t.Fatalf("library planned %d vectors at a JS string site, want 0", len(js))
	}
	text := libraryTemplatesFor(ContextAnalysis{Context: CtxHTMLText}, "M")
	if len(text) != len(Library) {
		t.Fatalf("library planned %d vectors at element content, want all %d", len(text), len(Library))
	}
	found := false
	for _, tpl := range text {
		if strings.Contains(tpl.value, "<video><source onerror=M>") {
			found = true
		}
		if tpl.trigger != TriggerLoad && tpl.trigger != TriggerInteraction {
			t.Fatalf("template %q has trigger %q", tpl.value, tpl.trigger)
		}
	}
	if !found {
		t.Fatal("the video/source family was not planned at element content")
	}
}

func TestLibraryIsOptInAtPlanLevel(t *testing.T) {
	rep := &ReflectionReport{Probe: Probe{Token: "M123"}}
	rep.Reflected = true
	rep.Locations = []ReflectionLocation{{Context: &ContextAnalysis{Context: CtxHTMLText}}}

	off := PlanCandidates(rep, PlanOptions{})
	on := PlanCandidates(rep, PlanOptions{EnableLibrary: true})
	if on == nil || off == nil {
		t.Fatal("no plan")
	}
	countLibrary := func(p *CandidatePlan) int {
		n := 0
		for _, c := range p.Candidates {
			if strings.Contains(c.Rationale, "library/") {
				n++
			}
		}
		return n
	}
	if got := countLibrary(off); got != 0 {
		t.Fatalf("default plan carried %d library candidates, want 0", got)
	}
	if got := countLibrary(on); got == 0 {
		t.Fatal("EnableLibrary planned no library candidates")
	}
}

// The library must not re-send a shape the canonical planner already carries:
// tags here are the ones candidate.go already builds (details/ontoggle, the
// autofocus trio, body onpageshow/onload, svg animate, img/svg/script/a).
// A new family that needs one of these tags belongs in candidate.go instead.
func TestLibraryDoesNotDuplicateCanonicalShapes(t *testing.T) {
	carried := map[string]bool{
		"details": true, "input": true, "select": true, "textarea": true,
		"body": true, "svg": true, "img": true, "script": true, "a": true,
	}
	for _, v := range Library {
		payload := v.Build("M")
		tag := payload[1:]
		for i, r := range tag {
			if r == '>' || r == ' ' || r == '/' {
				tag = tag[:i]
				break
			}
		}
		if carried[strings.ToLower(tag)] {
			t.Fatalf("%s builds <%s>, a tag the canonical planner already carries; prune it or move it to candidate.go", v.ID, tag)
		}
	}
}
