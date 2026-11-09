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
	// A vector must only be planned at a context it declares. An element-content
	// family at a JS-string site wastes a request on bytes that cannot parse.
	for _, want := range []Context{CtxHTMLText, CtxHTMLAttrValue, CtxJSString, CtxJSCode, CtxURL, CtxHTMLComment} {
		var declared int
		for _, v := range Library {
			if vectorFitsContext(v, want) {
				declared++
			}
		}
		got := libraryTemplatesFor(ContextAnalysis{Context: want}, "M")
		if len(got) != declared {
			t.Fatalf("context %s planned %d vectors, want %d", want, len(got), declared)
		}
		for _, tpl := range got {
			if tpl.trigger != TriggerLoad && tpl.trigger != TriggerInteraction {
				t.Fatalf("template %q has trigger %q", tpl.value, tpl.trigger)
			}
		}
	}

	// A context no family declares must produce nothing (never a blind send).
	if got := libraryTemplatesFor(ContextAnalysis{Context: CtxCSS}, "M"); len(got) != 0 {
		t.Fatalf("CSS site planned %d vectors, want 0", len(got))
	}
	// Element content is where most families live; the video/source family in
	// particular must still be reachable there.
	found := false
	for _, tpl := range libraryTemplatesFor(ContextAnalysis{Context: CtxHTMLText}, "M") {
		if strings.Contains(tpl.value, "<video><source onerror=M>") {
			found = true
		}
	}
	if !found {
		t.Fatal("the video/source family was not planned at element content")
	}
	// JS-string sites get string breakouts and the script-element breakout,
	// not the element families.
	for _, tpl := range libraryTemplatesFor(ContextAnalysis{Context: CtxJSString}, "M") {
		if strings.Contains(tpl.value, "<video") || strings.Contains(tpl.value, "<object") {
			t.Fatalf("element family planned at a JS string site: %q", tpl.value)
		}
	}
}

// Needs must be honest: a family that claims a character it does not use is
// dropped for no reason, and one that uses a character it does not claim is
// sent even after the target proves it encodes that character.
func TestLibraryNeedsMatchThePayload(t *testing.T) {
	for _, v := range Library {
		payload := v.Build("MARKER123")
		for _, ch := range v.Needs {
			if !strings.ContainsRune(payload, ch) {
				t.Fatalf("%s: needs %q but payload %q never uses it", v.ID, string(ch), payload)
			}
		}
	}
}

// The library is a detection probe set, not a weapon: no callbacks, no cookie
// theft, no dialog functions.
func TestLibraryVectorsAreNotWeaponised(t *testing.T) {
	for _, v := range Library {
		payload := strings.ToLower(v.Build("MARKER123"))
		for _, bad := range []string{"http://", "https://", "//", "document.cookie", "fetch(", "xmlhttprequest", "sendbeacon", "eval("} {
			// "//" is allowed only as the comment terminator of a JS breakout.
			if bad == "//" && strings.HasSuffix(payload, "//") && strings.Count(payload, "//") == 1 {
				continue
			}
			if strings.Contains(payload, bad) {
				t.Fatalf("%s: payload looks weaponised, found %q in %q", v.ID, bad, payload)
			}
		}
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
		if strings.HasPrefix(v.ID, "cs_") {
			continue // generated sheet families: overlap with canonical is expected in shape, not in event
		}
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

// The generated sheet table must stay a clean data set: one entry per event,
// one vector per entry, and every id distinct.
func TestCheatSheetFamiliesAreDistinct(t *testing.T) {
	ids := map[string]bool{}
	vectors := map[string]bool{}
	n := 0
	for _, v := range Library {
		if !strings.HasPrefix(v.ID, "cs_") {
			continue
		}
		n++
		if ids[v.ID] {
			t.Fatalf("duplicate id %q", v.ID)
		}
		ids[v.ID] = true
		payload := v.Build("MARKER123")
		if vectors[payload] {
			t.Fatalf("duplicate vector %q", payload)
		}
		vectors[payload] = true
		if len(v.Contexts) == 0 || v.Why == "" {
			t.Fatalf("%s: incomplete entry", v.ID)
		}
	}
	if n < 100 {
		t.Fatalf("generated families = %d, want the full extracted table (>=100)", n)
	}
}

// The sheet carries every event family; the plan must not. With the library
// enabled and the widest profile, the count is bounded and the load-triggering
// families (which need no verifier action) come before the interaction ones.
func TestLibraryPlanIsCappedAndLoadFirst(t *testing.T) {
	rep := &ReflectionReport{Probe: Probe{Token: "M123"}}
	rep.Reflected = true
	rep.Locations = []ReflectionLocation{{Context: &ContextAnalysis{Context: CtxHTMLText}}}
	spec, err := ResolveProfile("thorough", MaxCandidatesCeiling)
	if err != nil {
		t.Fatal(err)
	}
	plan := PlanCandidates(rep, PlanOptions{EnableLibrary: true, Profile: spec})
	if plan == nil {
		t.Fatal("no plan")
	}
	n := 0
	sawInteraction := false
	for _, c := range plan.Candidates {
		if !strings.HasPrefix(c.Rationale, "library/") {
			continue
		}
		n++
		if c.Trigger == TriggerInteraction {
			sawInteraction = true
		} else if sawInteraction {
			t.Fatalf("load-triggering library candidate %q came after an interaction one", c.Value)
		}
	}
	if n == 0 {
		t.Fatal("no library candidates planned")
	}
	if n > MaxLibraryCandidatesPerInjectionPoint {
		t.Fatalf("planned %d library candidates, cap is %d", n, MaxLibraryCandidatesPerInjectionPoint)
	}
	if plan.LibraryCapped == 0 {
		t.Fatal("the library has far more families than the cap; LibraryCapped should be non-zero")
	}
}
