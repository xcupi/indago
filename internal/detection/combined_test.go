package detection_test

import (
	"strings"
	"testing"

	"github.com/indago/indago/internal/detection"
)

// TestPlanCombinedCandidate_HTMLAttr verifies the html_attribute combined
// decomposition: the "closer" half (Value) carries no executable reference
// at all, the "breakout" half (ValueB) carries the marker inside a brand
// new <svg onload> element, and the needed characters are split exactly as
// documented (closer needs only its own quote + ">"; breakout needs "<"+">"
// but no quote).
func TestPlanCombinedCandidate_HTMLAttr(t *testing.T) {
	marker := "idgTESTMARKER"
	cases := []struct {
		sub       string
		wantValue string
	}{
		{"double_quoted", `">`},
		{"single_quoted", `'>`},
		{"unquoted", `>`},
	}
	for _, c := range cases {
		cand, ok := detection.PlanCombinedCandidate(detection.CtxHTMLAttrValue, c.sub, marker)
		if !ok {
			t.Fatalf("sub=%s: expected ok=true", c.sub)
		}
		if cand.Value != c.wantValue {
			t.Errorf("sub=%s: Value = %q, want %q", c.sub, cand.Value, c.wantValue)
		}
		if strings.Contains(cand.Value, marker) {
			t.Errorf("sub=%s: closer half must NOT embed the marker, got %q", c.sub, cand.Value)
		}
		wantValueB := "<svg onload=" + marker + ">"
		if cand.ValueB != wantValueB {
			t.Errorf("sub=%s: ValueB = %q, want %q", c.sub, cand.ValueB, wantValueB)
		}
		if !cand.Combined {
			t.Errorf("sub=%s: Combined must be true", c.sub)
		}
		if cand.Category != detection.CatHTMLAttr || cand.Context != detection.CtxHTMLAttrValue {
			t.Errorf("sub=%s: Category/Context = %s/%s, want html_attribute/html_attr_value", c.sub, cand.Category, cand.Context)
		}
		if cand.Trigger != detection.TriggerLoad {
			t.Errorf("sub=%s: Trigger = %s, want load (auto-fires, passively confirmable)", c.sub, cand.Trigger)
		}
	}
}

// TestPlanCombinedCandidate_JSString verifies the js_string combined
// decomposition for both quote kinds, and that a template literal (no
// closing-quote character to split on) is correctly out of scope.
func TestPlanCombinedCandidate_JSString(t *testing.T) {
	marker := "idgTESTMARKER"

	cand, ok := detection.PlanCombinedCandidate(detection.CtxJSString, "double_quoted", marker)
	if !ok {
		t.Fatal("double_quoted: expected ok=true")
	}
	if cand.Value != `";` {
		t.Errorf("double_quoted: Value = %q, want %q", cand.Value, `";`)
	}
	if cand.ValueB != marker+"//" {
		t.Errorf("double_quoted: ValueB = %q, want %q", cand.ValueB, marker+"//")
	}

	cand2, ok := detection.PlanCombinedCandidate(detection.CtxJSString, "single_quoted", marker)
	if !ok {
		t.Fatal("single_quoted: expected ok=true")
	}
	if cand2.Value != `';` {
		t.Errorf("single_quoted: Value = %q, want %q", cand2.Value, `';`)
	}

	if _, ok := detection.PlanCombinedCandidate(detection.CtxJSString, "template_literal", marker); ok {
		t.Error("template_literal: expected ok=false (no closing-quote character to split on)")
	}
}

// TestPlanCombinedCandidate_UnsupportedContext verifies the two-category
// boundary: any context other than html_attr_value/js_string returns false,
// never a generic/unknown combined template.
func TestPlanCombinedCandidate_UnsupportedContext(t *testing.T) {
	for _, ctx := range []detection.Context{detection.CtxHTMLText, detection.CtxCSS, detection.CtxURL, detection.CtxUnknown, detection.CtxJSCode} {
		if _, ok := detection.PlanCombinedCandidate(ctx, "double_quoted", "m"); ok {
			t.Errorf("context %s: expected ok=false (out of this piece's bounded 2-category scope)", ctx)
		}
	}
}

// TestPlanCombinedCandidate_DedupKeyDisjoint verifies a combined candidate's
// DedupKey can never collide with a single-parameter candidate's (the
// "combined\x00" prefix is unique to this path).
func TestPlanCombinedCandidate_DedupKeyDisjoint(t *testing.T) {
	cand, ok := detection.PlanCombinedCandidate(detection.CtxHTMLAttrValue, "double_quoted", "m")
	if !ok {
		t.Fatal("expected ok=true")
	}
	if !strings.HasPrefix(cand.DedupKey, "combined\x00") {
		t.Errorf("DedupKey = %q, want a combined\\x00-prefixed key", cand.DedupKey)
	}
}

// TestPlanCombinedCandidate_Deterministic: 20 runs produce byte-identical
// output, mirroring TestPlanDeterministic for the single-parameter planner —
// this piece must be just as pure/deterministic.
func TestPlanCombinedCandidate_Deterministic(t *testing.T) {
	var first *detection.Candidate
	for i := 0; i < 20; i++ {
		cand, ok := detection.PlanCombinedCandidate(detection.CtxHTMLAttrValue, "double_quoted", "idgFIXED")
		if !ok {
			t.Fatal("expected ok=true")
		}
		if first == nil {
			first = cand
			continue
		}
		if *first != *cand {
			t.Fatalf("run %d differs from run 0: %+v vs %+v", i, cand, first)
		}
	}
}

// TestPlanCombinedCandidate_BenignMarkerOnly mirrors
// TestPlanCandidatesAreBenignMarkers for the combined planner: neither half
// of either combined template ever contains a weaponized construct.
func TestPlanCombinedCandidate_BenignMarkerOnly(t *testing.T) {
	forbidden := []string{"alert(", "document.cookie", "fetch(", "XMLHttpRequest"}
	marker := "idgBENIGN"
	for _, ctx := range []detection.Context{detection.CtxHTMLAttrValue, detection.CtxJSString} {
		for _, sub := range []string{"double_quoted", "single_quoted"} {
			cand, ok := detection.PlanCombinedCandidate(ctx, sub, marker)
			if !ok {
				continue
			}
			for _, f := range forbidden {
				if strings.Contains(cand.Value, f) || strings.Contains(cand.ValueB, f) {
					t.Errorf("ctx=%s sub=%s: combined candidate contains forbidden construct %q", ctx, sub, f)
				}
			}
		}
	}
}
