package detection_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/indago/indago/internal/detection"
)

func planWith(t *testing.T, doc string, transform func(string) string, spec detection.ProfileSpec) *detection.CandidatePlan {
	t.Helper()
	body := []byte(strings.Replace(doc, "{{M}}", transform(candProbe.Value()), 1))
	rep := detection.AnalyzeReflection(candProbe, nil, body)
	rep.Parameter = "q"
	detection.ClassifyContexts(&rep, body, detection.ContextOptions{ContentType: candHTML})
	return detection.PlanCandidates(&rep, detection.PlanOptions{ScanID: candScan, InjectionPointID: candIP, Profile: spec})
}

func ident(s string) string { return s }

// multiSite reflects one parameter into three distinct execution contexts, so
// the unbounded plan has several candidates per context.
const multiSite = `<p>{{M}}</p><input value="{{M}}"><script>var a = "{{M}}";</script>`

func multiSitePlan(t *testing.T, spec detection.ProfileSpec) *detection.CandidatePlan {
	t.Helper()
	body := strings.ReplaceAll(multiSite, "{{M}}", candProbe.Value())
	rep := detection.AnalyzeReflection(candProbe, nil, []byte(body))
	rep.Parameter = "q"
	detection.ClassifyContexts(&rep, []byte(body), detection.ContextOptions{ContentType: candHTML})
	return detection.PlanCandidates(&rep, detection.PlanOptions{ScanID: candScan, InjectionPointID: candIP, Profile: spec})
}

func TestResolveProfile(t *testing.T) {
	cases := []struct {
		name    string
		max     int
		want    int
		wantErr bool
	}{
		{"", 0, 8, false}, // empty = standard
		{"standard", 0, 8, false},
		{"minimal", 0, 3, false},
		{"thorough", 0, 16, false},
		{"standard", 5, 5, false},                                 // override
		{"thorough", detection.MaxCandidatesCeiling, 32, false},   // ceiling is allowed
		{"standard", detection.MaxCandidatesCeiling + 1, 0, true}, // above the ceiling
		{"standard", -1, 0, true},
		{"aggressive", 0, 0, true},
	}
	for _, c := range cases {
		spec, err := detection.ResolveProfile(c.name, c.max)
		if (err != nil) != c.wantErr {
			t.Fatalf("ResolveProfile(%q,%d) err = %v, wantErr %v", c.name, c.max, err, c.wantErr)
		}
		if err == nil && spec.MaxPerInjectionPoint != c.want {
			t.Fatalf("ResolveProfile(%q,%d) cap = %d, want %d", c.name, c.max, spec.MaxPerInjectionPoint, c.want)
		}
	}
}

// The zero ProfileSpec is the pre-profile planner: nothing dropped, no policy
// recorded on the plan.
func TestZeroProfileKeepsEveryCandidate(t *testing.T) {
	plan := multiSitePlan(t, detection.ProfileSpec{})
	if plan.Profile != "" || plan.Dropped != 0 || len(plan.Candidates) < 5 {
		t.Fatalf("zero profile changed the plan: profile=%q dropped=%d n=%d", plan.Profile, plan.Dropped, len(plan.Candidates))
	}
}

// Candidate counts are bounded per injection point (across all its sites), and
// the plan records what was applied and how much was left unsent.
func TestProfileBoundsCandidatesPerInjectionPoint(t *testing.T) {
	full := multiSitePlan(t, detection.ProfileSpec{})
	for _, max := range []int{1, 2, 3, 4} {
		spec, err := detection.ResolveProfile("thorough", max)
		if err != nil {
			t.Fatal(err)
		}
		plan := multiSitePlan(t, spec)
		if len(plan.Candidates) != max {
			t.Fatalf("max=%d: selected %d candidates: %v", max, len(plan.Candidates), valuesOf(plan))
		}
		if plan.Limit != max || plan.Profile != detection.ProfileThorough {
			t.Fatalf("max=%d: plan did not record its policy: %+v", max, plan)
		}
		if plan.Dropped != len(full.Candidates)-max {
			t.Fatalf("max=%d: dropped = %d, want %d", max, plan.Dropped, len(full.Candidates)-max)
		}
	}
	// The built-in profiles never exceed their cap on this 3-context point.
	for name, cap := range map[string]int{"minimal": 3, "standard": 8, "thorough": 16} {
		spec, _ := detection.ResolveProfile(name, 0)
		if n := len(multiSitePlan(t, spec).Candidates); n > cap {
			t.Fatalf("%s selected %d > cap %d", name, n, cap)
		}
	}
}

// A tight cap must not starve a whole execution context: with three distinct
// contexts reflecting, a cap of 3 yields one candidate from each.
func TestProfileCapKeepsOneCandidatePerContextFirst(t *testing.T) {
	spec, _ := detection.ResolveProfile("thorough", 3)
	plan := multiSitePlan(t, spec)
	ctxs := map[detection.Context]int{}
	for _, c := range plan.Candidates {
		ctxs[c.Context]++
	}
	if len(ctxs) != 3 {
		t.Fatalf("cap 3 across 3 contexts should cover each once, got %v from %v", ctxs, valuesOf(plan))
	}
}

// Deterministic ordering: a profile's selection is stable across runs and is
// emitted in the planner's own order (priority desc, then category/value/site).
func TestProfileSelectionIsDeterministicAndOrdered(t *testing.T) {
	spec, _ := detection.ResolveProfile("standard", 4)
	first := valuesOf(multiSitePlan(t, spec))
	for i := 0; i < 25; i++ {
		if got := valuesOf(multiSitePlan(t, spec)); !reflect.DeepEqual(got, first) {
			t.Fatalf("run %d selected %v, first run %v", i, got, first)
		}
	}
	plan := multiSitePlan(t, spec)
	for i := 1; i < len(plan.Candidates); i++ {
		if plan.Candidates[i].Priority > plan.Candidates[i-1].Priority {
			t.Fatalf("not in priority order: %v", valuesOf(plan))
		}
	}
}

// Selecting twice (a re-planned retry) from a shuffled input is the same.
func TestProfileSelectIsOrderInsensitive(t *testing.T) {
	plan := multiSitePlan(t, detection.ProfileSpec{})
	spec, _ := detection.ResolveProfile("minimal", 0)
	want, _ := spec.Select(plan.Candidates)
	rev := make([]detection.Candidate, len(plan.Candidates))
	for i, c := range plan.Candidates {
		rev[len(rev)-1-i] = c
	}
	got, _ := spec.Select(rev)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("selection depends on input order:\n got %v\nwant %v", got, want)
	}
}

// minimal sends only candidates that can fire on page load — the only kind the
// passive verifier can confirm — and never an interaction-only or markup probe.
func TestMinimalProfileSelectsLoadTriggerCandidatesOnly(t *testing.T) {
	spec, _ := detection.ResolveProfile("minimal", 0)
	plan := multiSitePlan(t, spec)
	if len(plan.Candidates) == 0 {
		t.Fatal("minimal selected nothing")
	}
	for _, c := range plan.Candidates {
		if c.Trigger != detection.TriggerLoad {
			t.Fatalf("minimal selected a %q-trigger candidate %q", c.Trigger, c.Value)
		}
		if c.Transformation != "raw" {
			t.Fatalf("minimal selected a neutralized candidate %q (%s)", c.Value, c.Transformation)
		}
	}
}

// Transformation-aware selection: when the site HTML-encodes <, >, and quotes,
// minimal skips the neutralized breakouts — but a reflecting context is never
// left with nothing: its best candidate is still tried once, so the site ends
// as a documented rejected attempt instead of silently vanishing.
func TestMinimalProfileNeverLeavesAReflectingContextEmpty(t *testing.T) {
	spec, _ := detection.ResolveProfile("minimal", 0)
	encode := func(v string) string { return strings.NewReplacer("<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(v) }
	full := planWith(t, `<p>{{M}}</p>`, encode, detection.ProfileSpec{})
	if len(full.Candidates) != 2 {
		t.Fatalf("setup: the unfiltered plan should hold both html_text candidates, got %v", valuesOf(full))
	}
	for _, c := range full.Candidates {
		if c.Transformation == "raw" {
			t.Fatalf("setup: %q should be neutralized at an entity-encoding site", c.Value)
		}
	}
	plan := planWith(t, `<p>{{M}}</p>`, encode, spec)
	if len(plan.Candidates) != 1 || plan.Candidates[0].Transformation == "raw" {
		t.Fatalf("the filters remove both neutralized candidates, so exactly the context's best must be kept for the record; got %v", valuesOf(plan))
	}
}

// Interaction-only contexts (a reflected URL start) are kept by minimal's
// fallback but are not Confirm-capable; the trigger says so.
func TestInteractionOnlyContextIsTaggedNotDropped(t *testing.T) {
	spec, _ := detection.ResolveProfile("minimal", 0)
	plan := planWith(t, `<a href="{{M}}">x</a>`, ident, spec)
	if len(plan.Candidates) != 1 || plan.Candidates[0].Trigger != detection.TriggerInteraction {
		t.Fatalf("expected the single interaction-trigger javascript: candidate, got %v", valuesOf(plan))
	}
}

// Coverage matrix for the built-in set (docs/reflection-candidates.md): every
// built-in template carries a trigger, and the executable ones reference the
// marker as a JavaScript expression.
func TestBuiltInCandidatesAreAllTagged(t *testing.T) {
	docs := map[string]string{
		"html_text":      `<p>{{M}}</p>`,
		"html_attr_dq":   `<input value="{{M}}">`,
		"html_attr_sq":   `<input value='{{M}}'>`,
		"html_attr_unq":  `<input value={{M}}>`,
		"html_comment":   `<!-- {{M}} -->`,
		"js_string_dq":   `<script>var a = "{{M}}";</script>`,
		"js_string_sq":   `<script>var a = '{{M}}';</script>`,
		"js_template":    "<script>var a = `{{M}}`;</script>",
		"js_code":        `<script>var a = {{M}};</script>`,
		"url_start":      `<a href="{{M}}">x</a>`,
		"css_style_body": `<style>.a { color: {{M}}; }</style>`,
		"rcdata_title":   `<title>{{M}}</title>`,
	}
	seen := 0
	for name, doc := range docs {
		plan := planWith(t, doc, ident, detection.ProfileSpec{})
		for _, c := range plan.Candidates {
			seen++
			switch c.Trigger {
			case detection.TriggerLoad, detection.TriggerInteraction, detection.TriggerNone:
			default:
				t.Fatalf("%s: candidate %q has trigger %q", name, c.Value, c.Trigger)
			}
			if c.Trigger == detection.TriggerLoad && !strings.Contains(c.Value, candProbe.Token) {
				t.Fatalf("%s: load-trigger candidate %q does not reference the marker", name, c.Value)
			}
		}
	}
	if seen == 0 {
		t.Fatal("no candidates planned for any context")
	}
}
