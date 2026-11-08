package detection_test

import (
	"strings"
	"testing"

	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
)

const angularBody = `<!doctype html><html><body ng-app><p>You searched for: '<input autofocus ng-focus="x">'</p>` +
	`<script src="/js/angular.min.js"></script></body></html>`

func TestAngularCSPBypassEligible(t *testing.T) {
	nonAngular := []byte(`<!doctype html><html><body><p>hello</p></body></html>`)
	cases := []struct {
		name string
		csp  string
		body []byte
		want bool
	}{
		{"no CSP header", "", []byte(angularBody), false},
		{"script-src allows unsafe-inline", "script-src 'self' 'unsafe-inline'", []byte(angularBody), false},
		{"script-src forbids inline", "script-src 'self'", []byte(angularBody), true},
		{"default-src forbids inline", "default-src 'self'", []byte(angularBody), true},
		{"script-src later directive allows unsafe-inline", "default-src 'self'; script-src 'self' 'unsafe-inline'", []byte(angularBody), false},
		{"script-src overrides default-src unsafe-inline", "default-src 'unsafe-inline'; script-src 'self'", []byte(angularBody), true},
		{"policy without a script directive", "img-src *", []byte(angularBody), false},
		{"CSP present, body is not Angular", "script-src 'self'", nonAngular, false},
		{"Angular body, CSP absent", "", nonAngular, false},
		{"unsafe-inline only as a host substring", "script-src 'self' https://unsafe-inline.example", []byte(angularBody), true},
		{"header list where one policy blocks inline", "script-src 'self' 'unsafe-inline', script-src 'self'", []byte(angularBody), true},
		{"case-insensitive keyword", "script-src 'self' 'UNSAFE-INLINE'", []byte(angularBody), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := detection.AngularCSPBypassEligible(tc.csp, tc.body); got != tc.want {
				t.Fatalf("AngularCSPBypassEligible(%q, body) = %v, want %v", tc.csp, got, tc.want)
			}
		})
	}
}

func TestHTMLUsesAngular(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"ng-app", `<body ng-app>`, true},
		{"data-ng-app", `<body data-ng-app="app">`, true},
		{"x-ng-app", `<body x-ng-app>`, true},
		{"ng:app", `<body ng:app>`, true},
		{"ng-controller", `<div ng-controller="C"></div>`, true},
		{"script tag loading angular", `<script src="/static/angular.js"></script>`, true},
		{"script tag loading angular.min.js with a cache buster", `<script src="/a/angular.min.js?v=1"></script>`, true},
		{"bare marker token in text", `<body><div>ng-app is just text here</div></body>`, true},
		{"attribute-name prefix only", `<div ng-application="x"></div>`, false},
		{"prose mentioning angular.js", `<p>we do not ship angular.js</p>`, false},
		{"empty body", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := detection.HTMLUsesAngular([]byte(tc.body)); got != tc.want {
				t.Fatalf("HTMLUsesAngular(%q) = %v, want %v", tc.body, got, tc.want)
			}
		})
	}
}

// planAngular plans the standard profile over a document whose single {{M}} is
// replaced by the probe value, with the Angular gate in the given state.
func planAngular(t *testing.T, doc string, bypass bool) *detection.CandidatePlan {
	t.Helper()
	if strings.Count(doc, "{{M}}") != 1 {
		t.Fatalf("doc must contain exactly one {{M}}: %q", doc)
	}
	body := []byte(strings.Replace(doc, "{{M}}", candProbe.Value(), 1))
	rep := detection.AnalyzeReflection(candProbe, nil, body)
	rep.Parameter = "q"
	rep.Location = domain.LocationQuery
	detection.ClassifyContexts(&rep, body, detection.ContextOptions{ContentType: candHTML})
	spec, err := detection.ResolveProfile(string(detection.ProfileStandard), 0)
	if err != nil {
		t.Fatal(err)
	}
	return detection.PlanCandidates(&rep, detection.PlanOptions{
		ScanID: candScan, InjectionPointID: candIP, Profile: spec, AngularCSPBypass: bypass,
	})
}

const angularPlanDoc = `<!doctype html><html><body ng-app><p>You searched for: '{{M}}'</p><script src="/angular.js"></script></body></html>`

func angularCandidate(t *testing.T, p *detection.CandidatePlan) (detection.Candidate, bool) {
	t.Helper()
	for _, c := range p.Candidates {
		if c.Technique == detection.AngularCSPBypassTechnique {
			return c, true
		}
	}
	return detection.Candidate{}, false
}

func expressionCandidate(t *testing.T, p *detection.CandidatePlan) (detection.Candidate, bool) {
	t.Helper()
	for _, c := range p.Candidates {
		if c.Technique == detection.AngularCSPExpressionTechnique {
			return c, true
		}
	}
	return detection.Candidate{}, false
}

func TestPlanAngularCSPBypassGatedAndFirst(t *testing.T) {
	on := planAngular(t, angularPlanDoc, true)
	cand, ok := angularCandidate(t, on)
	if !ok {
		t.Fatalf("AngularCSPBypass=true must plan the %s candidate; got %v", detection.AngularCSPBypassTechnique, valuesOf(on))
	}
	wantValue := `<input autofocus ng-focus="$event.composedPath()|orderBy:'` + candProbe.Token + `'">`
	if cand.Value != wantValue {
		t.Fatalf("candidate value = %q, want the canonical bypass value %q", cand.Value, wantValue)
	}
	if cand.Value != detection.AngularCSPBypassValue(candProbe.Token) {
		t.Fatalf("candidate value is not AngularCSPBypassValue(marker): %q", cand.Value)
	}
	if cand.Trigger != detection.TriggerLoad {
		t.Fatalf("candidate trigger = %q, want a load trigger", cand.Trigger)
	}
	if cand.Priority != 92 {
		t.Fatalf("candidate priority = %d, want 92", cand.Priority)
	}
	if !strings.Contains(cand.Rationale, "CSP") || !strings.Contains(cand.Rationale, "composedPath") {
		t.Fatalf("rationale must explain the CSP + composedPath mechanism: %q", cand.Rationale)
	}
	if cand.Value == "" || !strings.Contains(cand.Value, candProbe.Token) {
		t.Fatalf("candidate must embed the benign marker: %q", cand.Value)
	}
	for _, banned := range []string{"alert", "cookie", "fetch", "XMLHttpRequest"} {
		if strings.Contains(strings.ToLower(cand.Value), banned) {
			t.Fatalf("candidate value must stay benign, found %q in %q", banned, cand.Value)
		}
	}
	if on.Candidates[0].Technique != detection.AngularCSPExpressionTechnique {
		t.Fatalf("the confirmable interpolation must sort first within the standard profile, got %q first (all: %v)", on.Candidates[0].Technique, valuesOf(on))
	}
	if len(on.Candidates) > 8 {
		t.Fatalf("standard profile cap is 8, plan has %d", len(on.Candidates))
	}

	// The interpolation is the shape that can actually be CONFIRMED: its value
	// joins the marker from two literals at runtime, so the rendered page can
	// only carry the joined result if Angular evaluated it. Both shapes are
	// planned under the same gate, and the interpolation sorts first because the
	// standard profile truncates the plan — the confirmable one must never be
	// the one dropped.
	expr, ok := expressionCandidate(t, on)
	if !ok {
		t.Fatalf("AngularCSPBypass=true must plan the %s candidate; got %v", detection.AngularCSPExpressionTechnique, valuesOf(on))
	}
	if expr.Value != detection.AngularCSPExpressionValue(candProbe.Token) {
		t.Fatalf("expression candidate value = %q, want AngularCSPExpressionValue(marker)", expr.Value)
	}
	if expr.Priority != 94 || expr.Trigger != detection.TriggerLoad {
		t.Fatalf("expression candidate priority/trigger = %d/%q, want 94/load", expr.Priority, expr.Trigger)
	}
	if got, want := detection.AngularCSPExpressionResult(candProbe.Token), candProbe.Token+"x"; got != want {
		t.Fatalf("expression result = %q, want %q", got, want)
	}
	if strings.Contains(expr.Value, detection.AngularCSPExpressionResult(candProbe.Token)) {
		t.Fatalf("the evaluated result %q must NOT appear literally in the value %q — otherwise an echo could fake it",
			detection.AngularCSPExpressionResult(candProbe.Token), expr.Value)
	}
	for _, banned := range []string{"alert", "cookie", "fetch", "XMLHttpRequest"} {
		if strings.Contains(strings.ToLower(expr.Value), banned) {
			t.Fatalf("expression candidate must stay benign, found %q in %q", banned, expr.Value)
		}
	}

	off := planAngular(t, angularPlanDoc, false)
	if _, ok := angularCandidate(t, off); ok {
		t.Fatalf("AngularCSPBypass=false must not plan the bypass; got %v", valuesOf(off))
	}
	// The zero-value plan must be byte-identical to the pre-existing plan: the
	// flag-off plan equals a default PlanOptions plan over the same report.
	repBody := []byte(strings.Replace(angularPlanDoc, "{{M}}", candProbe.Value(), 1))
	rep := detection.AnalyzeReflection(candProbe, nil, repBody)
	rep.Parameter = "q"
	rep.Location = domain.LocationQuery
	detection.ClassifyContexts(&rep, repBody, detection.ContextOptions{ContentType: candHTML})
	defaultPlan := detection.PlanCandidates(&rep, detection.PlanOptions{ScanID: candScan, InjectionPointID: candIP})
	if len(defaultPlan.Candidates) != len(off.Candidates) {
		t.Fatalf("flag-off plan has %d candidates, default plan has %d", len(off.Candidates), len(defaultPlan.Candidates))
	}
	for i := range off.Candidates {
		if off.Candidates[i].Value != defaultPlan.Candidates[i].Value {
			t.Fatalf("flag-off candidate %d = %q, default = %q", i, off.Candidates[i].Value, defaultPlan.Candidates[i].Value)
		}
	}
}

func TestAngularCSPBypassNotPlannedOutsideHTMLElementText(t *testing.T) {
	// A comment site needs "--> " to close the enclosing construct first, so the
	// exact candidate value cannot be injected there.
	doc := `<!doctype html><html><body ng-app><!-- You searched for: '{{M}}' --><script src="/angular.js"></script></body></html>`
	plan := planAngular(t, doc, true)
	if _, ok := angularCandidate(t, plan); ok {
		t.Fatalf("the bypass must not be planned inside an HTML comment; got %v", valuesOf(plan))
	}
}

// The automatic evasion escalation re-plans with EnableEvasion forced on. It
// must never re-derive the Angular CSP bypass: the gate lives on the mutated
// response's CSP + body, not on the evasion opt-in, so an escalation must not
// smuggle the shape into a context that fails the gate.
func TestEvasionEscalationNeverReDerivesAngularCSPBypass(t *testing.T) {
	body := []byte(strings.Replace(angularPlanDoc, "{{M}}", candProbe.Value(), 1))
	rep := detection.AnalyzeReflection(candProbe, nil, body)
	rep.Parameter = "q"
	rep.Location = domain.LocationQuery
	detection.ClassifyContexts(&rep, body, detection.ContextOptions{ContentType: candHTML})
	opts := detection.PlanOptions{ScanID: candScan, InjectionPointID: candIP}
	if plan := detection.PlanCandidates(&rep, opts); plan == nil {
		t.Fatal("canonical plan is nil")
	}
	got := detection.EvasionEscalationCandidates(&rep, opts)
	if len(got) == 0 {
		t.Fatal("escalation returned no candidates; the check would be vacuous")
	}
	for _, c := range got {
		if c.Technique == detection.AngularCSPBypassTechnique {
			t.Fatalf("escalation re-derived the gated Angular CSP bypass: %q", c.Value)
		}
	}
}
