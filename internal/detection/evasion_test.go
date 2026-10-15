package detection_test

import (
	"strings"
	"testing"

	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
)

var (
	evScan  = domain.ID("scan-evasion")
	evIP    = domain.ID("ip-evasion")
	evProbe = detection.NewProbe(evScan, evIP)
)

func planWithEvasion(t *testing.T, body []byte, enable bool) *detection.ReflectionReport {
	t.Helper()
	rep := detection.AnalyzeReflection(evProbe, nil, body)
	rep.Parameter = "q"
	rep.Location = domain.LocationQuery
	detection.ClassifyContexts(&rep, body, detection.ContextOptions{ContentType: "text/html"})
	detection.PlanCandidates(&rep, detection.PlanOptions{ScanID: evScan, InjectionPointID: evIP, EnableEvasion: enable})
	return &rep
}

// Off by default: EnableEvasion=false (the PlanOptions zero value) must never
// plan a Technique-tagged candidate, matching domain.ScanConfig.EnableEvasion
// defaulting to false (AGENTS.md §2.3, conservative by design).
func TestEvasionCandidatesAreOffByDefault(t *testing.T) {
	body := []byte("<p>" + evProbe.Value() + "</p>")
	rep := planWithEvasion(t, body, false)
	for _, c := range rep.Plan.Candidates {
		if c.Technique != "" {
			t.Fatalf("EnableEvasion=false but got a technique-tagged candidate: %+v", c)
		}
	}
}

// EnableEvasion=true adds Technique-tagged variants ON TOP OF the canonical
// set — the canonical candidates must still all be present.
func TestEvasionCandidatesAreAdditive(t *testing.T) {
	body := []byte("<p>" + evProbe.Value() + "</p>")
	off := planWithEvasion(t, body, false)
	on := planWithEvasion(t, body, true)
	if len(on.Plan.Candidates) <= len(off.Plan.Candidates) {
		t.Fatalf("enabling evasion did not add candidates: off=%d on=%d", len(off.Plan.Candidates), len(on.Plan.Candidates))
	}
	canonical := map[string]bool{}
	for _, c := range off.Plan.Candidates {
		canonical[c.DedupKey] = true
	}
	for key := range canonical {
		found := false
		for _, c := range on.Plan.Candidates {
			if c.DedupKey == key {
				found = true
			}
		}
		if !found {
			t.Fatalf("canonical candidate %q disappeared when evasion was enabled", key)
		}
	}
	sawTechnique := false
	for _, c := range on.Plan.Candidates {
		if c.Technique != "" {
			sawTechnique = true
		}
	}
	if !sawTechnique {
		t.Fatal("EnableEvasion=true produced no technique-tagged candidate")
	}
}

// Same guardrail as the canonical set (TestPlanCandidatesAreBenignMarkers):
// every evasion candidate is still a benign-marker detection probe, never a
// weaponized payload (no alert/cookie/exfiltration construct), regardless of
// which bypass shape it uses.
func TestEvasionCandidatesAreBenignMarkers(t *testing.T) {
	body := []byte("<p>" + evProbe.Value() + "</p><input value=\"" + evProbe.Value() + "\">" +
		"<style>" + evProbe.Value() + "</style>")
	rep := planWithEvasion(t, body, true)
	banned := []string{"alert(", "confirm(", "prompt(", "eval(", "fetch(",
		"document.cookie", ".cookie", "xmlhttprequest", "navigator.", "location=",
		"location.", "window.", "import(", "atob(", "=document"}
	seenEvasion := false
	for _, c := range rep.Plan.Candidates {
		if c.Technique == "" {
			continue
		}
		seenEvasion = true
		lower := strings.ToLower(c.Value)
		for _, b := range banned {
			if strings.Contains(lower, strings.ToLower(b)) {
				t.Fatalf("evasion candidate %q (technique %s) contains banned construct %q", c.Value, c.Technique, b)
			}
		}
		if !strings.Contains(c.Value, evProbe.Token) && !strings.Contains(strings.ToLower(c.Value), strings.ToLower(evProbe.Token)) {
			t.Fatalf("evasion candidate %q (technique %s) does not embed the benign marker", c.Value, c.Technique)
		}
	}
	if !seenEvasion {
		t.Fatal("no evasion candidate was planned for this body")
	}
}
