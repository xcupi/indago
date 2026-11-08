package detection_test

import (
	"strings"
	"testing"

	"github.com/indago/indago/internal/detection"
)

func TestCSPReportURIParamsExtractsOnlyPolicyNamedParameters(t *testing.T) {
	for _, tc := range []struct {
		name string
		csp  string
		want []string
	}{
		{"report-uri with token", "default-src 'self'; report-uri /csp-report?token=", []string{"token"}},
		{"report-uri with two params", "default-src 'self'; report-uri /r?a=1&b=2", []string{"a", "b"}},
		{"report-to fallback", "default-src 'self'; report-to /r?k=v", []string{"k"}},
		{"no csp", "", nil},
		{"no report-uri", "default-src 'self'; script-src 'self'", nil},
		{"report-uri without query", "default-src 'self'; report-uri /csp-report", nil},
		{"duplicate names collapse", "report-uri /r?a=1; report-uri /r?a=2", []string{"a"}},
		{"empty name skipped", "report-uri /r?=1&b=2", []string{"b"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := detection.CSPReportURIParams(tc.csp)
			if len(got) != len(tc.want) {
				t.Fatalf("params = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("params = %v, want %v", got, tc.want)
				}
			}
		})
	}
}

func TestCSPReportURIParamsIsBounded(t *testing.T) {
	csp := "report-uri /r?a=1&b=2&c=3&d=4&e=5&f=6"
	if got := detection.CSPReportURIParams(csp); len(got) > 4 {
		t.Fatalf("params = %v, want at most 4 (bounded)", got)
	}
}

func TestCSPDirectiveInjectionValueRelaxesInlineScriptElementsOnly(t *testing.T) {
	v := detection.CSPDirectiveInjectionValue()
	if !strings.HasPrefix(v, ";") {
		t.Fatalf("value %q must start by closing the URI query", v)
	}
	if !strings.Contains(v, "script-src-elem") || !strings.Contains(v, "'unsafe-inline'") {
		t.Fatalf("value %q must add exactly script-src-elem 'unsafe-inline'", v)
	}
	for _, banned := range []string{"unsafe-eval", "*", "script-src 'unsafe-inline'"} {
		if strings.Contains(v, banned) {
			t.Fatalf("value %q must not widen the policy with %q", v, banned)
		}
	}
}

func TestCSPInjectionMarkerNeedsTheCanaryVerbatim(t *testing.T) {
	if detection.CSPInjectionMarker("a; report-uri /r?t=inddeadbeef", "inddeadbeef") != true {
		t.Fatal("a verbatim canary must be reported")
	}
	if detection.CSPInjectionMarker("a; report-uri /r?t=ind%20deadbeef", "ind deadbeef") {
		t.Fatal("an encoded canary must not count as injected verbatim")
	}
	if detection.CSPInjectionMarker("", "x") {
		t.Fatal("an empty header must never match")
	}
}
