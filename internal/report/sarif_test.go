package report

import (
	"strings"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
)

// A SARIF alert must be a finding worth reviewing, not every rejected attempt.
// A plain rejected diagnostic is excluded and counted; a rejected attempt whose
// own candidates say the negative is not clean is kept as a review item.
func TestSARIFExcludesOnlyPlainDiagnostics(t *testing.T) {
	now := time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)
	plain := &domain.Finding{
		ID: "plain", VulnClass: domain.VulnReflectedXSS, Verdict: domain.VerdictRejected,
		Severity: domain.SeverityLow, Title: "plain rejected attempt", CreatedAt: now,
	}
	interaction := &domain.Finding{
		ID: "interaction", VulnClass: domain.VulnReflectedXSS, Verdict: domain.VerdictRejected,
		Severity: domain.SeverityLow, Title: "interaction-only attempt", CreatedAt: now.Add(time.Second),
		Detail: []byte(`{"candidates":[{"trigger":"interaction","transformation":"raw","value":"<x onmouseover=1>"}]}`),
	}
	confirmed := &domain.Finding{
		ID: "confirmed", VulnClass: domain.VulnReflectedXSS, Verdict: domain.VerdictConfirmed,
		Severity: domain.SeverityHigh, Title: "confirmed", CreatedAt: now.Add(2 * time.Second),
	}

	kept, excluded := sarifFindings([]*domain.Finding{plain, interaction, confirmed})
	if excluded != 1 {
		t.Fatalf("excluded = %d, want 1 (only the plain diagnostic)", excluded)
	}
	if len(kept) != 2 {
		t.Fatalf("kept %d findings, want 2 (confirmed + interaction review)", len(kept))
	}
	seen := map[domain.ID]bool{}
	for _, f := range kept {
		seen[f.ID] = true
	}
	if seen["plain"] {
		t.Fatal("a plain rejected diagnostic was uploaded as an alert")
	}
	if !seen["interaction"] || !seen["confirmed"] {
		t.Fatalf("kept = %v, want the interaction review and the confirmed finding", seen)
	}
	if got := sarifKind(interaction.Verdict); got != "review" {
		t.Fatalf("interaction-only rejected finding kind = %q, want review", got)
	}
}

// A future engine's class must still produce a usable rule, but with no
// invented CWE, score or level.
func TestSARIFUnknownClassDoesNotInventClassification(t *testing.T) {
	rule := buildSARIFRule("future_engine")
	if rule.ID != "indago/future_engine" {
		t.Fatalf("rule id = %q", rule.ID)
	}
	if rule.ShortDescription.Text == "" || rule.ShortDescription.Text == "future_engine" {
		t.Fatalf("rule description = %q, want a humanised class name", rule.ShortDescription.Text)
	}
	if rule.Properties == nil || len(rule.Properties.Tags) != 1 || rule.Properties.Tags[0] != "security" {
		t.Fatalf("rule properties = %+v, want only the security tag", rule.Properties)
	}
	if rule.Properties.CWE != "" || rule.Properties.SecuritySeverity != "" || rule.Properties.CVSSVector != "" {
		t.Fatalf("unknown class invented a classification: %+v", rule.Properties)
	}
	if rule.DefaultConfiguration != nil || rule.HelpURI != "" || rule.Help != nil {
		t.Fatalf("unknown class invented rule metadata: %+v", rule)
	}
}

func TestSARIFArtifactURI(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "https://app.example.test/search?q=<script>&a=1", want: "https://app.example.test/search?a=1&q=%3Cscript%3E"},
		{in: "http://lab.example.test:8080/x", want: "http://lab.example.test:8080/x"},
		{in: "HTTPS://APP.EXAMPLE.TEST/x", want: "https://APP.EXAMPLE.TEST/x"},
		{in: "/relative/path", wantErr: true},
		{in: "file:///etc/passwd", wantErr: true},
		{in: "https://app.example.test/x\r\nInjected: 1", wantErr: true},
		{in: "", wantErr: true},
	}
	for _, tc := range cases {
		got := sarifArtifactURI(tc.in)
		if tc.wantErr {
			if got != "" {
				t.Errorf("sarifArtifactURI(%q) = %q, want empty", tc.in, got)
			}
			continue
		}
		if got != tc.want {
			t.Errorf("sarifArtifactURI(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestSARIFRuleIDsAreConservative(t *testing.T) {
	for _, tc := range []struct {
		in   domain.VulnClass
		want string
	}{
		{domain.VulnSecurityHeaders, "indago/security_headers"},
		{domain.VulnTLSConfig, "indago/tls_config"},
		{"Future Engine / v2", "indago/future-engine---v2"},
		{"", "indago/unclassified"},
	} {
		if got := sarifRuleID(tc.in); got != tc.want {
			t.Errorf("sarifRuleID(%q) = %q, want %q", tc.in, got, tc.want)
		}
		if strings.ContainsAny(sarifRuleID(tc.in), " \t\r\n") {
			t.Errorf("sarifRuleID(%q) contains whitespace", tc.in)
		}
	}
}
