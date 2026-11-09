package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
)

func templateFixture() Data {
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	return Data{
		Project: domain.Project{ID: "p1", Name: "Acme Program"},
		Scan: domain.Scan{
			ID: "s1", Name: "acme-web", Profile: domain.ProfileConservative,
			SeedURLs: []string{"https://shop.example.test/"},
		},
		Findings: []*domain.Finding{
			{
				ID: "f1", ScanID: "s1", VulnClass: domain.VulnReflectedXSS,
				Verdict: domain.VerdictConfirmed, Severity: domain.SeverityHigh,
				Confidence: domain.ConfidenceHigh, Title: `Reflected XSS in "search"`,
				Summary:    "The search query is reflected into an HTML attribute without encoding.",
				EndpointID: "e1", EvidenceIDs: []domain.ID{"ev1"},
			},
			{
				ID: "f2", ScanID: "s1", VulnClass: domain.VulnIDOR,
				Verdict: domain.VerdictConfirmed, Severity: domain.SeverityMedium,
				Confidence: domain.ConfidenceMedium, Title: "IDOR on invoice", Summary: "Another user's invoice is readable.",
			},
			{
				ID: "f3", ScanID: "s1", VulnClass: domain.VulnAccessControl,
				Verdict: domain.VerdictRejected, Severity: domain.SeverityInfo,
				Confidence: domain.ConfidenceLow, Title: "Admin probe rejected",
			},
		},
		Evidence: []*domain.Evidence{
			{ID: "ev1", Kind: domain.EvidenceResponse, Size: 2048},
		},
		GeneratedAt: now, ToolVersion: "v9",
		Completeness: Completeness{State: domain.ScanCompleted},
	}
}

func TestPentestTemplateSections(t *testing.T) {
	data := templateFixture()
	data.Template = TemplatePentest
	var b strings.Builder
	if err := (MarkdownGenerator{}).Generate(&b, data); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"# Penetration Test Report — Acme Program",
		"## Statement of Confidentiality",
		"## Engagement & Scope",
		"## Executive Summary",
		"## Approach & Methodology",
		"## Summary of Findings",
		"## Technical Findings Details",
		"## Remediation Summary",
		"## Appendix A — Finding Severities",
		"## Appendix B — Evidence Inventory",
		"## Appendix C — Coverage",
		"CWE-79",
		"CWE-639",
		"2 confirmed finding(s): 1 high, 1 medium",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("pentest markdown missing %q\n%s", want, out)
		}
	}
	if strings.Contains(out, "Admin probe rejected") {
		t.Fatal("rejected diagnostics must not appear in the deliverable body")
	}
	if !strings.Contains(out, "1 rejected diagnostic attempt(s)") {
		t.Fatal("the rejected count should be stated, not silently dropped")
	}
}

func TestBugBountyTemplateSections(t *testing.T) {
	data := templateFixture()
	data.Template = TemplateBugBounty
	var b strings.Builder
	if err := (MarkdownGenerator{}).Generate(&b, data); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"# Bug Bounty Report — Acme Program",
		"## Scope & Asset",
		"## Finding 1 —",
		"### Steps to reproduce",
		"### Impact",
		"### Remediation",
		"### Evidence",
		"CWE-79",
		"CWE-639",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("bug bounty markdown missing %q\n%s", want, out)
		}
	}
}

func TestDeliverableHTMLIsPrintReadyAndEscaped(t *testing.T) {
	data := templateFixture()
	data.Template = TemplatePentest
	data.Project.Name = `<script>alert(1)</script>`
	var b bytes.Buffer
	if err := (HTMLGenerator{}).Generate(&b, data); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.Contains(out, "@page { size: A4") {
		t.Fatal("HTML should carry print page rules for the PDF renderer")
	}
	if strings.Contains(out, "<script>alert(1)</script>") {
		t.Fatal("project name must be escaped")
	}
	if !strings.Contains(out, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Fatal("escaped project name missing")
	}
}

func TestTemplateValidity(t *testing.T) {
	for _, tc := range []struct {
		tmpl Template
		ok   bool
	}{
		{TemplateTechnical, true},
		{TemplatePentest, true},
		{TemplateBugBounty, true},
		{"hta", false},
	} {
		if got := tc.tmpl.IsValid(); got != tc.ok {
			t.Fatalf("%q valid = %v, want %v", tc.tmpl, got, tc.ok)
		}
	}
}
