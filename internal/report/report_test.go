package report_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/report"
)

func TestSummarize(t *testing.T) {
	scan := domain.NewID()
	findings := []*domain.Finding{
		{Verdict: domain.VerdictConfirmed, Severity: domain.SeverityHigh, VulnClass: domain.VulnReflectedXSS},
		{Verdict: domain.VerdictConfirmed, Severity: domain.SeverityCritical, VulnClass: domain.VulnReflectedXSS},
		{Verdict: domain.VerdictRejected, Severity: domain.SeverityLow, VulnClass: domain.VulnReflectedXSS},
	}
	s := report.Summarize(scan, findings)
	if s.TotalFindings != 3 || s.ConfirmedCount != 2 {
		t.Fatalf("summary counts: total=%d confirmed=%d", s.TotalFindings, s.ConfirmedCount)
	}
	if s.ByVerdict[domain.VerdictConfirmed] != 2 || s.BySeverity[domain.SeverityHigh] != 1 {
		t.Fatalf("breakdown wrong: %+v", s)
	}
}

func TestJSONGeneratorProducesValidReport(t *testing.T) {
	gen, err := report.For(domain.ReportJSON)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	data := report.Data{
		Scan:        domain.Scan{ID: domain.NewID(), Name: "s1"},
		Project:     domain.Project{ID: domain.NewID(), Name: "p1"},
		Findings:    nil,
		GeneratedAt: time.Now(),
		ToolVersion: "test",
	}
	if err := gen.Generate(&buf, data); err != nil {
		t.Fatalf("generate: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if out["tool"] != "indago" {
		t.Fatalf("tool field = %v", out["tool"])
	}
}

func TestHTMLGeneratorProducesValidReport(t *testing.T) {
	gen, err := report.For(domain.ReportHTML)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	findingID := domain.NewID()
	data := report.Data{
		Scan:    domain.Scan{ID: domain.NewID(), Name: "s1"},
		Project: domain.Project{ID: domain.NewID(), Name: "p1"},
		Findings: []*domain.Finding{
			{
				ID:        findingID,
				Title:     "<script>alert(1)</script>",
				Verdict:   domain.VerdictConfirmed,
				Severity:  domain.SeverityHigh,
				VulnClass: domain.VulnReflectedXSS,
				CreatedAt: now,
			},
		},
		GeneratedAt: now,
		ToolVersion: "test",
	}
	var buf bytes.Buffer
	if err := gen.Generate(&buf, data); err != nil {
		t.Fatalf("generate: %v", err)
	}
	out := buf.String()
	if !strings.HasPrefix(out, "<!doctype html>") {
		t.Fatalf("output does not look like HTML:\n%s", out)
	}
	if strings.Contains(out, "<script>alert(1)</script>") {
		t.Fatal("finding title was not HTML-escaped: report would be self-executing")
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Fatalf("expected escaped finding title in output:\n%s", out)
	}
}

func TestReportGeneratorsAreDeterministic(t *testing.T) {
	now := time.Now()
	data := report.Data{
		Scan:    domain.Scan{ID: domain.NewID(), Name: "s1"},
		Project: domain.Project{ID: domain.NewID(), Name: "p1"},
		Findings: []*domain.Finding{
			{ID: "b", Verdict: domain.VerdictConfirmed, CreatedAt: now},
			{ID: "a", Verdict: domain.VerdictRejected, CreatedAt: now},
		},
		GeneratedAt: now,
		ToolVersion: "test",
	}
	reversed := report.Data{
		Scan:        data.Scan,
		Project:     data.Project,
		Findings:    []*domain.Finding{data.Findings[1], data.Findings[0]},
		GeneratedAt: now,
		ToolVersion: "test",
	}
	for _, format := range []domain.ReportFormat{domain.ReportJSON, domain.ReportMarkdown, domain.ReportHTML} {
		gen, err := report.For(format)
		if err != nil {
			t.Fatal(err)
		}
		var buf1, buf2 bytes.Buffer
		if err := gen.Generate(&buf1, data); err != nil {
			t.Fatalf("%s: generate: %v", format, err)
		}
		if err := gen.Generate(&buf2, reversed); err != nil {
			t.Fatalf("%s: generate (reversed input): %v", format, err)
		}
		if buf1.String() != buf2.String() {
			t.Fatalf("%s: output depends on input finding order (not deterministic)", format)
		}
	}
}
