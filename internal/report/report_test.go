package report_test

import (
	"bytes"
	"encoding/json"
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

func TestMarkdownNotImplemented(t *testing.T) {
	if _, err := report.For(domain.ReportMarkdown); err == nil {
		t.Fatal("markdown should not be implemented in Phase 0")
	}
}
