package report_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/report"
)

func sampleReportData() report.Data {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	verifiedAt := now.Add(time.Minute)
	return report.Data{
		Project:     domain.Project{ID: "proj1", Name: "Acme"},
		Scan:        domain.Scan{ID: "scan1", Name: "nightly"},
		GeneratedAt: now,
		ToolVersion: "1.2.3",
		Findings: []*domain.Finding{
			{
				ID: "f2", ScanID: "scan1", VulnClass: domain.VulnReflectedXSS,
				Verdict: domain.VerdictConfirmed, Severity: domain.SeverityHigh, Confidence: domain.ConfidenceHigh,
				Title:      "Reflected XSS candidate (html_text) in parameter \"q\"",
				EndpointID: "ep1", InjectionPointID: "ip1", Location: domain.LocationQuery,
				EvidenceIDs: []domain.ID{"ev1", "ev2"},
				Detail:      []byte(`{"method":"GET","parameter_name":"q","dedup_key":"k","occurrences":1}`),
				Provenance: domain.Provenance{
					DiscoverySource: domain.SourceCrawler, DetectedAt: now, VerifiedAt: &verifiedAt,
				},
				CreatedAt: now, UpdatedAt: now,
			},
			{
				ID: "f1", ScanID: "scan1", VulnClass: domain.VulnReflectedXSS,
				Verdict: domain.VerdictPending, Severity: domain.SeverityLow, Confidence: domain.ConfidenceLow,
				Title:     "Reflected XSS candidate (unknown_mixed) in parameter \"r\"",
				CreatedAt: now.Add(-time.Hour), UpdatedAt: now.Add(-time.Hour),
			},
		},
	}
}

func TestMarkdownGeneratorProducesValidReport(t *testing.T) {
	gen, err := report.For(domain.ReportMarkdown)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := gen.Generate(&buf, sampleReportData()); err != nil {
		t.Fatalf("generate: %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		"# Indago Scan Report",
		"indago 1.2.3",
		"Acme",
		"nightly",
		"## Summary",
		"**Total findings:** 2",
		"**Confirmed:** 1",
		"## Findings",
		"CONFIRMED",
		"PENDING",
		"Reflected XSS candidate (html_text)",
		"crawler",
		"`ev1`", "`ev2`",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("markdown missing %q; got:\n%s", want, out)
		}
	}
}

// Findings are rendered oldest-first regardless of input order, so a report
// reads chronologically and is reproducible.
func TestMarkdownGeneratorOrdersFindingsByCreatedAt(t *testing.T) {
	gen, _ := report.For(domain.ReportMarkdown)
	var buf bytes.Buffer
	if err := gen.Generate(&buf, sampleReportData()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	pendingIdx := strings.Index(out, "Reflected XSS candidate (unknown_mixed)")
	confirmedIdx := strings.Index(out, "Reflected XSS candidate (html_text)")
	if pendingIdx < 0 || confirmedIdx < 0 {
		t.Fatalf("both findings should be rendered: %s", out)
	}
	if pendingIdx > confirmedIdx {
		t.Fatal("the earlier-created (pending) finding should be rendered before the later one")
	}
}

func TestMarkdownGeneratorEmptyFindings(t *testing.T) {
	gen, _ := report.For(domain.ReportMarkdown)
	data := report.Data{
		Project: domain.Project{Name: "p"}, Scan: domain.Scan{Name: "s"}, GeneratedAt: time.Now(),
	}
	var buf bytes.Buffer
	if err := gen.Generate(&buf, data); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "No findings") || !strings.Contains(out, "**Total findings:** 0") {
		t.Fatalf("empty report wrong: %s", out)
	}
}

// Deterministic output: the same Data produces byte-identical Markdown across
// repeated calls — summary breakdowns come from Go maps, so this also proves
// their rendering is sorted, not map-iteration-order-dependent.
func TestMarkdownGeneratorDeterministic(t *testing.T) {
	data := sampleReportData()
	gen, _ := report.For(domain.ReportMarkdown)

	var first bytes.Buffer
	if err := gen.Generate(&first, data); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		var buf bytes.Buffer
		if err := gen.Generate(&buf, data); err != nil {
			t.Fatal(err)
		}
		if buf.String() != first.String() {
			t.Fatalf("run %d differs from the first:\n--- first ---\n%s\n--- run %d ---\n%s", i, first.String(), i, buf.String())
		}
	}
}

// The JSON generator's output must also be deterministic for the same input,
// since Summarize's maps are likewise iterated — json.Marshal sorts map keys,
// but this nails the end-to-end guarantee down as a regression test.
func TestJSONGeneratorDeterministic(t *testing.T) {
	data := sampleReportData()
	gen, _ := report.For(domain.ReportJSON)

	var first bytes.Buffer
	if err := gen.Generate(&first, data); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		var buf bytes.Buffer
		if err := gen.Generate(&buf, data); err != nil {
			t.Fatal(err)
		}
		if buf.String() != first.String() {
			t.Fatalf("run %d differs from the first", i)
		}
	}
}
