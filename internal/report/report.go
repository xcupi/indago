// Package report renders scan results. JSON, Markdown, and HTML reporters are
// all pure serialization — no security logic, no LLM.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/indago/indago/internal/domain"
)

// Data is the input to a report generator.
type Data struct {
	Project     domain.Project
	Scan        domain.Scan
	Findings    []*domain.Finding
	GeneratedAt time.Time
	ToolVersion string
	// Evidence is the metadata (never content) of the evidence the findings
	// reference. Optional: without it a report lists evidence IDs only and
	// cannot label roles or the verified candidate's artifacts.
	Evidence []*domain.Evidence
	// Selection and ScanFindings describe how Findings was chosen from the
	// scan (zero values: unspecified — older callers). Every generator states
	// them, so a "confirmed only" report can never be mistaken for the whole
	// scan.
	Selection    domain.ReportSelection
	ScanFindings int
	// AISummary, when non-empty, is an advisory executive summary drafted
	// by the AI Gateway (domain.AIDraftReport) — rendered prominently
	// labeled as AI-generated and unverified, NEVER as part of the
	// findings themselves. Empty (the default: AI disabled, not
	// requested, or the advisory call failed) renders no AI section at
	// all — see AGENTS.md §2.5: the scanner must work identically with AI
	// disabled, and AI output is never authoritative.
	AISummary string
}

// dataSummary is Summarize plus the report's own selection metadata.
func dataSummary(data Data, findings []*domain.Finding) domain.ReportSummary {
	s := Summarize(data.Scan.ID, findings)
	s.Selection = data.Selection
	s.ScanFindings = data.ScanFindings
	return s
}

// selectionLine renders a report's selection for humans, or "" when unset.
func selectionLine(s domain.ReportSummary) string {
	label := map[domain.ReportSelection]string{
		domain.ReportSelectAll:       "all findings",
		domain.ReportSelectConfirmed: "confirmed findings only",
		domain.ReportSelectSelected:  "selected findings",
	}[s.Selection]
	if label == "" {
		return ""
	}
	return fmt.Sprintf("%s (%d of %d findings in the scan)", label, s.TotalFindings, s.ScanFindings)
}

// Generator renders a report in a specific format.
type Generator interface {
	Format() domain.ReportFormat
	Generate(w io.Writer, data Data) error
}

// Summarize computes an aggregate summary over a set of findings.
func Summarize(scanID domain.ID, findings []*domain.Finding) domain.ReportSummary {
	s := domain.ReportSummary{
		ByVerdict:         map[domain.Verdict]int{},
		BySeverity:        map[domain.Severity]int{},
		ByVulnClass:       map[domain.VulnClass]int{},
		GeneratedFromScan: scanID,
	}
	for _, f := range findings {
		s.TotalFindings++
		s.ByVerdict[f.Verdict]++
		s.BySeverity[f.Severity]++
		s.ByVulnClass[f.VulnClass]++
		if f.Verdict == domain.VerdictConfirmed {
			s.ConfirmedCount++
		}
	}
	return s
}

// JSONGenerator renders a report as indented JSON.
type JSONGenerator struct{}

// Format implements Generator.
func (JSONGenerator) Format() domain.ReportFormat { return domain.ReportJSON }

type jsonReport struct {
	Tool        string               `json:"tool"`
	Version     string               `json:"version"`
	GeneratedAt time.Time            `json:"generated_at"`
	Project     domain.Project       `json:"project"`
	Scan        domain.Scan          `json:"scan"`
	Summary     domain.ReportSummary `json:"summary"`
	Findings    []jsonFinding        `json:"findings"`
}

// jsonFinding is the stored finding plus its presentation: section, the
// verified candidate (confirmed findings), every attempt as a child
// diagnostic, and role-labelled evidence metadata.
type jsonFinding struct {
	*domain.Finding
	FindingView
}

// Generate implements Generator. Output is deterministic: findings are ordered
// by Prioritized (confirmed first), so the same Data always yields identical
// output.
func (JSONGenerator) Generate(w io.Writer, data Data) error {
	findings := Prioritized(data.Findings)
	idx := EvidenceIndex(data.Evidence)
	out := make([]jsonFinding, 0, len(findings))
	for _, f := range findings {
		out = append(out, jsonFinding{Finding: f, FindingView: NewFindingView(f, idx)})
	}
	rep := jsonReport{
		Tool:        "indago",
		Version:     data.ToolVersion,
		GeneratedAt: data.GeneratedAt,
		Project:     data.Project,
		Scan:        data.Scan,
		Summary:     dataSummary(data, findings),
		Findings:    out,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(rep); err != nil {
		return fmt.Errorf("report: encode json: %w", err)
	}
	return nil
}

var _ Generator = JSONGenerator{}

// For returns a generator for the given format.
func For(format domain.ReportFormat) (Generator, error) {
	switch format {
	case domain.ReportJSON:
		return JSONGenerator{}, nil
	case domain.ReportMarkdown:
		return MarkdownGenerator{}, nil
	case domain.ReportHTML:
		return HTMLGenerator{}, nil
	default:
		return nil, fmt.Errorf("report: unknown format %q", format)
	}
}
