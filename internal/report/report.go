// Package report renders scan results. JSON, Markdown, and HTML reporters are
// all pure serialization — no security logic, no LLM.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
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
}

// Generator renders a report in a specific format.
type Generator interface {
	Format() domain.ReportFormat
	Generate(w io.Writer, data Data) error
}

// sortedFindings returns a copy of findings sorted by (CreatedAt, ID) so every
// generator's output is deterministic regardless of the order the caller
// supplies findings in (store list order is not guaranteed stable across
// calls: it is "ORDER BY created_at" with no tiebreaker).
func sortedFindings(findings []*domain.Finding) []*domain.Finding {
	out := append([]*domain.Finding(nil), findings...)
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out
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
	Findings    []*domain.Finding    `json:"findings"`
}

// Generate implements Generator. Output is deterministic: see sortedFindings.
func (JSONGenerator) Generate(w io.Writer, data Data) error {
	findings := sortedFindings(data.Findings)
	if findings == nil {
		findings = []*domain.Finding{}
	}
	rep := jsonReport{
		Tool:        "indago",
		Version:     data.ToolVersion,
		GeneratedAt: data.GeneratedAt,
		Project:     data.Project,
		Scan:        data.Scan,
		Summary:     Summarize(data.Scan.ID, findings),
		Findings:    findings,
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
