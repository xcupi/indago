// Package report renders scan results. JSON and Markdown reporters are
// implemented (pure serialization — no security logic, no LLM). An HTML
// reporter is planned; For returns ErrNotImplemented for it until then.
package report

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/indago/indago/internal/domain"
)

// ErrNotImplemented is returned for report formats not yet available.
var ErrNotImplemented = errors.New("report: format not implemented")

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

// Generate implements Generator.
func (JSONGenerator) Generate(w io.Writer, data Data) error {
	findings := data.Findings
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

// For returns a generator for the given format. HTML is not yet implemented.
func For(format domain.ReportFormat) (Generator, error) {
	switch format {
	case domain.ReportJSON:
		return JSONGenerator{}, nil
	case domain.ReportMarkdown:
		return MarkdownGenerator{}, nil
	case domain.ReportHTML:
		return nil, fmt.Errorf("%w: %s", ErrNotImplemented, format)
	default:
		return nil, fmt.Errorf("report: unknown format %q", format)
	}
}
