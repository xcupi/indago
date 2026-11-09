// Package report renders scan results. JSON, Markdown, and HTML reporters are
// all pure serialization — no security logic, no LLM.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
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
	// Endpoints maps an endpoint id to its URL, so a deliverable can name the
	// exact endpoint a finding belongs to (the verified request usually carries
	// the injected query string, which is the same on every row).
	Endpoints map[domain.ID]string
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
	// Completeness is how much of the scan actually ran. Every generator
	// states it, so a report from a failed, canceled or still-running scan
	// (or one with dead jobs / errored test cases) can never present missing
	// coverage as "no findings". It is pure data supplied by the caller: the
	// generators render it and make no security decision from it.
	Completeness Completeness
	// Template selects the deliverable layout: empty is the technical
	// evidence-first report; pentest and bug_bounty reshape the same data for
	// a client or a bounty program. Only the Markdown/HTML/PDF generators act
	// on it (JSON stays the machine format).
	Template Template
	// AISummary, when non-empty, is an advisory executive summary drafted
	// by the AI Gateway (domain.AIDraftReport) — rendered prominently
	// labeled as AI-generated and unverified, NEVER as part of the
	// findings themselves. Empty (the default: AI disabled, not
	// requested, or the advisory call failed) renders no AI section at
	// all — see AGENTS.md §2.5: the scanner must work identically with AI
	// disabled, and AI output is never authoritative.
	AISummary string
}

// Completeness records the scan coverage a report was generated from: the
// scan's lifecycle state plus the counts of work that did not complete. It
// carries no verdict and no finding: it exists so a reader can tell a clean
// result from a report over an unfinished scan.
type Completeness struct {
	State            domain.ScanState `json:"state"`
	DeadJobs         int              `json:"dead_jobs"`
	FailedJobs       int              `json:"failed_jobs"`
	CanceledJobs     int              `json:"canceled_jobs"`
	ErrorTestCases   int              `json:"error_test_cases"`
	TimeoutTestCases int              `json:"timeout_test_cases"`
}

// HasJobGaps reports whether a job-level gap makes coverage incomplete: a
// dead, failed or canceled job means work that should have run did not.
func (c Completeness) HasJobGaps() bool {
	return c.DeadJobs > 0 || c.FailedJobs > 0 || c.CanceledJobs > 0
}

// HasTestCaseGaps reports whether any test case ended in error or timeout.
// On its own this is NOT an incomplete scan: the bounded worker retry may
// have recovered it, which is why it is surfaced as a neutral note.
func (c Completeness) HasTestCaseGaps() bool {
	return c.ErrorTestCases > 0 || c.TimeoutTestCases > 0
}

// Complete reports whether the scan finished with no JOB-level coverage gap.
// Test-case errors/timeouts alone do not make it incomplete — the job retry
// may have recovered them; they render as a neutral coverage note instead.
func (c Completeness) Complete() bool {
	return c.State == domain.ScanCompleted && !c.HasJobGaps()
}

// NeedsCoverageNote reports tier 2: a complete scan (no job gaps) that still
// recorded errored or timed-out test cases worth mentioning calmly.
func (c Completeness) NeedsCoverageNote() bool {
	return c.Complete() && c.HasTestCaseGaps()
}

// testCaseGapText describes the tier-2 counts for the neutral note.
func (c Completeness) testCaseGapText() string {
	return fmt.Sprintf("%d test case(s) ended in error and %d timed out", c.ErrorTestCases, c.TimeoutTestCases)
}

// coverageFor resolves the coverage metadata to render: the caller's
// Completeness, falling back to the scan's own state for callers that only
// populate Data.Scan.
func coverageFor(data Data) Completeness {
	c := data.Completeness
	if c.State == "" {
		c.State = data.Scan.State
	}
	return c
}

// incompleteEmptyText replaces the plain "No findings" sentence whenever the
// scan did not cover the target. It never claims a vulnerability; it prevents
// missing coverage from being read as a clean result.
const incompleteEmptyText = "No findings recorded — coverage is incomplete, this does NOT mean the target is clean."

// writeIncompleteBanner is the Markdown coverage banner: prominent, before the
// summary, naming the scan state and every gap count.
func writeIncompleteBanner(b *strings.Builder, c Completeness) {
	fmt.Fprintf(b, "> **⚠ Incomplete scan — this report does NOT cover the whole target.**\n>\n")
	fmt.Fprintf(b, "> Scan state: `%s` · Dead jobs: %d · Failed jobs: %d · Canceled jobs: %d · Error test cases: %d · Timeout test cases: %d\n\n",
		nonEmpty(string(c.State), "unknown"), c.DeadJobs, c.FailedJobs, c.CanceledJobs, c.ErrorTestCases, c.TimeoutTestCases)
}

// writeCoverageNote is the tier-2 Markdown notice: a completed scan whose only
// gap is a test case that may have been recovered by the worker retry. It is
// deliberately neutral — not an "incomplete scan" warning.
func writeCoverageNote(b *strings.Builder, c Completeness) {
	fmt.Fprintf(b, "> **Coverage note:** %s; their jobs completed, so some may have been recovered by retry.\n\n", c.testCaseGapText())
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
	Tool         string               `json:"tool"`
	Version      string               `json:"version"`
	GeneratedAt  time.Time            `json:"generated_at"`
	Project      domain.Project       `json:"project"`
	Scan         domain.Scan          `json:"scan"`
	Summary      domain.ReportSummary `json:"summary"`
	Completeness jsonCompleteness     `json:"completeness"`
	Findings     []jsonFinding        `json:"findings"`
}

// jsonCompleteness is the additive JSON shape: the counts plus the tier-1
// completeness boolean (job-level gaps only), so consumers do not recompute it.
type jsonCompleteness struct {
	Completeness
	IsComplete bool `json:"complete"`
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
	cov := coverageFor(data)
	rep := jsonReport{
		Tool:         "indago",
		Version:      data.ToolVersion,
		GeneratedAt:  data.GeneratedAt,
		Project:      data.Project,
		Scan:         data.Scan,
		Summary:      dataSummary(data, findings),
		Completeness: jsonCompleteness{Completeness: cov, IsComplete: cov.Complete()},
		Findings:     out,
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
