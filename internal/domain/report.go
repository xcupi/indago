package domain

import "time"

// ReportFormat is the rendered format of a report. Phase 0 implements JSON;
// Markdown and HTML are designed-for.
type ReportFormat string

const (
	ReportJSON     ReportFormat = "json"
	ReportMarkdown ReportFormat = "markdown"
	ReportHTML     ReportFormat = "html"
)

// IsValid reports whether the report format is a known value.
func (f ReportFormat) IsValid() bool {
	switch f {
	case ReportJSON, ReportMarkdown, ReportHTML:
		return true
	default:
		return false
	}
}

// ReportSummary is an aggregate rollup included in every report.
type ReportSummary struct {
	TotalFindings     int               `json:"total_findings"`
	ByVerdict         map[Verdict]int   `json:"by_verdict"`
	BySeverity        map[Severity]int  `json:"by_severity"`
	ByVulnClass       map[VulnClass]int `json:"by_vuln_class"`
	ConfirmedCount    int               `json:"confirmed_count"`
	GeneratedFromScan ID                `json:"generated_from_scan"`
	// Selection is how the report's findings were chosen from the scan
	// (ReportSelectAll/Confirmed/Selected); ScanFindings is how many findings
	// the scan held at generation time, so "3 of 8" is always reconstructible.
	// Both are additive JSON fields on the persisted summary blob.
	Selection    ReportSelection `json:"selection,omitempty"`
	ScanFindings int             `json:"scan_findings,omitempty"`
}

// ReportSelection names how a report's findings were chosen.
type ReportSelection string

const (
	ReportSelectAll       ReportSelection = "all"       // every finding in the scan
	ReportSelectConfirmed ReportSelection = "confirmed" // only verdict=confirmed
	ReportSelectSelected  ReportSelection = "selected"  // an explicit list of finding IDs
)

// IsValid reports whether the selection is a known value.
func (s ReportSelection) IsValid() bool {
	switch s {
	case ReportSelectAll, ReportSelectConfirmed, ReportSelectSelected:
		return true
	default:
		return false
	}
}

// Report is a generated artifact summarizing a scan's findings. The rendered
// output is written to Path (under the data directory); this record is the
// index entry.
type Report struct {
	ID        ID            `json:"id"`
	ScanID    ID            `json:"scan_id"`
	ProjectID ID            `json:"project_id"`
	Format    ReportFormat  `json:"format"`
	Path      string        `json:"path"`
	Summary   ReportSummary `json:"summary"`
	CreatedAt time.Time     `json:"created_at"`
}
