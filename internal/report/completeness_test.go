package report_test

// Coverage honesty: a report over an unfinished scan (failed, canceled,
// still running, dead jobs, errored/timeout test cases) must say so near the
// top and must never present the empty result as a clean target. Only a
// completed scan with no recorded gap may print the plain "No findings"
// sentence. These are behavioral tests over the real generators.

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/report"
)

const (
	incompleteEmptyText = "No findings recorded — coverage is incomplete, this does NOT mean the target is clean."
	// tier-2 (completed scan, no job gaps, only recovered test-case errors).
	calmEmptyText = "No findings recorded. 1 test case(s) ended in error and 0 timed out (they may have been recovered by retry) — review before treating the target as clean."
)

func renderFormat(t *testing.T, format domain.ReportFormat, data report.Data) string {
	t.Helper()
	gen, err := report.For(format)
	if err != nil {
		t.Fatalf("generator for %s: %v", format, err)
	}
	var buf bytes.Buffer
	if err := gen.Generate(&buf, data); err != nil {
		t.Fatalf("generate %s: %v", format, err)
	}
	return buf.String()
}

func coverageData(c report.Completeness) report.Data {
	return report.Data{
		Project:      domain.Project{ID: "proj1", Name: "Acme"},
		Scan:         domain.Scan{ID: "scan1", Name: "nightly", State: c.State},
		Completeness: c,
		GeneratedAt:  time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		ToolVersion:  "1.2.3",
	}
}

// A failed scan with dead/failed/canceled jobs and errored/timeout test cases
// renders a prominent banner naming the state and every count, and the empty
// findings section refuses to read as "target is clean".
func TestMarkdownIncompleteScanBanner(t *testing.T) {
	c := report.Completeness{
		State: domain.ScanFailed, DeadJobs: 1, FailedJobs: 2, CanceledJobs: 3,
		ErrorTestCases: 4, TimeoutTestCases: 5,
	}
	out := renderFormat(t, domain.ReportMarkdown, coverageData(c))

	for _, want := range []string{
		"Incomplete scan",
		"this report does NOT cover the whole target",
		"Scan state: `failed`",
		"Dead jobs: 1",
		"Failed jobs: 2",
		"Canceled jobs: 3",
		"Error test cases: 4",
		"Timeout test cases: 5",
		incompleteEmptyText,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("incomplete Markdown missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "_No findings._") {
		t.Fatalf("incomplete report still prints the clean-scan sentence:\n%s", out)
	}
	if banner, summary := strings.Index(out, "Incomplete scan"), strings.Index(out, "## Summary"); banner < 0 || banner > summary {
		t.Fatalf("banner must appear near the top, before the Summary section:\n%s", out)
	}

	if again := renderFormat(t, domain.ReportMarkdown, coverageData(c)); again != out {
		t.Fatal("Markdown output with completeness metadata is not deterministic")
	}
}

// The state string is dynamic text; the HTML generator must escape it rather
// than inject it.
func TestHTMLIncompleteScanBannerEscapesState(t *testing.T) {
	c := report.Completeness{
		State: domain.ScanState(`<script>alert(1)</script>`), DeadJobs: 1, ErrorTestCases: 2,
	}
	out := renderFormat(t, domain.ReportHTML, coverageData(c))

	for _, want := range []string{
		"Incomplete scan",
		"this report does NOT cover the whole target",
		"Dead jobs: 1",
		"Error test cases: 2",
		incompleteEmptyText,
		`class="incomplete"`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("incomplete HTML missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, `<script>alert(1)</script>`) {
		t.Fatalf("state was injected raw into the HTML report:\n%s", out)
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Fatalf("expected escaped state text in the banner:\n%s", out)
	}
}

// JSON keeps its existing top-level schema and adds the coverage counts.
func TestJSONReportCompleteness(t *testing.T) {
	c := report.Completeness{
		State: domain.ScanCanceled, DeadJobs: 1, FailedJobs: 2, CanceledJobs: 3,
		ErrorTestCases: 4, TimeoutTestCases: 5,
	}
	var out struct {
		Tool         string      `json:"tool"`
		Scan         domain.Scan `json:"scan"`
		Completeness struct {
			report.Completeness
			IsComplete bool `json:"complete"`
		} `json:"completeness"`
		Findings []any                `json:"findings"`
		Summary  domain.ReportSummary `json:"summary"`
	}
	if err := json.Unmarshal([]byte(renderFormat(t, domain.ReportJSON, coverageData(c))), &out); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if out.Tool != "indago" || len(out.Findings) != 0 || out.Summary.TotalFindings != 0 {
		t.Fatalf("existing JSON fields changed: %+v", out)
	}
	if out.Scan.ID != "scan1" || out.Scan.State != domain.ScanCanceled {
		t.Fatalf("scan object not preserved: %+v", out.Scan)
	}
	if out.Completeness.Completeness != c || out.Completeness.IsComplete {
		t.Fatalf("completeness = %+v complete=%t, want %+v complete=false", out.Completeness.Completeness, out.Completeness.IsComplete, c)
	}
}

// Negative control: a genuinely completed scan with no recorded gaps keeps the
// plain "No findings" sentence and no banner.
func TestCompletedCleanScanSaysPlainNoFindings(t *testing.T) {
	data := coverageData(report.Completeness{State: domain.ScanCompleted})

	md := renderFormat(t, domain.ReportMarkdown, data)
	if !strings.Contains(md, "## Findings\n\n_No findings._") {
		t.Fatalf("completed clean scan must keep the plain sentence:\n%s", md)
	}
	if strings.Contains(md, "Incomplete scan") || strings.Contains(md, "coverage is incomplete") {
		t.Fatalf("completed clean scan must not warn about coverage:\n%s", md)
	}
	if strings.Contains(md, "Coverage note") {
		t.Fatalf("completed clean scan must not render a coverage note:\n%s", md)
	}

	html := renderFormat(t, domain.ReportHTML, data)
	if !strings.Contains(html, "<em>No findings.</em>") {
		t.Fatalf("completed clean scan must keep the plain HTML sentence:\n%s", html)
	}
	if strings.Contains(html, "Incomplete scan") {
		t.Fatalf("completed clean scan must not render the banner:\n%s", html)
	}
	if strings.Contains(html, `class="coverage-note"`) || strings.Contains(html, "Coverage note") {
		t.Fatalf("completed clean scan must not render a coverage note:\n%s", html)
	}
}

// Findings do not make coverage complete: a partial scan that found something
// still warns, and it does not print the empty-findings sentence.
func TestPartialScanWithFindingsStillBanners(t *testing.T) {
	data := sampleReportData()
	data.Completeness = report.Completeness{State: domain.ScanCompleted, CanceledJobs: 1}

	md := renderFormat(t, domain.ReportMarkdown, data)
	if !strings.Contains(md, "Incomplete scan") || !strings.Contains(md, "Canceled jobs: 1") {
		t.Fatalf("partial scan with findings must still show the banner:\n%s", md)
	}
	if !strings.Contains(md, "Reflected XSS candidate (html_text)") {
		t.Fatalf("findings must still be rendered:\n%s", md)
	}
	if strings.Contains(md, incompleteEmptyText) {
		t.Fatalf("a report WITH findings must not claim there are none:\n%s", md)
	}

	html := renderFormat(t, domain.ReportHTML, data)
	if !strings.Contains(html, "Incomplete scan") || !strings.Contains(html, "Reflected XSS candidate (html_text)") {
		t.Fatalf("partial HTML report must show banner and findings:\n%s", html)
	}
}

// A selection filter can make the report empty while the scan is not clean;
// the banner stays and the selection line still says what was chosen.
func TestIncompleteBannerSurvivesSelectionModes(t *testing.T) {
	data := coverageData(report.Completeness{State: domain.ScanFailed})
	data.Selection = domain.ReportSelectConfirmed
	data.ScanFindings = 3
	data.Findings = nil

	md := renderFormat(t, domain.ReportMarkdown, data)
	if !strings.Contains(md, "Incomplete scan") {
		t.Fatalf("selection mode hid the incomplete banner:\n%s", md)
	}
	if !strings.Contains(md, "**Selection:** confirmed findings only (0 of 3 findings in the scan)") {
		t.Fatalf("selection line regressed:\n%s", md)
	}

	html := renderFormat(t, domain.ReportHTML, data)
	if !strings.Contains(html, "Incomplete scan") || !strings.Contains(html, "confirmed findings only (0 of 3 findings in the scan)") {
		t.Fatalf("HTML selection report lost banner or selection line:\n%s", html)
	}
}

// Tier 2: a completed scan with no job-level gap but one errored test case is
// NOT an incomplete scan — the bounded worker retry may have recovered it. It
// gets a neutral coverage note and a calm empty sentence, never the red banner.
func TestCompletedScanWithRecoveredTestCaseErrorGetsNoteNotBanner(t *testing.T) {
	data := coverageData(report.Completeness{State: domain.ScanCompleted, ErrorTestCases: 1})

	md := renderFormat(t, domain.ReportMarkdown, data)
	if strings.Contains(md, "Incomplete scan") {
		t.Fatalf("recovered retry must not be labelled an incomplete scan:\n%s", md)
	}
	for _, want := range []string{"Coverage note", "1 test case(s) ended in error and 0 timed out", "recovered by retry", calmEmptyText} {
		if !strings.Contains(md, want) {
			t.Fatalf("markdown missing %q:\n%s", want, md)
		}
	}

	html := renderFormat(t, domain.ReportHTML, data)
	if strings.Contains(html, "Incomplete scan") || strings.Contains(html, `class="incomplete"`) {
		t.Fatalf("html labelled a recovered retry as incomplete:\n%s", html)
	}
	for _, want := range []string{`class="coverage-note"`, "Coverage note", "1 test case(s) ended in error and 0 timed out", calmEmptyText} {
		if !strings.Contains(html, want) {
			t.Fatalf("html missing %q:\n%s", want, html)
		}
	}

	var out struct {
		Completeness struct {
			report.Completeness
			IsComplete bool `json:"complete"`
		} `json:"completeness"`
	}
	if err := json.Unmarshal([]byte(renderFormat(t, domain.ReportJSON, data)), &out); err != nil {
		t.Fatalf("json report: %v", err)
	}
	if !out.Completeness.IsComplete || out.Completeness.ErrorTestCases != 1 || out.Completeness.TimeoutTestCases != 0 {
		t.Fatalf("json completeness = %+v complete=%t", out.Completeness.Completeness, out.Completeness.IsComplete)
	}
}

// Tier 1 wins over tier 2: any job-level gap keeps the red banner and never
// downgrades into a soft note.
func TestCompletedScanWithDeadJobStaysIncomplete(t *testing.T) {
	data := coverageData(report.Completeness{State: domain.ScanCompleted, DeadJobs: 1, ErrorTestCases: 1})

	md := renderFormat(t, domain.ReportMarkdown, data)
	if !strings.Contains(md, "Incomplete scan") || !strings.Contains(md, "Dead jobs: 1") {
		t.Fatalf("dead job must keep the red banner:\n%s", md)
	}
	if strings.Contains(md, "Coverage note") {
		t.Fatalf("dead job must not downgrade to a soft note:\n%s", md)
	}

	html := renderFormat(t, domain.ReportHTML, data)
	if !strings.Contains(html, "Incomplete scan") || strings.Contains(html, `class="coverage-note"`) {
		t.Fatalf("html tier-1 handling wrong:\n%s", html)
	}
}
