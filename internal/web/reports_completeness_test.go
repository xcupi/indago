package web_test

// Coverage honesty at the API boundary: reports created from real scans whose
// state/jobs/test cases show unfinished coverage must carry that fact in all
// three formats, and a genuinely completed clean scan must keep the plain
// "No findings" wording.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/report"
)

const incompleteEmptyText = "No findings recorded — coverage is incomplete, this does NOT mean the target is clean."

func mustSetScanState(t *testing.T, a api, scanID domain.ID, state domain.ScanState) {
	t.Helper()
	ctx := context.Background()
	sc, err := a.st.Scans().Get(ctx, scanID)
	if err != nil {
		t.Fatalf("load scan: %v", err)
	}
	sc.State = state
	if err := a.st.Scans().Update(ctx, sc); err != nil {
		t.Fatalf("update scan state: %v", err)
	}
}

func seedJob(t *testing.T, a api, scanID domain.ID, state domain.JobState) {
	t.Helper()
	now := time.Now()
	j := &domain.TestJob{
		ID: domain.NewID(), ScanID: scanID, Type: domain.JobTest, State: state,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := a.st.Jobs().Create(context.Background(), j); err != nil {
		t.Fatalf("create job: %v", err)
	}
}

func seedTestCaseOutcome(t *testing.T, a api, scanID domain.ID, outcome domain.TestOutcome) {
	t.Helper()
	now := time.Now()
	tc := &domain.TestCase{
		ID: domain.NewID(), ScanID: scanID, JobID: domain.NewID(),
		Status: domain.TestCaseCompleted, Outcome: outcome, CreatedAt: now, UpdatedAt: now,
	}
	if err := a.st.TestCases().Create(context.Background(), tc); err != nil {
		t.Fatalf("create test case: %v", err)
	}
}

func generateReportContent(t *testing.T, a api, scanID domain.ID, format string, extra map[string]any) string {
	t.Helper()
	body := map[string]any{"format": format}
	for k, v := range extra {
		body[k] = v
	}
	var rpt domain.Report
	a.mustJSON(a.do("POST", "/api/scans/"+string(scanID)+"/reports", body), http.StatusCreated, &rpt)
	rec := a.do("GET", "/api/reports/"+string(rpt.ID)+"/content", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("%s content status = %d: %s", format, rec.Code, rec.Body.String())
	}
	return rec.Body.String()
}

type reportCompletenessResp struct {
	Tool         string               `json:"tool"`
	Scan         domain.Scan          `json:"scan"`
	Summary      domain.ReportSummary `json:"summary"`
	Completeness struct {
		report.Completeness
		IsComplete bool `json:"complete"`
	} `json:"completeness"`
	Findings []json.RawMessage `json:"findings"`
}

// A failed scan with dead/failed/canceled jobs and errored/timeout test cases:
// every format says so, and the empty result never reads as a clean target.
func TestReportIncompleteScanCoverageAllFormats(t *testing.T) {
	a := newAPI(t, nil)
	scanID := createTestScan(t, a)
	mustSetScanState(t, a, scanID, domain.ScanFailed)
	seedJob(t, a, scanID, domain.JobDead)
	seedJob(t, a, scanID, domain.JobFailed)
	seedJob(t, a, scanID, domain.JobCanceled)
	seedTestCaseOutcome(t, a, scanID, domain.OutcomeError)
	seedTestCaseOutcome(t, a, scanID, domain.OutcomeTimeout)

	md := generateReportContent(t, a, scanID, "markdown", nil)
	for _, want := range []string{
		"Incomplete scan",
		"Scan state: `failed`",
		"Dead jobs: 1",
		"Failed jobs: 1",
		"Canceled jobs: 1",
		"Error test cases: 1",
		"Timeout test cases: 1",
		incompleteEmptyText,
	} {
		if !strings.Contains(md, want) {
			t.Fatalf("markdown missing %q:\n%s", want, md)
		}
	}

	html := generateReportContent(t, a, scanID, "html", nil)
	for _, want := range []string{
		"Incomplete scan",
		"Scan state: <code>failed</code>",
		"Dead jobs: 1",
		"Failed jobs: 1",
		"Canceled jobs: 1",
		"Error test cases: 1",
		"Timeout test cases: 1",
		incompleteEmptyText,
		`class="incomplete"`,
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("html missing %q:\n%s", want, html)
		}
	}

	var js reportCompletenessResp
	if err := json.Unmarshal([]byte(generateReportContent(t, a, scanID, "json", nil)), &js); err != nil {
		t.Fatalf("json report: %v", err)
	}
	want := report.Completeness{
		State: domain.ScanFailed, DeadJobs: 1, FailedJobs: 1, CanceledJobs: 1,
		ErrorTestCases: 1, TimeoutTestCases: 1,
	}
	if js.Completeness.Completeness != want || js.Completeness.IsComplete {
		t.Fatalf("json completeness = %+v complete=%t, want %+v complete=false", js.Completeness.Completeness, js.Completeness.IsComplete, want)
	}
	if js.Tool != "indago" || js.Scan.State != domain.ScanFailed || js.Summary.TotalFindings != 0 || len(js.Findings) != 0 {
		t.Fatalf("existing JSON fields changed: %+v", js)
	}
}

// A completed scan can still contain dead work: completion alone is not enough
// to print the plain sentence.
func TestReportCompletedScanWithDeadJobStillBanners(t *testing.T) {
	a := newAPI(t, nil)
	scanID := createTestScan(t, a)
	mustSetScanState(t, a, scanID, domain.ScanCompleted)
	seedJob(t, a, scanID, domain.JobDead)

	md := generateReportContent(t, a, scanID, "markdown", nil)
	if !strings.Contains(md, "Incomplete scan") || !strings.Contains(md, "Dead jobs: 1") {
		t.Fatalf("completed scan with a dead job must still warn:\n%s", md)
	}
	if strings.Contains(md, "_No findings._") || !strings.Contains(md, incompleteEmptyText) {
		t.Fatalf("dead job must suppress the plain clean sentence:\n%s", md)
	}

	html := generateReportContent(t, a, scanID, "html", nil)
	if !strings.Contains(html, "Incomplete scan") || !strings.Contains(html, incompleteEmptyText) {
		t.Fatalf("html coverage result wrong:\n%s", html)
	}
	if strings.Contains(html, "<em>No findings.</em>") {
		t.Fatalf("html dead-job report prints the plain clean sentence:\n%s", html)
	}
}

func TestReportCanceledScanBannersWithoutGapCounts(t *testing.T) {
	a := newAPI(t, nil)
	scanID := createTestScan(t, a)
	mustSetScanState(t, a, scanID, domain.ScanCanceled)

	md := generateReportContent(t, a, scanID, "markdown", nil)
	if !strings.Contains(md, "Incomplete scan") || !strings.Contains(md, "Scan state: `canceled`") {
		t.Fatalf("canceled scan report does not name its state:\n%s", md)
	}
	if !strings.Contains(md, incompleteEmptyText) {
		t.Fatalf("canceled scan report claims a plain empty result:\n%s", md)
	}
}

// Negative control: completed scan, only successful work, zero findings.
func TestReportCompletedCleanScanSaysPlainNoFindings(t *testing.T) {
	a := newAPI(t, nil)
	scanID := createTestScan(t, a)
	mustSetScanState(t, a, scanID, domain.ScanCompleted)
	seedJob(t, a, scanID, domain.JobSucceeded)
	seedTestCaseOutcome(t, a, scanID, domain.OutcomeSuccess)

	md := generateReportContent(t, a, scanID, "markdown", nil)
	if !strings.Contains(md, "## Findings\n\n_No findings._") {
		t.Fatalf("completed clean scan must keep the plain sentence:\n%s", md)
	}
	if strings.Contains(md, "Incomplete scan") || strings.Contains(md, "coverage is incomplete") {
		t.Fatalf("completed clean scan must not warn:\n%s", md)
	}

	html := generateReportContent(t, a, scanID, "html", nil)
	if !strings.Contains(html, "<em>No findings.</em>") || strings.Contains(html, "Incomplete scan") {
		t.Fatalf("completed clean scan html wrong:\n%s", html)
	}

	var js reportCompletenessResp
	if err := json.Unmarshal([]byte(generateReportContent(t, a, scanID, "json", nil)), &js); err != nil {
		t.Fatalf("json report: %v", err)
	}
	if js.Completeness.Completeness != (report.Completeness{State: domain.ScanCompleted}) || !js.Completeness.IsComplete {
		t.Fatalf("completed clean completeness = %+v complete=%t, want state-only complete=true", js.Completeness.Completeness, js.Completeness.IsComplete)
	}
}

// Findings do not make coverage complete.
func TestReportPartialScanWithFindingsStillBanners(t *testing.T) {
	a := newAPI(t, nil)
	scanID := createTestScan(t, a)
	mustSetScanState(t, a, scanID, domain.ScanCompleted)
	seedJob(t, a, scanID, domain.JobCanceled)
	f := seedVerdictFinding(t, a, scanID, domain.VerdictPending, "Reflected XSS candidate", time.Now())

	md := generateReportContent(t, a, scanID, "markdown", nil)
	if !strings.Contains(md, "Incomplete scan") || !strings.Contains(md, "Canceled jobs: 1") {
		t.Fatalf("partial scan with findings must still warn:\n%s", md)
	}
	if !strings.Contains(md, f.Title) {
		t.Fatalf("finding missing from partial report:\n%s", md)
	}

	html := generateReportContent(t, a, scanID, "html", nil)
	if !strings.Contains(html, "Incomplete scan") || !strings.Contains(html, f.Title) {
		t.Fatalf("partial html report must warn and show findings:\n%s", html)
	}
}

// Every selection mode keeps the banner; the selection line still explains an
// empty result that came from filtering rather than from the scan.
func TestReportSelectionModesKeepIncompleteBanner(t *testing.T) {
	a := newAPI(t, nil)
	scanID := createTestScan(t, a)
	mustSetScanState(t, a, scanID, domain.ScanFailed)
	f := seedVerdictFinding(t, a, scanID, domain.VerdictPending, "Reflected XSS candidate", time.Now())

	modes := []struct {
		name string
		req  map[string]any
		line string
	}{
		{"all", map[string]any{"mode": "all"}, "all findings (1 of 1 findings in the scan)"},
		{"confirmed", map[string]any{"mode": "confirmed"}, "confirmed findings only (0 of 1 findings in the scan)"},
		{"selected", map[string]any{"mode": "selected", "finding_ids": []string{string(f.ID)}}, "selected findings (1 of 1 findings in the scan)"},
	}
	for _, tc := range modes {
		t.Run(tc.name, func(t *testing.T) {
			md := generateReportContent(t, a, scanID, "markdown", tc.req)
			if !strings.Contains(md, "Incomplete scan") {
				t.Fatalf("%s: selection hid the incomplete banner:\n%s", tc.name, md)
			}
			if !strings.Contains(md, "**Selection:** "+tc.line) {
				t.Fatalf("%s: selection line = missing/regressed:\n%s", tc.name, md)
			}
			html := generateReportContent(t, a, scanID, "html", tc.req)
			if !strings.Contains(html, "Incomplete scan") || !strings.Contains(html, tc.line) {
				t.Fatalf("%s: html lost banner or selection line:\n%s", tc.name, html)
			}
		})
	}
}

// A completed scan whose only gap is a test case the worker retry recovered:
// neutral coverage note (not the red banner) in every selection mode, with a
// calm empty sentence when the filter selects nothing.
func TestReportRecoveredTestCaseErrorGetsCoverageNote(t *testing.T) {
	a := newAPI(t, nil)
	scanID := createTestScan(t, a)
	mustSetScanState(t, a, scanID, domain.ScanCompleted)
	seedJob(t, a, scanID, domain.JobSucceeded)
	seedTestCaseOutcome(t, a, scanID, domain.OutcomeError)
	f := seedVerdictFinding(t, a, scanID, domain.VerdictPending, "Reflected XSS candidate", time.Now())

	const calm = "No findings recorded. 1 test case(s) ended in error and 0 timed out (they may have been recovered by retry) — review before treating the target as clean."
	modes := []struct {
		name string
		req  map[string]any
		line string
	}{
		{"all", map[string]any{"mode": "all"}, "all findings (1 of 1 findings in the scan)"},
		{"confirmed", map[string]any{"mode": "confirmed"}, "confirmed findings only (0 of 1 findings in the scan)"},
		{"selected", map[string]any{"mode": "selected", "finding_ids": []string{string(f.ID)}}, "selected findings (1 of 1 findings in the scan)"},
	}
	for _, tc := range modes {
		t.Run(tc.name, func(t *testing.T) {
			md := generateReportContent(t, a, scanID, "markdown", tc.req)
			if strings.Contains(md, "Incomplete scan") {
				t.Fatalf("%s: recovered retry labelled incomplete:\n%s", tc.name, md)
			}
			for _, want := range []string{"Coverage note", "1 test case(s) ended in error and 0 timed out", "recovered by retry", "**Selection:** " + tc.line} {
				if !strings.Contains(md, want) {
					t.Fatalf("%s: markdown missing %q:\n%s", tc.name, want, md)
				}
			}
			html := generateReportContent(t, a, scanID, "html", tc.req)
			if strings.Contains(html, "Incomplete scan") || strings.Contains(html, `class="incomplete"`) {
				t.Fatalf("%s: html labelled recovered retry incomplete:\n%s", tc.name, html)
			}
			if !strings.Contains(html, `class="coverage-note"`) || !strings.Contains(html, tc.line) {
				t.Fatalf("%s: html missing note or selection line:\n%s", tc.name, html)
			}
		})
	}

	if md := generateReportContent(t, a, scanID, "markdown", map[string]any{"mode": "confirmed"}); !strings.Contains(md, calm) {
		t.Fatalf("calm empty text missing:\n%s", md)
	}

	var js reportCompletenessResp
	if err := json.Unmarshal([]byte(generateReportContent(t, a, scanID, "json", nil)), &js); err != nil {
		t.Fatalf("json report: %v", err)
	}
	if !js.Completeness.IsComplete || js.Completeness.ErrorTestCases != 1 || js.Completeness.TimeoutTestCases != 0 {
		t.Fatalf("json completeness = %+v complete=%t, want complete=true error=1", js.Completeness.Completeness, js.Completeness.IsComplete)
	}
}
