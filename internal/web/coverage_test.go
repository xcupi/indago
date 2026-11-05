package web_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/evidence"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/scan"
	"github.com/indago/indago/internal/store/memory"
	"github.com/indago/indago/internal/web"
)

// coverageAPI builds a handler whose server advertises caps, plus a created
// (not started) scan whose test cases the caller seeds directly.
func coverageAPI(t *testing.T, caps web.Capabilities) (api, domain.ID) {
	t.Helper()
	st := memory.New()
	q := queue.NewMemory()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctrl := scan.NewController(st, q, log, "test", scan.Options{})
	t.Cleanup(ctrl.Shutdown)
	ev, err := evidence.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv := web.NewServer(st, ctrl, "test", log, ev, t.TempDir())
	srv.SetCapabilities(caps)
	a := api{t: t, h: srv.Handler(), st: st, ev: ev}
	site := testSite(t)
	projectID, targetID := setupScan(a, site.URL)
	var created map[string]any
	a.mustJSON(a.do("POST", "/api/scans", map[string]any{"project_id": projectID, "target_id": targetID, "profile": "fast"}), 201, &created)
	return a, domain.ID(created["id"].(string))
}

func seedTest(t *testing.T, a api, scanID domain.ID, class domain.VulnClass, status domain.TestCaseStatus, outcome domain.TestOutcome, url, note string) {
	t.Helper()
	now := time.Now()
	tc := &domain.TestCase{
		ID: domain.NewID(), ScanID: scanID, JobID: domain.NewID(), VulnClass: class, Status: status, Outcome: outcome,
		Method: "GET", URL: url, Note: note, Detail: []byte(`{"secret":"detail-must-not-be-listed"}`),
		CreatedAt: now, UpdatedAt: now,
	}
	if err := a.st.TestCases().Create(context.Background(), tc); err != nil {
		t.Fatal(err)
	}
}

func TestCapabilitiesAdvertisesBrowserAndDefaultsToDisabled(t *testing.T) {
	a, _ := coverageAPI(t, web.Capabilities{BrowserEnabled: true, BrowserSandbox: true, StateChangingAllowed: false})
	var got map[string]any
	a.mustJSON(a.do("GET", "/api/capabilities", nil), 200, &got)
	if got["browser_enabled"] != true || got["browser_sandbox"] != true || got["state_changing_allowed"] != false {
		t.Fatalf("capabilities = %v", got)
	}
	if got["interactive_login"] != false {
		t.Fatalf("interactive login is only available when a login function is wired: %v", got)
	}

	// A zero Server must report everything off rather than inventing coverage.
	zero, _ := coverageAPI(t, web.Capabilities{})
	var off map[string]any
	zero.mustJSON(zero.do("GET", "/api/capabilities", nil), 200, &off)
	if off["browser_enabled"] != false {
		t.Fatalf("an unconfigured server must report the browser as disabled: %v", off)
	}
}

type coverageResp struct {
	BrowserEnabled bool `json:"browser_enabled"`
	CoverageGaps   bool `json:"coverage_gaps"`
	Tests          struct {
		Total, Completed, Skipped, Failed int
	} `json:"tests"`
	Reasons []struct {
		Code     string   `json:"code"`
		Severity string   `json:"severity"`
		Title    string   `json:"title"`
		Advice   string   `json:"advice"`
		Count    int      `json:"count"`
		Examples []string `json:"examples"`
	} `json:"reasons"`
	Warnings []struct {
		Code     string `json:"code"`
		Severity string `json:"severity"`
		Message  string `json:"message"`
	} `json:"warnings"`
}

func (c coverageResp) warning(code string) bool {
	for _, w := range c.Warnings {
		if w.Code == code {
			return true
		}
	}
	return false
}

// The scenario the readiness audit hit: a browser-less server completes a scan
// of a DOM-vulnerable page with zero findings and every DOM probe skipped. The
// API must say so instead of letting "completed, 0 findings" read as clean.
func TestCoverageFlagsBrowserlessScanAsGapsNotClean(t *testing.T) {
	a, id := coverageAPI(t, web.Capabilities{BrowserEnabled: false})
	for i := 0; i < 7; i++ {
		seedTest(t, a, id, domain.VulnDOMXSS, domain.TestCaseSkipped, "", "http://127.0.0.1:1/dom?q=hello", "dom-xss probe skipped: no browser configured for this scan")
	}
	seedTest(t, a, id, domain.VulnReflectedXSS, domain.TestCaseCompleted, domain.OutcomeSuccess, "http://127.0.0.1:1/safe?q=a", "not reflected")

	var c coverageResp
	a.mustJSON(a.do("GET", "/api/scans/"+string(id)+"/coverage", nil), 200, &c)
	if !c.CoverageGaps || c.BrowserEnabled {
		t.Fatalf("a browser-less scan with skipped DOM probes must report coverage gaps: %+v", c)
	}
	if !c.warning("browser_disabled") {
		t.Fatalf("missing browser_disabled warning: %+v", c.Warnings)
	}
	if c.Tests.Total != 8 || c.Tests.Skipped != 7 || c.Tests.Completed != 1 {
		t.Fatalf("test totals = %+v", c.Tests)
	}
	if len(c.Reasons) != 1 || c.Reasons[0].Code != "browser_unavailable" || c.Reasons[0].Count != 7 || c.Reasons[0].Severity != "high" {
		t.Fatalf("seven identical skips must be one grouped reason: %+v", c.Reasons)
	}
	if c.Reasons[0].Advice == "" || !strings.Contains(c.Reasons[0].Advice, "-browser") {
		t.Fatalf("the reason must say how to fix it: %+v", c.Reasons[0])
	}
}

func TestCoverageGroupsReasonsAndKeepsBenignSkipsAsInfo(t *testing.T) {
	a, id := coverageAPI(t, web.Capabilities{BrowserEnabled: true})
	for i := 0; i < 3; i++ {
		seedTest(t, a, id, domain.VulnDOMXSS, domain.TestCaseSkipped, "", "http://127.0.0.1:1/a?q=1", "query-string DOM-XSS source not tested: no discovered query parameter on this endpoint")
	}
	seedTest(t, a, id, domain.VulnReflectedXSS, domain.TestCaseSkipped, "", "http://127.0.0.1:1/post", "reflection test skipped: POST is state-changing and AllowStateChanging is off")
	seedTest(t, a, id, domain.VulnReflectedXSS, domain.TestCaseSkipped, "", "http://127.0.0.1:1/put", "reflection test skipped: PUT is state-changing and AllowStateChanging is off")

	var c coverageResp
	a.mustJSON(a.do("GET", "/api/scans/"+string(id)+"/coverage", nil), 200, &c)
	by := map[string]int{}
	sev := map[string]string{}
	for _, r := range c.Reasons {
		by[r.Code] = r.Count
		sev[r.Code] = r.Severity
	}
	if by["source_not_applicable"] != 3 || sev["source_not_applicable"] != "info" {
		t.Fatalf("benign skips must group as info: %+v", c.Reasons)
	}
	if by["state_changing_disabled"] != 2 || sev["state_changing_disabled"] != "medium" {
		t.Fatalf("PUT and POST skips are one reason: %+v", c.Reasons)
	}
	if !c.CoverageGaps {
		t.Fatalf("a medium skip reason is a coverage gap: %+v", c)
	}
	if c.warning("browser_disabled") {
		t.Fatalf("the browser is enabled here: %+v", c.Warnings)
	}
}

func TestCoverageCleanScanHasNoGaps(t *testing.T) {
	a, id := coverageAPI(t, web.Capabilities{BrowserEnabled: true})
	seedTest(t, a, id, domain.VulnReflectedXSS, domain.TestCaseCompleted, domain.OutcomeSuccess, "http://127.0.0.1:1/x?q=1", "not reflected")
	seedTest(t, a, id, domain.VulnDOMXSS, domain.TestCaseSkipped, "", "http://127.0.0.1:1/x?q=1", "localStorage source not tested: no storage key was present and no getItem key was observed")
	var c coverageResp
	a.mustJSON(a.do("GET", "/api/scans/"+string(id)+"/coverage", nil), 200, &c)
	if c.CoverageGaps || len(c.Warnings) != 0 {
		t.Fatalf("informational skips alone are not gaps: %+v", c)
	}
}

func TestCoverageTreatsErroredTestsAsUntestedNotClean(t *testing.T) {
	a, id := coverageAPI(t, web.Capabilities{BrowserEnabled: true})
	seedTest(t, a, id, domain.VulnReflectedXSS, domain.TestCaseFailed, domain.OutcomeError, "http://127.0.0.1:1/e", "")
	seedTest(t, a, id, domain.VulnReflectedXSS, domain.TestCaseFailed, domain.OutcomeTimeout, "http://127.0.0.1:1/t", "")
	var c coverageResp
	a.mustJSON(a.do("GET", "/api/scans/"+string(id)+"/coverage", nil), 200, &c)
	if !c.warning("tests_errored") || !c.CoverageGaps || c.Tests.Failed != 2 {
		t.Fatalf("errored and timed-out tests are untested, not negative: %+v", c)
	}
}

func TestCoverageUnknownScanIsNotFound(t *testing.T) {
	a, _ := coverageAPI(t, web.Capabilities{})
	if rec := a.do("GET", "/api/scans/does-not-exist/coverage", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d", rec.Code)
	}
	if rec := a.do("GET", "/api/scans/does-not-exist/tests", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d", rec.Code)
	}
}

type testsResp struct {
	Total  int `json:"total"`
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
	Items  []struct {
		ID         string `json:"id"`
		VulnClass  string `json:"vuln_class"`
		Status     string `json:"status"`
		Outcome    string `json:"outcome"`
		URL        string `json:"url"`
		Note       string `json:"note"`
		ReasonCode string `json:"reason_code"`
	} `json:"items"`
}

func TestTestsListFiltersPaginatesAndNeverLeaksDetail(t *testing.T) {
	a, id := coverageAPI(t, web.Capabilities{BrowserEnabled: true})
	for i := 0; i < 5; i++ {
		seedTest(t, a, id, domain.VulnDOMXSS, domain.TestCaseSkipped, "", "http://127.0.0.1:1/s", "dom-xss probe skipped: no browser configured for this scan")
	}
	seedTest(t, a, id, domain.VulnReflectedXSS, domain.TestCaseCompleted, domain.OutcomeSuccess, "http://127.0.0.1:1/ok", "reflected at html_text")
	seedTest(t, a, id, domain.VulnReflectedXSS, domain.TestCaseFailed, domain.OutcomeTimeout, "http://127.0.0.1:1/slow", "")
	seedTest(t, a, id, domain.VulnReflectedXSS, domain.TestCaseFailed, domain.OutcomeError, "http://127.0.0.1:1/boom", "")

	base := "/api/scans/" + string(id) + "/tests"
	var all testsResp
	rec := a.do("GET", base, nil)
	a.mustJSON(rec, 200, &all)
	if all.Total != 8 || len(all.Items) != 8 || all.Limit != 100 {
		t.Fatalf("all = total %d items %d limit %d", all.Total, len(all.Items), all.Limit)
	}
	if strings.Contains(rec.Body.String(), "detail-must-not-be-listed") {
		t.Fatal("the opaque engine Detail blob must not be part of the list")
	}

	var skipped testsResp
	a.mustJSON(a.do("GET", base+"?status=skipped", nil), 200, &skipped)
	if skipped.Total != 5 || skipped.Items[0].ReasonCode != "browser_unavailable" {
		t.Fatalf("skipped filter = %+v", skipped)
	}

	var problems testsResp
	a.mustJSON(a.do("GET", base+"?outcome=error,timeout", nil), 200, &problems)
	if problems.Total != 2 {
		t.Fatalf("outcome list filter = %+v", problems)
	}

	var byReason testsResp
	a.mustJSON(a.do("GET", base+"?reason=browser_unavailable", nil), 200, &byReason)
	if byReason.Total != 5 {
		t.Fatalf("reason filter = %+v", byReason)
	}

	var page testsResp
	a.mustJSON(a.do("GET", base+"?limit=3&offset=6", nil), 200, &page)
	if page.Total != 8 || len(page.Items) != 2 || page.Limit != 3 || page.Offset != 6 {
		t.Fatalf("pagination = %+v", page)
	}

	var capped testsResp
	a.mustJSON(a.do("GET", base+"?limit=100000", nil), 200, &capped)
	if capped.Limit != 500 {
		t.Fatalf("limit must be capped at 500, got %d", capped.Limit)
	}
	if rec := a.do("GET", base+"?limit=-1", nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("negative limit status = %d", rec.Code)
	}
	if rec := a.do("GET", base+"?status=nonsense", nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown status must be a 400, got %d", rec.Code)
	}
}

func TestCapabilitiesJSONShapeIsStable(t *testing.T) {
	a, _ := coverageAPI(t, web.Capabilities{})
	var raw map[string]json.RawMessage
	a.mustJSON(a.do("GET", "/api/capabilities", nil), 200, &raw)
	for _, k := range []string{"version", "browser_enabled", "browser_sandbox", "state_changing_allowed", "interactive_login"} {
		if _, ok := raw[k]; !ok {
			t.Errorf("capabilities is missing %q", k)
		}
	}
}
