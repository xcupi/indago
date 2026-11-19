package web_test

// Real-browser test for the SARIF option in the dashboard's report picker.
//
// The API has rendered SARIF for a while, but an operator could not ask for it
// from the UI. This drives the actual picker: it must offer the labelled
// option, send format=sarif, and the server must persist the artifact with the
// .sarif extension and SARIF content. Skips quickly without Chromium, like the
// other UI tests.

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
)

func TestUIReportPickerExportsSARIF(t *testing.T) {
	u := newUIHarness(t)
	scanID := uiFindingsScan(t, u)
	uiFinding(t, u, scanID, domain.VerdictConfirmed, uiFindingOpts{path: "/s"}, time.Now())
	u.openScanTab(scanID, "reports")

	u.waitUI("SARIF option offered", `(function(){
		var s = document.getElementById('r_fmt');
		return !!s && /SARIF 2\.1\.0 \(\.sarif\)/.test(s.textContent);
	})()`)
	u.waitUI("confirmed preview", `/Will include 1 of 1 finding\(s\): confirmed 1\./.test(document.getElementById('reportPreview').textContent)`)

	u.setVal("r_fmt", "sarif")
	u.click("generateReport")
	u.waitUI("SARIF report listed", `/sarif/.test(document.getElementById('reportsBody').textContent) && !/No reports yet/.test(document.getElementById('reportsBody').textContent)`)

	reports, err := u.st.Reports().ListByScan(context.Background(), scanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(reports) != 1 {
		t.Fatalf("reports = %d, want the one SARIF export", len(reports))
	}
	rpt := reports[0]
	if rpt.Format != domain.ReportSARIF {
		t.Fatalf("report format = %q, want sarif", rpt.Format)
	}
	if !strings.HasSuffix(rpt.Path, ".sarif") {
		t.Fatalf("stored report path = %q, want .sarif", rpt.Path)
	}
	body, _ := u.eval(fmt.Sprintf(`fetch('/api/reports/%s/content').then(function(r){return r.text();})`, rpt.ID)).(string)
	if !strings.Contains(body, `"version": "2.1.0"`) || !strings.Contains(body, `"$schema"`) {
		t.Fatalf("SARIF export is not a 2.1.0 log:\n%s", truncate(body, 400))
	}
}
