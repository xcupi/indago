package report_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/report"
)

// A report reader sees the throttled fact only if the rendered output carries
// it: the finding's Notes come from Summary, and the review label comes from
// ReviewReasonLabel. This pins BOTH formats, because the 429-then-403 row is
// exactly the one whose block_detail says "403" and whose label must not
// promise the bounded pass a 403 would get.
func TestReportsStateBackpressureForAThrottledBlockRow(t *testing.T) {
	now := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)
	throttled := &domain.Finding{
		ID: "throttled", ScanID: "scan1", VulnClass: domain.VulnReflectedXSS,
		Verdict: domain.VerdictInconclusive, Severity: domain.SeverityInfo, Confidence: domain.ConfidenceLow,
		Title:      "Diagnostic: possible WAF/rate-limit/maintenance block",
		EndpointID: "ep1", InjectionPointID: "ip1", Location: domain.LocationQuery,
		Detail: []byte(`{"parameter_name":"q","block_suspected":true,` +
			`"block_detail":"status changed 200 -> 403 from baseline while testing this parameter",` +
			`"throttled":true,"occurrences":2}`),
		Summary: "status changed 200 -> 403 from baseline while testing this parameter — backpressure (429/503) was observed at this point, so this is not a clean filter negative and the bounded bypass fallback is not escalated here",
		Provenance: domain.Provenance{
			DiscoverySource: domain.SourceCrawler, DetectedAt: now,
		},
		CreatedAt: now, UpdatedAt: now,
	}
	// Two rows: one with the summary the pipeline writes, one WITHOUT it. The
	// second is the real question — the fact must come from the finding's own
	// detail (via the review reason), not only from a summary string that a
	// caller could leave empty (a JSON-only row, an older row).
	bare := *throttled
	bare.ID = "throttled-no-summary"
	bare.Summary = ""

	data := report.Data{
		Project:     domain.Project{ID: "proj1", Name: "Acme"},
		Scan:        domain.Scan{ID: "scan1", Name: "nightly"},
		GeneratedAt: now, ToolVersion: "1.2.3",
		Findings: []*domain.Finding{throttled, &bare},
	}

	for _, format := range []domain.ReportFormat{domain.ReportMarkdown, domain.ReportHTML} {
		gen, err := report.For(format)
		if err != nil {
			t.Fatalf("%s renderer: %v", format, err)
		}
		var buf bytes.Buffer
		if err := gen.Generate(&buf, data); err != nil {
			t.Fatalf("%s generate: %v", format, err)
		}
		out := buf.String()
		if !strings.Contains(out, "429") || !strings.Contains(out, "503") {
			t.Errorf("%s report does not name the statuses that suppressed the fallback:\n%s", format, excerpt(out))
		}
		if !strings.Contains(strings.ToLower(out), "not escalated") {
			t.Errorf("%s report does not say the bounded fallback is not escalated here:\n%s", format, excerpt(out))
		}
		if strings.Contains(out, "can still get the bounded pass") {
			t.Errorf("%s report promises the 403 pass to a throttled point:\n%s", format, excerpt(out))
		}
	}
}

// excerpt keeps a failure readable: the label lives in one long line.
func excerpt(s string) string {
	const max = 1200
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
