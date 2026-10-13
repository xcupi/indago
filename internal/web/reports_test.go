package web_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
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

func TestCreateReportAllFindingsEachFormat(t *testing.T) {
	a := newAPI(t, nil)
	scanID := createTestScan(t, a)
	f, _, _ := seedFinding(t, a, scanID)

	for _, tc := range []struct {
		format string
		ct     string
		marker string
	}{
		{"json", "application/json", `"id": "` + string(f.ID) + `"`},
		{"markdown", "text/markdown", "# Indago Scan Report"},
		{"html", "text/html", "<!doctype html>"},
	} {
		var rpt domain.Report
		rec := a.do("POST", "/api/scans/"+string(scanID)+"/reports", map[string]any{"format": tc.format})
		a.mustJSON(rec, http.StatusCreated, &rpt)
		if rpt.Format != domain.ReportFormat(tc.format) || rpt.ScanID != scanID {
			t.Fatalf("%s: report row = %+v", tc.format, rpt)
		}
		if rpt.Summary.TotalFindings != 1 {
			t.Fatalf("%s: summary = %+v", tc.format, rpt.Summary)
		}

		content := a.do("GET", "/api/reports/"+string(rpt.ID)+"/content", nil)
		if content.Code != http.StatusOK {
			t.Fatalf("%s: content status = %d: %s", tc.format, content.Code, content.Body.String())
		}
		if ct := content.Header().Get("Content-Type"); !strings.HasPrefix(ct, tc.ct) {
			t.Fatalf("%s: content-type = %q", tc.format, ct)
		}
		if !strings.Contains(content.Body.String(), tc.marker) {
			t.Fatalf("%s: body missing marker %q:\n%s", tc.format, tc.marker, content.Body.String())
		}
		if d := content.Header().Get("Content-Disposition"); !strings.HasPrefix(d, "inline") {
			t.Fatalf("%s: expected inline by default, got %q", tc.format, d)
		}

		assertSandboxedContent(t, content.Header())
		download := a.do("GET", "/api/reports/"+string(rpt.ID)+"/content?download", nil)
		if d := download.Header().Get("Content-Disposition"); !strings.HasPrefix(d, "attachment") {
			t.Fatalf("%s: expected attachment with ?download, got %q", tc.format, d)
		}
	}
}

func TestCreateReportSelectedFindingsOnly(t *testing.T) {
	a := newAPI(t, nil)
	scanID := createTestScan(t, a)
	f, _, _ := seedFinding(t, a, scanID)

	var rpt domain.Report
	rec := a.do("POST", "/api/scans/"+string(scanID)+"/reports", map[string]any{
		"format": "json", "finding_ids": []string{string(f.ID)},
	})
	a.mustJSON(rec, http.StatusCreated, &rpt)
	if rpt.Summary.TotalFindings != 1 {
		t.Fatalf("summary = %+v", rpt.Summary)
	}
}

func TestCreateReportUnknownFindingID(t *testing.T) {
	a := newAPI(t, nil)
	scanID := createTestScan(t, a)
	seedFinding(t, a, scanID)

	rec := a.do("POST", "/api/scans/"+string(scanID)+"/reports", map[string]any{
		"format": "json", "finding_ids": []string{string(domain.NewID())},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
	}
}

func TestCreateReportInvalidFormat(t *testing.T) {
	a := newAPI(t, nil)
	scanID := createTestScan(t, a)

	rec := a.do("POST", "/api/scans/"+string(scanID)+"/reports", map[string]any{"format": "yaml"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
	}
}

func TestListReportsByScan(t *testing.T) {
	a := newAPI(t, nil)
	scanID := createTestScan(t, a)
	seedFinding(t, a, scanID)

	a.mustJSON(a.do("POST", "/api/scans/"+string(scanID)+"/reports", map[string]any{"format": "json"}), http.StatusCreated, nil)
	a.mustJSON(a.do("POST", "/api/scans/"+string(scanID)+"/reports", map[string]any{"format": "markdown"}), http.StatusCreated, nil)

	var list []domain.Report
	a.mustJSON(a.do("GET", "/api/scans/"+string(scanID)+"/reports", nil), http.StatusOK, &list)
	if len(list) != 2 {
		t.Fatalf("report list = %+v", list)
	}
}

func TestReportGenerationIsDeterministic(t *testing.T) {
	a := newAPI(t, nil)
	scanID := createTestScan(t, a)
	seedFinding(t, a, scanID)

	var r1, r2 domain.Report
	a.mustJSON(a.do("POST", "/api/scans/"+string(scanID)+"/reports", map[string]any{"format": "markdown"}), http.StatusCreated, &r1)
	a.mustJSON(a.do("POST", "/api/scans/"+string(scanID)+"/reports", map[string]any{"format": "markdown"}), http.StatusCreated, &r2)

	c1 := a.do("GET", "/api/reports/"+string(r1.ID)+"/content", nil)
	c2 := a.do("GET", "/api/reports/"+string(r2.ID)+"/content", nil)
	if c1.Body.String() != c2.Body.String() {
		t.Fatalf("two reports over the same findings produced different content:\n%s\n---\n%s", c1.Body.String(), c2.Body.String())
	}
}

// TestInternalErrorDoesNotLeakDetailToClient proves a genuine internal
// failure (here: report storage) is logged server-side but never exposes its
// raw detail — which can include local filesystem paths — in the API
// response. The fault is injected by making reportsDir a path that cannot be
// mkdir'd into (a regular file sits where a directory is needed).
func TestInternalErrorDoesNotLeakDetailToClient(t *testing.T) {
	dir := t.TempDir()
	reportsDir := filepath.Join(dir, "reports")
	if err := os.WriteFile(reportsDir, []byte("not a directory"), 0o640); err != nil {
		t.Fatal(err)
	}

	st := memory.New()
	q := queue.NewMemory()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctrl := scan.NewController(st, q, log, "test", scan.Options{})
	t.Cleanup(ctrl.Shutdown)
	evStore, err := evidence.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h := web.NewServer(st, ctrl, "test", log, evStore, reportsDir).Handler()
	a := api{t: t, h: h, st: st, ev: evStore}

	scanID := createTestScan(t, a)
	seedFinding(t, a, scanID)

	rec := a.do("POST", "/api/scans/"+string(scanID)+"/reports", map[string]any{"format": "json"})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, reportsDir) || strings.Contains(body, dir) {
		t.Fatalf("response leaked the local filesystem path: %s", body)
	}
	if strings.Contains(strings.ToLower(body), "not a directory") {
		t.Fatalf("response leaked the raw OS error text: %s", body)
	}
	if !strings.Contains(body, "store report failed") {
		t.Fatalf("response should carry the generic error message: %s", body)
	}
}

// seedVerdictFinding stores a minimal finding with the given verdict.
func seedVerdictFinding(t *testing.T, a api, scanID domain.ID, v domain.Verdict, title string, at time.Time) *domain.Finding {
	t.Helper()
	f := &domain.Finding{ID: domain.NewID(), ScanID: scanID, VulnClass: domain.VulnReflectedXSS, Verdict: v,
		Severity: domain.SeverityHigh, Confidence: domain.ConfidenceMedium, Title: title, CreatedAt: at, UpdatedAt: at}
	if err := a.st.Findings().Create(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	return f
}

type reportPreview struct {
	TotalFindings  int            `json:"total_findings"`
	ConfirmedCount int            `json:"confirmed_count"`
	ByVerdict      map[string]int `json:"by_verdict"`
	Selection      string         `json:"selection"`
	ScanFindings   int            `json:"scan_findings"`
}

// Explicit selection modes: All Findings, Confirmed Only, Selected Findings.
// The preview reports exactly what generate will include, and the persisted
// report summary carries the same counts, verdict breakdown, and mode.
func TestReportSelectionModes(t *testing.T) {
	a := newAPI(t, nil)
	scanID := createTestScan(t, a)
	base := time.Now()
	c1 := seedVerdictFinding(t, a, scanID, domain.VerdictConfirmed, "c1", base)
	seedVerdictFinding(t, a, scanID, domain.VerdictConfirmed, "c2", base.Add(time.Second))
	r1 := seedVerdictFinding(t, a, scanID, domain.VerdictRejected, "r1", base.Add(2*time.Second))
	seedVerdictFinding(t, a, scanID, domain.VerdictPending, "p1", base.Add(3*time.Second))

	cases := []struct {
		name      string
		mode      string
		ids       []string
		total     int
		confirmed int
		byVerdict map[string]int
	}{
		{"all", "all", nil, 4, 2, map[string]int{"confirmed": 2, "rejected": 1, "pending": 1}},
		{"confirmed", "confirmed", nil, 2, 2, map[string]int{"confirmed": 2}},
		{"selected", "selected", []string{string(c1.ID), string(r1.ID)}, 2, 1, map[string]int{"confirmed": 1, "rejected": 1}},
	}
	for _, tc := range cases {
		q := "?mode=" + tc.mode
		for _, id := range tc.ids {
			q += "&finding_id=" + id
		}
		var pv reportPreview
		a.mustJSON(a.do("GET", "/api/scans/"+string(scanID)+"/reports/preview"+q, nil), http.StatusOK, &pv)
		check := func(where string, got reportPreview) {
			t.Helper()
			if got.TotalFindings != tc.total || got.ConfirmedCount != tc.confirmed || got.Selection != tc.mode || got.ScanFindings != 4 {
				t.Fatalf("%s/%s: %+v", tc.name, where, got)
			}
			if len(got.ByVerdict) != len(tc.byVerdict) {
				t.Fatalf("%s/%s: by_verdict = %v, want %v", tc.name, where, got.ByVerdict, tc.byVerdict)
			}
			for k, v := range tc.byVerdict {
				if got.ByVerdict[k] != v {
					t.Fatalf("%s/%s: by_verdict = %v, want %v", tc.name, where, got.ByVerdict, tc.byVerdict)
				}
			}
		}
		check("preview", pv)

		var rpt struct {
			ID      domain.ID     `json:"id"`
			Summary reportPreview `json:"summary"`
		}
		a.mustJSON(a.do("POST", "/api/scans/"+string(scanID)+"/reports", map[string]any{"format": "markdown", "mode": tc.mode, "finding_ids": tc.ids}), http.StatusCreated, &rpt)
		check("generated", rpt.Summary)

		body := a.do("GET", "/api/reports/"+string(rpt.ID)+"/content", nil).Body.String()
		if !strings.Contains(body, "**Selection:**") || !strings.Contains(body, fmt.Sprintf("(%d of 4 findings in the scan)", tc.total)) {
			t.Fatalf("%s: report does not state its own selection:\n%s", tc.name, body)
		}
	}
}

// Confirmed Only filters on the STORED verdict; with none confirmed it yields
// an honest, empty report rather than inventing or upgrading anything.
func TestReportConfirmedOnlyWithNoneConfirmed(t *testing.T) {
	a := newAPI(t, nil)
	scanID := createTestScan(t, a)
	seedVerdictFinding(t, a, scanID, domain.VerdictRejected, "r", time.Now())
	var pv reportPreview
	a.mustJSON(a.do("GET", "/api/scans/"+string(scanID)+"/reports/preview?mode=confirmed", nil), http.StatusOK, &pv)
	if pv.TotalFindings != 0 || pv.ScanFindings != 1 {
		t.Fatalf("preview = %+v", pv)
	}
}

func TestReportSelectionValidation(t *testing.T) {
	a := newAPI(t, nil)
	scanID := createTestScan(t, a)
	f := seedVerdictFinding(t, a, scanID, domain.VerdictConfirmed, "c", time.Now())
	for _, body := range []map[string]any{
		{"format": "json", "mode": "selected"},                                         // selected with no ids
		{"format": "json", "mode": "confirmed", "finding_ids": []string{string(f.ID)}}, // ids ignored by mode
		{"format": "json", "mode": "all", "finding_ids": []string{string(f.ID)}},
		{"format": "json", "mode": "bogus"},
	} {
		if rec := a.do("POST", "/api/scans/"+string(scanID)+"/reports", body); rec.Code != http.StatusBadRequest {
			t.Fatalf("%v: status = %d, want 400: %s", body, rec.Code, rec.Body.String())
		}
	}
	if rec := a.do("GET", "/api/scans/"+string(scanID)+"/reports/preview?mode=selected", nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("preview selected-without-ids: status = %d, want 400", rec.Code)
	}
}

// Same mode over the same findings is byte-identical across all formats,
// regardless of the order the IDs were selected in.
func TestReportSelectionDeterministic(t *testing.T) {
	a := newAPI(t, nil)
	scanID := createTestScan(t, a)
	base := time.Now()
	f1 := seedVerdictFinding(t, a, scanID, domain.VerdictConfirmed, "a", base)
	f2 := seedVerdictFinding(t, a, scanID, domain.VerdictRejected, "b", base.Add(time.Second))
	strip := func(s string) string {
		// GeneratedAt differs per generation by design; compare the rest.
		var out []string
		for _, line := range strings.Split(s, "\n") {
			if !strings.Contains(line, "enerated") {
				out = append(out, line)
			}
		}
		return strings.Join(out, "\n")
	}
	for _, format := range []string{"json", "markdown", "html"} {
		var r1, r2 struct {
			ID domain.ID `json:"id"`
		}
		a.mustJSON(a.do("POST", "/api/scans/"+string(scanID)+"/reports", map[string]any{"format": format, "mode": "selected", "finding_ids": []string{string(f1.ID), string(f2.ID)}}), http.StatusCreated, &r1)
		a.mustJSON(a.do("POST", "/api/scans/"+string(scanID)+"/reports", map[string]any{"format": format, "mode": "selected", "finding_ids": []string{string(f2.ID), string(f1.ID)}}), http.StatusCreated, &r2)
		b1 := strip(a.do("GET", "/api/reports/"+string(r1.ID)+"/content", nil).Body.String())
		b2 := strip(a.do("GET", "/api/reports/"+string(r2.ID)+"/content", nil).Body.String())
		if b1 != b2 {
			t.Fatalf("%s: output depends on selection order:\n%s\n---\n%s", format, b1, b2)
		}
	}
}
