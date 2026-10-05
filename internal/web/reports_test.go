package web_test

import (
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
