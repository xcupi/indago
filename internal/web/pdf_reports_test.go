package web_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/evidence"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/scan"
	"github.com/indago/indago/internal/store/memory"
	"github.com/indago/indago/internal/web"
)

type stubPDFRenderer struct {
	doc   []byte
	calls int
	err   error
}

func (s *stubPDFRenderer) Render(_ context.Context, doc []byte) ([]byte, error) {
	s.calls++
	s.doc = doc
	if s.err != nil {
		return nil, s.err
	}
	return []byte("%PDF-1.7\nstub pdf body\n"), nil
}

type pdfAPI struct {
	api
	srv  *web.Server
	stub *stubPDFRenderer
}

// newPDFAPI builds a server with a stub PDF renderer so the HTTP contract can
// be tested without a Chromium on the test machine.
func newPDFAPI(t *testing.T, withRenderer bool) pdfAPI {
	t.Helper()
	st := memory.New()
	q := queue.NewMemory()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctrl := scan.NewController(st, q, log, "test", scan.Options{})
	t.Cleanup(ctrl.Shutdown)
	evStore, err := evidence.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv := web.NewServer(st, ctrl, "test", log, evStore, t.TempDir())
	stub := &stubPDFRenderer{}
	if withRenderer {
		srv.SetPDFRenderer(stub)
	}
	return pdfAPI{api: api{t: t, h: srv.Handler(), st: st, ev: evStore}, srv: srv, stub: stub}
}

func TestCreatePDFReportRendersTemplate(t *testing.T) {
	a := newPDFAPI(t, true)
	scanID := createTestScan(t, a.api)
	f, _, _ := seedFinding(t, a.api, scanID)

	var rpt domain.Report
	rec := a.do("POST", "/api/scans/"+string(scanID)+"/reports",
		map[string]any{"format": "pdf", "template": "bug_bounty"})
	a.mustJSON(rec, http.StatusCreated, &rpt)

	if rpt.Format != domain.ReportPDF {
		t.Fatalf("format = %q", rpt.Format)
	}
	if !strings.HasSuffix(rpt.Path, ".pdf") {
		t.Fatalf("stored path = %q, want .pdf", rpt.Path)
	}
	if a.stub.calls != 1 {
		t.Fatalf("renderer calls = %d, want 1", a.stub.calls)
	}
	doc := string(a.stub.doc)
	for _, want := range []string{"Bug Bounty Report", "Steps to reproduce", f.Title, "CWE-79"} {
		if !strings.Contains(doc, want) {
			t.Fatalf("rendered HTML missing %q", want)
		}
	}

	content := a.do("GET", "/api/reports/"+string(rpt.ID)+"/content", nil)
	if content.Code != http.StatusOK {
		t.Fatalf("content status = %d: %s", content.Code, content.Body.String())
	}
	if ct := content.Header().Get("Content-Type"); ct != "application/pdf" {
		t.Fatalf("content-type = %q", ct)
	}
	if !strings.HasPrefix(content.Body.String(), "%PDF") {
		t.Fatalf("body is not a PDF: %q", content.Body.String())
	}
}

func TestPDFDefaultsToPentestTemplate(t *testing.T) {
	a := newPDFAPI(t, true)
	scanID := createTestScan(t, a.api)
	seedFinding(t, a.api, scanID)

	rec := a.do("POST", "/api/scans/"+string(scanID)+"/reports", map[string]any{"format": "pdf"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	doc := string(a.stub.doc)
	if !strings.Contains(doc, "Penetration Test Report") || !strings.Contains(doc, "Statement of Confidentiality") {
		t.Fatalf("default pdf template is not the pentest layout: %.200s", doc)
	}
}

func TestPDFWithoutRendererIsUnavailable(t *testing.T) {
	a := newPDFAPI(t, false)
	scanID := createTestScan(t, a.api)
	seedFinding(t, a.api, scanID)

	rec := a.do("POST", "/api/scans/"+string(scanID)+"/reports", map[string]any{"format": "pdf"})
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "chromium") && !strings.Contains(rec.Body.String(), "Chromium") {
		t.Fatalf("error should name the missing dependency: %s", rec.Body.String())
	}
}

func TestUnknownTemplateRejected(t *testing.T) {
	a := newPDFAPI(t, true)
	scanID := createTestScan(t, a.api)
	seedFinding(t, a.api, scanID)

	rec := a.do("POST", "/api/scans/"+string(scanID)+"/reports",
		map[string]any{"format": "html", "template": "fancy"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "unknown template") {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

func TestPDFRenderFailureIsReported(t *testing.T) {
	a := newPDFAPI(t, true)
	a.stub.err = errors.New("chromium: boom")
	scanID := createTestScan(t, a.api)
	seedFinding(t, a.api, scanID)

	rec := a.do("POST", "/api/scans/"+string(scanID)+"/reports", map[string]any{"format": "pdf"})
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "pdf export failed") {
		t.Fatalf("body = %s", rec.Body.String())
	}
}
