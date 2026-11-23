package web_test

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
)

type scanTechResp struct {
	ScanID            domain.ID `json:"scan_id"`
	EndpointsAnalyzed int       `json:"endpoints_analyzed"`
	Technologies      []struct {
		Name       string   `json:"name"`
		Category   string   `json:"category"`
		Confidence string   `json:"confidence"`
		Count      int      `json:"count"`
		Sources    []string `json:"sources"`
		Examples   []string `json:"examples"`
	} `json:"technologies"`
	Languages    []string       `json:"languages"`
	Frameworks   []string       `json:"frameworks"`
	Templates    []string       `json:"templates"`
	Servers      []string       `json:"servers"`
	PoweredBy    []string       `json:"powered_by"`
	WAFVendors   []string       `json:"waf_vendors"`
	ContentKinds map[string]int `json:"content_kinds"`
}

func TestScanTechUnknownScan(t *testing.T) {
	a := newAPI(t, nil)
	rec := a.do("GET", "/api/scans/"+string(domain.NewID())+"/tech", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestScanTechEmptyScan(t *testing.T) {
	a := newAPI(t, nil)
	scanID := createTestScan(t, a)

	var got scanTechResp
	a.mustJSON(a.do("GET", "/api/scans/"+string(scanID)+"/tech", nil), http.StatusOK, &got)

	if got.ScanID != scanID {
		t.Fatalf("scan_id = %q, want %q", got.ScanID, scanID)
	}
	if got.EndpointsAnalyzed != 0 {
		t.Fatalf("endpoints_analyzed = %d, want 0", got.EndpointsAnalyzed)
	}
	if len(got.Technologies) != 0 || len(got.Languages) != 0 || len(got.Frameworks) != 0 || len(got.Templates) != 0 || len(got.Servers) != 0 {
		t.Fatalf("expected empty tech summary, got %+v", got)
	}
}

func TestScanTechDetectsStackAndRedactsSecrets(t *testing.T) {
	a := newAPI(t, nil)
	scanID := createTestScan(t, a)
	ctx := context.Background()
	now := time.Now()

	// 1. PHP + nginx response linked via TestCase with sensitive query/userinfo in URL
	//    and a Set-Cookie value that must never leak.
	phpRaw := "HTTP/1.1 200 OK\r\n" +
		"Server: nginx/1.24.0\r\n" +
		"X-Powered-By: PHP/8.2.1\r\n" +
		"Set-Cookie: PHPSESSID=super-secret-session-value; HttpOnly\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"\r\n" +
		"<html><body>Hello from PHP</body></html>"
	phpRef, err := a.ev.Put(scanID, domain.EvidenceResponse, ".http", []byte(phpRaw))
	if err != nil {
		t.Fatal(err)
	}
	phpEv := &domain.Evidence{
		ID:        domain.NewID(),
		ScanID:    scanID,
		Kind:      domain.EvidenceResponse,
		MediaType: "message/http",
		BlobPath:  phpRef.BlobPath,
		Size:      phpRef.Size,
		SHA256:    phpRef.SHA256,
		CreatedAt: now,
	}
	if err := a.st.Evidence().Create(ctx, phpEv); err != nil {
		t.Fatal(err)
	}
	tc1 := &domain.TestCase{
		ID:          domain.NewID(),
		ScanID:      scanID,
		JobID:       domain.NewID(),
		Status:      domain.TestCaseCompleted,
		URL:         "http://admin:topsecretpass@example.test/index.php?api_key=secret12345",
		EvidenceIDs: []domain.ID{phpEv.ID},
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := a.st.TestCases().Create(ctx, tc1); err != nil {
		t.Fatal(err)
	}

	// 2. Next.js + Cloudflare response linked via Note URL.
	nextRaw := "HTTP/1.1 200 OK\r\n" +
		"CF-Ray: 8a1b2c3d4e5f-SIN\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"\r\n" +
		`<!doctype html><html><head></head><body><div id="__next"></div><script id="__NEXT_DATA__" type="application/json">{}</script></body></html>`
	nextRef, err := a.ev.Put(scanID, domain.EvidenceResponse, ".http", []byte(nextRaw))
	if err != nil {
		t.Fatal(err)
	}
	nextEv := &domain.Evidence{
		ID:        domain.NewID(),
		ScanID:    scanID,
		Kind:      domain.EvidenceResponse,
		MediaType: "message/http",
		BlobPath:  nextRef.BlobPath,
		Size:      nextRef.Size,
		SHA256:    nextRef.SHA256,
		Note:      "baseline GET http://example.test/app response",
		CreatedAt: now,
	}
	if err := a.st.Evidence().Create(ctx, nextEv); err != nil {
		t.Fatal(err)
	}

	rec := a.do("GET", "/api/scans/"+string(scanID)+"/tech", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	bodyStr := rec.Body.String()
	for _, secret := range []string{"super-secret-session-value", "secret12345", "topsecretpass"} {
		if strings.Contains(bodyStr, secret) {
			t.Fatalf("response leaked secret %q: %s", secret, bodyStr)
		}
	}

	var got scanTechResp
	a.mustJSON(rec, http.StatusOK, &got)

	if got.EndpointsAnalyzed != 2 {
		t.Fatalf("endpoints_analyzed = %d, want 2", got.EndpointsAnalyzed)
	}
	if !slices.Contains(got.Languages, "php") || !slices.Contains(got.Languages, "node") {
		t.Fatalf("languages = %v, want php and node", got.Languages)
	}
	if !slices.Contains(got.Frameworks, "nextjs") {
		t.Fatalf("frameworks = %v, want nextjs", got.Frameworks)
	}
	if !slices.Contains(got.Servers, "nginx/1.24.0") {
		t.Fatalf("servers = %v, want nginx/1.24.0", got.Servers)
	}
	if !slices.Contains(got.PoweredBy, "PHP/8.2.1") {
		t.Fatalf("powered_by = %v, want PHP/8.2.1", got.PoweredBy)
	}
	if !slices.Contains(got.WAFVendors, "cloudflare") {
		t.Fatalf("waf_vendors = %v, want cloudflare", got.WAFVendors)
	}
	if got.ContentKinds["html"] != 2 {
		t.Fatalf("content_kinds[html] = %d, want 2", got.ContentKinds["html"])
	}
	if len(got.Technologies) == 0 {
		t.Fatalf("expected non-empty technologies list")
	}
}
