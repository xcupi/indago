package main

// End-to-end: a generated report must carry the finding's CWE/CVSS baseline and
// a runnable curl PoC reproduced from the stored request, with the credential
// values turned into shell variables. This exercises the real server path
// (evidence blobs read server-side → report.Data.RequestEvidence → generator),
// not just the generator in isolation.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
)

// storedRequestWithSecrets is the message/http evidence an executor writes: the
// exact request line plus the auth headers that were sent.
const storedRequestWithSecrets = "GET /search?q=%3Csvg%20onload%3Dindago123%3E HTTP/1.1\r\n" +
	"Host: 127.0.0.1\r\n" +
	"User-Agent: indago/0\r\n" +
	"Cookie: session=REPORT-SECRET-COOKIE\r\n" +
	"Authorization: Bearer REPORT-SECRET-TOKEN\r\n" +
	"Accept: */*\r\n\r\n"

// addRequestEvidence stores a request blob for the finding and links it, the way
// a real candidate execution does.
func TestCLIReportRendersClassificationAndRedactedCurlPoC(t *testing.T) {
	c, _, st, ev := newTestServerAndStore(t)
	scanID, findingID := seedScanWithFinding(t, c, st, ev)
	ctx := context.Background()

	ref, err := ev.Put(scanID, domain.EvidenceRequest, ".http", []byte(storedRequestWithSecrets))
	if err != nil {
		t.Fatal(err)
	}
	row := &domain.Evidence{
		ID: domain.NewID(), ScanID: scanID, FindingID: findingID, Kind: domain.EvidenceRequest,
		MediaType: "message/http", BlobPath: ref.BlobPath, Size: ref.Size, SHA256: ref.SHA256,
		Note: "test_case=cand1 request", CreatedAt: time.Now(),
	}
	if err := st.Evidence().Create(ctx, row); err != nil {
		t.Fatal(err)
	}
	f, err := st.Findings().Get(ctx, findingID)
	if err != nil {
		t.Fatal(err)
	}
	f.EvidenceIDs = append(f.EvidenceIDs, row.ID)
	if err := st.Findings().Update(ctx, f); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	mdPath := filepath.Join(dir, "report.md")
	var out strings.Builder
	cc := newCLI(c.server, &out)
	if err := cc.runClient("report", []string{"create", "-scan", string(scanID), "-format", "markdown", "-out", mdPath}); err != nil {
		t.Fatalf("report create: %v", err)
	}
	raw, err := os.ReadFile(mdPath)
	if err != nil {
		t.Fatal(err)
	}
	md := string(raw)
	for _, want := range []string{
		"CWE-79",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
		"6.1 medium",
		"**Reproducible curl PoC**",
		"`" + string(row.ID) + "`",
		`-b "$INDAGO_COOKIE"`,
		`-H "Authorization: Bearer $INDAGO_TOKEN"`,
	} {
		if !strings.Contains(md, want) {
			t.Fatalf("markdown report missing %q:\n%s", want, md)
		}
	}
	// The whole point of the default: the secrets never reach the document.
	for _, leak := range []string{"REPORT-SECRET-COOKIE", "REPORT-SECRET-TOKEN"} {
		if strings.Contains(md, leak) {
			t.Fatalf("the markdown report leaked %q:\n%s", leak, md)
		}
	}

	jsonPath := filepath.Join(dir, "report.json")
	out.Reset()
	if err := cc.runClient("report", []string{"create", "-scan", string(scanID), "-format", "json", "-out", jsonPath}); err != nil {
		t.Fatalf("report create json: %v", err)
	}
	rawJSON, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	js := string(rawJSON)
	for _, want := range []string{`"classification"`, `"cwe"`, `"base_score": 6.1`, `"curl_poc"`, `INDAGO_COOKIE`} {
		if !strings.Contains(js, want) {
			t.Fatalf("json report missing %q:\n%s", want, js)
		}
	}
	for _, leak := range []string{"REPORT-SECRET-COOKIE", "REPORT-SECRET-TOKEN"} {
		if strings.Contains(js, leak) {
			t.Fatalf("the json report leaked %q:\n%s", leak, js)
		}
	}
}
