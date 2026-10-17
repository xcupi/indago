package main

// CLI integration test for `indago finding poc` — exercises the real HTTP
// path (CLI -> GET /api/scans/{id}/findings/{fid}/poc -> scan.GeneratePoC),
// not just the Go function in isolation. Confirms the server-side refusal
// (HTTP 409) surfaces as a CLI error for a non-Confirmed finding, and that a
// Confirmed finding's PoC is written to -out with a meaningful, non-empty
// artifact.

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/evidence"
	"github.com/indago/indago/internal/store"
)

// seedConfirmedFinding is seedScanWithFinding's Confirmed counterpart: a
// Query-location finding whose Detail carries one candidate and one
// confirming attempt — the minimal real shape GeneratePoC needs.
func seedConfirmedFinding(t *testing.T, c *cli, st store.Store, ev evidence.Store) (scanID, findingID domain.ID) {
	t.Helper()
	scanID, findingID = seedScanWithFinding(t, c, st, ev)

	ctx := context.Background()
	f, err := st.Findings().Get(ctx, findingID)
	if err != nil {
		t.Fatal(err)
	}
	marker := "INDAGOPOCMARKER"
	detail := `{"method":"GET","parameter_name":"q","dedup_key":"dk","occurrences":1,` +
		`"candidates":[{"source":"builtin","category":"html_text","context":"html_text","parameter":"q","location":"query",` +
		`"value":"<svg onload=` + marker + `>","dedup_key":"ck","rationale":"survives raw"}],` +
		`"attempts":[{"candidate_value":"<svg onload=` + marker + `>","candidate_dedup_key":"ck",` +
		`"verdict":"confirmed","confidence":"high","notes":"execution verified","at":"2024-01-01T00:00:00Z"}]}`
	f.Verdict = domain.VerdictConfirmed
	f.Confidence = domain.ConfidenceHigh
	f.Detail = []byte(detail)
	f.UpdatedAt = time.Now()
	if err := st.Findings().Update(ctx, f); err != nil {
		t.Fatal(err)
	}
	return scanID, findingID
}

func TestCLIFindingPoCConfirmedWritesStandaloneHTML(t *testing.T) {
	c, _, st, ev := newTestServerAndStore(t)
	scanID, findingID := seedConfirmedFinding(t, c, st, ev)

	dir := t.TempDir()
	path := dir + "/poc.html"
	var out strings.Builder
	cc := newCLI(c.server, &out)
	if err := cc.runClient("finding", []string{"poc", "-scan", string(scanID), "-out", path, string(findingID)}); err != nil {
		t.Fatalf("finding poc: %v", err)
	}
	if !strings.Contains(out.String(), "wrote standalone PoC to "+path) {
		t.Fatalf("cli output: %q", out.String())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read generated PoC: %v", err)
	}
	html := string(data)
	for _, want := range []string{"<!doctype html>", "INDAGOPOCMARKER", "curl", "Confirmed"} {
		if !strings.Contains(html, want) {
			t.Fatalf("generated PoC missing %q:\n%s", want, html)
		}
	}
	// A plain GET/query finding must be a true one-click artifact.
	if !strings.Contains(html, `http-equiv="refresh"`) {
		t.Fatalf("expected a one-click auto-navigating PoC for a Query-location finding:\n%s", html)
	}
}

func TestCLIFindingPoCAuthenticatedArtifactUsesCookieJarPlaceholder(t *testing.T) {
	c, _, st, ev := newTestServerAndStore(t)
	scanID, findingID := seedConfirmedFinding(t, c, st, ev)
	statePath := t.TempDir() + "/storage-state.json"
	secret := "cli-test-session-cookie-not-real"
	if err := os.WriteFile(statePath, []byte(`{"cookies":[{"name":"sid","value":"`+secret+`"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	scan, err := st.Scans().Get(context.Background(), scanID)
	if err != nil {
		t.Fatal(err)
	}
	sessionID := domain.NewID()
	scan.SessionID = sessionID
	if err := st.Scans().Update(context.Background(), scan); err != nil {
		t.Fatal(err)
	}
	if err := st.Sessions().Create(context.Background(), &domain.Session{
		ID: sessionID, ScanID: scanID, Mode: domain.AuthExisting,
		State: domain.SessionActive, StatePath: statePath, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	storedSession, err := st.Sessions().Get(context.Background(), sessionID)
	if err != nil || storedSession.Mode != domain.AuthExisting || storedSession.ScanID != scanID {
		t.Fatalf("session metadata lookup failed: mode=%q scan_matches=%t err=%v", storedSession.Mode, storedSession.ScanID == scanID, err)
	}

	path := t.TempDir() + "/poc.html"
	var out strings.Builder
	cc := newCLI(c.server, &out)
	if err := cc.runClient("finding", []string{"poc", "-scan", string(scanID), "-out", path, string(findingID)}); err != nil {
		t.Fatalf("finding poc: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read generated PoC: %v", err)
	}
	html := string(data)
	for _, want := range []string{"own authorized authenticated session", "session cookies are not embedded", "-b", "INDAGO_COOKIE_JAR", "INDAGOPOCMARKER"} {
		if !strings.Contains(html, want) {
			t.Fatalf("CLI PoC missing %q", want)
		}
	}
	for _, forbidden := range []string{secret, statePath, `http-equiv="refresh"`} {
		if strings.Contains(html, forbidden) {
			t.Fatal("CLI PoC exposed session material or claimed one-click navigation")
		}
	}
}

// A non-Confirmed finding must be refused (server returns 409) — the CLI
// surfaces that as an error, never writing a fabricated PoC file.
func TestCLIFindingPoCRefusesNonConfirmed(t *testing.T) {
	c, _, st, ev := newTestServerAndStore(t)
	scanID, findingID := seedScanWithFinding(t, c, st, ev) // seeded as Pending

	dir := t.TempDir()
	path := dir + "/poc.html"
	var out strings.Builder
	cc := newCLI(c.server, &out)
	err := cc.runClient("finding", []string{"poc", "-scan", string(scanID), "-out", path, string(findingID)})
	if err == nil {
		t.Fatal("expected an error generating a PoC for a Pending finding")
	}
	if !strings.Contains(err.Error(), "Confirmed") {
		t.Fatalf("error = %v, want it to explain the Confirmed-only requirement", err)
	}
	if _, statErr := os.Stat(path); statErr == nil {
		t.Fatal("no PoC file should have been written for a refused request")
	}
}
