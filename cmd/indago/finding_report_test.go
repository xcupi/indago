package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/evidence"
	"github.com/indago/indago/internal/store"
)

// seedScanWithFinding creates a project/scope/target/scan through the CLI
// (exercising the same API path every other CLI test does), then seeds one
// finding (with endpoint, parameter, and evidence) directly in the store.
// Detection/verification are out of scope for this phase: it exposes
// already-correlated data over HTTP/CLI, it does not generate it.
func seedScanWithFinding(t *testing.T, c *cli, st store.Store, ev evidence.Store) (scanID, findingID domain.ID) {
	t.Helper()
	site := targetSite(t)

	must := func(group string, args ...string) string {
		t.Helper()
		var b strings.Builder
		cc := newCLI(c.server, &b)
		if err := cc.runClient(group, args); err != nil {
			t.Fatalf("indago %s %v: %v", group, args, err)
		}
		return b.String()
	}

	projOut := must("project", "create", "Acme")
	project := idFromString(t, projOut)
	must("scope", "set", "-project", project, "-include", "127.0.0.1")
	tgtOut := must("target", "add", "-project", project, "-name", "site", "-url", site.URL)
	target := idFromString(t, tgtOut)
	scOut := must("scan", "create", "-project", project, "-target", target)
	scanID = domain.ID(idFromString(t, scOut))

	ctx := context.Background()
	now := time.Now()
	ep := &domain.Endpoint{ID: domain.NewID(), ScanID: scanID, URL: site.URL + "/search", Method: domain.MethodGET, Source: domain.SourceCrawler, CreatedAt: now}
	if err := st.Endpoints().Create(ctx, ep); err != nil {
		t.Fatal(err)
	}
	param := &domain.Parameter{ID: domain.NewID(), ScanID: scanID, EndpointID: ep.ID, Name: "q", Location: domain.LocationQuery, Source: domain.SourceCrawler, CreatedAt: now}
	if err := st.Parameters().Create(ctx, param); err != nil {
		t.Fatal(err)
	}
	detail := `{"method":"GET","parameter_name":"q","occurrences":1,"candidates":[{"category":"html_text","context":"html_text","value":"<mark>","rationale":"survives raw"}]}`
	f := &domain.Finding{
		ID: domain.NewID(), ScanID: scanID, ProjectID: domain.ID(project), VulnClass: domain.VulnReflectedXSS,
		Verdict: domain.VerdictPending, Severity: domain.SeverityHigh, Confidence: domain.ConfidenceMedium,
		Title: "Reflected XSS candidate", EndpointID: ep.ID, ParameterID: param.ID, Location: domain.LocationQuery,
		Provenance: domain.Provenance{Engine: "reflected_xss", DiscoverySource: domain.SourceCrawler, DetectedAt: now},
		Detail:     []byte(detail), CreatedAt: now, UpdatedAt: now,
	}
	if err := st.Findings().Create(ctx, f); err != nil {
		t.Fatal(err)
	}
	ref, err := ev.Put(scanID, domain.EvidenceResponse, ".html", []byte("captured response"))
	if err != nil {
		t.Fatal(err)
	}
	evRow := &domain.Evidence{ID: domain.NewID(), ScanID: scanID, FindingID: f.ID, Kind: domain.EvidenceResponse, MediaType: "text/html", BlobPath: ref.BlobPath, Size: ref.Size, SHA256: ref.SHA256, CreatedAt: now}
	if err := st.Evidence().Create(ctx, evRow); err != nil {
		t.Fatal(err)
	}
	f.EvidenceIDs = []domain.ID{evRow.ID}
	if err := st.Findings().Update(ctx, f); err != nil {
		t.Fatal(err)
	}
	return scanID, f.ID
}

// idFromString extracts the first UUID from s (idFrom's logic, over a plain
// string instead of the shared *bytes.Buffer CLI tests usually capture into).
func idFromString(t *testing.T, s string) string {
	t.Helper()
	id := uuidRe.FindString(s)
	if id == "" {
		t.Fatalf("no ID in output: %q", s)
	}
	return id
}

func TestCLIFindingListAndShow(t *testing.T) {
	c, _, st, ev := newTestServerAndStore(t)
	scanID, findingID := seedScanWithFinding(t, c, st, ev)

	var out strings.Builder
	cList := newCLI(c.server, &out)
	if err := cList.runClient("finding", []string{"list", "-scan", string(scanID)}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), string(findingID)) || !strings.Contains(out.String(), "Reflected XSS candidate") {
		t.Fatalf("finding list output: %q", out.String())
	}

	out.Reset()
	if err := cList.runClient("finding", []string{"show", "-scan", string(scanID), string(findingID)[:8]}); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	for _, want := range []string{
		string(findingID), "Verdict    pending", "GET " /* endpoint method */, "q (query)", /* parameter */
		"html_text", "survives raw", "Evidence (1)", "open: " + c.server + "/api/evidence/",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("finding show output missing %q:\n%s", want, got)
		}
	}
}

func TestCLIFindingShowJSON(t *testing.T) {
	c, _, st, ev := newTestServerAndStore(t)
	scanID, findingID := seedScanWithFinding(t, c, st, ev)

	var out strings.Builder
	cc := newCLI(c.server, &out)
	if err := cc.runClient("finding", []string{"show", "-scan", string(scanID), string(findingID), "-json"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"id": "`+string(findingID)+`"`) {
		t.Fatalf("json output: %s", out.String())
	}
}

func TestCLIReportCreateListShow(t *testing.T) {
	c, _, st, ev := newTestServerAndStore(t)
	scanID, _ := seedScanWithFinding(t, c, st, ev)

	var createOut strings.Builder
	cc := newCLI(c.server, &createOut)
	if err := cc.runClient("report", []string{"create", "-scan", string(scanID), "-format", "markdown"}); err != nil {
		t.Fatal(err)
	}
	reportID := idFromString(t, createOut.String())
	if !strings.Contains(createOut.String(), "1 finding(s)") {
		t.Fatalf("report create output: %q", createOut.String())
	}

	var listOut strings.Builder
	cl := newCLI(c.server, &listOut)
	if err := cl.runClient("report", []string{"list", "-scan", string(scanID)}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(listOut.String(), reportID) {
		t.Fatalf("report list output: %q", listOut.String())
	}

	var showOut strings.Builder
	cs := newCLI(c.server, &showOut)
	if err := cs.runClient("report", []string{"show", reportID}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(showOut.String(), "# Indago Scan Report") {
		t.Fatalf("report show output: %q", showOut.String())
	}
}

func TestCLIReportCreateWithOutFile(t *testing.T) {
	c, _, st, ev := newTestServerAndStore(t)
	scanID, _ := seedScanWithFinding(t, c, st, ev)

	dir := t.TempDir()
	path := dir + "/report.json"
	var out strings.Builder
	cc := newCLI(c.server, &out)
	if err := cc.runClient("report", []string{"create", "-scan", string(scanID), "-format", "json", "-out", path}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "wrote report to "+path) {
		t.Fatalf("output: %q", out.String())
	}
}
