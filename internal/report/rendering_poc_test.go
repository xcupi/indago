package report_test

// Report rendering of the two "what a triager asks for" fields: the class-level
// CWE/CVSS v3.1 classification and a reproducible curl PoC built from the
// finding's own stored request evidence.
//
// The PoC tests pin the credential rule in the direction that matters: a report
// is a document people forward, so auth values must be shell variables and the
// literal secret must never appear in the rendered output — while the command
// still has to be runnable once the reader exports those variables.

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/report"
)

const (
	pocSecretToken  = "Bearer s3cr3t-token-value"
	pocSecretCookie = "session=SUPERSECRET-cookie-value"
)

// storedPocRequest is the message/http evidence an executor writes: an
// origin-form request line plus the headers that were actually sent.
const storedPocRequest = "GET /search?q=%3Csvg%20onload%3Dindago1234%3E HTTP/1.1\r\n" +
	"Host: shop.example.test\r\n" +
	"User-Agent: indago/0\r\n" +
	"Cookie: " + pocSecretCookie + "\r\n" +
	"Authorization: " + pocSecretToken + "\r\n" +
	"Accept: */*\r\n\r\n"

const storedPocBaselineRequest = "GET /search?q=hello HTTP/1.1\r\n" +
	"Host: shop.example.test\r\n" +
	"Cookie: " + pocSecretCookie + "\r\n\r\n"

// pocData is one confirmed reflected-XSS finding whose candidate request is
// stored, so the report can reproduce it.
func pocData(requests map[domain.ID][]byte) report.Data {
	d := verifiedData()
	d.RequestEvidence = requests
	// The confirmed finding's own evidence, role-labelled: the candidate
	// request is the one that carries the payload; the baseline is the
	// unmodified reference.
	d.Evidence = append(d.Evidence,
		&domain.Evidence{ID: "cand-req-baseline", ScanID: "scan1", Kind: domain.EvidenceRequest, MediaType: "message/http",
			Note: domain.EvidenceNoteBaselinePrefix + "GET http://shop.example.test/search?q=hello request", CreatedAt: t0},
	)
	confirmed := d.Findings[2]
	confirmed.EvidenceIDs = append(confirmed.EvidenceIDs, "cand-req-baseline")
	return d
}

func TestMarkdownReportRendersCWEAndCVSSBaseline(t *testing.T) {
	out := generate(t, domain.ReportMarkdown, pocData(nil))

	if !strings.Contains(out, "CWE-79") {
		t.Fatalf("markdown has no CWE id:\n%s", out)
	}
	for _, want := range []string{
		"CVSS v3.1 (class baseline):",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
		"6.1 medium",
		report.ClassificationNote,
		// A finding that was NOT confirmed must not present the baseline as a
		// confirmed score (same rule as SeverityLabel).
		"CVSS v3.1 (class baseline — this finding is NOT confirmed):",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("markdown missing %q:\n%s", want, out)
		}
	}
}

func TestJSONReportCarriesCWEAndCVSSBaseline(t *testing.T) {
	raw := generate(t, domain.ReportJSON, pocData(nil))

	var doc struct {
		Findings []struct {
			Title          string `json:"title"`
			Classification *struct {
				Class string `json:"class"`
				CWE   struct {
					ID   int    `json:"id"`
					Name string `json:"name"`
				} `json:"cwe"`
				CVSS struct {
					Vector    string  `json:"vector"`
					BaseScore float64 `json:"base_score"`
					Severity  string  `json:"severity"`
				} `json:"cvss"`
				Note string `json:"note"`
			} `json:"classification"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatalf("json report: %v", err)
	}
	if len(doc.Findings) == 0 {
		t.Fatal("json report has no findings")
	}
	got := doc.Findings[0].Classification
	if got == nil {
		t.Fatalf("the first (confirmed) finding carries no classification:\n%s", raw)
	}
	if got.Class != string(domain.VulnReflectedXSS) || got.CWE.ID != 79 {
		t.Fatalf("classification = %+v, want reflected_xss/CWE-79", got)
	}
	if got.CVSS.Vector != "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" || got.CVSS.BaseScore != 6.1 || got.CVSS.Severity != "medium" {
		t.Fatalf("cvss = %+v", got.CVSS)
	}
	if got.Note != report.ClassificationNote {
		t.Fatalf("classification must ship its caveat, got %q", got.Note)
	}
}

// A class the table does not know is reported as unclassified — never given an
// invented weakness or score.
func TestUnclassifiedClassRendersNoClassification(t *testing.T) {
	data := pocData(nil)
	data.Findings = []*domain.Finding{{
		ID: "f-x", ScanID: "scan1", VulnClass: domain.VulnClass("custom_unclassified_class"),
		Verdict: domain.VerdictConfirmed, Severity: domain.SeverityHigh, Title: "Unknown class finding",
		CreatedAt: t0,
	}}

	md := generate(t, domain.ReportMarkdown, data)
	if !strings.Contains(md, "not classified") {
		t.Fatalf("markdown must say the class is not classified:\n%s", md)
	}
	if strings.Contains(md, "CVSS:3.1/") {
		t.Fatalf("markdown invented a CVSS vector for an unclassified class:\n%s", md)
	}

	raw := generate(t, domain.ReportJSON, data)
	if strings.Contains(raw, `"classification"`) {
		t.Fatalf("json invented a classification:\n%s", raw)
	}
}

func TestMarkdownReproducibleCurlPoCRedactsCredentials(t *testing.T) {
	requests := map[domain.ID][]byte{"cand-req": []byte(storedPocRequest)}
	out := generate(t, domain.ReportMarkdown, pocData(requests))

	for _, want := range []string{
		"**Reproducible curl PoC**",
		"`cand-req`",
		"```sh\n",
		"curl -sS -i -X GET 'https://shop.example.test/search?q=%3Csvg%20onload%3Dindago1234%3E'",
		`-b "$INDAGO_COOKIE"`,
		`-H "Authorization: Bearer $INDAGO_TOKEN"`,
		"export them before running",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("markdown missing %q:\n%s", want, out)
		}
	}
	// The rule that matters: no literal secret reaches the document.
	for _, leak := range []string{"SUPERSECRET-cookie-value", "s3cr3t-token-value"} {
		if strings.Contains(out, leak) {
			t.Fatalf("the report leaked the credential literal %q:\n%s", leak, out)
		}
	}
}

func TestJSONReproducibleCurlPoCRedactsCredentials(t *testing.T) {
	requests := map[domain.ID][]byte{"cand-req": []byte(storedPocRequest)}
	raw := generate(t, domain.ReportJSON, pocData(requests))

	var doc struct {
		Findings []struct {
			CurlPoC *struct {
				EvidenceID string `json:"evidence_id"`
				Curl       string `json:"curl"`
				Note       string `json:"note"`
			} `json:"curl_poc"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatalf("json report: %v", err)
	}
	got := doc.Findings[0].CurlPoC
	if got == nil {
		t.Fatalf("no curl_poc on the confirmed finding:\n%s", raw)
	}
	if got.EvidenceID != "cand-req" {
		t.Fatalf("curl_poc.evidence_id = %q, want the candidate request", got.EvidenceID)
	}
	if !strings.Contains(got.Curl, "curl -sS -i") || !strings.Contains(got.Curl, `"$INDAGO_COOKIE"`) {
		t.Fatalf("curl_poc.curl = %q", got.Curl)
	}
	if !strings.Contains(got.Note, "shell variables") {
		t.Fatalf("curl_poc.note = %q", got.Note)
	}
	if strings.Contains(raw, "SUPERSECRET-cookie-value") || strings.Contains(raw, "s3cr3t-token-value") {
		t.Fatalf("the json report leaked a credential literal:\n%s", raw)
	}
}

// Without the caller supplying request blob content there is nothing to
// reproduce: the report says nothing rather than inventing a command.
func TestNoRequestEvidenceMeansNoPoC(t *testing.T) {
	md := generate(t, domain.ReportMarkdown, pocData(nil))
	if strings.Contains(md, "Reproducible curl PoC") || strings.Contains(md, "curl -sS") {
		t.Fatalf("markdown invented a PoC without request evidence:\n%s", md)
	}
	raw := generate(t, domain.ReportJSON, pocData(nil))
	if strings.Contains(raw, `"curl_poc"`) {
		t.Fatalf("json invented a PoC without request evidence:\n%s", raw)
	}
}

// Baseline evidence is the UNMODIFIED request: a command reproduced from it
// could not reproduce the finding, so it is never used as the PoC.
func TestBaselineRequestIsNotUsedAsPoC(t *testing.T) {
	requests := map[domain.ID][]byte{
		"cand-req-baseline": []byte(storedPocBaselineRequest),
	}
	md := generate(t, domain.ReportMarkdown, pocData(requests))
	if strings.Contains(md, "Reproducible curl PoC") {
		t.Fatalf("a baseline request must not be rendered as the PoC:\n%s", md)
	}
}

// An origin-form stored request has no scheme of its own; the finding's own
// recorded http:// URL decides it, so a plain-HTTP lab target gets a command
// that can actually connect.
func TestPoCUsesTheFindingsSchemeForOriginFormRequests(t *testing.T) {
	data := pocData(map[domain.ID][]byte{"cand-req": []byte(storedPocRequest)})
	// The verified attempt URL is what the verifier navigated to.
	detail := `{"method":"GET","parameter_name":"q","attempts":[
	  {"candidate_value":"<svg onload=indago1234>","url":"http://shop.example.test/search?q=x","verify_test_case_id":"vt9","verdict":"confirmed","evidence_ids":["cand-req"],"at":"2026-03-01T10:00:01Z"}]}`
	data.Findings = []*domain.Finding{{
		ID: "f-http", ScanID: "scan1", VulnClass: domain.VulnReflectedXSS,
		Verdict: domain.VerdictConfirmed, Severity: domain.SeverityHigh, Title: "confirmed",
		EvidenceIDs: []domain.ID{"cand-req"}, Detail: []byte(detail), CreatedAt: t0,
	}}

	md := generate(t, domain.ReportMarkdown, data)
	if !strings.Contains(md, "'http://shop.example.test/search?q=%3Csvg%20onload%3Dindago1234%3E'") {
		t.Fatalf("the PoC must use the finding's http scheme:\n%s", md)
	}
}

// Rendering is deterministic with request evidence in the input too: the PoC
// derivation must not depend on map iteration order.
func TestPoCRenderingIsDeterministic(t *testing.T) {
	data := pocData(map[domain.ID][]byte{
		"cand-req":          []byte(storedPocRequest),
		"cand-req-baseline": []byte(storedPocBaselineRequest),
	})
	gen, _ := report.For(domain.ReportMarkdown)
	var first bytes.Buffer
	if err := gen.Generate(&first, data); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		var buf bytes.Buffer
		if err := gen.Generate(&buf, data); err != nil {
			t.Fatal(err)
		}
		if buf.String() != first.String() {
			t.Fatalf("run %d differs from the first", i)
		}
	}
}

// The HTML layout shows the same classification and PoC, so the three formats
// cannot disagree about a finding's CWE/CVSS.
func TestHTMLReportRendersClassificationAndPoC(t *testing.T) {
	out := generate(t, domain.ReportHTML, pocData(map[domain.ID][]byte{"cand-req": []byte(storedPocRequest)}))
	for _, want := range []string{"CWE-79", "CVSS:3.1/", "6.1 medium", "Reproducible curl PoC", "$INDAGO_COOKIE"} {
		if !strings.Contains(out, want) {
			t.Fatalf("html missing %q", want)
		}
	}
	if strings.Contains(out, "SUPERSECRET-cookie-value") {
		t.Fatal("the html report leaked a credential literal")
	}
}
