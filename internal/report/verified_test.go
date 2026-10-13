package report_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/report"
)

const (
	payload   = `<svg onload=ind1234>`
	probeVal  = `<ind1234x>`
	baseValue = "hello"
)

var t0 = time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)

func ev(id string, kind domain.EvidenceKind, note string, at time.Duration) *domain.Evidence {
	mt := map[domain.EvidenceKind]string{domain.EvidenceScreenshot: "image/png", domain.EvidenceDOM: "text/html"}[kind]
	if mt == "" {
		mt = "message/http"
	}
	return &domain.Evidence{ID: domain.ID(id), ScanID: "scan1", Kind: kind, MediaType: mt, Size: 100, SHA256: "abcdef0123456789abcdef", Note: note, CreatedAt: t0.Add(at)}
}

// verifiedData is one scan with: a CONFIRMED finding (confirmed candidate + a
// rejected markup probe at the same location, evidence from the baseline, the
// candidate, and the browser), a REJECTED finding at another location, and a
// PENDING one.
func verifiedData() report.Data {
	attempts := `[
	  {"candidate_value":"` + probeVal + `","verify_test_case_id":"vt1","verdict":"rejected","evidence_ids":["base-req","base-resp","cand-req-probe"],"at":"2026-03-01T10:00:02Z"},
	  {"candidate_value":"` + payload + `","verify_test_case_id":"vt2","verdict":"confirmed","confidence":"high","notes":"uncaught ReferenceError named the marker","evidence_ids":["base-req","base-resp","cand-req","shot","dom"],"at":"2026-03-01T10:00:01Z"}
	]`
	confirmedDetail := `{"method":"GET","parameter_name":"q","occurrences":2,"candidates":[
	  {"source":"builtin","category":"html_text","context":"html_text","value":"` + payload + `","trigger":"load","rationale":"inject svg"},
	  {"source":"builtin","category":"html_text","context":"html_text","value":"` + probeVal + `","trigger":"none"}],
	  "attempts":` + attempts + `}`
	rejectedDetail := `{"method":"GET","parameter_name":"r","candidates":[{"context":"html_text","value":"` + payload + `"}],
	  "attempts":[{"candidate_value":"` + payload + `","verify_test_case_id":"vt3","verdict":"rejected","evidence_ids":["base-req"],"at":"2026-03-01T10:00:03Z"}]}`
	return report.Data{
		Project: domain.Project{ID: "p", Name: "Acme"}, Scan: domain.Scan{ID: "scan1", Name: "s"},
		GeneratedAt: t0, ToolVersion: "t",
		Findings: []*domain.Finding{
			{ID: "f-rej", ScanID: "scan1", VulnClass: domain.VulnReflectedXSS, Verdict: domain.VerdictRejected, Severity: domain.SeverityHigh,
				Title: `Reflected XSS candidate in parameter "r" (html_text) at GET /encoded?r`, EvidenceIDs: []domain.ID{"base-req"}, Detail: []byte(rejectedDetail), CreatedAt: t0.Add(-2 * time.Hour)},
			{ID: "f-pend", ScanID: "scan1", VulnClass: domain.VulnReflectedXSS, Verdict: domain.VerdictPending, Severity: domain.SeverityMedium,
				Title: `Reflected XSS candidate in parameter "z" (html_text) at POST /form?z`, CreatedAt: t0.Add(-time.Hour)},
			{ID: "f-conf", ScanID: "scan1", VulnClass: domain.VulnReflectedXSS, Verdict: domain.VerdictConfirmed, Severity: domain.SeverityHigh, Confidence: domain.ConfidenceHigh,
				Title: `Reflected XSS in parameter "q" (html_text) at GET /search?q`, Summary: "uncaught ReferenceError named the marker",
				EvidenceIDs: []domain.ID{"cand-req-probe", "base-resp", "dom", "base-req", "shot", "cand-req"}, Detail: []byte(confirmedDetail), CreatedAt: t0},
		},
		Evidence: []*domain.Evidence{
			ev("base-req", domain.EvidenceRequest, "baseline GET http://x/search?q=hello request", 0),
			ev("base-resp", domain.EvidenceResponse, "baseline GET http://x/search?q=hello response", 0),
			ev("cand-req", domain.EvidenceRequest, "test_case=c1 request", time.Second),
			ev("cand-req-probe", domain.EvidenceRequest, "test_case=c2 request", 2*time.Second),
			ev("shot", domain.EvidenceScreenshot, "test_case=vt2 screenshot", 3*time.Second),
			ev("dom", domain.EvidenceDOM, "test_case=vt2 rendered DOM", 3*time.Second),
		},
	}
}

func generate(t *testing.T, f domain.ReportFormat, d report.Data) string {
	t.Helper()
	gen, err := report.For(f)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := gen.Generate(&buf, d); err != nil {
		t.Fatalf("%s: %v", f, err)
	}
	return buf.String()
}

func indexOf(t *testing.T, s, sub string) int {
	t.Helper()
	i := strings.Index(s, sub)
	if i < 0 {
		t.Fatalf("missing %q in:\n%s", sub, s)
	}
	return i
}

// The report leads with confirmed vulnerabilities, shows the candidate whose
// browser verification succeeded and its evidence, and keeps the rejected
// attempt as a child diagnostic.
func TestMarkdownReportPrioritizesVerifiedCandidateAndEvidence(t *testing.T) {
	out := generate(t, domain.ReportMarkdown, verifiedData())

	confirmed := indexOf(t, out, "## Confirmed vulnerabilities")
	review := indexOf(t, out, "## Unconfirmed — needs review")
	diag := indexOf(t, out, "## Diagnostics — rejected attempts (not vulnerabilities)")
	if !(confirmed < review && review < diag) {
		t.Fatalf("sections out of order: %d %d %d", confirmed, review, diag)
	}
	verified := indexOf(t, out, "**Verified candidate**")
	if verified < confirmed || verified > review {
		t.Fatal("the verified candidate must be shown inside the confirmed section")
	}
	// The payload sits in a code fence directly under the Verified candidate label.
	if !strings.Contains(out[verified:review], "```\n"+payload+"\n```") {
		t.Fatalf("verified payload not in a code fence:\n%s", out[verified:review])
	}
	if !strings.Contains(out, "uncaught ReferenceError named the marker") {
		t.Fatal("the verification signal is missing")
	}
	// Evidence for the verified candidate: browser artifacts first, baseline last.
	evBlock := out[indexOf(t, out, "**Evidence for the verified candidate:**"):review]
	shot, dom := strings.Index(evBlock, "`shot`"), strings.Index(evBlock, "`dom`")
	creq, base := strings.Index(evBlock, "`cand-req`"), strings.Index(evBlock, "`base-req`")
	if shot < 0 || dom < 0 || creq < 0 || base < 0 || !(shot < creq && dom < creq && creq < base) {
		t.Fatalf("evidence not ordered browser → candidate → baseline:\n%s", evBlock)
	}
	// The rejected markup probe is an attempt, listed under "Other attempts".
	other := out[indexOf(t, out, "**Other attempts**"):review]
	if !strings.Contains(other, probeVal) || !strings.Contains(other, "rejected") {
		t.Fatalf("rejected attempt missing from the finding's attempts:\n%s", other)
	}
}

// A rejected finding is a diagnostic — not presented as a vulnerability.
func TestMarkdownReportDoesNotPresentRejectedAsVulnerability(t *testing.T) {
	out := generate(t, domain.ReportMarkdown, verifiedData())
	diag := indexOf(t, out, "## Diagnostics")
	rejectedTitle := indexOf(t, out, `parameter "r" (html_text) at GET /encoded?r`)
	if rejectedTitle < diag {
		t.Fatal("the rejected finding appears above the diagnostics heading")
	}
	if !strings.Contains(out[diag:], "not vulnerabilities") {
		t.Fatal("diagnostics must say they are not vulnerabilities")
	}
	if strings.Contains(out[:diag], "/encoded?r") {
		t.Fatal("a rejected finding leaked into a vulnerability section")
	}
	if !strings.Contains(out, "**Confirmed:** 1") || !strings.Contains(out, "**Diagnostics (rejected, not vulnerabilities):** 1") {
		t.Fatalf("summary counts wrong:\n%s", out)
	}
}

// Only a confirmed finding is labelled "Verified"/"Severity": a rejected one
// shows "Verification run"/"Severity (if confirmed)", in both human formats,
// so it never reads as a verified vulnerability at a glance.
func TestReportLabelsUnconfirmedSeverityAndVerificationTime(t *testing.T) {
	d := verifiedData()
	vt := t0.Add(time.Minute)
	for _, f := range d.Findings {
		f.Provenance.VerifiedAt = &vt
	}
	for _, format := range []domain.ReportFormat{domain.ReportMarkdown, domain.ReportHTML} {
		out := generate(t, format, d)
		rej := indexOf(t, out, "/encoded?r")
		conf := indexOf(t, out, "/search?q")
		if conf > rej {
			t.Fatalf("%s: confirmed finding should precede the rejected one", format)
		}
		confPart, rejPart := out[conf:rej], out[rej:]
		for _, want := range []string{"Verified:", "Severity:"} {
			if !strings.Contains(strings.ReplaceAll(confPart, "</strong>", ""), want) {
				t.Errorf("%s: confirmed finding missing %q", format, want)
			}
		}
		rejPlain := strings.ReplaceAll(rejPart, "</strong>", "")
		for _, want := range []string{"Verification run:", "Severity (if confirmed):"} {
			if !strings.Contains(rejPlain, want) {
				t.Errorf("%s: rejected finding missing %q", format, want)
			}
		}
		for _, bad := range []string{"Verified:", "Severity:"} {
			if strings.Contains(rejPlain, bad) {
				t.Errorf("%s: rejected finding labelled %q", format, bad)
			}
		}
	}
}

// The baseline request (q=hello) is labelled as a reference and is never the
// verified payload.
func TestBaselineEvidenceIsLabelledAndNeverThePayload(t *testing.T) {
	for _, format := range []domain.ReportFormat{domain.ReportMarkdown, domain.ReportHTML} {
		out := generate(t, format, verifiedData())
		if !strings.Contains(out, "baseline reference (the unmodified request — not a payload)") {
			t.Fatalf("%s: baseline evidence is not labelled", format)
		}
	}
	var rep struct {
		Findings []struct {
			ID       string `json:"id"`
			Verified *struct {
				CandidateValue string `json:"candidate_value"`
			} `json:"verified_candidate"`
			Candidates []struct {
				Value string `json:"value"`
			} `json:"candidates"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(generate(t, domain.ReportJSON, verifiedData())), &rep); err != nil {
		t.Fatal(err)
	}
	for _, f := range rep.Findings {
		if f.Verified != nil && f.Verified.CandidateValue == baseValue {
			t.Fatal("the baseline value was reported as the verified payload")
		}
		for _, c := range f.Candidates {
			if c.Value == baseValue {
				t.Fatal("the baseline value was reported as a candidate")
			}
		}
	}
}

func TestJSONReportCarriesVerifiedCandidateAttemptsAndRoleOrderedEvidence(t *testing.T) {
	var rep struct {
		Summary  domain.ReportSummary `json:"summary"`
		Findings []struct {
			ID       string `json:"id"`
			Section  string `json:"section"`
			Verified *struct {
				CandidateValue string `json:"candidate_value"`
				Verdict        string `json:"verdict"`
				Notes          string `json:"notes"`
				Evidence       []struct {
					ID   string `json:"id"`
					Role string `json:"role"`
				} `json:"evidence"`
			} `json:"verified_candidate"`
			Attempts []struct {
				CandidateValue string `json:"candidate_value"`
				Verdict        string `json:"verdict"`
			} `json:"attempts"`
			Evidence []struct {
				ID   string `json:"id"`
				Role string `json:"role"`
			} `json:"evidence"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(generate(t, domain.ReportJSON, verifiedData())), &rep); err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) != 3 {
		t.Fatalf("findings = %d", len(rep.Findings))
	}
	order := []string{rep.Findings[0].Section, rep.Findings[1].Section, rep.Findings[2].Section}
	if strings.Join(order, ",") != "confirmed,needs_review,diagnostic" || rep.Findings[0].ID != "f-conf" {
		t.Fatalf("findings not confirmed-first: %v (first %s)", order, rep.Findings[0].ID)
	}
	c := rep.Findings[0]
	if c.Verified == nil || c.Verified.CandidateValue != payload || c.Verified.Verdict != "confirmed" {
		t.Fatalf("verified candidate = %+v", c.Verified)
	}
	if len(c.Attempts) != 2 || c.Attempts[0].CandidateValue != payload || c.Attempts[1].Verdict != "rejected" {
		t.Fatalf("attempts (chronological) = %+v", c.Attempts)
	}
	var roles []string
	for _, e := range c.Evidence {
		roles = append(roles, e.Role)
	}
	if got := strings.Join(roles, ","); got != "browser,browser,candidate,candidate,baseline,baseline" {
		t.Fatalf("evidence roles = %s, want browser first and baseline last", got)
	}
	if rep.Findings[2].Verified != nil {
		t.Fatal("a rejected finding must have no verified candidate")
	}
	if rep.Summary.ConfirmedCount != 1 {
		t.Fatalf("summary = %+v", rep.Summary)
	}
}

// The payload is a breakout string. In HTML it must be escaped, or the report
// itself would execute it; in Markdown it must not escape its code fence.
func TestReportsRenderPayloadsSafely(t *testing.T) {
	nasty := "x`` ``` ````y\n</pre><script>alert(1)</script>"
	d := verifiedData()
	d.Findings[2].Detail = []byte(`{"parameter_name":"q","attempts":[{"candidate_value":` + mustJSON(nasty) + `,"verify_test_case_id":"v","verdict":"confirmed","at":"2026-03-01T10:00:01Z"}]}`)

	html := generate(t, domain.ReportHTML, d)
	if strings.Contains(html, "<script>alert(1)</script>") || strings.Contains(html, "</pre><script>") {
		t.Fatal("the payload was rendered unescaped in the HTML report")
	}
	if !strings.Contains(html, "&lt;/pre&gt;&lt;script&gt;") {
		t.Fatal("the escaped payload is missing from the HTML report")
	}

	md := generate(t, domain.ReportMarkdown, d)
	i := indexOf(t, md, "**Verified candidate**")
	block := md[i:]
	open := strings.Index(block, "\n`")
	fence := block[open+1 : open+1+strings.IndexByte(block[open+1:], '\n')]
	if len(fence) < 5 || strings.Trim(fence, "`") != "" {
		t.Fatalf("fence %q is not longer than the payload's longest backtick run (4)", fence)
	}
}

func mustJSON(s string) string { b, _ := json.Marshal(s); return string(b) }

// Same data, any input order, any repetition: byte-identical output.
func TestVerifiedReportsAreDeterministic(t *testing.T) {
	for _, format := range []domain.ReportFormat{domain.ReportJSON, domain.ReportMarkdown, domain.ReportHTML} {
		d := verifiedData()
		want := generate(t, format, d)
		shuffled := verifiedData()
		fs, es := shuffled.Findings, shuffled.Evidence
		fs[0], fs[2] = fs[2], fs[0]
		es[0], es[5] = es[5], es[0]
		for i := 0; i < 5; i++ {
			if got := generate(t, format, shuffled); got != want {
				t.Fatalf("%s run %d differs from the reference", format, i)
			}
		}
	}
}

// Without evidence metadata a report still lists the evidence IDs (and never
// invents roles).
func TestReportWithoutEvidenceMetadataListsIDs(t *testing.T) {
	d := verifiedData()
	d.Evidence = nil
	out := generate(t, domain.ReportMarkdown, d)
	if !strings.Contains(out, "`shot`") || strings.Contains(out, "browser verification ·") {
		t.Fatalf("expected bare evidence IDs and no invented roles:\n%s", out)
	}
}
