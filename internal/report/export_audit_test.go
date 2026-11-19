package report_test

// Export audit: every VulnClass Indago can report must render cleanly in all
// four export formats — HTML, Markdown, JSON and SARIF — with its CWE, CVSS
// baseline, typical impact and remediation, and without a generic fallback
// placeholder. The test parses the JSON and SARIF output as a consumer would
// (with its own structs, so a renamed JSON tag fails here) and checks the
// human formats contain the same class context.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/report"
)

// auditClasses is the canonical domain class list. Using domain.AllVulnClasses
// means a class added to the domain is picked up here automatically; if the
// report tables do not classify it, the checks below fail instead of the class
// silently disappearing from every export.
var auditClasses = domain.AllVulnClasses()

// The seven capabilities named by the export audit must be in that canonical
// list, so a renamed/removed constant cannot make this test pass vacuously.
func TestExportAuditCoversRequestedClasses(t *testing.T) {
	want := []domain.VulnClass{
		domain.VulnSecurityHeaders,
		domain.VulnCookiePolicy,
		domain.VulnHostHeader,
		domain.VulnJWT,
		domain.VulnNoSQLi,
		domain.VulnHTTPMethods,
		domain.VulnTLSConfig,
	}
	have := map[domain.VulnClass]bool{}
	for _, class := range auditClasses {
		have[class] = true
	}
	for _, class := range want {
		if !have[class] {
			t.Fatalf("export audit is missing the requested class %q", class)
		}
	}
}

// auditJSON mirrors the fields a JSON consumer reads. It deliberately does not
// reuse the generator's structs: a broken `json` tag must fail here.
type auditJSON struct {
	Tool    string `json:"tool"`
	Version string `json:"version"`
	Summary struct {
		TotalFindings int            `json:"total_findings"`
		Confirmed     int            `json:"confirmed_count"`
		ByVulnClass   map[string]int `json:"by_vuln_class"`
	} `json:"summary"`
	Findings []struct {
		ID         string `json:"id"`
		VulnClass  string `json:"vuln_class"`
		Verdict    string `json:"verdict"`
		Severity   string `json:"severity"`
		Title      string `json:"title"`
		Classified *struct {
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
		Intel *struct {
			Name        string   `json:"name"`
			Impact      string   `json:"impact"`
			Remediation string   `json:"remediation"`
			References  []string `json:"references"`
		} `json:"class_intel"`
	} `json:"findings"`
}

type auditSARIF struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []struct {
		Tool struct {
			Driver struct {
				Name    string `json:"name"`
				Version string `json:"version"`
				Rules   []struct {
					ID                   string                  `json:"id"`
					ShortDescription     struct{ Text string }   `json:"shortDescription"`
					FullDescription      *struct{ Text string }  `json:"fullDescription"`
					HelpURI              string                  `json:"helpUri"`
					Help                 *struct{ Text string }  `json:"help"`
					DefaultConfiguration *struct{ Level string } `json:"defaultConfiguration"`
					Properties           *struct {
						Tags             []string `json:"tags"`
						SecuritySeverity string   `json:"security-severity"`
						CVSSVector       string   `json:"cvssVector"`
						CVSSScore        string   `json:"cvssScore"`
						CWE              string   `json:"cwe"`
					} `json:"properties"`
				} `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []struct {
			RuleID    string                `json:"ruleId"`
			RuleIndex int                   `json:"ruleIndex"`
			Kind      string                `json:"kind"`
			Level     string                `json:"level"`
			Message   struct{ Text string } `json:"message"`
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						URI string `json:"uri"`
					} `json:"artifactLocation"`
				} `json:"physicalLocation"`
			} `json:"locations"`
			PartialFingerprints map[string]string `json:"partialFingerprints"`
			Properties          struct {
				FindingID  string `json:"findingId"`
				Verdict    string `json:"verdict"`
				Severity   string `json:"severity"`
				VulnClass  string `json:"vulnClass"`
				CWE        string `json:"cwe"`
				CVSSVector string `json:"cvssVector"`
				CVSSScore  string `json:"cvssScore"`
			} `json:"properties"`
		} `json:"results"`
		Properties struct {
			DiagnosticsExcluded int  `json:"diagnosticsExcluded"`
			Complete            bool `json:"complete"`
		} `json:"properties"`
	} `json:"runs"`
}

// exportAuditData builds one confirmed finding per domain class plus one
// rejected diagnostic, with a real endpoint URL for every class so the SARIF
// locations can be validated.
func exportAuditData(t *testing.T) report.Data {
	t.Helper()
	now := time.Date(2026, 11, 19, 9, 0, 0, 0, time.UTC)

	if got, want := len(report.Classes()), len(auditClasses); got != want {
		t.Fatalf("report.Classes() returns %d classes; the audit fixture names %d domain classes", got, want)
	}
	known := map[domain.VulnClass]bool{}
	for _, c := range report.Classes() {
		known[c] = true
	}
	for _, class := range auditClasses {
		if !known[class] {
			t.Fatalf("domain class %q has no report classification", class)
		}
	}

	endpoints := make(map[domain.ID]string, len(auditClasses))
	findings := make([]*domain.Finding, 0, len(auditClasses)+1)
	for i, class := range auditClasses {
		classification, ok := report.Classify(class)
		if !ok {
			t.Fatalf("Classify(%q) failed", class)
		}
		findingID := domain.ID(fmt.Sprintf("f-%02d", i+1))
		endpointID := domain.ID(fmt.Sprintf("e-%02d", i+1))
		endpoints[endpointID] = fmt.Sprintf("https://app.example.test/%s/probe?probe=1", class)
		findings = append(findings, &domain.Finding{
			ID:               findingID,
			ScanID:           "scan-export-audit",
			VulnClass:        class,
			Verdict:          domain.VerdictConfirmed,
			Severity:         auditSeverity(classification.CVSS.Severity),
			Confidence:       domain.ConfidenceHigh,
			Title:            fmt.Sprintf("%s audit finding", class),
			Summary:          "Fixture used to verify every export format renders this class.",
			EndpointID:       endpointID,
			InjectionPointID: domain.ID(fmt.Sprintf("ip-%02d", i+1)),
			Location:         domain.LocationQuery,
			Detail:           []byte(`{"method":"GET","parameter_name":"probe"}`),
			Provenance:       domain.Provenance{DiscoverySource: domain.SourceCrawler, DetectedAt: now},
			CreatedAt:        now.Add(time.Duration(i) * time.Second),
			UpdatedAt:        now.Add(time.Duration(i) * time.Second),
		})
	}
	// A rejected attempt is a diagnostic, not a vulnerability: every human
	// format keeps it in its diagnostics section, JSON keeps it as a row, and
	// SARIF must not upload it as an alert.
	findings = append(findings, &domain.Finding{
		ID:         "f-rejected",
		ScanID:     "scan-export-audit",
		VulnClass:  domain.VulnDOMXSS,
		Verdict:    domain.VerdictRejected,
		Severity:   domain.SeverityLow,
		Confidence: domain.ConfidenceLow,
		Title:      "Rejected diagnostic (must not become a SARIF alert)",
		CreatedAt:  now.Add(time.Hour),
		UpdatedAt:  now.Add(time.Hour),
	})

	return report.Data{
		Project:      domain.Project{ID: "p-audit", Name: "Export Audit"},
		Scan:         domain.Scan{ID: "scan-export-audit", Name: "export-audit", State: domain.ScanCompleted},
		Findings:     findings,
		Endpoints:    endpoints,
		GeneratedAt:  now,
		ToolVersion:  "audit-1.0",
		Selection:    domain.ReportSelectAll,
		ScanFindings: len(findings),
		Completeness: report.Completeness{State: domain.ScanCompleted},
	}
}

func auditSeverity(sev report.CVSSSeverity) domain.Severity {
	switch sev {
	case report.CVSSSeverityCritical:
		return domain.SeverityCritical
	case report.CVSSSeverityHigh:
		return domain.SeverityHigh
	case report.CVSSSeverityMedium:
		return domain.SeverityMedium
	case report.CVSSSeverityLow:
		return domain.SeverityLow
	default:
		return domain.SeverityInfo
	}
}

func TestReportExportAuditCoversEveryClassInEveryFormat(t *testing.T) {
	data := exportAuditData(t)
	formats := []domain.ReportFormat{domain.ReportJSON, domain.ReportMarkdown, domain.ReportHTML, domain.ReportSARIF}

	outputs := make(map[domain.ReportFormat]string, len(formats))
	for _, format := range formats {
		gen, err := report.For(format)
		if err != nil {
			t.Fatalf("For(%q): %v", format, err)
		}
		if gen.Format() != format {
			t.Fatalf("For(%q).Format() = %q", format, gen.Format())
		}
		var first, second bytes.Buffer
		if err := gen.Generate(&first, data); err != nil {
			t.Fatalf("%s: generate: %v", format, err)
		}
		if err := gen.Generate(&second, data); err != nil {
			t.Fatalf("%s: generate again: %v", format, err)
		}
		if first.String() != second.String() {
			t.Fatalf("%s output is not deterministic", format)
		}
		outputs[format] = first.String()
	}

	parsedJSON := parseAuditJSON(t, outputs[domain.ReportJSON])
	parsedSARIF := parseAuditSARIF(t, outputs[domain.ReportSARIF])

	// JSON: one classified row per class, with CWE, CVSS, impact, remediation
	// and references. No class may fall back to an unclassified placeholder.
	if len(parsedJSON.Findings) != len(auditClasses)+1 {
		t.Fatalf("JSON has %d findings, want %d", len(parsedJSON.Findings), len(auditClasses)+1)
	}
	jsonByClass := map[string]int{}
	for i, f := range parsedJSON.Findings {
		if f.Verdict != string(domain.VerdictConfirmed) {
			continue
		}
		jsonByClass[f.VulnClass] = i
	}
	if len(jsonByClass) != len(auditClasses) {
		t.Fatalf("JSON has %d distinct confirmed classes, want %d", len(jsonByClass), len(auditClasses))
	}

	md := outputs[domain.ReportMarkdown]
	htmlOut := html.UnescapeString(outputs[domain.ReportHTML])

	for _, class := range auditClasses {
		classification, ok := report.Classify(class)
		if !ok {
			t.Fatalf("Classify(%q) failed", class)
		}
		idx, ok := jsonByClass[string(class)]
		if !ok {
			t.Fatalf("JSON has no confirmed finding for class %q", class)
		}
		jf := parsedJSON.Findings[idx]
		if jf.Classified == nil {
			t.Fatalf("JSON finding for %q has no classification", class)
		}
		if jf.Classified.CWE.ID != classification.CWE.ID {
			t.Fatalf("%s: JSON CWE id = %d, want %d", class, jf.Classified.CWE.ID, classification.CWE.ID)
		}
		if jf.Classified.CVSS.Vector != classification.CVSS.Vector {
			t.Fatalf("%s: JSON CVSS vector = %q, want %q", class, jf.Classified.CVSS.Vector, classification.CVSS.Vector)
		}
		if jf.Classified.CVSS.BaseScore != classification.CVSS.BaseScore {
			t.Fatalf("%s: JSON CVSS score = %v, want %v", class, jf.Classified.CVSS.BaseScore, classification.CVSS.BaseScore)
		}
		if jf.Classified.Note == "" {
			t.Fatalf("%s: JSON classification has no baseline caveat", class)
		}
		if jf.Intel == nil {
			t.Fatalf("%s: JSON has no class_intel (impact/remediation would be missing)", class)
		}
		if jf.Intel.Name == "" || jf.Intel.Impact == "" || jf.Intel.Remediation == "" {
			t.Fatalf("%s: incomplete class_intel: %+v", class, jf.Intel)
		}
		if len(jf.Intel.References) == 0 {
			t.Fatalf("%s: class_intel has no references", class)
		}

		cwe := classification.CWE.String()
		for name, out := range map[string]string{"HTML": htmlOut, "Markdown": md} {
			if !strings.Contains(out, cwe) {
				t.Fatalf("%s missing %s", name, cwe)
			}
			if !strings.Contains(out, classification.CVSS.Vector) {
				t.Fatalf("%s missing CVSS vector for %s", name, class)
			}
			if !strings.Contains(out, "Typical impact:") {
				t.Fatalf("%s has no impact line for %s", name, class)
			}
			if !strings.Contains(out, "Remediation:") {
				t.Fatalf("%s has no remediation line for %s", name, class)
			}
			if !strings.Contains(out, jf.Intel.Impact) {
				t.Fatalf("%s does not render the impact text for %s", name, class)
			}
			if !strings.Contains(out, jf.Intel.Remediation) {
				t.Fatalf("%s does not render the remediation text for %s", name, class)
			}
		}
		if strings.Contains(md, "CWE: n/a") || strings.Contains(htmlOut, "CWE: n/a") {
			t.Fatalf("a known class rendered the generic \"CWE: n/a\" fallback")
		}
	}

	// The human formats keep sectioning: confirmed findings first, the
	// rejected diagnostic last and explicitly labelled as not a vulnerability.
	if !strings.Contains(md, "## Confirmed vulnerabilities") {
		t.Fatal("Markdown has no confirmed-findings section")
	}
	if !strings.Contains(md, "## Diagnostics — rejected attempts (not vulnerabilities)") {
		t.Fatal("Markdown does not label the rejected diagnostic section")
	}
	if !strings.Contains(md, "Rejected diagnostic (must not become a SARIF alert)") {
		t.Fatal("Markdown dropped the rejected diagnostic instead of keeping it as a diagnostic")
	}
	if !strings.Contains(htmlOut, "<h2>Confirmed vulnerabilities</h2>") {
		t.Fatal("HTML has no confirmed-findings section")
	}
	if !strings.Contains(htmlOut, "Diagnostics — rejected attempts (not vulnerabilities)") {
		t.Fatal("HTML does not label the rejected diagnostic section")
	}
	if strings.Contains(md, "not classified") || strings.Contains(htmlOut, "not classified") {
		t.Fatal("a known class was rendered as unclassified")
	}

	// The client-deliverable layouts are the templates a triager actually
	// reads, and they had their own fallback path. They must carry the same
	// class context for every class too.
	for _, tmpl := range []report.Template{report.TemplatePentest, report.TemplateBugBounty} {
		data.Template = tmpl
		docs := map[string]string{
			"Markdown": renderFormat(t, domain.ReportMarkdown, data),
			"HTML":     html.UnescapeString(renderFormat(t, domain.ReportHTML, data)),
		}
		for name, out := range docs {
			if strings.Contains(out, "CWE: n/a") {
				t.Fatalf("%s %s rendered the generic \"CWE: n/a\" fallback", tmpl, name)
			}
			for _, class := range auditClasses {
				classification, _ := report.Classify(class)
				idx := jsonByClass[string(class)]
				intel := parsedJSON.Findings[idx].Intel
				if !strings.Contains(out, fmt.Sprintf("CWE-%d", classification.CWE.ID)) {
					t.Fatalf("%s %s missing %s", tmpl, name, classification.CWE)
				}
				if !strings.Contains(out, intel.Impact) || !strings.Contains(out, intel.Remediation) {
					t.Fatalf("%s %s missing impact/remediation for %s", tmpl, name, class)
				}
			}
		}
	}

	// SARIF: schema, rules and results must line up, and every rule must carry
	// the same CWE/CVSS baseline plus remediation help.
	if parsedSARIF.Version != "2.1.0" {
		t.Fatalf("SARIF version = %q, want 2.1.0", parsedSARIF.Version)
	}
	if !strings.Contains(parsedSARIF.Schema, "sarif-schema-2.1.0") {
		t.Fatalf("SARIF $schema = %q", parsedSARIF.Schema)
	}
	if len(parsedSARIF.Runs) != 1 {
		t.Fatalf("SARIF has %d runs, want 1", len(parsedSARIF.Runs))
	}
	run := parsedSARIF.Runs[0]
	if run.Tool.Driver.Name != "indago" || run.Tool.Driver.Version != "audit-1.0" {
		t.Fatalf("SARIF driver = %+v", run.Tool.Driver)
	}
	if len(run.Tool.Driver.Rules) != len(auditClasses) {
		t.Fatalf("SARIF has %d rules, want %d", len(run.Tool.Driver.Rules), len(auditClasses))
	}
	ruleIndex := map[string]int{}
	for i, rule := range run.Tool.Driver.Rules {
		if _, dup := ruleIndex[rule.ID]; dup {
			t.Fatalf("SARIF duplicate rule id %q", rule.ID)
		}
		ruleIndex[rule.ID] = i
	}
	for _, class := range auditClasses {
		classification, _ := report.Classify(class)
		ruleID := "indago/" + string(class)
		i, ok := ruleIndex[ruleID]
		if !ok {
			t.Fatalf("SARIF has no rule %q", ruleID)
		}
		rule := run.Tool.Driver.Rules[i]
		if rule.ShortDescription.Text == "" {
			t.Fatalf("%s: rule has no shortDescription", ruleID)
		}
		if rule.Properties == nil {
			t.Fatalf("%s: rule has no properties", ruleID)
		}
		if rule.Properties.CWE != classification.CWE.String() {
			t.Fatalf("%s: rule CWE = %q, want %q", ruleID, rule.Properties.CWE, classification.CWE.String())
		}
		if rule.Properties.CVSSVector != classification.CVSS.Vector {
			t.Fatalf("%s: rule CVSS vector = %q", ruleID, rule.Properties.CVSSVector)
		}
		if rule.Properties.CVSSScore != classification.CVSS.Score() {
			t.Fatalf("%s: rule CVSS score = %q, want %q", ruleID, rule.Properties.CVSSScore, classification.CVSS.Score())
		}
		score, err := strconv.ParseFloat(rule.Properties.SecuritySeverity, 64)
		if err != nil || score != classification.CVSS.BaseScore {
			t.Fatalf("%s: security-severity = %q (%v), want %v", ruleID, rule.Properties.SecuritySeverity, err, classification.CVSS.BaseScore)
		}
		wantTag := fmt.Sprintf("external/cwe/cwe-%03d", classification.CWE.ID)
		if !containsString(rule.Properties.Tags, "security") || !containsString(rule.Properties.Tags, wantTag) {
			t.Fatalf("%s: tags = %v, want security and %s", ruleID, rule.Properties.Tags, wantTag)
		}
		if rule.HelpURI != classification.CWE.URL() {
			t.Fatalf("%s: helpUri = %q, want %q", ruleID, rule.HelpURI, classification.CWE.URL())
		}
		if rule.Help == nil || !strings.Contains(rule.Help.Text, "Remediation:") {
			t.Fatalf("%s: rule help carries no remediation", ruleID)
		}
		if rule.DefaultConfiguration == nil || !validSARIFLevel(rule.DefaultConfiguration.Level) {
			t.Fatalf("%s: rule default level = %+v", ruleID, rule.DefaultConfiguration)
		}
	}

	// The rejected diagnostic is excluded from results, not uploaded as an
	// alert, and the run says so.
	if len(run.Results) != len(auditClasses) {
		t.Fatalf("SARIF has %d results, want %d confirmed findings", len(run.Results), len(auditClasses))
	}
	if run.Properties.DiagnosticsExcluded != 1 {
		t.Fatalf("SARIF diagnosticsExcluded = %d, want 1", run.Properties.DiagnosticsExcluded)
	}
	if !run.Properties.Complete {
		t.Fatal("SARIF run should be marked complete for a completed scan")
	}
	if len(parsedJSON.Summary.ByVulnClass) != len(auditClasses) {
		t.Fatalf("JSON summary covers %d classes, want %d", len(parsedJSON.Summary.ByVulnClass), len(auditClasses))
	}
	for class, n := range parsedJSON.Summary.ByVulnClass {
		if n < 1 {
			t.Fatalf("JSON summary class %q has %d findings", class, n)
		}
	}

	for _, result := range run.Results {
		i, ok := ruleIndex[result.RuleID]
		if !ok {
			t.Fatalf("SARIF result references unknown rule %q", result.RuleID)
		}
		if result.RuleIndex != i {
			t.Fatalf("%s: ruleIndex = %d, want %d", result.RuleID, result.RuleIndex, i)
		}
		if result.Message.Text == "" {
			t.Fatalf("%s: result has no message", result.RuleID)
		}
		if result.Kind != "fail" {
			t.Fatalf("%s: confirmed result kind = %q, want fail", result.RuleID, result.Kind)
		}
		if !validSARIFLevel(result.Level) {
			t.Fatalf("%s: result level = %q", result.RuleID, result.Level)
		}
		if result.Level != sarifLevelForSeverity(result.Properties.Severity) {
			t.Fatalf("%s: level %q does not match severity %q", result.RuleID, result.Level, result.Properties.Severity)
		}
		if len(result.Locations) != 1 {
			t.Fatalf("%s: result has %d locations, want 1", result.RuleID, len(result.Locations))
		}
		loc, err := url.Parse(result.Locations[0].PhysicalLocation.ArtifactLocation.URI)
		if err != nil || loc.Scheme != "https" || loc.Host != "app.example.test" {
			t.Fatalf("%s: location URI = %q (%v)", result.RuleID, result.Locations[0].PhysicalLocation.ArtifactLocation.URI, err)
		}
		if len(result.PartialFingerprints["indagoFinding/v1"]) != 16 {
			t.Fatalf("%s: partial fingerprint = %v", result.RuleID, result.PartialFingerprints)
		}
		classification, _ := report.Classify(domain.VulnClass(result.Properties.VulnClass))
		if result.Properties.FindingID == "" || result.Properties.Verdict != "confirmed" {
			t.Fatalf("%s: result properties = %+v", result.RuleID, result.Properties)
		}
		if result.Properties.CWE != classification.CWE.String() || result.Properties.CVSSScore != classification.CVSS.Score() {
			t.Fatalf("%s: result classification = %+v", result.RuleID, result.Properties)
		}
	}
}

func parseAuditJSON(t *testing.T, out string) auditJSON {
	t.Helper()
	var parsed auditJSON
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("JSON export is not valid JSON: %v", err)
	}
	if parsed.Tool != "indago" || parsed.Version != "audit-1.0" {
		t.Fatalf("JSON header = tool %q version %q", parsed.Tool, parsed.Version)
	}
	if parsed.Summary.TotalFindings != len(auditClasses)+1 {
		t.Fatalf("JSON summary total = %d, want %d", parsed.Summary.TotalFindings, len(auditClasses)+1)
	}
	return parsed
}

func parseAuditSARIF(t *testing.T, out string) auditSARIF {
	t.Helper()
	var parsed auditSARIF
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("SARIF export is not valid JSON: %v", err)
	}
	return parsed
}

func sarifLevelForSeverity(sev string) string {
	switch domain.Severity(sev) {
	case domain.SeverityCritical, domain.SeverityHigh:
		return "error"
	case domain.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func validSARIFLevel(level string) bool {
	switch level {
	case "none", "note", "warning", "error":
		return true
	default:
		return false
	}
}

func containsString(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}
