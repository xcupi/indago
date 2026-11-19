package report

// SARIFGenerator renders the same Data the JSON/Markdown/HTML generators do as
// a SARIF 2.1.0 log, the format GitHub code scanning, Azure DevOps and most
// SAST dashboards ingest.
//
// It is pure serialization: every result is a finding the scan already
// decided, and every rule is derived from the same CWE/CVSS table and class
// intel the other formats use. It invents no verdict, score or weakness.
//
// Results cover the findings a deliverable would show: confirmed findings and
// those still awaiting review. A plain rejected diagnostic — an attempt that
// produced no confirming signal from its engine and gives no reason to doubt
// the negative — is NOT a vulnerability, so it is excluded from the results and
// counted in the run properties instead of being uploaded as an alert. A
// rejected attempt whose own candidates say the negative is not clean is kept
// as a review result.
//
// A SARIF location is an artifact URI; for a web finding that is the in-scope
// endpoint URL (or the exact verified request when no endpoint URL is known).
// A finding with no absolute http(s) URL gets no location — a fabricated file
// path would point a triager at something that does not exist.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"

	"github.com/indago/indago/internal/domain"
)

const (
	sarifVersion = "2.1.0"
	// sarifSchema is the OASIS-published 2.1.0 schema, the one SARIF
	// consumers validate against.
	sarifSchema = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json"
)

// SARIFGenerator renders a report as a SARIF 2.1.0 log.
type SARIFGenerator struct{}

// Format implements Generator.
func (SARIFGenerator) Format() domain.ReportFormat { return domain.ReportSARIF }

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Invocations []sarifInvocation `json:"invocations,omitempty"`
	Results     []sarifResult     `json:"results"`
	Properties  *sarifRunProps    `json:"properties,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID                   string         `json:"id"`
	ShortDescription     sarifText      `json:"shortDescription"`
	FullDescription      *sarifText     `json:"fullDescription,omitempty"`
	HelpURI              string         `json:"helpUri,omitempty"`
	Help                 *sarifText     `json:"help,omitempty"`
	DefaultConfiguration *sarifRuleConf `json:"defaultConfiguration,omitempty"`
	Properties           *sarifRuleProp `json:"properties,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifRuleConf struct {
	Level string `json:"level"`
}

// sarifRuleProp mirrors the property bag GitHub reads: tags carry the CWE
// taxonomy link and security-severity carries the CVSS base score as a
// numeric string. The extra keys are additive and harmless to other consumers.
type sarifRuleProp struct {
	Tags             []string `json:"tags,omitempty"`
	SecuritySeverity string   `json:"security-severity,omitempty"`
	CVSSVector       string   `json:"cvssVector,omitempty"`
	CVSSScore        string   `json:"cvssScore,omitempty"`
	CWE              string   `json:"cwe,omitempty"`
}

type sarifInvocation struct {
	ExecutionSuccessful bool   `json:"executionSuccessful"`
	EndTimeUTC          string `json:"endTimeUtc,omitempty"`
}

type sarifRunProps struct {
	ScanID              string `json:"scanId,omitempty"`
	Selection           string `json:"selection,omitempty"`
	ScanFindings        int    `json:"scanFindings,omitempty"`
	DiagnosticsExcluded int    `json:"diagnosticsExcluded,omitempty"`
	ScanState           string `json:"scanState,omitempty"`
	Complete            bool   `json:"complete"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Kind                string            `json:"kind,omitempty"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Properties          *sarifResultProps `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifResultProps struct {
	FindingID        string `json:"findingId"`
	Verdict          string `json:"verdict"`
	Severity         string `json:"severity"`
	Confidence       string `json:"confidence,omitempty"`
	VulnClass        string `json:"vulnClass"`
	CWE              string `json:"cwe,omitempty"`
	CVSSVector       string `json:"cvssVector,omitempty"`
	CVSSScore        string `json:"cvssScore,omitempty"`
	EndpointID       string `json:"endpointId,omitempty"`
	InjectionPointID string `json:"injectionPointId,omitempty"`
	Location         string `json:"location,omitempty"`
	Parameter        string `json:"parameter,omitempty"`
	Method           string `json:"method,omitempty"`
	Summary          string `json:"summary,omitempty"`
}

// Generate implements Generator. Output is deterministic: findings are ordered
// by Prioritized, rules by the classification table's own order (unknown
// classes last, lexicographically), and the one map iteration (unknown classes)
// is sorted before it is emitted.
func (SARIFGenerator) Generate(w io.Writer, data Data) error {
	findings, diagnostics := sarifFindings(data.Findings)
	idx := EvidenceIndex(data.Evidence)
	cov := coverageFor(data)

	// One rule per distinct class actually reported, in table order so the
	// rule list is stable across scans that report the same classes.
	ruleIdx := make(map[domain.VulnClass]int, len(findings))
	rules := make([]sarifRule, 0, len(findings))
	for _, class := range sarifRuleClasses(findings) {
		ruleIdx[class] = len(rules)
		rules = append(rules, buildSARIFRule(class))
	}

	results := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		v := NewFindingViewWithRequests(f, idx, data.RequestEvidence)
		results = append(results, buildSARIFResult(data, f, v, ruleIdx[f.VulnClass]))
	}

	run := sarifRun{
		Tool: sarifTool{Driver: sarifDriver{
			Name:           "indago",
			Version:        data.ToolVersion,
			InformationURI: "https://github.com/indago/indago",
			Rules:          rules,
		}},
		Invocations: []sarifInvocation{{
			ExecutionSuccessful: cov.Complete(),
			EndTimeUTC:          data.GeneratedAt.UTC().Format("2006-01-02T15:04:05Z"),
		}},
		Results: results,
		Properties: &sarifRunProps{
			ScanID:              string(data.Scan.ID),
			Selection:           string(data.Selection),
			ScanFindings:        data.ScanFindings,
			DiagnosticsExcluded: diagnostics,
			ScanState:           string(cov.State),
			Complete:            cov.Complete(),
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(sarifLog{Schema: sarifSchema, Version: sarifVersion, Runs: []sarifRun{run}}); err != nil {
		return fmt.Errorf("report: encode sarif: %w", err)
	}
	return nil
}

// sarifFindings returns the findings a SARIF log reports (confirmed first,
// then those awaiting review) and the number of pure diagnostics kept out of
// the results. Sectioning is FindingSection's, not a bare verdict test: a
// rejected attempt whose negative is not clean is a review item and stays in,
// while a plain rejected diagnostic does not become an alert.
func sarifFindings(findings []*domain.Finding) ([]*domain.Finding, int) {
	all := Prioritized(findings)
	out := make([]*domain.Finding, 0, len(all))
	diagnostics := 0
	for _, f := range all {
		if FindingSection(f) == SectionDiagnostic {
			diagnostics++
			continue
		}
		out = append(out, f)
	}
	return out, diagnostics
}

// sarifRuleClasses lists the distinct classes among findings in a stable order:
// the classification table's order first, then unknown classes sorted.
func sarifRuleClasses(findings []*domain.Finding) []domain.VulnClass {
	seen := make(map[domain.VulnClass]bool, len(findings))
	for _, f := range findings {
		seen[f.VulnClass] = true
	}
	known := Classes()
	out := make([]domain.VulnClass, 0, len(seen))
	added := make(map[domain.VulnClass]bool, len(seen))
	for _, class := range known {
		if seen[class] {
			out = append(out, class)
			added[class] = true
		}
	}
	var unknown []domain.VulnClass
	for class := range seen {
		if !added[class] {
			unknown = append(unknown, class)
		}
	}
	sort.Slice(unknown, func(i, j int) bool { return unknown[i] < unknown[j] })
	return append(out, unknown...)
}

// buildSARIFRule derives one rule from the same CWE/CVSS classification and
// class intel the other formats render. A class the table does not know gets a
// rule with no invented CWE or score, and its name as the description.
func buildSARIFRule(class domain.VulnClass) sarifRule {
	rule := sarifRule{
		ID:               sarifRuleID(class),
		ShortDescription: sarifText{Text: humanClass(class)},
		Properties:       &sarifRuleProp{Tags: []string{"security"}},
	}
	classification, ok := Classify(class)
	if !ok {
		return rule
	}
	in := intelFor(class)
	desc := nonEmpty(in.Name, humanClass(class))
	rule.ShortDescription = sarifText{Text: desc}
	rule.HelpURI = classification.CWE.URL()
	rule.Properties = &sarifRuleProp{
		Tags:             []string{"security", fmt.Sprintf("external/cwe/cwe-%03d", classification.CWE.ID)},
		SecuritySeverity: classification.CVSS.Score(),
		CVSSVector:       classification.CVSS.Vector,
		CVSSScore:        classification.CVSS.Score(),
		CWE:              classification.CWE.String(),
	}
	rule.DefaultConfiguration = &sarifRuleConf{Level: sarifLevelForCVSS(classification.CVSS.Severity)}
	if in.Impact != "" {
		rule.FullDescription = &sarifText{Text: in.Impact}
	}
	help := []string{}
	if in.Impact != "" {
		help = append(help, "Typical impact: "+in.Impact)
	}
	if in.Remediation != "" {
		help = append(help, "Remediation: "+in.Remediation)
	}
	if classification.Note != "" {
		help = append(help, "Note: "+classification.Note)
	}
	if len(help) > 0 {
		rule.Help = &sarifText{Text: strings.Join(help, "\n\n")}
	}
	return rule
}

func buildSARIFResult(data Data, f *domain.Finding, v FindingView, ruleIndex int) sarifResult {
	class := string(f.VulnClass)
	res := sarifResult{
		RuleID:    sarifRuleID(f.VulnClass),
		RuleIndex: ruleIndex,
		Kind:      sarifKind(f.Verdict),
		Level:     sarifLevel(f),
		Message:   sarifText{Text: nonEmpty(f.Title, humanClass(f.VulnClass))},
		Properties: &sarifResultProps{
			FindingID:        string(f.ID),
			Verdict:          string(f.Verdict),
			Severity:         string(f.Severity),
			Confidence:       string(f.Confidence),
			VulnClass:        class,
			EndpointID:       string(f.EndpointID),
			InjectionPointID: string(f.InjectionPointID),
			Location:         string(f.Location),
			Parameter:        v.ParamName,
			Method:           v.Method,
			Summary:          f.Summary,
		},
	}
	if c := v.Classification; c != nil {
		res.Properties.CWE = c.CWE.String()
		res.Properties.CVSSVector = c.CVSS.Vector
		res.Properties.CVSSScore = c.CVSS.Score()
	}
	if loc := sarifLocationFor(data, f, v); loc != nil {
		res.Locations = []sarifLocation{*loc}
	}
	res.PartialFingerprints = map[string]string{"indagoFinding/v1": sarifFingerprint(data, f, v)}
	return res
}

// sarifLocationFor picks the most useful real URI for a result: the endpoint
// the scan recorded, then the exact verified request. It never invents a path.
func sarifLocationFor(data Data, f *domain.Finding, v FindingView) *sarifLocation {
	raw := data.Endpoints[f.EndpointID]
	if raw == "" && v.Verified != nil {
		raw = v.Verified.URL
	}
	uri := sarifArtifactURI(raw)
	if uri == "" {
		return nil
	}
	return &sarifLocation{PhysicalLocation: sarifPhysicalLocation{
		ArtifactLocation: sarifArtifactLocation{URI: uri},
	}}
}

// sarifArtifactURI normalises an absolute http(s) URL into the URI a SARIF
// artifactLocation carries. Anything else (relative target, non-http scheme,
// control character) is rejected rather than emitted as a broken location.
func sarifArtifactURI(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.ContainsAny(raw, "\r\n\x00") {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return ""
	}
	u.Scheme = scheme
	// Re-encode the query so a payload character that RFC 3986 does not
	// allow cannot make the URI invalid.
	u.RawQuery = u.Query().Encode()
	return u.String()
}

// sarifFingerprint is a stable identity for the result across runs: class,
// asset, parameter, location and title. It is not a verdict and carries no
// secret — only values already present in the report.
func sarifFingerprint(data Data, f *domain.Finding, v FindingView) string {
	asset := data.Endpoints[f.EndpointID]
	if asset == "" && v.Verified != nil {
		asset = v.Verified.URL
	}
	key := strings.Join([]string{
		string(f.VulnClass), asset, v.ParamName, string(f.Location), f.Title,
	}, "\x00")
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])[:16]
}

// sarifRuleID names the rule for a class. It is a SARIF id (not a display
// name), so it is restricted to a conservative token set.
func sarifRuleID(class domain.VulnClass) string {
	raw := strings.TrimSpace(string(class))
	if raw == "" {
		return "indago/unclassified"
	}
	var b strings.Builder
	for _, r := range strings.ToLower(raw) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_', r == '-', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return "indago/" + b.String()
}

// humanClass renders an unknown class token for a description.
func humanClass(class domain.VulnClass) string {
	name := strings.ReplaceAll(strings.TrimSpace(string(class)), "_", " ")
	if name == "" {
		return "unclassified finding"
	}
	return name
}

// sarifLevel maps a finding to the SARIF result level. Only a confirmed
// finding is a failure; a finding awaiting review is a review item, never an
// error, and a rejected diagnostic is not emitted at all.
func sarifLevel(f *domain.Finding) string {
	if f.Verdict != domain.VerdictConfirmed {
		return "note"
	}
	switch f.Severity {
	case domain.SeverityCritical, domain.SeverityHigh:
		return "error"
	case domain.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

// sarifKind distinguishes a confirmed failure from an item that still needs a
// human decision (SARIF 2.1.0 result.kind).
func sarifKind(v domain.Verdict) string {
	if v == domain.VerdictConfirmed {
		return "fail"
	}
	return "review"
}

// sarifLevelForCVSS is the rule's default level, derived from the class
// baseline rather than from any one finding.
func sarifLevelForCVSS(sev CVSSSeverity) string {
	switch sev {
	case CVSSSeverityCritical, CVSSSeverityHigh:
		return "error"
	case CVSSSeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

var _ Generator = SARIFGenerator{}
