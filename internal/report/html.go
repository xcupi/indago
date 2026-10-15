package report

// HTMLGenerator renders the same Data a JSONGenerator/MarkdownGenerator does as
// a self-contained HTML document, with the same layout: confirmed
// vulnerabilities first (each with the candidate whose browser verification
// succeeded and its evidence), then findings needing review, then diagnostics
// (rejected attempts — not vulnerabilities). Like the other generators it is
// pure serialization through the shared FindingView — never importing
// internal/scan or internal/detection.
//
// All interpolated values go through html/template, which HTML-escapes by
// default. That matters here specifically: a Candidate's Value is a reflected-
// XSS breakout string by design, so rendering it unescaped into the report
// would make the report itself executable in a browser.

import (
	"fmt"
	"html/template"
	"io"
	"sort"
	"strings"

	"github.com/indago/indago/internal/domain"
)

// HTMLGenerator renders a report as a single self-contained HTML page (no
// external resources: no CDN scripts or stylesheets).
type HTMLGenerator struct{}

// Format implements Generator.
func (HTMLGenerator) Format() domain.ReportFormat { return domain.ReportHTML }

type htmlCount struct {
	Label string
	Count int
}

type htmlEvidence struct {
	ID, Role, RoleLabel, Kind, MediaType, Hash string
	Size                                       int64
}

type htmlAttempt struct {
	Candidate, Verdict, VerdictLower string
}

type htmlFinding struct {
	N               int
	Title           string
	Verdict         string
	VerdictLower    string
	Severity        string
	SeverityLabel   string
	VerifiedAtLabel string
	Confidence      string
	VulnClass       string
	EndpointID      string
	InjPointID      string
	Location        string
	Parameter       string
	Method          string
	Discovery       string
	AIAssisted      bool
	DetectedAt      string
	VerifiedAt      string
	Summary         string
	ReviewReason    string

	// Verified candidate (confirmed findings with a recorded confirming attempt).
	HasVerified      bool
	VerifiedValue    string
	VerifiedSignal   string
	VerifiedContext  string
	VerifiedEvidence []htmlEvidence
	// Candidates that reflected, when the confirming attempt was not recorded.
	LegacyCandidates []string

	Others      []htmlAttempt
	OthersLabel string
	Evidence    []htmlEvidence
	EvidenceID  []string // IDs only, when no evidence metadata was supplied
}

type htmlSection struct {
	Title    string
	Note     string
	Findings []htmlFinding
}

type htmlView struct {
	ToolVersion   string
	GeneratedAt   string
	ProjectName   string
	ScanName      string
	ScanID        string
	Selection     string
	TotalFindings int
	Confirmed     int
	NeedsReview   int
	Diagnostics   int
	ByVerdict     []htmlCount
	BySeverity    []htmlCount
	ByVulnClass   []htmlCount
	Sections      []htmlSection
}

// Generate implements Generator. Output is deterministic: findings are ordered
// by Prioritized, attempts and evidence by their own stable orders, and every
// map-keyed breakdown is rendered in sorted key order, so the same Data always
// produces byte-identical HTML.
func (HTMLGenerator) Generate(w io.Writer, data Data) error {
	findings := Prioritized(data.Findings)
	idx := EvidenceIndex(data.Evidence)
	summary := dataSummary(data, findings)
	counts := sectionCounts(findings)

	view := htmlView{
		ToolVersion:   nonEmpty(data.ToolVersion, "dev"),
		GeneratedAt:   data.GeneratedAt.UTC().Format("2006-01-02T15:04:05Z"),
		ProjectName:   nonEmpty(data.Project.Name, string(data.Project.ID)),
		ScanName:      nonEmpty(data.Scan.Name, string(data.Scan.ID)),
		ScanID:        string(data.Scan.ID),
		Selection:     selectionLine(summary),
		TotalFindings: summary.TotalFindings,
		Confirmed:     summary.ConfirmedCount,
		NeedsReview:   counts[SectionNeedsReview],
		Diagnostics:   counts[SectionDiagnostic],
		ByVerdict:     countTable(summary.ByVerdict),
		BySeverity:    countTable(summary.BySeverity),
		ByVulnClass:   countTable(summary.ByVulnClass),
	}
	n := 0
	for _, sec := range sectionOrder {
		hs := htmlSection{Title: sec.Title()}
		if sec == SectionDiagnostic {
			hs.Note = "These candidates reflected but browser verification found no execution. They are kept for diagnosis; they are not vulnerabilities."
		}
		for _, f := range findings {
			if FindingSection(f) != sec {
				continue
			}
			n++
			hs.Findings = append(hs.Findings, toHTMLFinding(n, f, NewFindingView(f, idx)))
		}
		if len(hs.Findings) > 0 {
			view.Sections = append(view.Sections, hs)
		}
	}
	return htmlTemplate.Execute(w, view)
}

func toHTMLEvidence(evs []EvidenceView) []htmlEvidence {
	out := make([]htmlEvidence, 0, len(evs))
	for _, e := range evs {
		out = append(out, htmlEvidence{ID: string(e.ID), Role: string(e.Role), RoleLabel: roleLabel(e.Role),
			Kind: string(e.Kind), MediaType: e.MediaType, Size: e.Size, Hash: shortHash(e.SHA256)})
	}
	return out
}

func toHTMLFinding(n int, f *domain.Finding, v FindingView) htmlFinding {
	hf := htmlFinding{
		N:               n,
		Title:           nonEmpty(f.Title, "(untitled finding)"),
		Verdict:         strings.ToUpper(string(f.Verdict)),
		VerdictLower:    strings.ToLower(string(f.Verdict)),
		Severity:        string(f.Severity),
		SeverityLabel:   SeverityLabel(f.Verdict),
		VerifiedAtLabel: VerifiedAtLabel(f.Verdict),
		Confidence:      string(f.Confidence),
		VulnClass:       string(f.VulnClass),
		EndpointID:      string(f.EndpointID),
		InjPointID:      string(f.InjectionPointID),
		Location:        string(f.Location),
		Parameter:       v.ParamName,
		Method:          v.Method,
		Discovery:       string(f.Provenance.DiscoverySource),
		AIAssisted:      f.Provenance.AIAssisted,
		Summary:         f.Summary,
		ReviewReason:    v.ReviewReasonLabel,
	}
	if !f.Provenance.DetectedAt.IsZero() {
		hf.DetectedAt = f.Provenance.DetectedAt.UTC().Format("2006-01-02T15:04:05Z")
	}
	if f.Provenance.VerifiedAt != nil {
		hf.VerifiedAt = f.Provenance.VerifiedAt.UTC().Format("2006-01-02T15:04:05Z")
	}
	if v.Verified != nil {
		hf.HasVerified = true
		hf.VerifiedValue = v.Verified.CandidateValue
		hf.VerifiedSignal = v.Verified.Notes
		if c := candidateFor(v, v.Verified.CandidateValue); c != nil {
			hf.VerifiedContext = c.Context
		}
		hf.VerifiedEvidence = toHTMLEvidence(v.Verified.Evidence)
	} else if f.Verdict == domain.VerdictConfirmed {
		for _, c := range v.Candidates {
			hf.LegacyCandidates = append(hf.LegacyCandidates, c.Value)
		}
	}
	hf.OthersLabel = "Other attempts (kept as diagnostics)"
	if v.Verified == nil {
		hf.OthersLabel = "Attempts"
	}
	for _, a := range otherAttempts(v) {
		hf.Others = append(hf.Others, htmlAttempt{Candidate: a.CandidateValue, Verdict: string(a.Verdict), VerdictLower: string(a.Verdict)})
	}
	hf.Evidence = toHTMLEvidence(v.Evidence)
	if len(hf.Evidence) == 0 {
		for _, id := range f.EvidenceIDs {
			hf.EvidenceID = append(hf.EvidenceID, string(id))
		}
	}
	return hf
}

// countTable renders a map-keyed breakdown in sorted key order, so output is
// deterministic.
func countTable[K ~string](counts map[K]int) []htmlCount {
	keys := make([]K, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	out := make([]htmlCount, 0, len(keys))
	for _, k := range keys {
		out = append(out, htmlCount{Label: string(k), Count: counts[k]})
	}
	return out
}

var htmlTemplate = template.Must(template.New("report").Funcs(template.FuncMap{
	"methodSuffix": func(method string) string {
		if method == "" {
			return ""
		}
		return fmt.Sprintf(" (%s)", method)
	},
}).Parse(htmlTemplateSrc))

const htmlTemplateSrc = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Indago Scan Report — {{.ScanName}}</title>
<style>
  body { font-family: -apple-system, Segoe UI, Helvetica, Arial, sans-serif; max-width: 900px; margin: 2rem auto; padding: 0 1rem; color: #1b1f23; overflow-wrap: anywhere; }
  h1, h2, h3 { color: #0b3d91; }
  table { border-collapse: collapse; margin: 0.5rem 0 1.5rem; }
  th, td { border: 1px solid #d0d7de; padding: 0.4rem 0.8rem; text-align: left; vertical-align: top; }
  th { background: #f6f8fa; }
  .finding { border: 1px solid #d0d7de; border-radius: 6px; padding: 1rem; margin-bottom: 1rem; }
  .verdict-confirmed { color: #b42318; font-weight: bold; }
  .verdict-pending { color: #8a6d00; font-weight: bold; }
  .verdict-rejected { color: #57606a; font-weight: bold; }
  .verdict-inconclusive { color: #57606a; font-weight: bold; }
  .meta { color: #57606a; font-size: 0.9em; }
  code { background: #f6f8fa; padding: 0.1rem 0.3rem; border-radius: 4px; }
  pre.payload { background: #f6f8fa; border: 1px solid #d0d7de; border-left: 4px solid #b42318; border-radius: 4px; padding: 0.6rem 0.8rem; white-space: pre-wrap; overflow-wrap: anywhere; margin: 0.3rem 0 0.8rem; }
  .note { color: #57606a; font-style: italic; }
  .baseline { color: #57606a; }
</style>
</head>
<body>
<h1>Indago Scan Report</h1>
<p class="meta">
  <strong>Tool:</strong> indago {{.ToolVersion}}<br>
  <strong>Generated:</strong> {{.GeneratedAt}}<br>
  <strong>Project:</strong> {{.ProjectName}}<br>
  <strong>Scan:</strong> {{.ScanName}} (<code>{{.ScanID}}</code>)
</p>

<h2>Summary</h2>
{{if .Selection}}<p><strong>Selection:</strong> {{.Selection}}</p>{{end}}
<p><strong>Total findings:</strong> {{.TotalFindings}} &nbsp; <strong>Confirmed:</strong> {{.Confirmed}} &nbsp; <strong>Needs review:</strong> {{.NeedsReview}} &nbsp; <strong>Diagnostics (rejected, not vulnerabilities):</strong> {{.Diagnostics}}</p>

{{if .ByVerdict}}<h3>By verdict</h3>
<table><tr><th>Value</th><th>Count</th></tr>
{{range .ByVerdict}}<tr><td>{{.Label}}</td><td>{{.Count}}</td></tr>
{{end}}</table>{{end}}

{{if .BySeverity}}<h3>By severity</h3>
<table><tr><th>Value</th><th>Count</th></tr>
{{range .BySeverity}}<tr><td>{{.Label}}</td><td>{{.Count}}</td></tr>
{{end}}</table>{{end}}

{{if .ByVulnClass}}<h3>By vulnerability class</h3>
<table><tr><th>Value</th><th>Count</th></tr>
{{range .ByVulnClass}}<tr><td>{{.Label}}</td><td>{{.Count}}</td></tr>
{{end}}</table>{{end}}

{{if not .Sections}}<h2>Findings</h2><p><em>No findings.</em></p>{{end}}
{{range .Sections}}
<h2>{{.Title}}</h2>
{{if .Note}}<p class="note">{{.Note}}</p>{{end}}
{{range .Findings}}
<div class="finding">
  <h3>{{.N}}. {{.Title}}</h3>
  <p class="verdict-{{.VerdictLower}}">Verdict: {{.Verdict}}</p>
  {{if .HasVerified}}
  <p><strong>Verified candidate</strong> (the payload whose browser verification confirmed execution):</p>
  <pre class="payload">{{.VerifiedValue}}</pre>
  {{if .VerifiedSignal}}<p><strong>Verification signal:</strong> {{.VerifiedSignal}}</p>{{end}}
  {{if .VerifiedContext}}<p><strong>Context:</strong> {{.VerifiedContext}}</p>{{end}}
  {{if .VerifiedEvidence}}<p><strong>Evidence for the verified candidate:</strong></p>
  <ul>{{range .VerifiedEvidence}}<li{{if eq .Role "baseline"}} class="baseline"{{end}}><code>{{.ID}}</code> — {{.RoleLabel}} · {{.Kind}}{{if .MediaType}} · {{.MediaType}}{{end}} · {{.Size}} bytes{{if .Hash}} · sha256:{{.Hash}}{{end}}</li>{{end}}</ul>{{end}}
  {{else if .LegacyCandidates}}
  <p class="note">The confirming attempt was not recorded for this finding (it predates per-attempt tracking). Candidates that reflected:</p>
  {{range .LegacyCandidates}}<pre class="payload">{{.}}</pre>{{end}}
  {{end}}
  <ul>
    <li><strong>{{.SeverityLabel}}:</strong> {{.Severity}}</li>
    <li><strong>Confidence:</strong> {{.Confidence}}</li>
    <li><strong>Vulnerability class:</strong> {{.VulnClass}}</li>
    {{if .EndpointID}}<li><strong>Endpoint:</strong> <code>{{.EndpointID}}</code></li>{{end}}
    {{if .InjPointID}}<li><strong>Injection point:</strong> <code>{{.InjPointID}}</code></li>{{end}}
    {{if .Location}}<li><strong>Location:</strong> {{.Location}}</li>{{end}}
    {{if or .Parameter .Method}}<li><strong>Parameter:</strong> {{.Parameter}}{{methodSuffix .Method}}</li>{{end}}
    {{if .Discovery}}<li><strong>Discovery source:</strong> {{.Discovery}}</li>{{end}}
    {{if .AIAssisted}}<li><strong>AI-assisted:</strong> yes (advisory only; not the verdict authority)</li>{{end}}
    {{if .DetectedAt}}<li><strong>Detected:</strong> {{.DetectedAt}}</li>{{end}}
    {{if .VerifiedAt}}<li><strong>{{.VerifiedAtLabel}}:</strong> {{.VerifiedAt}}</li>{{end}}
    {{if .Summary}}<li><strong>Notes:</strong> {{.Summary}}</li>{{end}}
    {{if .ReviewReason}}<li><strong>Why this needs manual review (not a clean negative):</strong> {{.ReviewReason}}</li>{{end}}
  </ul>
  {{if .Others}}<p><strong>{{.OthersLabel}}:</strong></p>
  <table><tr><th>Candidate</th><th>Verdict</th></tr>
  {{range .Others}}<tr><td><code>{{.Candidate}}</code></td><td class="verdict-{{.VerdictLower}}">{{.Verdict}}</td></tr>{{end}}</table>{{end}}
  {{if .Evidence}}<p><strong>All evidence ({{len .Evidence}}):</strong></p>
  <ul>{{range .Evidence}}<li{{if eq .Role "baseline"}} class="baseline"{{end}}><code>{{.ID}}</code> — {{.RoleLabel}} · {{.Kind}}{{if .MediaType}} · {{.MediaType}}{{end}} · {{.Size}} bytes{{if .Hash}} · sha256:{{.Hash}}{{end}}</li>{{end}}</ul>
  {{else if .EvidenceID}}<p><strong>Evidence ({{len .EvidenceID}}):</strong> {{range .EvidenceID}}<code>{{.}}</code> {{end}}</p>{{end}}
</div>
{{end}}
{{end}}
</body>
</html>
`

var _ Generator = HTMLGenerator{}
