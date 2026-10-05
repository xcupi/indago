package report

// HTMLGenerator renders the same Data a JSONGenerator/MarkdownGenerator does as
// a self-contained HTML document. Like the other generators, this is pure
// serialization: every value comes straight from the Finding/Scan/Project the
// caller supplies, decoded through the same local, read-only markdownDetail
// shape Markdown uses (see its doc comment) — never by importing
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

type htmlFinding struct {
	N            int
	Title        string
	Verdict      string
	VerdictLower string
	Severity     string
	Confidence   string
	VulnClass    string
	EndpointID   string
	InjPointID   string
	Location     string
	Parameter    string
	Method       string
	Discovery    string
	AIAssisted   bool
	DetectedAt   string
	VerifiedAt   string
	Summary      string
	EvidenceID   []string
}

type htmlView struct {
	ToolVersion   string
	GeneratedAt   string
	ProjectName   string
	ScanName      string
	ScanID        string
	TotalFindings int
	Confirmed     int
	ByVerdict     []htmlCount
	BySeverity    []htmlCount
	ByVulnClass   []htmlCount
	Findings      []htmlFinding
}

// Generate implements Generator. Output is deterministic: findings are sorted
// by (CreatedAt, ID) (see sortedFindings) and every map-keyed breakdown is
// rendered in sorted key order, so the same Data always produces byte-
// identical HTML.
func (HTMLGenerator) Generate(w io.Writer, data Data) error {
	findings := sortedFindings(data.Findings)
	summary := Summarize(data.Scan.ID, findings)

	view := htmlView{
		ToolVersion:   nonEmpty(data.ToolVersion, "dev"),
		GeneratedAt:   data.GeneratedAt.UTC().Format("2006-01-02T15:04:05Z"),
		ProjectName:   nonEmpty(data.Project.Name, string(data.Project.ID)),
		ScanName:      nonEmpty(data.Scan.Name, string(data.Scan.ID)),
		ScanID:        string(data.Scan.ID),
		TotalFindings: summary.TotalFindings,
		Confirmed:     summary.ConfirmedCount,
		ByVerdict:     countTable(summary.ByVerdict),
		BySeverity:    countTable(summary.BySeverity),
		ByVulnClass:   countTable(summary.ByVulnClass),
	}
	for i, f := range findings {
		view.Findings = append(view.Findings, toHTMLFinding(i+1, f))
	}

	return htmlTemplate.Execute(w, view)
}

func toHTMLFinding(n int, f *domain.Finding) htmlFinding {
	md := decodeMarkdownDetail(f.Detail)
	hf := htmlFinding{
		N:            n,
		Title:        nonEmpty(f.Title, "(untitled finding)"),
		Verdict:      strings.ToUpper(string(f.Verdict)),
		VerdictLower: strings.ToLower(string(f.Verdict)),
		Severity:     string(f.Severity),
		Confidence:   string(f.Confidence),
		VulnClass:    string(f.VulnClass),
		EndpointID:   string(f.EndpointID),
		InjPointID:   string(f.InjectionPointID),
		Location:     string(f.Location),
		Parameter:    md.ParameterName,
		Method:       md.Method,
		Discovery:    string(f.Provenance.DiscoverySource),
		AIAssisted:   f.Provenance.AIAssisted,
		Summary:      f.Summary,
	}
	if !f.Provenance.DetectedAt.IsZero() {
		hf.DetectedAt = f.Provenance.DetectedAt.UTC().Format("2006-01-02T15:04:05Z")
	}
	if f.Provenance.VerifiedAt != nil {
		hf.VerifiedAt = f.Provenance.VerifiedAt.UTC().Format("2006-01-02T15:04:05Z")
	}
	for _, id := range f.EvidenceIDs {
		hf.EvidenceID = append(hf.EvidenceID, string(id))
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
  body { font-family: -apple-system, Segoe UI, Helvetica, Arial, sans-serif; max-width: 900px; margin: 2rem auto; padding: 0 1rem; color: #1b1f23; }
  h1, h2, h3 { color: #0b3d91; }
  table { border-collapse: collapse; margin: 0.5rem 0 1.5rem; }
  th, td { border: 1px solid #d0d7de; padding: 0.4rem 0.8rem; text-align: left; }
  th { background: #f6f8fa; }
  .finding { border: 1px solid #d0d7de; border-radius: 6px; padding: 1rem; margin-bottom: 1rem; }
  .verdict-confirmed { color: #b42318; font-weight: bold; }
  .verdict-pending { color: #8a6d00; font-weight: bold; }
  .verdict-rejected { color: #57606a; font-weight: bold; }
  .verdict-inconclusive { color: #57606a; font-weight: bold; }
  .meta { color: #57606a; font-size: 0.9em; }
  code { background: #f6f8fa; padding: 0.1rem 0.3rem; border-radius: 4px; }
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
<p><strong>Total findings:</strong> {{.TotalFindings}} &nbsp; <strong>Confirmed:</strong> {{.Confirmed}}</p>

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

<h2>Findings</h2>
{{if not .Findings}}<p><em>No findings.</em></p>{{end}}
{{range .Findings}}
<div class="finding">
  <h3>{{.N}}. {{.Title}}</h3>
  <p class="verdict-{{.VerdictLower}}">Verdict: {{.Verdict}}</p>
  <ul>
    <li><strong>Severity:</strong> {{.Severity}}</li>
    <li><strong>Confidence:</strong> {{.Confidence}}</li>
    <li><strong>Vulnerability class:</strong> {{.VulnClass}}</li>
    {{if .EndpointID}}<li><strong>Endpoint:</strong> <code>{{.EndpointID}}</code></li>{{end}}
    {{if .InjPointID}}<li><strong>Injection point:</strong> <code>{{.InjPointID}}</code></li>{{end}}
    {{if .Location}}<li><strong>Location:</strong> {{.Location}}</li>{{end}}
    {{if or .Parameter .Method}}<li><strong>Parameter:</strong> {{.Parameter}}{{methodSuffix .Method}}</li>{{end}}
    {{if .Discovery}}<li><strong>Discovery source:</strong> {{.Discovery}}</li>{{end}}
    {{if .AIAssisted}}<li><strong>AI-assisted:</strong> yes (advisory only; not the verdict authority)</li>{{end}}
    {{if .DetectedAt}}<li><strong>Detected:</strong> {{.DetectedAt}}</li>{{end}}
    {{if .VerifiedAt}}<li><strong>Verified:</strong> {{.VerifiedAt}}</li>{{end}}
    {{if .Summary}}<li><strong>Notes:</strong> {{.Summary}}</li>{{end}}
    {{if .EvidenceID}}<li><strong>Evidence ({{len .EvidenceID}}):</strong> {{range .EvidenceID}}<code>{{.}}</code> {{end}}</li>{{end}}
  </ul>
</div>
{{end}}
</body>
</html>
`
