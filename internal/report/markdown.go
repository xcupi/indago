package report

// MarkdownGenerator renders the same Data a JSONGenerator does as readable
// Markdown. Like JSONGenerator, this is pure serialization: every value comes
// straight from the Finding/Scan/Project the caller supplies. It makes no
// security decision, computes no verdict, and does not depend on
// internal/detection or internal/verification — a Finding's Detail (an
// opaque, engine-specific JSON blob; see domain.Finding) is decoded here only
// through a small, local, read-only shape, never by importing those packages.

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/indago/indago/internal/domain"
)

// MarkdownGenerator renders a report as Markdown.
type MarkdownGenerator struct{}

// Format implements Generator.
func (MarkdownGenerator) Format() domain.ReportFormat { return domain.ReportMarkdown }

// markdownDetail is the handful of Finding.Detail fields worth surfacing in a
// human-readable report. It intentionally mirrors only part of
// scan.findingDetail's shape (by field name, via JSON) — report stays
// decoupled from the scan/detection packages that produce Detail.
type markdownDetail struct {
	Method        string `json:"method,omitempty"`
	ParameterName string `json:"parameter_name,omitempty"`
	Occurrences   int    `json:"occurrences,omitempty"`
}

// Generate implements Generator. Output is deterministic: findings are sorted
// by (CreatedAt, ID) (see sortedFindings) and every map-keyed breakdown is
// rendered in sorted key order, so the same Data always produces byte-
// identical Markdown.
func (MarkdownGenerator) Generate(w io.Writer, data Data) error {
	findings := sortedFindings(data.Findings)
	summary := Summarize(data.Scan.ID, findings)

	var b strings.Builder
	fmt.Fprintf(&b, "# Indago Scan Report\n\n")
	fmt.Fprintf(&b, "- **Tool:** indago %s\n", nonEmpty(data.ToolVersion, "dev"))
	fmt.Fprintf(&b, "- **Generated:** %s\n", data.GeneratedAt.UTC().Format("2006-01-02T15:04:05Z"))
	fmt.Fprintf(&b, "- **Project:** %s\n", nonEmpty(data.Project.Name, string(data.Project.ID)))
	fmt.Fprintf(&b, "- **Scan:** %s (`%s`)\n\n", nonEmpty(data.Scan.Name, string(data.Scan.ID)), data.Scan.ID)

	b.WriteString("## Summary\n\n")
	fmt.Fprintf(&b, "- **Total findings:** %d\n", summary.TotalFindings)
	fmt.Fprintf(&b, "- **Confirmed:** %d\n\n", summary.ConfirmedCount)

	writeCountTable(&b, "By verdict", summary.ByVerdict)
	writeCountTable(&b, "By severity", summary.BySeverity)
	writeCountTable(&b, "By vulnerability class", summary.ByVulnClass)

	b.WriteString("## Findings\n\n")
	if len(findings) == 0 {
		b.WriteString("_No findings._\n")
	}
	for i, f := range findings {
		writeFinding(&b, i+1, f)
	}

	_, err := io.WriteString(w, b.String())
	return err
}

func writeCountTable[K ~string](b *strings.Builder, heading string, counts map[K]int) {
	if len(counts) == 0 {
		return
	}
	keys := make([]K, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	fmt.Fprintf(b, "**%s**\n\n", heading)
	b.WriteString("| Value | Count |\n|---|---|\n")
	for _, k := range keys {
		fmt.Fprintf(b, "| %s | %d |\n", string(k), counts[k])
	}
	b.WriteString("\n")
}

func writeFinding(b *strings.Builder, n int, f *domain.Finding) {
	fmt.Fprintf(b, "### %d. %s\n\n", n, nonEmpty(f.Title, "(untitled finding)"))
	fmt.Fprintf(b, "- **Verdict:** %s\n", strings.ToUpper(string(f.Verdict)))
	fmt.Fprintf(b, "- **Severity:** %s\n", f.Severity)
	fmt.Fprintf(b, "- **Confidence:** %s\n", f.Confidence)
	fmt.Fprintf(b, "- **Vulnerability class:** %s\n", f.VulnClass)
	if f.EndpointID != "" {
		fmt.Fprintf(b, "- **Endpoint:** `%s`\n", f.EndpointID)
	}
	if f.InjectionPointID != "" {
		fmt.Fprintf(b, "- **Injection point:** `%s`\n", f.InjectionPointID)
	}
	if f.Location != "" {
		fmt.Fprintf(b, "- **Location:** %s\n", f.Location)
	}
	if md := decodeMarkdownDetail(f.Detail); md.ParameterName != "" || md.Method != "" {
		fmt.Fprintf(b, "- **Parameter:** %s%s\n", md.ParameterName, methodSuffix(md.Method))
	}
	if f.Provenance.DiscoverySource != "" {
		fmt.Fprintf(b, "- **Discovery source:** %s\n", f.Provenance.DiscoverySource)
	}
	if f.Provenance.AIAssisted {
		b.WriteString("- **AI-assisted:** yes (advisory only; not the verdict authority)\n")
	}
	if !f.Provenance.DetectedAt.IsZero() {
		fmt.Fprintf(b, "- **Detected:** %s\n", f.Provenance.DetectedAt.UTC().Format("2006-01-02T15:04:05Z"))
	}
	if f.Provenance.VerifiedAt != nil {
		fmt.Fprintf(b, "- **Verified:** %s\n", f.Provenance.VerifiedAt.UTC().Format("2006-01-02T15:04:05Z"))
	}
	if f.Summary != "" {
		fmt.Fprintf(b, "- **Notes:** %s\n", f.Summary)
	}
	if len(f.EvidenceIDs) > 0 {
		ids := make([]string, len(f.EvidenceIDs))
		for i, id := range f.EvidenceIDs {
			ids[i] = "`" + string(id) + "`"
		}
		fmt.Fprintf(b, "- **Evidence (%d):** %s\n", len(f.EvidenceIDs), strings.Join(ids, ", "))
	}
	b.WriteString("\n")
}

func methodSuffix(method string) string {
	if method == "" {
		return ""
	}
	return " (" + method + ")"
}

func decodeMarkdownDetail(b []byte) markdownDetail {
	var d markdownDetail
	if len(b) > 0 {
		_ = json.Unmarshal(b, &d)
	}
	return d
}

func nonEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

var _ Generator = MarkdownGenerator{}
