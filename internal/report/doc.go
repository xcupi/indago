package report

// Report documents that read like a deliverable, not like a scanner dump.
//
// The technical generator (Data.Template == "") keeps the evidence-first layout
// the engine has always produced. Two additional templates reshape the SAME
// data into the two formats operators actually hand over:
//
//   - pentest: confidentiality, engagement/scope, executive summary, approach,
//     findings summary, technical findings (CWE, impact, remediation,
//     references), remediation roadmap, appendices.
//   - bug_bounty: one submission-shaped block per finding (asset, severity,
//     CWE, steps to reproduce, impact, remediation, references, evidence).
//
// Both are built from a small document model (sections of paragraphs, lists,
// tables and code) and rendered to Markdown or a print-ready HTML page. The
// model is pure data: no I/O and no security logic.

import (
	"fmt"
	"html"
	"strings"

	"github.com/indago/indago/internal/domain"
)

type docBlockKind int

const (
	docParagraph docBlockKind = iota
	docList
	docTable
	docCode
	docSubheading
)

type docBlock struct {
	Kind    docBlockKind
	Text    string
	Items   []string
	Headers []string
	Rows    [][]string
}

type docSection struct {
	Heading string
	Body    []docBlock
}

type doc struct {
	Title    string
	Subtitle string
	Meta     [][2]string
	Sections []docSection
}

func para(text string) docBlock { return docBlock{Kind: docParagraph, Text: text} }

func list(items ...string) docBlock { return docBlock{Kind: docList, Items: items} }

func table(headers []string, rows [][]string) docBlock {
	return docBlock{Kind: docTable, Headers: headers, Rows: rows}
}

func code(text string) docBlock { return docBlock{Kind: docCode, Text: text} }

func section(heading string, body ...docBlock) docSection {
	return docSection{Heading: heading, Body: body}
}

// renderMarkdown writes the document as Markdown.
func (d doc) renderMarkdown(b *strings.Builder) {
	fmt.Fprintf(b, "# %s\n\n", d.Title)
	if d.Subtitle != "" {
		fmt.Fprintf(b, "_%s_\n\n", d.Subtitle)
	}
	for _, kv := range d.Meta {
		fmt.Fprintf(b, "- **%s:** %s\n", kv[0], kv[1])
	}
	if len(d.Meta) > 0 {
		b.WriteString("\n")
	}
	for _, sec := range d.Sections {
		fmt.Fprintf(b, "## %s\n\n", sec.Heading)
		for _, blk := range sec.Body {
			switch blk.Kind {
			case docParagraph:
				fmt.Fprintf(b, "%s\n\n", blk.Text)
			case docList:
				for _, item := range blk.Items {
					fmt.Fprintf(b, "- %s\n", item)
				}
				b.WriteString("\n")
			case docTable:
				if len(blk.Headers) == 0 {
					continue
				}
				fmt.Fprintf(b, "| %s |\n", strings.Join(blk.Headers, " | "))
				sep := make([]string, len(blk.Headers))
				for i := range sep {
					sep[i] = "---"
				}
				fmt.Fprintf(b, "| %s |\n", strings.Join(sep, " | "))
				for _, row := range blk.Rows {
					cells := make([]string, len(blk.Headers))
					for i := range cells {
						if i < len(row) {
							cells[i] = mdCell(row[i])
						}
					}
					fmt.Fprintf(b, "| %s |\n", strings.Join(cells, " | "))
				}
				b.WriteString("\n")
			case docCode:
				fmt.Fprintf(b, "```\n%s\n```\n\n", blk.Text)
			case docSubheading:
				fmt.Fprintf(b, "### %s\n\n", blk.Text)
			}
		}
	}
}

// renderHTML writes the document as one self-contained, print-ready page:
// no external assets, page breaks before each top-level section, monospace
// evidence blocks. Every interpolated value is HTML-escaped.
func (d doc) renderHTML(b *strings.Builder) {
	b.WriteString(`<!doctype html><html lang="en"><head><meta charset="utf-8">`)
	fmt.Fprintf(b, "<title>%s</title>", html.EscapeString(d.Title))
	b.WriteString(`<style>
:root { color-scheme: light; }
@page { size: A4; margin: 18mm 16mm; }
body { font: 10.5pt/1.45 -apple-system, Segoe UI, Roboto, sans-serif; color: #18181b; margin: 0; }
h1 { font-size: 22pt; margin: 0 0 4px; }
.sub { color: #52525b; font-size: 11pt; margin-bottom: 18px; }
h2 { font-size: 14pt; margin: 22px 0 8px; padding-bottom: 4px; border-bottom: 1px solid #d4d4d8; page-break-after: avoid; }
h3 { font-size: 12pt; margin: 16px 0 6px; page-break-after: avoid; }
p { margin: 0 0 8px; }
ul { margin: 0 0 10px 18px; padding: 0; }
li { margin: 0 0 3px; }
table { width: 100%; border-collapse: collapse; margin: 6px 0 12px; font-size: 9.5pt; page-break-inside: avoid; }
th { text-align: left; background: #f4f4f5; border: 1px solid #d4d4d8; padding: 5px 6px; font-size: 9pt; text-transform: uppercase; letter-spacing: .02em; }
td { border: 1px solid #e4e4e7; padding: 5px 6px; vertical-align: top; word-break: break-word; }
pre { background: #fafafa; border: 1px solid #e4e4e7; padding: 8px; font: 8.5pt/1.4 ui-monospace, Menlo, Consolas, monospace; white-space: pre-wrap; word-break: break-all; page-break-inside: avoid; }
.meta { margin: 0 0 4px; padding: 0; list-style: none; font-size: 9.5pt; color: #3f3f46; }
.page-break { page-break-before: always; }
.badge { display: inline-block; border: 1px solid #d4d4d8; border-radius: 999px; padding: 1px 8px; font-size: 8.5pt; margin-right: 4px; }
.finding { page-break-inside: avoid; }
.footer { margin-top: 26px; border-top: 1px solid #e4e4e7; padding-top: 6px; font-size: 8.5pt; color: #71717a; }
</style></head><body>`)
	fmt.Fprintf(b, "<h1>%s</h1>", html.EscapeString(d.Title))
	if d.Subtitle != "" {
		fmt.Fprintf(b, `<div class="sub">%s</div>`, html.EscapeString(d.Subtitle))
	}
	if len(d.Meta) > 0 {
		b.WriteString(`<ul class="meta">`)
		for _, kv := range d.Meta {
			fmt.Fprintf(b, "<li><strong>%s:</strong> %s</li>", html.EscapeString(kv[0]), html.EscapeString(kv[1]))
		}
		b.WriteString("</ul>")
	}
	for i, sec := range d.Sections {
		cls := ""
		if i > 0 {
			cls = ` class="page-break"`
		}
		fmt.Fprintf(b, "<h2%s>%s</h2>", cls, html.EscapeString(sec.Heading))
		for _, blk := range sec.Body {
			switch blk.Kind {
			case docParagraph:
				fmt.Fprintf(b, "<p>%s</p>", html.EscapeString(blk.Text))
			case docList:
				b.WriteString("<ul>")
				for _, item := range blk.Items {
					fmt.Fprintf(b, "<li>%s</li>", html.EscapeString(item))
				}
				b.WriteString("</ul>")
			case docTable:
				if len(blk.Headers) == 0 {
					continue
				}
				b.WriteString("<table><thead><tr>")
				for _, h := range blk.Headers {
					fmt.Fprintf(b, "<th>%s</th>", html.EscapeString(h))
				}
				b.WriteString("</tr></thead><tbody>")
				for _, row := range blk.Rows {
					b.WriteString("<tr>")
					for i := range blk.Headers {
						cell := ""
						if i < len(row) {
							cell = row[i]
						}
						fmt.Fprintf(b, "<td>%s</td>", html.EscapeString(cell))
					}
					b.WriteString("</tr>")
				}
				b.WriteString("</tbody></table>")
			case docCode:
				fmt.Fprintf(b, "<pre>%s</pre>", html.EscapeString(blk.Text))
			case docSubheading:
				fmt.Fprintf(b, "<h3>%s</h3>", html.EscapeString(blk.Text))
			}
		}
	}
	fmt.Fprintf(b, `<div class="footer">Generated by indago %s · %s</div>`,
		html.EscapeString(docToolVersion(d)), html.EscapeString(docGeneratedAt(d)))
	b.WriteString("</body></html>")
}

// docToolVersion / docGeneratedAt are stamped onto the document by the builder
// so the renderers need no access to Data.
func docToolVersion(d doc) string {
	for _, kv := range d.Meta {
		if kv[0] == "Tool" {
			return kv[1]
		}
	}
	return "dev"
}

func docGeneratedAt(d doc) string {
	for _, kv := range d.Meta {
		if kv[0] == "Generated" {
			return kv[1]
		}
	}
	return ""
}

// docPreamble is the meta every template starts with.
func docPreamble(data Data) [][2]string {
	return [][2]string{
		{"Tool", "indago " + nonEmpty(data.ToolVersion, "dev")},
		{"Generated", data.GeneratedAt.UTC().Format("2006-01-02 15:04:05Z")},
		{"Project", nonEmpty(data.Project.Name, string(data.Project.ID))},
		{"Scan", fmt.Sprintf("%s (%s)", nonEmpty(data.Scan.Name, string(data.Scan.ID)), data.Scan.ID)},
	}
}

// findingAsset is the human-readable asset line for a finding: the endpoint id
// is what the store exposes, and the verified attempt URL is the exact request
// when one exists.
func findingAsset(f *domain.Finding, v FindingView) string {
	if v.Verified != nil && v.Verified.URL != "" {
		return v.Verified.URL
	}
	if v.Method != "" && v.ParamName != "" {
		return fmt.Sprintf("%s · parameter %q", v.Method, v.ParamName)
	}
	if f.EndpointID != "" {
		return string(f.EndpointID)
	}
	return "—"
}

// findingEvidenceText lists the evidence ids a finding references, with the
// kind/size from the metadata index when available.
func findingEvidenceText(f *domain.Finding, idx map[domain.ID]*domain.Evidence) string {
	if len(f.EvidenceIDs) == 0 {
		return "No stored evidence."
	}
	parts := make([]string, 0, len(f.EvidenceIDs))
	for _, id := range f.EvidenceIDs {
		if ev := idx[id]; ev != nil {
			parts = append(parts, fmt.Sprintf("%s (%s, %d bytes)", id, ev.Kind, ev.Size))
			continue
		}
		parts = append(parts, string(id))
	}
	return strings.Join(parts, "; ")
}
