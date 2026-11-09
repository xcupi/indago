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
	// Widths, when set, gives each table column a CSS width ("9%", "24%" …).
	// Without it a long URL column starves the text columns beside it.
	Widths []string
	Rows   [][]string
}

type docSection struct {
	Heading string
	Body    []docBlock
}

type doc struct {
	Title    string
	Subtitle string
	Meta     [][2]string
	// Highlights are the cover KPI cards: a label and a short value. They are
	// presentation only (a reader-facing summary of numbers already stated in
	// the body), never a new claim about the target.
	Highlights [][2]string
	Sections   []docSection
}

func para(text string) docBlock { return docBlock{Kind: docParagraph, Text: text} }

func list(items ...string) docBlock { return docBlock{Kind: docList, Items: items} }

func table(headers []string, rows [][]string) docBlock {
	return docBlock{Kind: docTable, Headers: headers, Rows: rows}
}

// sizedTable is table() with explicit column widths (percentages).
func sizedTable(headers, widths []string, rows [][]string) docBlock {
	return docBlock{Kind: docTable, Headers: headers, Widths: widths, Rows: rows}
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
	template := "Pentest"
	if data.Template == TemplateBugBounty {
		template = "Bug bounty"
	}
	scanLabel := string(data.Scan.ID)
	if data.Scan.Name != "" && data.Scan.Name != string(data.Scan.ID) {
		scanLabel = fmt.Sprintf("%s (%s)", data.Scan.Name, data.Scan.ID)
	}
	return [][2]string{
		{"Template", template},
		{"Tool", "indago " + nonEmpty(data.ToolVersion, "dev")},
		{"Generated", data.GeneratedAt.UTC().Format("2006-01-02 15:04:05Z")},
		{"Project", nonEmpty(data.Project.Name, string(data.Project.ID))},
		{"Scan", scanLabel},
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
