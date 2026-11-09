package report

// HTML/print rendering for the deliverable templates.
//
// One inline stylesheet serves both the browser view and the PDF printer: no
// remote fonts, no external CSS, nothing that survives as a network dependency
// in an air-gapped report. The layout is deliberately restrained — a dark ink
// colour, one accent (teal), severity colour only where it carries meaning —
// because the document's job is to be read, not decorated.

import (
	"fmt"
	"html"
	"strings"
)

const docHTMLStyle = `<style>
:root { color-scheme: light; }
@page {
  size: A4; margin: 20mm 17mm 22mm;
  @bottom-left { content: "INDAGO · CONFIDENTIAL"; font: 7.5pt Arial, sans-serif; letter-spacing: .08em; color: #8a9bb0; }
  @bottom-right { content: counter(page) " / " counter(pages); font: 7.5pt Arial, sans-serif; color: #8a9bb0; }
}
* { box-sizing: border-box; }
body { font: 10pt/1.62 Arial, Helvetica, sans-serif; color: #243449; margin: 0; }
a { color: #0f766e; text-decoration: none; }

/* Cover */
.cover { min-height: 232mm; padding-top: 16mm; border-top: 6px solid #0d9488; break-after: page; }
.brand { font: 800 13pt/1 Arial, sans-serif; letter-spacing: .3em; color: #10263d; }
.eyebrow { font: bold 7.5pt/1 Arial, sans-serif; letter-spacing: .2em; color: #0f766e; margin: 5mm 0 26mm; }
h1 { font: 700 30pt/1.12 Arial, sans-serif; letter-spacing: -.025em; color: #10263d; margin: 0 0 2mm; max-width: 150mm; overflow-wrap: anywhere; }
.subject { font: 700 17pt/1.25 Arial, sans-serif; color: #0f766e; margin: 0 0 4mm; overflow-wrap: anywhere; }
.sub { font-size: 11pt; color: #4a5f78; margin: 0 0 10mm; overflow-wrap: anywhere; }
.kpis { display: grid; grid-template-columns: repeat(4, 1fr); gap: 4mm; margin: 0 0 12mm; }
.kpi { border-top: 3px solid #0d9488; background: #f2f7f8; padding: 4mm 3mm 4.5mm; }
.kpi b { display: block; font: 700 17pt/1.1 Arial, sans-serif; color: #10263d; margin-bottom: 1.5mm; }
.kpi span { display: block; font: bold 7pt/1.3 Arial, sans-serif; letter-spacing: .12em; text-transform: uppercase; color: #52657a; }
.meta { display: grid; grid-template-columns: 1fr 1fr; gap: 5mm 8mm; padding-top: 6mm; border-top: 1px solid #cbd5e1; list-style: none; margin: 0; }
.meta li { font-size: 8.5pt; overflow-wrap: anywhere; }
.meta strong { display: block; font: bold 7pt/1.3 Arial, sans-serif; letter-spacing: .12em; text-transform: uppercase; color: #52657a; margin-bottom: 1.5mm; }

/* Contents */
.contents { padding: 0 0 8mm; margin-bottom: 9mm; border-bottom: 1px solid #cbd5e1; break-after: avoid; }
.contents .eyebrow { margin: 0 0 4mm; color: #52657a; }
.contents ol { columns: 2; column-gap: 12mm; margin: 0; padding: 0; list-style: none; font-size: 9pt; }
.contents li { break-inside: avoid; padding: 1.2mm 0; display: flex; align-items: baseline; gap: 2.5mm; }
.contents .tn { font: bold 7.5pt/1 Arial, sans-serif; color: #0f766e; min-width: 6mm; }
.contents a { flex: 1; }
/* No page numbers here: the print engine has no target-counter(), and a
   wrong number is worse than none. Entries stay links in the HTML view. */

/* Sections */
section { break-inside: auto; }
h2 { font: 700 15pt/1.28 Arial, sans-serif; color: #10263d; margin: 10mm 0 4mm; padding-bottom: 2.5mm; border-bottom: 1px solid #dbe6ec; break-after: avoid; }
h2 .n { font: bold 8pt/1 Arial, sans-serif; color: #0f766e; margin-right: 4mm; }
h3 { font: 700 10.5pt/1.4 Arial, sans-serif; color: #10263d; margin: 6mm 0 2.5mm; padding-left: 3mm; border-left: 3px solid #0d9488; break-after: avoid; }
p { margin: 0 0 2.5mm; orphans: 3; widows: 3; overflow-wrap: anywhere; max-width: 148mm; }
ul, ol { margin: 0 0 3mm; padding-left: 5mm; }
li { margin: 0 0 1mm; overflow-wrap: anywhere; }
.major { break-before: page; }

/* Tables */
table { width: 100%; border-collapse: collapse; margin: 2mm 0 5mm; font-size: 8.5pt; table-layout: fixed; }
thead { display: table-header-group; }
table.keep { break-inside: avoid; }
tr { break-inside: avoid; }
th { background: #10263d; color: #fff; text-align: left; font: bold 6.7pt/1.3 Arial, sans-serif; letter-spacing: .1em; text-transform: uppercase; padding: 2.6mm 2mm; }
td { padding: 2.4mm 2mm; border-bottom: 1px solid #e2ebf0; vertical-align: top; overflow-wrap: anywhere; }
td.mono { font: 7.6pt/1.45 ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace; color: #3c5068; }
tbody tr:nth-child(even) { background: #f7fafb; }

/* Pills for severity and verdict cells */
.pill { display: inline-block; border-radius: 999px; padding: .6mm 2.4mm; font: bold 6.8pt/1.5 Arial, sans-serif; letter-spacing: .06em; text-transform: uppercase; white-space: nowrap; }
.sev-critical { background: #fee2e2; color: #991b1b; }
.sev-high { background: #ffedd5; color: #9a3412; }
.sev-medium { background: #fef3c7; color: #854d0e; }
.sev-low { background: #dbeafe; color: #1e40af; }
.sev-info { background: #e2e8f0; color: #334155; }
.verdict-confirmed { background: #d1fae5; color: #065f46; }
.verdict-review { background: #fef3c7; color: #854d0e; }
.verdict-rejected { background: #e2e8f0; color: #475569; }

/* Evidence blocks */
pre { font: 8pt/1.55 ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace; background: #f2f7f8; border-left: 3px solid #0d9488; padding: 3.5mm 4mm; margin: 2mm 0 4mm; white-space: pre-wrap; overflow-wrap: anywhere; break-inside: auto; }

.footer { margin-top: 10mm; padding-top: 3mm; border-top: 1px solid #dbe6ec; font-size: 7.5pt; color: #8a9bb0; }

@media screen {
  body { max-width: 186mm; margin: 24px auto 48px; padding: 26px 26px 12px; background: #fff; box-shadow: 0 10px 50px #10263d1f; }
  .cover { min-height: auto; padding-bottom: 14mm; }
}
@media print { * { -webkit-print-color-adjust: exact; print-color-adjust: exact; } }
</style>`

// pillClass maps a table cell value to the pill class that should wrap it.
// Only cells whose ENTIRE value is a known severity/verdict get a pill, so a
// sentence that happens to contain "high" is never styled as one.
func pillClass(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "critical":
		return "pill sev-critical"
	case "high":
		return "pill sev-high"
	case "medium":
		return "pill sev-medium"
	case "low":
		return "pill sev-low"
	case "info", "informational":
		return "pill sev-info"
	case "confirmed":
		return "pill verdict-confirmed"
	case "needs review", "needs_review", "inconclusive", "pending":
		return "pill verdict-review"
	case "rejected":
		return "pill verdict-rejected"
	}
	return ""
}

// monoColumn marks columns whose values are identifiers or URLs: they read
// better in a monospace face and may break anywhere.
func monoColumn(header string) bool {
	switch strings.ToLower(strings.TrimSpace(header)) {
	case "asset", "endpoint", "url", "evidence", "scan", "id":
		return true
	}
	return false
}

// renderHTML writes the document as one self-contained, print-ready page.
// Every interpolated value is HTML-escaped.
func (d doc) renderHTML(b *strings.Builder) {
	b.WriteString(`<!doctype html><html lang="en"><head><meta charset="utf-8">`)
	fmt.Fprintf(b, "<title>%s</title>", html.EscapeString(d.Title))
	b.WriteString(docHTMLStyle)
	b.WriteString(`</head><body><header class="cover"><div class="brand">INDAGO</div>`)
	b.WriteString(`<div class="eyebrow">SECURITY ASSESSMENT · CONFIDENTIAL</div>`)
	// A long "Kind — Subject" title breaks mid-token at the hyphen; split it so
	// the subject gets its own line and the scan id stays intact.
	headline, subject := d.Title, ""
	if i := strings.Index(d.Title, " — "); i > 0 {
		headline, subject = d.Title[:i], d.Title[i+len(" — "):]
	}
	fmt.Fprintf(b, "<h1>%s</h1>", html.EscapeString(headline))
	if subject != "" {
		fmt.Fprintf(b, `<div class="subject">%s</div>`, html.EscapeString(subject))
	}
	if d.Subtitle != "" {
		fmt.Fprintf(b, `<div class="sub">%s</div>`, html.EscapeString(d.Subtitle))
	}
	if len(d.Highlights) > 0 {
		b.WriteString(`<div class="kpis">`)
		for _, h := range d.Highlights {
			fmt.Fprintf(b, `<div class="kpi"><b>%s</b><span>%s</span></div>`,
				html.EscapeString(h[1]), html.EscapeString(h[0]))
		}
		b.WriteString(`</div>`)
	}
	if len(d.Meta) > 0 {
		b.WriteString(`<ul class="meta">`)
		for _, kv := range d.Meta {
			fmt.Fprintf(b, "<li><strong>%s</strong>%s</li>", html.EscapeString(kv[0]), html.EscapeString(kv[1]))
		}
		b.WriteString("</ul>")
	}
	b.WriteString(`</header>`)

	if len(d.Sections) > 0 {
		b.WriteString(`<nav class="contents"><div class="eyebrow">CONTENTS</div><ol>`)
		for i, sec := range d.Sections {
			fmt.Fprintf(b, `<li><span class="tn">%02d</span><a href="#s%d">%s</a></li>`,
				i+1, i+1, html.EscapeString(sec.Heading))
		}
		b.WriteString(`</ol></nav>`)
	}

	b.WriteString(`<main>`)
	for i, sec := range d.Sections {
		cls := ""
		// Only the appendices open a fresh page. Forcing one before the
		// findings left a half-empty page whenever the summary table was
		// short, which reads worse than a section starting mid-page.
		if strings.HasPrefix(sec.Heading, "Appendix") {
			cls = ` class="major"`
		}
		fmt.Fprintf(b, `<section id="s%d"><h2%s><span class="n">%02d</span>%s</h2>`, i+1, cls, i+1, html.EscapeString(sec.Heading))
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
				// A short table that splits leaves one stranded row on a
				// page of its own; keep it whole and let it move instead.
				tblClass := ""
				if len(blk.Rows) <= 10 {
					tblClass = ` class="keep"`
				}
				fmt.Fprintf(b, "<table%s>", tblClass)
				if len(blk.Widths) == len(blk.Headers) {
					b.WriteString("<colgroup>")
					for _, w := range blk.Widths {
						fmt.Fprintf(b, `<col style="width:%s">`, html.EscapeString(w))
					}
					b.WriteString("</colgroup>")
				}
				b.WriteString("<thead><tr>")
				for _, h := range blk.Headers {
					fmt.Fprintf(b, "<th>%s</th>", html.EscapeString(h))
				}
				b.WriteString("</tr></thead><tbody>")
				for _, row := range blk.Rows {
					b.WriteString("<tr>")
					for c := range blk.Headers {
						cell := ""
						if c < len(row) {
							cell = row[c]
						}
						tdClass := ""
						if monoColumn(blk.Headers[c]) {
							tdClass = ` class="mono"`
						}
						if class := pillClass(cell); class != "" {
							fmt.Fprintf(b, `<td%s><span class="%s">%s</span></td>`, tdClass, class, html.EscapeString(cell))
							continue
						}
						fmt.Fprintf(b, "<td%s>%s</td>", tdClass, html.EscapeString(cell))
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
		b.WriteString("</section>")
	}
	b.WriteString("</main>")
	fmt.Fprintf(b, `<div class="footer">Generated by %s · %s</div>`,
		html.EscapeString(docToolVersion(d)), html.EscapeString(docGeneratedAt(d)))
	b.WriteString("</body></html>")
}
