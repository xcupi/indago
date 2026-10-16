package report

// MarkdownGenerator renders the same Data a JSONGenerator does as readable
// Markdown. Like JSONGenerator, this is pure serialization: every value comes
// straight from the Finding/Scan/Project the caller supplies. It makes no
// security decision, computes no verdict, and does not depend on
// internal/detection or internal/verification — a Finding's Detail (an
// opaque, engine-specific JSON blob; see domain.Finding) is read through the
// shared FindingView (view.go), never by importing those packages.
//
// Layout: confirmed vulnerabilities first — each with the candidate whose
// browser verification succeeded and its evidence — then findings still needing
// review, then diagnostics (rejected attempts, explicitly NOT vulnerabilities).

import (
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

// Generate implements Generator. Output is deterministic: findings are ordered
// by Prioritized, attempts and evidence by their own stable orders, and every
// map-keyed breakdown is rendered in sorted key order, so the same Data always
// produces byte-identical Markdown.
func (MarkdownGenerator) Generate(w io.Writer, data Data) error {
	findings := Prioritized(data.Findings)
	idx := EvidenceIndex(data.Evidence)
	summary := dataSummary(data, findings)

	var b strings.Builder
	fmt.Fprintf(&b, "# Indago Scan Report\n\n")
	fmt.Fprintf(&b, "- **Tool:** indago %s\n", nonEmpty(data.ToolVersion, "dev"))
	fmt.Fprintf(&b, "- **Generated:** %s\n", data.GeneratedAt.UTC().Format("2006-01-02T15:04:05Z"))
	fmt.Fprintf(&b, "- **Project:** %s\n", nonEmpty(data.Project.Name, string(data.Project.ID)))
	fmt.Fprintf(&b, "- **Scan:** %s (`%s`)\n\n", nonEmpty(data.Scan.Name, string(data.Scan.ID)), data.Scan.ID)

	b.WriteString("## Summary\n\n")
	if sel := selectionLine(summary); sel != "" {
		fmt.Fprintf(&b, "- **Selection:** %s\n", sel)
	}
	fmt.Fprintf(&b, "- **Total findings:** %d\n", summary.TotalFindings)
	fmt.Fprintf(&b, "- **Confirmed:** %d\n", summary.ConfirmedCount)
	counts := sectionCounts(findings)
	fmt.Fprintf(&b, "- **Needs review:** %d\n", counts[SectionNeedsReview])
	fmt.Fprintf(&b, "- **Diagnostics (rejected, not vulnerabilities):** %d\n\n", counts[SectionDiagnostic])

	writeCountTable(&b, "By verdict", summary.ByVerdict)
	writeCountTable(&b, "By severity", summary.BySeverity)
	writeCountTable(&b, "By vulnerability class", summary.ByVulnClass)

	if len(findings) == 0 {
		b.WriteString("## Findings\n\n_No findings._\n")
	}
	n := 0
	for _, sec := range sectionOrder {
		var inSec []*domain.Finding
		for _, f := range findings {
			if FindingSection(f) == sec {
				inSec = append(inSec, f)
			}
		}
		if len(inSec) == 0 {
			continue
		}
		fmt.Fprintf(&b, "## %s\n\n", sec.Title())
		if sec == SectionDiagnostic {
			b.WriteString("_These candidates reflected but browser verification found no execution. They are kept for diagnosis; they are not vulnerabilities._\n\n")
		}
		for _, f := range inSec {
			n++
			writeFinding(&b, n, f, NewFindingView(f, idx))
		}
	}

	_, err := io.WriteString(w, b.String())
	return err
}

func sectionCounts(findings []*domain.Finding) map[Section]int {
	m := map[Section]int{}
	for _, f := range findings {
		m[FindingSection(f)]++
	}
	return m
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

func writeFinding(b *strings.Builder, n int, f *domain.Finding, v FindingView) {
	fmt.Fprintf(b, "### %d. %s\n\n", n, nonEmpty(f.Title, "(untitled finding)"))
	fmt.Fprintf(b, "- **Verdict:** %s\n", strings.ToUpper(string(f.Verdict)))
	fmt.Fprintf(b, "- **%s:** %s\n", SeverityLabel(f.Verdict), f.Severity)
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
	if v.ParamName != "" || v.Method != "" {
		fmt.Fprintf(b, "- **Parameter:** %s%s\n", v.ParamName, methodSuffix(v.Method))
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
		fmt.Fprintf(b, "- **%s:** %s\n", VerifiedAtLabel(f.Verdict), f.Provenance.VerifiedAt.UTC().Format("2006-01-02T15:04:05Z"))
	}
	if f.Summary != "" {
		fmt.Fprintf(b, "- **Notes:** %s\n", f.Summary)
	}
	if v.ReviewReasonLabel != "" {
		fmt.Fprintf(b, "- **Why this needs manual review (not a clean negative):** %s\n", v.ReviewReasonLabel)
		if v.ReviewReason == ReviewInteractionOnly {
			b.WriteString("- **How to check it yourself:** open the Tested URL for the attempt(s) below in a real browser and perform the action the candidate needs (hover, click, navigate) — Indago deliberately never simulates this (AGENTS.md §3).\n")
		}
	}
	b.WriteString("\n")

	if v.Verified != nil {
		b.WriteString("**Verified candidate** (the payload whose browser verification confirmed execution):\n\n")
		writeFence(b, v.Verified.CandidateValue)
		if v.Verified.Notes != "" {
			fmt.Fprintf(b, "- **Verification signal:** %s\n", v.Verified.Notes)
		}
		if c := candidateFor(v, v.Verified.CandidateValue); c != nil {
			fmt.Fprintf(b, "- **Context:** %s\n", c.Context)
			if c.Technique != "" {
				fmt.Fprintf(b, "- **Bypass technique:** %s — %s\n", c.Technique, c.Rationale)
			}
		}
		b.WriteString("\n")
		if len(v.Verified.Evidence) > 0 {
			b.WriteString("**Evidence for the verified candidate:**\n\n")
			writeEvidence(b, v.Verified.Evidence)
		}
	} else if f.Verdict == domain.VerdictConfirmed && len(v.Candidates) > 0 {
		b.WriteString("_The confirming attempt was not recorded for this finding (it predates per-attempt tracking). Candidates that reflected:_\n\n")
		for _, c := range v.Candidates {
			writeFence(b, c.Value)
		}
	}

	if others := otherAttempts(v); len(others) > 0 {
		heading := "**Other attempts** (kept as diagnostics):"
		if v.Verified == nil {
			heading = "**Attempts:**"
		}
		b.WriteString(heading + "\n\n| Candidate | Verdict | Tested URL |\n|---|---|---|\n")
		for _, a := range others {
			url := "—"
			if a.URL != "" {
				url = "`" + a.URL + "`"
			}
			fmt.Fprintf(b, "| %s | %s | %s |\n", mdCell(a.CandidateValue), a.Verdict, url)
		}
		b.WriteString("\n")
	}

	if len(v.Evidence) > 0 {
		fmt.Fprintf(b, "**All evidence (%d):**\n\n", len(v.Evidence))
		writeEvidence(b, v.Evidence)
	} else if len(f.EvidenceIDs) > 0 {
		ids := make([]string, len(f.EvidenceIDs))
		for i, id := range f.EvidenceIDs {
			ids[i] = "`" + string(id) + "`"
		}
		fmt.Fprintf(b, "- **Evidence (%d):** %s\n\n", len(f.EvidenceIDs), strings.Join(ids, ", "))
	}
}

// otherAttempts are the attempts other than the verified one, in the view's
// stable order.
func otherAttempts(v FindingView) []AttemptView {
	var out []AttemptView
	skipped := false
	for _, a := range v.Attempts {
		if v.Verified != nil && !skipped && a.VerifyTestCaseID == v.Verified.VerifyTestCaseID && a.CandidateValue == v.Verified.CandidateValue {
			skipped = true
			continue
		}
		out = append(out, a)
	}
	return out
}

func candidateFor(v FindingView, value string) *CandidateView {
	for i := range v.Candidates {
		if v.Candidates[i].Value == value {
			return &v.Candidates[i]
		}
	}
	return nil
}

// roleLabel names an evidence role for a reader. Baseline is spelled out so the
// ordinary value in it (e.g. q=hello) is never read as a payload.
func roleLabel(r domain.EvidenceRole) string {
	switch r {
	case domain.RoleBrowser:
		return "browser verification"
	case domain.RoleCandidate:
		return "candidate request/response"
	case domain.RoleBaseline:
		return "baseline reference (the unmodified request — not a payload)"
	}
	return string(r)
}

func writeEvidence(b *strings.Builder, evs []EvidenceView) {
	for _, e := range evs {
		fmt.Fprintf(b, "- `%s` — %s · %s", e.ID, roleLabel(e.Role), e.Kind)
		if e.MediaType != "" {
			fmt.Fprintf(b, " · %s", e.MediaType)
		}
		fmt.Fprintf(b, " · %d bytes", e.Size)
		if e.SHA256 != "" {
			fmt.Fprintf(b, " · sha256:%s", shortHash(e.SHA256))
		}
		b.WriteString("\n")
	}
	b.WriteString("\n")
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

// writeFence writes s as a fenced code block whose fence is longer than any
// backtick run inside s, so a candidate value can never break out of the block.
func writeFence(b *strings.Builder, s string) {
	longest, run := 0, 0
	for _, r := range s {
		if r == '`' {
			run++
			if run > longest {
				longest = run
			}
		} else {
			run = 0
		}
	}
	n := longest + 1
	if n < 3 {
		n = 3
	}
	fence := strings.Repeat("`", n)
	fmt.Fprintf(b, "%s\n%s\n%s\n\n", fence, s, fence)
}

// mdCell renders s inside a table cell: inline code with the pipe and any
// newline made safe.
func mdCell(s string) string {
	s = strings.NewReplacer("|", "\\|", "\n", "\\n", "\r", "").Replace(s)
	return "`" + strings.ReplaceAll(s, "`", "'") + "`"
}

func methodSuffix(method string) string {
	if method == "" {
		return ""
	}
	return " (" + method + ")"
}

func nonEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

var _ Generator = MarkdownGenerator{}
