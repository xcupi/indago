package report

// The two deliverable templates. See doc.go for the model and renderers.

import (
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"

	"github.com/indago/indago/internal/domain"
)

// docFor builds the document for the selected template. An unknown template
// (only reachable by bypassing Template.IsValid) falls back to pentest rather
// than producing a technical dump under a deliverable label.
func docFor(data Data) doc {
	if data.Template == TemplateBugBounty {
		return buildBugBountyDoc(data)
	}
	return buildPentestDoc(data)
}

// writeDocHTML renders the selected template as a self-contained HTML page.
func writeDocHTML(w io.Writer, data Data) error {
	var b strings.Builder
	docFor(data).renderHTML(&b)
	_, err := io.WriteString(w, b.String())
	return err
}

// Template selects the document layout a generator renders.
type Template string

const (
	// TemplateTechnical is the evidence-first layout the engine has always
	// produced (confirmed / needs review / diagnostics, with candidates).
	TemplateTechnical Template = ""
	TemplatePentest   Template = "pentest"
	TemplateBugBounty Template = "bug_bounty"
	// TemplateYesWeHack is the platform-specific submission layout: one
	// Markdown section per confirmed finding, with the platform's five
	// sections and its form fields as metadata. Markdown is its native
	// format; HTML/PDF fall back to the pentest document.
	TemplateYesWeHack Template = "yeswehack"
)

// IsValid reports whether the template is known. The empty value is the
// technical layout, so an older caller that never sets it keeps working.
func (t Template) IsValid() bool {
	switch t {
	case TemplateTechnical, TemplatePentest, TemplateBugBounty, TemplateYesWeHack:
		return true
	}
	return false
}

// classIntel is the factual per-class context a deliverable needs: the CWE the
// class maps to, the impact a reader should understand, and the remediation
// that class is normally fixed with. It is reference material — the finding's
// own verdict and evidence remain authoritative.
type classIntel struct {
	CWE         string
	Name        string
	Impact      string
	Remediation string
	References  []string
}

const refOWASPXSS = "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"

var classIntelByClass = map[domain.VulnClass]classIntel{
	domain.VulnReflectedXSS: {
		CWE:  "CWE-79",
		Name: "Reflected cross-site scripting",
		Impact: "An attacker can run script in a victim's browser in the context of this origin: read the " +
			"session, act as the user, or pivot to the user's other sessions. The payload is delivered in a " +
			"crafted link, so exploitation needs the victim to follow it.",
		Remediation: "Apply context-aware output encoding at the exact sink (HTML body, attribute, JS string, " +
			"URL), prefer framework auto-escaping, and add a Content-Security-Policy as defence in depth.",
		References: []string{"https://cwe.mitre.org/data/definitions/79.html", refOWASPXSS},
	},
	domain.VulnStoredXSS: {
		CWE:  "CWE-79",
		Name: "Stored cross-site scripting",
		Impact: "Script is persisted by the application and executes for every viewer: session theft, " +
			"action-on-behalf, or worm-like spread without a per-victim lure.",
		Remediation: "Encode on OUTPUT at the sink (not only on input), sanitise rich text with an allow-list, " +
			"and add a Content-Security-Policy.",
		References: []string{"https://cwe.mitre.org/data/definitions/79.html", refOWASPXSS},
	},
	domain.VulnDOMXSS: {
		CWE:  "CWE-79",
		Name: "DOM-based cross-site scripting",
		Impact: "Client-side code moves attacker-controlled data into an executable sink, so the server never " +
			"sees the payload and server-side filters do not apply.",
		Remediation: "Use safe sinks (textContent, setAttribute for non-URL attributes), validate URL schemes, " +
			"and avoid eval/Function/string timers with untrusted data.",
		References: []string{"https://cwe.mitre.org/data/definitions/79.html", "https://owasp.org/www-community/attacks/DOM_Based_XSS"},
	},
	domain.VulnIDOR: {
		CWE:  "CWE-639",
		Name: "Insecure direct object reference",
		Impact: "An authenticated user can read or act on another principal's object by changing an " +
			"identifier, exposing data across accounts.",
		Remediation: "Authorize every object access server-side against the caller's identity (not the " +
			"supplied id), and prefer unguessable identifiers as defence in depth.",
		References: []string{"https://cwe.mitre.org/data/definitions/639.html", "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"},
	},
	domain.VulnAccessControl: {
		CWE:  "CWE-284",
		Name: "Broken access control",
		Impact: "A privileged surface or action is reachable by a caller who should be denied, enabling " +
			"function-level escalation (admin actions, role changes, protected endpoints).",
		Remediation: "Enforce authorization server-side on every route and method (deny by default), and do " +
			"not trust client-supplied path/method/header overrides for the decision.",
		References: []string{"https://cwe.mitre.org/data/definitions/284.html", "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/"},
	},
	domain.VulnInfoDisclosure: {
		CWE:  "CWE-200",
		Name: "Information disclosure",
		Impact: "Configuration, source code, credentials or version data reachable by the caller shortens " +
			"the path to a deeper compromise.",
		Remediation: "Remove debug artefacts and served metadata from production, return generic errors, and " +
			"exclude repository/VCS files at the web root.",
		References: []string{"https://cwe.mitre.org/data/definitions/200.html"},
	},
}

func intelFor(class domain.VulnClass) classIntel {
	if in, ok := classIntelByClass[class]; ok {
		return in
	}
	name := strings.ReplaceAll(string(class), "_", " ")
	if name == "" {
		name = "finding"
	}
	return classIntel{
		CWE:         "n/a",
		Name:        name,
		Impact:      "Impact depends on the finding's own evidence; see the technical detail.",
		Remediation: "Fix the root cause identified in the finding and re-test the same request.",
		References:  []string{},
	}
}

// deliverableFindings returns the findings a deliverable reports: confirmed
// first, then those awaiting review. Rejected diagnostics are not
// vulnerabilities and stay out of the deliverable body; their count is noted.
func deliverableFindings(data Data) ([]*domain.Finding, int) {
	all := Prioritized(data.Findings)
	out := make([]*domain.Finding, 0, len(all))
	diagnostics := 0
	for _, f := range all {
		if f.Verdict == domain.VerdictRejected {
			diagnostics++
			continue
		}
		out = append(out, f)
	}
	return out, diagnostics
}

func severityCounts(findings []*domain.Finding) map[string]int {
	out := map[string]int{}
	for _, f := range findings {
		if f.Verdict != domain.VerdictConfirmed {
			continue
		}
		out[string(f.Severity)]++
	}
	return out
}

func severityLine(counts map[string]int) string {
	order := []string{"critical", "high", "medium", "low", "info"}
	parts := make([]string, 0, len(order))
	for _, sev := range order {
		if counts[sev] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[sev], sev))
		}
	}
	if len(parts) == 0 {
		return "no confirmed findings"
	}
	return strings.Join(parts, ", ")
}

func scopeSeeds(data Data) []string {
	if len(data.Scan.SeedURLs) > 0 {
		return data.Scan.SeedURLs
	}
	return []string{string(data.Scan.ID) + " (target base URL)"}
}

// buildPentestDoc is the client-deliverable layout: confidentiality, engagement,
// executive summary, approach, summary table, technical findings, remediation
// roadmap, appendices.
func buildPentestDoc(data Data) doc {
	findings, diagnostics := deliverableFindings(data)
	idx := EvidenceIndex(data.Evidence)
	coverage := coverageFor(data)
	view := NewFindingView
	counts := severityCounts(findings)
	seedLabel := seedLabelFor(len(scopeSeeds(data)))

	d := doc{
		Title:    fmt.Sprintf("Penetration Test Report — %s", nonEmpty(data.Project.Name, string(data.Project.ID))),
		Subtitle: nonEmpty(data.Scan.Name, string(data.Scan.ID)),
		Meta:     docPreamble(data),
		Highlights: [][2]string{
			{"Confirmed findings", fmt.Sprintf("%d", len(confirmedOnly(findings)))},
			{"High / critical", fmt.Sprintf("%d", counts["high"]+counts["critical"])},
			{"Coverage", coverageShort(coverage)},
			{seedLabel, fmt.Sprintf("%d", len(scopeSeeds(data)))},
		},
	}

	d.Sections = append(d.Sections, section("Statement of Confidentiality",
		para("This report contains confidential security information about the target described below. "+
			"It is provided to the commissioning party for the purpose of remediating the issues it documents, "+
			"and must not be redistributed outside that party without written consent. The assessment was "+
			"performed with authorization against the scope recorded here; findings describe the state observed "+
			"at the time of testing and are not a guarantee that the target is free of other issues."),
	))

	scope := []string{}
	for _, seed := range scopeSeeds(data) {
		scope = append(scope, "In-scope seed: "+seed)
	}
	scope = append(scope,
		fmt.Sprintf("Profile: %s · scan %s", data.Scan.Profile, data.Scan.ID),
		fmt.Sprintf("Findings included: %s", selectionLine(dataSummary(data, findings))),
	)
	if data.Scan.StartedAt != nil {
		scope = append(scope, "Testing started: "+data.Scan.StartedAt.UTC().Format("2006-01-02 15:04"))
	}
	if data.Scan.EndedAt != nil {
		scope = append(scope, "Testing ended: "+data.Scan.EndedAt.UTC().Format("2006-01-02 15:04"))
	}
	d.Sections = append(d.Sections, section("Engagement & Scope", list(scope...)))

	execHeadline := fmt.Sprintf("%d confirmed finding(s): %s.", len(confirmedOnly(findings)), severityLine(counts))
	var execFindings []string
	for _, f := range findings {
		if f.Verdict != domain.VerdictConfirmed {
			continue
		}
		execFindings = append(execFindings, fmt.Sprintf("%s — %s (%s)", f.Title, strings.ToUpper(string(f.Severity)), intelFor(f.VulnClass).CWE))
	}
	exec := execFindings
	if len(exec) == 0 {
		exec = append(exec, "No confirmed findings were recorded in the selected set.")
	}
	if diagnostics > 0 {
		exec = append(exec, fmt.Sprintf("%d rejected diagnostic attempt(s) are excluded from this body; they are not vulnerabilities.", diagnostics))
	}
	execBlocks := []docBlock{
		para(fmt.Sprintf("%s was assessed with indago. %s", nonEmpty(data.Project.Name, "The target"), coverageSentence(coverage))),
	}
	execBlocks = append(execBlocks, para(execHeadline))
	if strings.TrimSpace(data.AISummary) != "" {
		execBlocks = append(execBlocks, para("AI-assisted draft (unverified, advisory only — the findings below are the authoritative record): "+data.AISummary))
	}
	if len(exec) > 0 {
		execBlocks = append(execBlocks, list(exec...))
	}
	d.Sections = append(d.Sections, section("Executive Summary", execBlocks...))

	approach := []string{
		"Discovery enumerated endpoints and parameters from the in-scope seeds, then classified each response position.",
		"Reflected and DOM XSS candidates are confirmed only by a real browser execution signal (a marker-specific ReferenceError), never by reflection alone.",
		"Access-control probes are differential and read-only: a denied surface must answer differently to the bypass variant, and the reachable surface must expose a privileged action.",
		"IDOR probes compare the caller's own object against a harvested foreign identifier and require a different principal's data.",
		"Information-disclosure probes classify bytes the scan already reached (debug pages, backup source, stack traces, served .git metadata).",
	}
	d.Sections = append(d.Sections, section("Approach & Methodology", list(approach...)))

	summaryRows := make([][]string, 0, len(findings))
	for i, f := range findings {
		summaryRows = append(summaryRows, []string{
			fmt.Sprintf("%d", i+1),
			strings.ToUpper(string(f.Severity)),
			intelFor(f.VulnClass).Name,
			f.Title,
			endpointLabel(f, view(f, idx), data.Endpoints[f.EndpointID]),
		})
	}
	if len(summaryRows) == 0 {
		summaryRows = append(summaryRows, []string{"—", "—", "—", "No findings in this selection", "—"})
	}
	targetLine := "Target: " + strings.Join(uniqueHosts(findings, view, idx), ", ")
	d.Sections = append(d.Sections, section("Summary of Findings",
		para(targetLine),
		sizedTable(
			[]string{"#", "Severity", "Class", "Finding", "Endpoint"},
			[]string{"5%", "11%", "17%", "50%", "17%"},
			summaryRows),
	))

	tech := []docBlock{}
	for i, f := range findings {
		v := view(f, idx)
		in := intelFor(f.VulnClass)
		tech = append(tech, sub(fmt.Sprintf("%d. %s — %s", i+1, f.Title, strings.ToUpper(string(f.Severity)))))
		tech = append(tech, list(
			"CWE: "+in.CWE+" ("+in.Name+")",
			"Verdict: "+strings.ToUpper(string(f.Verdict))+" · severity "+string(f.Severity)+" · confidence "+string(f.Confidence),
			"Affected asset: "+findingAsset(f, v),
		))
		if f.Summary != "" {
			tech = append(tech, para("Description: "+f.Summary))
		}
		tech = append(tech, para("Impact: "+in.Impact))
		tech = append(tech, para("Remediation: "+in.Remediation))
		if len(in.References) > 0 {
			tech = append(tech, list(prefixed("Reference: ", in.References)...))
		}
		if v.Verified != nil && v.Verified.CandidateValue != "" {
			tech = append(tech, para("Verified request / payload:"), code(candidateProof(v)))
		}
		if len(f.EvidenceIDs) > 0 {
			tech = append(tech, sub("Evidence"), evidenceTable(f, idx))
		} else {
			tech = append(tech, para("Evidence: no stored artifacts for this finding."))
		}
	}
	if len(tech) == 0 {
		tech = append(tech, para("No confirmed or reviewable findings in this selection."))
	}
	d.Sections = append(d.Sections, section("Technical Findings Details", tech...))

	short, medium, long := []string{}, []string{}, []string{}
	shortM, mediumM, longM := map[string]*roadmapItem{}, map[string]*roadmapItem{}, map[string]*roadmapItem{}
	for _, f := range findings {
		in := intelFor(f.VulnClass)
		switch f.Severity {
		case domain.SeverityCritical, domain.SeverityHigh:
			addRoadmap(shortM, in, f.Title)
		case domain.SeverityMedium:
			addRoadmap(mediumM, in, f.Title)
		default:
			addRoadmap(longM, in, f.Title)
		}
	}
	short, medium, long = roadmapLines(shortM), roadmapLines(mediumM), roadmapLines(longM)
	roadmap := [][]string{
		{"Immediate", "0-7 days", joinOr(short, "None in this selection.")},
		{"Planned", "30 days", joinOr(medium, "None in this selection.")},
		{"Backlog", "90 days", joinOr(long, "None in this selection.")},
	}
	d.Sections = append(d.Sections, section("Remediation Summary",
		para("Ordered by the severity of the finding each item fixes. Timeframes are the usual triage windows, not a commitment made by this report."),
		sizedTable([]string{"Priority", "Timeframe", "Action"}, []string{"16%", "13%", "71%"}, roadmap),
	))

	d.Sections = append(d.Sections, section("Appendix A — Finding Severities",
		table([]string{"Severity", "Meaning"}, [][]string{
			{"Critical", "Direct path to broad compromise; fix before further exposure."},
			{"High", "Serious impact with realistic exploitation; fix in the short term."},
			{"Medium", "Material weakness requiring specific conditions; schedule a fix."},
			{"Low", "Limited impact or defence-in-depth gap."},
			{"Info", "Observation without a demonstrated security impact."},
		}),
	))

	evRows := [][]string{}
	for _, f := range findings {
		for _, id := range f.EvidenceIDs {
			kind, size := "—", ""
			if ev := idx[id]; ev != nil {
				kind = string(ev.Kind)
				size = fmt.Sprintf("%d bytes", ev.Size)
			}
			evRows = append(evRows, []string{string(id), f.Title, kind, size})
		}
	}
	if len(evRows) == 0 {
		evRows = append(evRows, []string{"—", "No evidence referenced by this selection", "—", "—"})
	}
	d.Sections = append(d.Sections, section("Appendix B — Evidence Inventory",
		sizedTable([]string{"Evidence", "Finding", "Kind", "Size"}, []string{"38%", "34%", "16%", "12%"}, evRows),
	))

	d.Sections = append(d.Sections, section("Appendix C — Coverage",
		para(coverageSentence(coverage)),
		list(coverageBullets(coverage)...),
	))
	return d
}

// buildBugBountyDoc renders one submission-shaped block per finding: asset,
// severity, CWE, reproduction, impact, remediation, references, evidence.
func buildBugBountyDoc(data Data) doc {
	findings, diagnostics := deliverableFindings(data)
	idx := EvidenceIndex(data.Evidence)
	view := NewFindingView
	seedLabel := seedLabelFor(len(scopeSeeds(data)))

	d := doc{
		Title:    fmt.Sprintf("Bug Bounty Report — %s", nonEmpty(data.Project.Name, string(data.Project.ID))),
		Subtitle: "Submission-ready findings from one authorized scan",
		Meta:     docPreamble(data),
		Highlights: [][2]string{
			{"Findings", fmt.Sprintf("%d", len(findings))},
			{"Confirmed", fmt.Sprintf("%d", len(confirmedOnly(findings)))},
			{"Highest severity", highestSeverity(findings)},
			{seedLabel, fmt.Sprintf("%d", len(scopeSeeds(data)))},
		},
	}

	assetList := []string{}
	for _, seed := range scopeSeeds(data) {
		assetList = append(assetList, seed)
	}
	if diagnostics > 0 {
		assetList = append(assetList, fmt.Sprintf("%d rejected diagnostic attempt(s) excluded (not vulnerabilities).", diagnostics))
	}
	d.Sections = append(d.Sections, section("Scope & Asset",
		list(assetList...),
		para("All testing was authorized and limited to the seeds above. Requests were rate-limited and read-only except where a probe required a benign form submission; no destructive action was performed."),
	))

	if len(findings) == 0 {
		d.Sections = append(d.Sections, section("Result", para("No confirmed or reviewable findings were recorded in this selection.")))
		return d
	}

	for i, f := range findings {
		v := view(f, idx)
		in := intelFor(f.VulnClass)
		body := []docBlock{
			list(
				"Asset: "+findingAsset(f, v),
				"Severity: "+strings.ToUpper(string(f.Severity))+" · confidence "+string(f.Confidence),
				"CWE: "+in.CWE+" ("+in.Name+")",
				"CVSS: not scored — severity is the engine's verdict, not a CVSS computation",
				"Vulnerability class: "+string(f.VulnClass),
			),
			sub("Description"),
			para(sentenceCase(nonEmpty(f.Summary, f.Title))),
		}
		body = append(body, sub("Steps to reproduce"))
		steps := []string{
			"Request the affected asset recorded above.",
		}
		if v.Method != "" && v.ParamName != "" {
			steps = append(steps, fmt.Sprintf("Inject into %s parameter %q.", v.Method, v.ParamName))
		}
		if v.Verified != nil && v.Verified.URL != "" {
			steps = append(steps, "Use the exact verified request below.")
		} else {
			steps = append(steps, "Use the candidate recorded in the evidence bundle.")
		}
		steps = append(steps, "Observe the browser signal recorded in the result block below.")
		body = append(body, list(steps...))
		if v.Verified != nil && v.Verified.CandidateValue != "" {
			body = append(body, code(candidateProof(v)))
		}
		body = append(body,
			sub("Impact"),
			para(in.Impact),
			sub("Remediation"),
			para(in.Remediation),
		)
		if len(in.References) > 0 {
			body = append(body, sub("References"), list(in.References...))
		}
		body = append(body, sub("Evidence"))
		if len(f.EvidenceIDs) > 0 {
			body = append(body, evidenceTable(f, idx))
		} else {
			body = append(body, para("No stored artifacts for this finding."))
		}

		heading := fmt.Sprintf("Finding %d — %s", i+1, f.Title)
		d.Sections = append(d.Sections, section(heading, body...))
	}

	d.Sections = append(d.Sections, section("Appendix — Severity Ratings",
		table([]string{"Severity", "Typical bounty band"}, [][]string{
			{"Critical", "Remote compromise of the asset's core trust boundary"},
			{"High", "Account/session compromise or privileged action as another user"},
			{"Medium", "Limited data exposure or action requiring user interaction"},
			{"Low", "Defence-in-depth or low-impact disclosure"},
			{"Info", "Observation without demonstrated impact"},
		}),
	))
	return d
}

// sub is a sub-heading block (h3 in HTML, "###" in Markdown).
func sub(text string) docBlock { return docBlock{Kind: docSubheading, Text: text} }

func prefixed(prefix string, items []string) []string {
	out := make([]string, 0, len(items))
	for _, s := range items {
		out = append(out, prefix+s)
	}
	return out
}

// roadmapItem groups the findings that share one fix, so a table cell does not
// repeat the same remediation paragraph once per finding.
type roadmapItem struct {
	fix    string
	cwe    string
	titles []string
}

func addRoadmap(m map[string]*roadmapItem, in classIntel, title string) {
	key := in.CWE + "|" + in.Remediation
	it := m[key]
	if it == nil {
		it = &roadmapItem{fix: in.Remediation, cwe: in.CWE}
		m[key] = it
	}
	it.titles = append(it.titles, title)
}

// roadmapLines renders one line per distinct fix, sorted so the report stays
// byte-identical between runs (map iteration order is not stable).
func roadmapLines(m map[string]*roadmapItem) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		it := m[k]
		out = append(out, fmt.Sprintf("%s — %s (%s)", strings.Join(it.titles, "; "), it.fix, it.cwe))
	}
	return out
}

// joinOr renders a roadmap cell: the items separated by "; ", or the fallback
// when the bucket is empty.
func joinOr(items []string, fallback string) string {
	if len(items) == 0 {
		return fallback
	}
	return strings.Join(items, "; ")
}

// seedLabel keeps the KPI label grammatical for one seed.
func seedLabelFor(n int) string {
	if n == 1 {
		return "In-scope seed"
	}
	return "In-scope seeds"
}

// coverageShort is the cover's one-word coverage state.
func coverageShort(c Completeness) string {
	switch {
	case c.Complete():
		return "Complete"
	case c.State == "":
		return "Unknown"
	default:
		return "Incomplete"
	}
}

// highestSeverity is the worst severity among the reported findings, for the
// bounty cover. It never derives a new rating: it is the max of stored values.
func highestSeverity(findings []*domain.Finding) string {
	rank := map[domain.Severity]int{
		domain.SeverityCritical: 5, domain.SeverityHigh: 4,
		domain.SeverityMedium: 3, domain.SeverityLow: 2, domain.SeverityInfo: 1,
	}
	best := domain.SeverityInfo
	bestRank := 0
	for _, f := range findings {
		if r := rank[f.Severity]; r > bestRank {
			best, bestRank = f.Severity, r
		}
	}
	if bestRank == 0 {
		return "—"
	}
	return strings.ToUpper(string(best))
}

// evidenceTable renders one finding's artifacts as rows, instead of the dense
// semicolon-separated paragraph the same data produces in the appendix note.
func evidenceTable(f *domain.Finding, idx map[domain.ID]*domain.Evidence) docBlock {
	rows := make([][]string, 0, len(f.EvidenceIDs))
	for _, id := range f.EvidenceIDs {
		kind, size := "artifact", ""
		if ev := idx[id]; ev != nil {
			kind = string(ev.Kind)
			size = humanBytes(ev.Size)
		}
		typ := kind
		if size != "" {
			typ = kind + " · " + size
		}
		rows = append(rows, []string{string(id), typ})
	}
	return sizedTable([]string{"Artifact", "Type"}, []string{"58%", "42%"}, rows)
}

// humanBytes keeps the size column short enough that an artefact table does
// not push a following section onto its own page.
func humanBytes(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0f KB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

// sentenceCase capitalises the first letter of an engine note used as a
// sentence ("the browser reported…" reads like a typo in a report body).
func sentenceCase(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	if r[0] >= 'a' && r[0] <= 'z' {
		r[0] = r[0] - 'a' + 'A'
	}
	return string(r)
}

// endpointLabel is the summary table's Endpoint cell: method plus path, with
// the query dropped (the injected value there is huge and differs per row
// only by the marker, so it hides which endpoint is which).
func endpointLabel(f *domain.Finding, v FindingView, endpointURL string) string {
	method := strings.TrimSpace(v.Method)
	u := endpointURL
	if u == "" {
		u = verifiedURL(v)
	}
	if u != "" {
		path := "/"
		if parsed, err := url.Parse(u); err == nil {
			if parsed.Path != "" {
				path = parsed.Path
			}
			// Keep the query KEYS (they say which parameter is exercised) but
			// drop the values, which are the injected payload.
			if keys := queryKeys(parsed.RawQuery); keys != "" {
				path += "?" + keys
			}
		}
		if method == "" {
			return path
		}
		return method + " " + path
	}
	if method != "" && v.ParamName != "" {
		return method + " · " + v.ParamName
	}
	return "—"
}

// queryKeys lists the parameter names in a raw query, without their values.
func queryKeys(raw string) string {
	if raw == "" {
		return ""
	}
	values, err := url.ParseQuery(raw)
	if err != nil {
		return ""
	}
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) > 2 {
		keys = keys[:2]
	}
	return strings.Join(keys, "&")
}

// verifiedURL is the exact request the verifier replayed, when there is one.
func verifiedURL(v FindingView) string {
	if v.Verified != nil {
		return v.Verified.URL
	}
	return ""
}

// uniqueHosts lists the distinct hosts the reported findings touch, so the
// summary table can be read without a (truncated) URL in every row.
func uniqueHosts(findings []*domain.Finding, view func(*domain.Finding, map[domain.ID]*domain.Evidence) FindingView, idx map[domain.ID]*domain.Evidence) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range findings {
		u := verifiedURL(view(f, idx))
		if u == "" {
			continue
		}
		parsed, err := url.Parse(u)
		if err != nil || parsed.Host == "" {
			continue
		}
		if !seen[parsed.Host] {
			seen[parsed.Host] = true
			out = append(out, parsed.Host)
		}
	}
	if len(out) == 0 {
		return []string{"see scope"}
	}
	sort.Strings(out)
	return out
}

func confirmedOnly(findings []*domain.Finding) []*domain.Finding {
	out := make([]*domain.Finding, 0, len(findings))
	for _, f := range findings {
		if f.Verdict == domain.VerdictConfirmed {
			out = append(out, f)
		}
	}
	return out
}

// candidateProof is the copy-paste proof block: URL first (when the verifier
// navigated), then the exact candidate value.
func candidateProof(v FindingView) string {
	parts := []string{}
	if v.Verified != nil {
		if v.Verified.URL != "" {
			parts = append(parts, "URL: "+v.Verified.URL)
		}
		if v.Verified.CandidateValue != "" {
			parts = append(parts, "Candidate: "+v.Verified.CandidateValue)
		}
		if v.Verified.Notes != "" {
			parts = append(parts, "Result: "+v.Verified.Notes)
		}
	}
	if len(parts) == 0 {
		return "No verified request recorded for this finding."
	}
	return strings.Join(parts, "\n")
}

func verificationSignal(v FindingView) string {
	if v.Verified != nil && v.Verified.Notes != "" {
		return v.Verified.Notes
	}
	if v.ReviewReasonLabel != "" {
		return v.ReviewReasonLabel
	}
	return "the stored evidence for this finding"
}

func coverageSentence(c Completeness) string {
	if c.Complete() {
		if c.HasTestCaseGaps() {
			return fmt.Sprintf("Scan reached the completed state; %s (worker retry may have recovered some).", c.testCaseGapText())
		}
		return "Scan completed without job-level coverage gaps."
	}
	return fmt.Sprintf("Coverage is INCOMPLETE: scan state %s, dead jobs %d, failed jobs %d, canceled jobs %d, error test cases %d, timeout test cases %d. Absence of findings does not mean the target is clean.",
		nonEmpty(string(c.State), "unknown"), c.DeadJobs, c.FailedJobs, c.CanceledJobs, c.ErrorTestCases, c.TimeoutTestCases)
}

func coverageBullets(c Completeness) []string {
	return []string{
		fmt.Sprintf("Scan state: %s", nonEmpty(string(c.State), "unknown")),
		fmt.Sprintf("Dead / failed / canceled jobs: %d / %d / %d", c.DeadJobs, c.FailedJobs, c.CanceledJobs),
		fmt.Sprintf("Error / timeout test cases: %d / %d", c.ErrorTestCases, c.TimeoutTestCases),
	}
}

// sortedSeverities is used by tests to keep deterministic output when checking
// severity keys.
func sortedSeverities(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
