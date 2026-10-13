package web_test

// Real-browser UI tests for the findings views: the default confirmed-only
// view and its filters, the verified candidate, role-labelled evidence,
// filter-aware selection across re-renders, report modes — and page layout
// (footer in flow, long text wrapping). Like ui_integration_test.go they drive
// the actual dashboard in headless Chromium against a live server and skip
// quickly without Chromium.

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/scan"
)

// uiFindingsScan creates a project/scope/target/scan directly (the operator
// workflow itself is covered by TestUIOperationalWorkflow).
func uiFindingsScan(t *testing.T, u *uiHarness) domain.ID {
	t.Helper()
	ctx := context.Background()
	now := time.Now()
	p := &domain.Project{ID: domain.NewID(), Name: "findings-ui", CreatedAt: now, UpdatedAt: now}
	if err := u.st.Projects().Create(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err := u.st.Scopes().Create(ctx, &domain.Scope{ID: domain.NewID(), ProjectID: p.ID, IncludeHosts: []string{"127.0.0.1"}, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	tg := &domain.Target{ID: domain.NewID(), ProjectID: p.ID, Name: "t", BaseURL: "http://127.0.0.1:9/", CreatedAt: now, UpdatedAt: now}
	if err := u.st.Targets().Create(ctx, tg); err != nil {
		t.Fatal(err)
	}
	sc, err := u.ctrl.CreateScan(ctx, scan.CreateScanParams{ProjectID: p.ID, TargetID: tg.ID, Name: "findings-ui"})
	if err != nil {
		t.Fatal(err)
	}
	return sc.ID
}

// uiFindingOpts tunes uiFinding.
type uiFindingOpts struct {
	payload string // the confirming/rejected candidate value (default: a short svg onload)
	path    string
	longURL bool // give the endpoint a very long query string
	// longMedia gives the browser evidence one very long, unbreakable media type.
	longMedia bool
}

// uiFinding stores a finding the way the real pipeline does: evidence rows
// created BEFORE the finding (no finding_id) and linked only through
// Finding.EvidenceIDs — a BASELINE request carrying the ordinary value
// "hello", the candidate's own request, and a browser-captured DOM (whose
// script must never run when opened) — plus per-attempt results in Detail.
func uiFinding(t *testing.T, u *uiHarness, scanID domain.ID, v domain.Verdict, o uiFindingOpts, at time.Time) *domain.Finding {
	t.Helper()
	ctx := context.Background()
	if o.payload == "" {
		o.payload = "<svg onload=ind" + strings.Trim(o.path, "/") + ">"
	}
	epURL := "http://127.0.0.1:9" + o.path + "?q=hello"
	if o.longURL {
		epURL += "&" + strings.Repeat("longparam", 30) + "=1"
	}
	ep := &domain.Endpoint{ID: domain.NewID(), ScanID: scanID, URL: epURL, Method: domain.MethodGET, Source: domain.SourceCrawler, CreatedAt: at}
	if err := u.st.Endpoints().Create(ctx, ep); err != nil {
		t.Fatal(err)
	}
	mk := func(kind domain.EvidenceKind, ext, mt, note, body string) domain.ID {
		ref, err := u.ev.Put(scanID, kind, ext, []byte(body+o.path))
		if err != nil {
			t.Fatal(err)
		}
		row := &domain.Evidence{ID: domain.NewID(), ScanID: scanID, Kind: kind, MediaType: mt, BlobPath: ref.BlobPath, Size: ref.Size, SHA256: ref.SHA256, Note: note, CreatedAt: at}
		if err := u.st.Evidence().Create(ctx, row); err != nil {
			t.Fatal(err)
		}
		return row.ID
	}
	baseReq := mk(domain.EvidenceRequest, ".http", "message/http", "baseline GET "+epURL+" request", "GET "+o.path+"?q=hello HTTP/1.1\r\n\r\n")
	candReq := mk(domain.EvidenceRequest, ".http", "message/http", "test_case=c request", "GET "+o.path+"?q="+o.payload+" HTTP/1.1\r\nCookie: s=1\r\n\r\n")
	domMedia := "text/html"
	if o.longMedia {
		domMedia = "text/x-" + strings.Repeat("verylongmediatype", 15)
	}
	dom := mk(domain.EvidenceDOM, ".html", domMedia, "test_case=v rendered DOM", "<html><head><title>captured</title></head><body><script>document.title='PWNED'</script></body></html>")
	ids := []domain.ID{baseReq, candReq, dom}

	title := fmt.Sprintf(`Reflected XSS candidate in parameter "q" (html_text) at GET %s?q`, o.path)
	attempt := func(val string, verdict domain.Verdict, notes string, evs ...domain.ID) string {
		q := make([]string, len(evs))
		for i, e := range evs {
			q[i] = `"` + string(e) + `"`
		}
		return fmt.Sprintf(`{"candidate_value":%q,"verify_test_case_id":"vt-%s-%s","verdict":%q,"notes":%q,"evidence_ids":[%s],"at":%q}`,
			val, o.path, verdict, verdict, notes, strings.Join(q, ","), at.Add(time.Second).UTC().Format(time.RFC3339Nano))
	}
	attempts := ""
	switch v {
	case domain.VerdictConfirmed:
		title = fmt.Sprintf(`Reflected XSS in parameter "q" (html_text) at GET %s?q`, o.path)
		attempts = attempt(o.payload, domain.VerdictConfirmed, "uncaught ReferenceError named the marker", baseReq, candReq, dom) + "," +
			attempt("<indprobe"+strings.Trim(o.path, "/")+"x>", domain.VerdictRejected, "", baseReq, candReq)
	case domain.VerdictRejected:
		attempts = attempt(o.payload, domain.VerdictRejected, "", baseReq, candReq, dom)
	}
	detail := fmt.Sprintf(`{"method":"GET","parameter_name":"q","occurrences":2,"candidates":[{"context":"html_text","value":%q,"trigger":"load"}],"attempts":[%s]}`, o.payload, attempts)
	f := &domain.Finding{
		ID: domain.NewID(), ScanID: scanID, VulnClass: domain.VulnReflectedXSS, Verdict: v,
		Severity: domain.SeverityHigh, Confidence: domain.ConfidenceMedium, EndpointID: ep.ID,
		Title: title, EvidenceIDs: ids, Detail: []byte(detail), CreatedAt: at, UpdatedAt: at,
	}
	if err := u.st.Findings().Create(ctx, f); err != nil {
		t.Fatal(err)
	}
	return f
}

// open navigates the dashboard (in place, no reload) to a scan tab.
func (u *uiHarness) openScanTab(scanID domain.ID, tab string) {
	u.eval(fmt.Sprintf(`navigate(%q)`, "#/scans/"+string(scanID)+"/"+tab))
}

func (u *uiHarness) rows() string {
	return `document.querySelectorAll('#findingsBody tr[data-finding-id]')`
}

// --- default view, verified candidate, baseline, filters --------------------

func TestUIFindingsDefaultViewShowsConfirmedWithVerifiedCandidate(t *testing.T) {
	u := newUIHarness(t)
	scanID := uiFindingsScan(t, u)
	base := time.Now()
	a := uiFinding(t, u, scanID, domain.VerdictConfirmed, uiFindingOpts{path: "/a"}, base)
	uiFinding(t, u, scanID, domain.VerdictConfirmed, uiFindingOpts{path: "/b"}, base.Add(time.Second))
	uiFinding(t, u, scanID, domain.VerdictRejected, uiFindingOpts{path: "/c"}, base.Add(2*time.Second))
	uiFinding(t, u, scanID, domain.VerdictPending, uiFindingOpts{path: "/d"}, base.Add(3*time.Second))

	u.openScanTab(scanID, "findings")
	u.waitUI("confirmed findings only", u.rows()+`.length===2`)

	// The rejected attempt and the unverified candidate are not shown as vulnerabilities.
	if u.evalBool(`/\/c\?q/.test(document.getElementById('findingsBody').textContent) || /\/d\?q/.test(document.getElementById('findingsBody').textContent)`) {
		t.Fatal("a rejected/unverified finding is listed in the default view")
	}
	// Filter buttons carry live counts; Confirmed is the active one.
	u.waitUI("filter counts", `document.getElementById('view_confirmed').textContent==='Confirmed vulnerabilities (2)'
		&& document.getElementById('view_review').textContent==='Needs review (1)'
		&& document.getElementById('view_diagnostic').textContent==='Diagnostics (rejected) (1)'
		&& document.getElementById('view_all').textContent==='All (4)'
		&& document.getElementById('view_confirmed').getAttribute('aria-pressed')==='true'`)

	// The verified candidate is shown in the list — and it is the payload, never
	// the ordinary baseline value.
	if got := u.evalStr(`document.querySelector('#findingsBody tr[data-finding-id="` + string(a.ID) + `"] td.verified-cell').textContent`); got != "<svg onload=inda>" {
		t.Fatalf("verified candidate cell = %q", got)
	}
	if u.evalBool(`/hello/.test(document.getElementById('findingsBody').textContent.replace(/\?q/g,''))`) {
		t.Fatal("the baseline value 'hello' appears in the findings table")
	}
	// A confirmed finding no longer calls itself a candidate.
	if u.evalBool(`/candidate in parameter/.test(document.getElementById('findingsBody').textContent)`) {
		t.Fatal("a confirmed finding is still titled a 'candidate'")
	}

	// Detail: the verified candidate is the first and most prominent thing,
	// with its own evidence; the rejected probe is an attempt below it; the
	// baseline is evidence labelled as a reference.
	u.eval(fmt.Sprintf(`(function(){document.querySelector('#findingsBody tr[data-finding-id=%q] td.clickable').click();return true;})()`, a.ID))
	u.waitUI("detail open", `document.querySelector('#findingsBody tr.detail-row .verified pre.payload')`)
	if got := u.evalStr(`document.querySelector('#findingsBody tr.detail-row .verified pre.payload').textContent`); got != "<svg onload=inda>" {
		t.Fatalf("verified payload box = %q", got)
	}
	if !u.evalBool(`document.querySelector('#findingsBody tr.detail-row .detail').firstElementChild.classList.contains('verified')`) {
		t.Fatal("the verified candidate must be the first element of the detail")
	}
	if !u.evalBool(`/uncaught ReferenceError named the marker/.test(document.querySelector('.verified').textContent)`) {
		t.Fatal("the verification signal is not shown with the verified candidate")
	}
	if u.evalBool(`/hello/.test(document.querySelector('.verified').textContent)`) {
		t.Fatal("the baseline value is shown inside the verified-candidate block")
	}
	if !u.evalBool(`/Other attempts \(1\)/.test(document.querySelector('#findingsBody tr.detail-row').textContent) && /<indprobeax>/.test(document.querySelector('#findingsBody tr.detail-row').textContent)`) {
		t.Fatal("the rejected attempt is not kept as a diagnostic child of the confirmed finding")
	}
	if !u.evalBool(`document.querySelectorAll('#findingsBody tr.detail-row li.baseline').length===1 && /baseline reference — the unmodified request, not a payload/.test(document.querySelector('#findingsBody tr.detail-row li.baseline').textContent)`) {
		t.Fatal("baseline evidence is not labelled as a non-payload reference")
	}
	u.eval(fmt.Sprintf(`(function(){document.querySelector('#findingsBody tr[data-finding-id=%q] td.clickable').click();return true;})()`, a.ID)) // collapse

	// Diagnostics view: the rejected finding, labelled not-a-vulnerability when opened.
	u.click("view_diagnostic")
	u.waitUI("diagnostics view", u.rows()+`.length===1 && /\/c\?q/.test(document.getElementById('findingsBody').textContent)`)
	u.eval(`(function(){document.querySelector('#findingsBody td.clickable').click();return true;})()`)
	u.waitUI("diagnostic note", `/Not a vulnerability/.test(document.querySelector('#findingsBody tr.detail-row').textContent) && !document.querySelector('#findingsBody tr.detail-row .verified')`)
	u.click("view_review")
	u.waitUI("needs-review view", u.rows()+`.length===1 && /\/d\?q/.test(document.getElementById('findingsBody').textContent)`)
	u.click("view_all")
	u.waitUI("all view", u.rows()+`.length===4`)
	u.click("view_confirmed")
	u.waitUI("back to confirmed", u.rows()+`.length===2`)

	if errs := u.page.PageErrors(); len(errs) > 0 {
		t.Fatalf("dashboard JS errors: %v", errs)
	}
}

// A scan with nothing confirmed says so, rather than listing unconfirmed items
// as if they were vulnerabilities.
func TestUIFindingsEmptyConfirmedViewExplainsHiddenItems(t *testing.T) {
	u := newUIHarness(t)
	scanID := uiFindingsScan(t, u)
	uiFinding(t, u, scanID, domain.VerdictRejected, uiFindingOpts{path: "/c"}, time.Now())
	u.openScanTab(scanID, "findings")
	u.waitUI("empty confirmed view", `/No confirmed vulnerabilities yet\. 1 other finding\(s\)/.test(document.getElementById('tabPanel').textContent) && `+u.rows()+`.length===0`)
}

// The project-level Findings page defaults to confirmed too.
func TestUIProjectFindingsPageDefaultsToConfirmed(t *testing.T) {
	u := newUIHarness(t)
	scanID := uiFindingsScan(t, u)
	sc, _ := u.st.Scans().Get(context.Background(), scanID)
	base := time.Now()
	uiFinding(t, u, scanID, domain.VerdictConfirmed, uiFindingOpts{path: "/a"}, base)
	uiFinding(t, u, scanID, domain.VerdictRejected, uiFindingOpts{path: "/c"}, base.Add(time.Second))
	u.eval(fmt.Sprintf(`loadProjects().then(function(){ setProject(%q); return true; })`, string(sc.ProjectID)))
	u.eval(`navigate('#/findings')`)
	u.waitUI("project findings confirmed only", `document.querySelectorAll('#view tbody tr').length===1 && /\/a\?q/.test(document.getElementById('view').textContent) && !/\/c\?q/.test(document.getElementById('view').textContent)`)
	u.click("view_diagnostic")
	u.waitUI("project diagnostics", `/\/c\?q/.test(document.getElementById('view').textContent) && !/\/a\?q/.test(document.getElementById('view').textContent)`)
}

// --- selection, rerenders, report modes, evidence ---------------------------

func TestUIFindingsSelectionAcrossFiltersRerendersAndReportModes(t *testing.T) {
	u := newUIHarness(t)
	scanID := uiFindingsScan(t, u)
	base := time.Now()
	f1 := uiFinding(t, u, scanID, domain.VerdictConfirmed, uiFindingOpts{path: "/a"}, base)
	uiFinding(t, u, scanID, domain.VerdictConfirmed, uiFindingOpts{path: "/b"}, base.Add(time.Second))
	uiFinding(t, u, scanID, domain.VerdictRejected, uiFindingOpts{path: "/c"}, base.Add(2*time.Second))

	// Fast live refresh so "survives re-renders" is exercised many times.
	u.eval(`prefs.set("refreshMs","500")`)
	u.openScanTab(scanID, "findings")
	u.waitUI("confirmed listed", u.rows()+`.length===2`)
	u.waitUI("empty selection", `document.getElementById('selectionCount').textContent==='0 of 2 selected' && !document.getElementById('selectAllBox').checked && !document.getElementById('selectAllBox').indeterminate`)

	// One row checked → indeterminate header.
	u.eval(`(function(){document.querySelector('#findingsBody input.finding-select').click();return true;})()`)
	u.waitUI("one selected, indeterminate", `document.getElementById('selectionCount').textContent==='1 of 2 selected' && document.getElementById('selectAllBox').indeterminate && !document.getElementById('selectAllBox').checked`)

	// Open a detail row; selection AND the open row survive several live ticks.
	u.eval(fmt.Sprintf(`(function(){document.querySelector('#findingsBody tr[data-finding-id=%q] td.clickable').click();return true;})()`, f1.ID))
	u.waitUI("detail open", `document.querySelector('#findingsBody tr.detail-row .verified')`)
	time.Sleep(2 * time.Second) // ≥3 refresh ticks at 500ms
	if !u.evalBool(`document.getElementById('selectionCount').textContent==='1 of 2 selected' && document.querySelectorAll('#findingsBody input.finding-select:checked').length===1 && document.querySelector('#findingsBody tr.detail-row .verified')`) {
		t.Fatalf("selection or open row lost across live refresh: %s", u.evalStr(`document.getElementById('selectionCount').textContent`))
	}

	// A genuinely new confirmed finding forces a real re-render: selection and
	// the open row are restored from state, and the count grows.
	uiFinding(t, u, scanID, domain.VerdictConfirmed, uiFindingOpts{path: "/d"}, base.Add(3*time.Second))
	u.waitUI("re-rendered with 3, selection kept", u.rows()+`.length===3 && document.getElementById('selectionCount').textContent==='1 of 3 selected' && document.querySelectorAll('#findingsBody input.finding-select:checked').length===1`)
	u.waitUI("open row restored after re-render", `document.querySelector('#findingsBody tr.detail-row .verified pre.payload')`)

	// Select all / clear selection / header checkbox act on the findings SHOWN.
	u.click("selectAll")
	u.waitUI("all shown selected", `document.getElementById('selectionCount').textContent==='3 of 3 selected' && document.getElementById('selectAllBox').checked && !document.getElementById('selectAllBox').indeterminate`)
	u.click("clearSelection")
	u.waitUI("cleared", `document.getElementById('selectionCount').textContent==='0 of 3 selected' && document.querySelectorAll('#findingsBody input.finding-select:checked').length===0`)
	u.click("selectAllBox")
	u.waitUI("header box selects all shown", `document.getElementById('selectionCount').textContent==='3 of 3 selected'`)
	u.click("selectAllBox")
	u.waitUI("header box clears shown", `document.getElementById('selectionCount').textContent==='0 of 3 selected'`)

	// Switching filters: Select all applies to what is shown; selections made in
	// another view are kept and reported, never silently dropped.
	u.click("view_diagnostic")
	u.waitUI("diagnostics shown", u.rows()+`.length===1`)
	u.click("selectAll")
	u.waitUI("diagnostic selected", `document.getElementById('selectionCount').textContent==='1 of 1 selected'`)
	u.click("view_confirmed")
	u.waitUI("hidden selection reported", u.rows()+`.length===3 && document.getElementById('selectionCount').textContent==='0 of 3 selected · 1 more selected in other views'`)
	u.click("selectAll")
	u.waitUI("confirmed all selected + hidden", `document.getElementById('selectionCount').textContent==='3 of 3 selected · 1 more selected in other views'`)

	// The Reports tab inherits the whole selection (4) and shows its exact makeup.
	u.mustClickText(".tabs a", "Reports")
	u.waitUI("selected mode carried over", `document.getElementById('r_mode_selected').checked && /Selected findings \(4\)/.test(document.getElementById('tabPanel').textContent)`)
	u.waitUI("selected preview", `/Will include 4 of 4 finding\(s\): confirmed 3, rejected 1\./.test(document.getElementById('reportPreview').textContent)`)

	// Explicit modes: Confirmed only, then generate and check the listed row.
	u.click("r_mode_confirmed")
	u.waitUI("confirmed preview", `/Will include 3 of 4 finding\(s\): confirmed 3\./.test(document.getElementById('reportPreview').textContent)`)
	u.setVal("r_fmt", "markdown")
	u.click("generateReport")
	u.waitUI("confirmed report listed", `/confirmed/.test(document.getElementById('reportsBody').textContent) && /3 of 4/.test(document.getElementById('reportsBody').textContent) && /confirmed 3/.test(document.getElementById('reportsBody').textContent)`)
	u.click("r_mode_all")
	u.waitUI("all preview", `/Will include 4 of 4 finding\(s\): confirmed 3, rejected 1\./.test(document.getElementById('reportPreview').textContent)`)

	// Clearing the selection with the mode still on the operator's explicit choice.
	u.mustClickText(".tabs a", "Findings")
	u.waitUI("selection kept across navigation", `document.getElementById('selectionCount').textContent==='3 of 3 selected · 1 more selected in other views'`)
	u.click("clearSelection")
	u.waitUI("everything cleared", `document.getElementById('selectionCount').textContent==='0 of 3 selected' && document.querySelectorAll('#findingsBody input.finding-select:checked').length===0`)

	// The generated report prioritizes the verified payload and its evidence.
	reports, _ := u.st.Reports().ListByScan(context.Background(), scanID)
	if len(reports) != 1 {
		t.Fatalf("reports = %d, want the one confirmed-only report", len(reports))
	}
	body, _ := u.eval(fmt.Sprintf(`fetch('/api/reports/%s/content').then(function(r){return r.text();})`, reports[0].ID)).(string)
	if !strings.Contains(body, "**Verified candidate**") || !strings.Contains(body, "<svg onload=inda>") || strings.Contains(body, "/c?q") {
		t.Fatalf("confirmed-only report is wrong:\n%s", body)
	}
	if !strings.Contains(body, "baseline reference (the unmodified request — not a payload)") {
		t.Fatalf("report does not label baseline evidence:\n%s", body)
	}

	if errs := u.page.PageErrors(); len(errs) > 0 {
		t.Fatalf("dashboard JS errors: %v", errs)
	}
}

// With nothing selected and no explicit choice the report mode is Confirmed
// only; with nothing confirmed Generate is disabled rather than producing an
// empty report; the operator can still pick All explicitly.
func TestUIReportModeDefaultsToConfirmedOnly(t *testing.T) {
	u := newUIHarness(t)
	scanID := uiFindingsScan(t, u)
	uiFinding(t, u, scanID, domain.VerdictRejected, uiFindingOpts{path: "/c"}, time.Now())
	u.openScanTab(scanID, "reports")
	u.waitUI("default mode confirmed", `document.getElementById('r_mode_confirmed').checked && /Will include 0 of 1 finding\(s\): no findings\./.test(document.getElementById('reportPreview').textContent)`)
	u.waitUI("generate disabled with nothing to report", `document.getElementById('generateReport').disabled`)
	u.click("r_mode_all")
	u.waitUI("all mode enables generate", `!document.getElementById('generateReport').disabled && /Will include 1 of 1 finding\(s\): rejected 1\./.test(document.getElementById('reportPreview').textContent)`)
}

func TestUIEvidenceTabLabelsRolesAndOpensSafely(t *testing.T) {
	u := newUIHarness(t)
	scanID := uiFindingsScan(t, u)
	base := time.Now()
	f1 := uiFinding(t, u, scanID, domain.VerdictConfirmed, uiFindingOpts{path: "/a"}, base)
	uiFinding(t, u, scanID, domain.VerdictRejected, uiFindingOpts{path: "/c"}, base.Add(time.Second))

	u.openScanTab(scanID, "evidence")
	u.waitUI("evidence listed", `/6 evidence item\(s\) across 2 finding\(s\)/.test(document.getElementById('evidenceBody').textContent) && document.querySelectorAll('#evidenceBody a').length===12`)
	// Confirmed finding's evidence is listed first, with its verified candidate.
	if !u.evalBool(`document.querySelector('#evidenceBody tbody tr td').textContent.indexOf('Reflected XSS in parameter')>=0 && /verified: <svg onload=inda>/.test(document.querySelector('#evidenceBody tbody tr td').textContent)`) {
		t.Fatal("the confirmed finding (with its verified candidate) must head the evidence list")
	}
	// Roles are labelled; the baseline rows are visually de-emphasised and say so.
	if !u.evalBool(`document.querySelectorAll('#evidenceBody tr.baseline').length===2 && /baseline reference — the unmodified request, not a payload/.test(document.querySelector('#evidenceBody tr.baseline').textContent)`) {
		t.Fatal("baseline evidence is not labelled/de-emphasised")
	}
	if !u.evalBool(`/browser verification/.test(document.getElementById('evidenceBody').textContent) && /candidate request\/response/.test(document.getElementById('evidenceBody').textContent)`) {
		t.Fatal("browser and candidate evidence roles are not labelled")
	}

	// Opening captured HTML evidence must not run its scripts: served under a
	// script-less CSP sandbox, the page keeps its own title.
	var domID domain.ID
	for _, id := range f1.EvidenceIDs {
		if ev, _ := u.st.Evidence().Get(context.Background(), id); ev != nil && ev.Kind == domain.EvidenceDOM {
			domID = id
		}
	}
	page2, err := u.bctx.NewPage(u.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := page2.Navigate(u.ctx, u.url+"/api/evidence/"+string(domID)+"/content", browser.NavOptions{}); err != nil {
		t.Fatal(err)
	}
	title, err := page2.Evaluate(u.ctx, "document.title")
	if err != nil {
		t.Fatal(err)
	}
	if title != "captured" {
		t.Fatalf("captured evidence script executed when opened (title=%v)", title)
	}
	if errs := u.page.PageErrors(); len(errs) > 0 {
		t.Fatalf("dashboard JS errors: %v", errs)
	}
}
