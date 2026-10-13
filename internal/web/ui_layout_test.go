package web_test

// Real-browser layout regression tests: the footer must stay in normal flow
// after the content (it used to overlap tall pages), and long unbroken values —
// candidate payloads, endpoint URLs, evidence metadata — must wrap inside their
// own boxes instead of crossing neighbouring elements. Checked at desktop width
// and, via a narrow same-origin iframe, at phone width (which exercises the
// real max-width media queries; the harness cannot resize the window).

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
)

// layoutJS defines window.__layout(doc, win) → []string of violations.
const layoutJS = `window.__layout = function(doc, win) {
  var v = [];
  var rect = function(e) { return e.getBoundingClientRect(); };
  var footer = doc.querySelector('footer.footer'), shell = doc.querySelector('.shell'), main = doc.querySelector('main.content');
  var side = doc.querySelector('#sidebar');
  var f = rect(footer), sh = rect(shell), m = rect(main), sb = rect(side);

  // The footer follows the shell in normal flow: never overlapping it.
  if (f.top < sh.bottom - 0.5) v.push('footer overlaps the main area: footer.top=' + f.top + ' shell.bottom=' + sh.bottom);
  if (f.top < m.bottom - 0.5) v.push('footer overlaps the content column: footer.top=' + f.top + ' content.bottom=' + m.bottom);
  // ...and no rendered descendant of the view reaches below the footer's top.
  var maxBottom = 0, lowest = '';
  doc.querySelectorAll('#view *').forEach(function(e) {
    var r = rect(e);
    if (r.height > 0 && r.bottom > maxBottom) { maxBottom = r.bottom; lowest = e.tagName; }
  });
  if (maxBottom > f.top + 0.5) v.push('<' + lowest + '> extends to ' + maxBottom + ', past the footer top ' + f.top);

  // No page-level horizontal scrolling.
  var root = doc.documentElement;
  if (root.scrollWidth > root.clientWidth + 1) v.push('page scrolls horizontally: scrollWidth ' + root.scrollWidth + ' > ' + root.clientWidth);

  // Sidebar and content never overlap (side by side on desktop, stacked on phones).
  var overlapX = sb.right > m.left + 1 && sb.left < m.right - 1;
  var overlapY = sb.bottom > m.top + 1 && sb.top < m.bottom - 1;
  if (overlapX && overlapY) v.push('sidebar overlaps the content');

  // Text stays inside its card and is wrapped, not scrolled or spilled.
  doc.querySelectorAll('#view .card').forEach(function(card) {
    var c = rect(card);
    if (card.scrollWidth > card.clientWidth + 1) v.push('a card scrolls horizontally (content wider than the card)');
    card.querySelectorAll('td, th, dd, li, pre, code, p, .pill').forEach(function(e) {
      var r = rect(e);
      if (r.width > 0 && r.right > c.right + 1) v.push('<' + e.tagName + '> crosses its card: ' + (e.textContent || '').slice(0, 40));
    });
  });
  doc.querySelectorAll('#view pre.payload, #view td.verified-cell').forEach(function(e) {
    if (e.scrollWidth > e.clientWidth + 1) v.push('<' + e.tagName + '.' + e.className + '> has horizontally clipped text (scrollWidth ' + e.scrollWidth + ' > ' + e.clientWidth + ')');
  });
  // Short fixed vocabulary never splits mid-word: headers, pills, and short
  // identifier cells (a value that fits its column's floor) stay on one line.
  var lines = function(e) {
    var r = doc.createRange(); r.selectNodeContents(e);
    var tops = {}; Array.prototype.forEach.call(r.getClientRects(), function(x) { if (x.width > 0) tops[Math.round(x.top)] = 1; });
    return Object.keys(tops).length;
  };
  doc.querySelectorAll('#view thead th, #view .pill, #view td.c-ident').forEach(function(e) {
    var t = (e.textContent || '').trim();
    if (t && t.length <= 14 && lines(e) > 1) v.push('<' + e.tagName + '> "' + t + '" is split across lines');
  });
  return v;
};
true`

func (u *uiHarness) violations(frame string) []string {
	u.t.Helper()
	doc, win := "document", "window"
	if frame != "" {
		doc = fmt.Sprintf("document.getElementById(%q).contentDocument", frame)
		win = fmt.Sprintf("document.getElementById(%q).contentWindow", frame)
	}
	raw, _ := u.eval(fmt.Sprintf("window.__layout(%s, %s)", doc, win)).([]any)
	var out []string
	for _, r := range raw {
		out = append(out, fmt.Sprint(r))
	}
	return out
}

// layoutScan seeds a scan tall enough to scroll (30 short confirmed findings)
// plus one whose payload, endpoint URL, and evidence media type are very long
// strings with no break opportunities.
func layoutScan(t *testing.T, u *uiHarness) (domain.ID, *domain.Finding) {
	t.Helper()
	scanID := uiFindingsScan(t, u)
	base := time.Now()
	for i := 0; i < 30; i++ {
		uiFinding(t, u, scanID, domain.VerdictConfirmed, uiFindingOpts{path: fmt.Sprintf("/p%02d", i)}, base.Add(time.Duration(i)*time.Second))
	}
	long := uiFinding(t, u, scanID, domain.VerdictConfirmed, uiFindingOpts{
		path: "/long", longURL: true, longMedia: true,
		payload: `"><svg onload=ind` + strings.Repeat("0123456789abcdef", 40) + `>`,
	}, base.Add(time.Hour))
	return scanID, long
}

func TestUILayoutFooterStaysAfterTallContentAndLongTextWraps(t *testing.T) {
	u := newUIHarness(t)
	u.eval(layoutJS)
	scanID, long := layoutScan(t, u)
	// --- Findings tab, desktop width, detail of the long finding expanded ---
	u.openScanTab(scanID, "findings")
	u.waitUI("31 confirmed rows", u.rows()+`.length===31`)
	u.eval(fmt.Sprintf(`(function(){document.querySelector('#findingsBody tr[data-finding-id=%q] td.clickable').click();return true;})()`, long.ID))
	u.waitUI("long detail open", `document.querySelector('#findingsBody tr.detail-row .verified pre.payload')`)
	if !u.evalBool(`document.documentElement.scrollHeight > window.innerHeight * 1.5`) {
		t.Fatal("setup: the page must be much taller than the viewport for the overlap check to mean anything")
	}
	if v := u.violations(""); len(v) > 0 {
		t.Fatalf("findings tab (desktop):\n  %s", strings.Join(v, "\n  "))
	}
	// The footer is at the end of the document, below the very last row.
	if !u.evalBool(`document.querySelector('footer.footer').getBoundingClientRect().top + window.scrollY >= document.getElementById('findingsBody').getBoundingClientRect().bottom + window.scrollY`) {
		t.Fatal("the footer is not below the findings table")
	}

	// --- Evidence tab: long media type / metadata wrap inside the table ---
	u.mustClickText(".tabs a", "Evidence")
	u.waitUI("evidence rows", `/evidence item\(s\)/.test(document.getElementById('evidenceBody').textContent) && /verylongmediatype/.test(document.getElementById('evidenceBody').textContent)`)
	if v := u.violations(""); len(v) > 0 {
		t.Fatalf("evidence tab (desktop):\n  %s", strings.Join(v, "\n  "))
	}

	// --- The same pages at phone width (media queries active) ---
	u.eval(`(function(){ var f = document.createElement('iframe'); f.id = 'narrow';
	  f.style.cssText = 'position:fixed;left:0;top:0;width:420px;height:700px;border:0;z-index:99999;background:#000';
	  f.src = location.pathname + '#/scans/` + string(scanID) + `/findings'; document.body.appendChild(f); return true; })()`)
	u.waitUI("narrow frame rendered", `document.getElementById('narrow').contentDocument.querySelectorAll('#findingsBody tr[data-finding-id]').length===31`)
	u.eval(layoutJS) // (idempotent) keep the helper available to the page
	if !u.evalBool(`document.getElementById('narrow').contentWindow.innerWidth===420 && document.getElementById('narrow').contentDocument.documentElement.scrollHeight > 1400`) {
		t.Fatal("setup: the narrow frame is not 420px wide and tall enough to scroll")
	}
	u.eval(fmt.Sprintf(`(function(){var d=document.getElementById('narrow').contentDocument;d.querySelector('#findingsBody tr[data-finding-id=%q] td.clickable').click();return true;})()`, long.ID))
	u.waitUI("narrow detail open", `document.getElementById('narrow').contentDocument.querySelector('#findingsBody tr.detail-row .verified pre.payload')`)
	if v := u.violations("narrow"); len(v) > 0 {
		t.Fatalf("findings tab (420px):\n  %s", strings.Join(v, "\n  "))
	}

	if errs := u.page.PageErrors(); len(errs) > 0 {
		t.Fatalf("dashboard JS errors: %v", errs)
	}
}

// A short page keeps the footer at the bottom of the window (the flex column
// is at least one viewport tall) — the fix must not turn it into a footer that
// floats mid-screen.
func TestUILayoutFooterSitsAtWindowBottomOnShortPages(t *testing.T) {
	u := newUIHarness(t)
	u.eval(layoutJS)
	u.eval(`navigate('#/findings')`) // no project selected: a one-card empty state
	u.waitUI("empty findings page rendered", `document.getElementById('view').dataset.view==='findings' && document.querySelectorAll('#view .empty-state').length===1`)
	if !u.evalBool(`Math.abs(document.querySelector('footer.footer').getBoundingClientRect().bottom - window.innerHeight) <= 1`) {
		t.Fatalf("footer bottom = %s, window height = %s", u.evalStr(`document.querySelector('footer.footer').getBoundingClientRect().bottom`), u.evalStr(`window.innerHeight`))
	}
	if v := u.violations(""); len(v) > 0 {
		t.Fatalf("short page:\n  %s", strings.Join(v, "\n  "))
	}
}
