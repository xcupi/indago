// Command akmeasure is a ONE-OFF measurement harness (not shipped code): it
// answers whether Chromium's access-key activation reaches the injection
// shapes our verification replays, and whether page focus changes the answer.
//
// It deliberately uses playwright-go directly so it can BringToFront and click
// with a real mouse — neither is exposed by internal/browser's Page, and the
// question is precisely whether those matter. The key press replicates
// internal/browser/playwright.go's pwPage.PressKeyChord byte for byte
// (CDP Input.dispatchKeyEvent with unmodifiedText, which Chromium's access-key
// matching reads), so a difference between this harness and the driver would
// be a difference in the harness, not the technique.
package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	pw "github.com/mxschmitt/playwright-go"
)

const marker = "indprobe4c1f9a"

var cdpModifierBits = map[string]int{"Alt": 1, "Control": 2, "Meta": 4, "Shift": 8}

// pressChord is a copy of pwPage.PressKeyChord's dispatch.
func pressChord(ctx pw.BrowserContext, page pw.Page, chord string) error {
	parts := splitPlus(chord)
	mods := 0
	for _, m := range parts[:len(parts)-1] {
		mods |= cdpModifierBits[m]
	}
	key := parts[len(parts)-1]
	shift := mods&cdpModifierBits["Shift"] != 0
	code, vk, text := keyFields(key, shift)
	cdp, err := ctx.NewCDPSession(page)
	if err != nil {
		return err
	}
	down := map[string]any{
		"type": "keyDown", "modifiers": mods, "key": key, "code": code,
		"windowsVirtualKeyCode": vk, "nativeVirtualKeyCode": vk,
		"text": text, "unmodifiedText": key,
	}
	if _, err := cdp.Send("Input.dispatchKeyEvent", down); err != nil {
		return err
	}
	up := map[string]any{
		"type": "keyUp", "modifiers": mods, "key": key, "code": code,
		"windowsVirtualKeyCode": vk, "nativeVirtualKeyCode": vk,
		"text": "", "unmodifiedText": "",
	}
	_, err = cdp.Send("Input.dispatchKeyEvent", up)
	return err
}

func splitPlus(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == '+' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(r)
	}
	return append(out, cur)
}

func keyFields(key string, shift bool) (code string, vk int, text string) {
	r := rune(key[0])
	switch {
	case r >= 'a' && r <= 'z':
		upper := r - 'a' + 'A'
		text = string(r)
		if shift {
			text = string(upper)
		}
		return "Key" + string(upper), int(upper), text
	case r >= 'A' && r <= 'Z':
		return "Key" + string(r), int(r), string(r)
	case r >= '0' && r <= '9':
		return "Digit" + string(r), int(r), string(r)
	}
	return "", int(r), string(r)
}

type observation struct {
	label       string
	hasFocus    bool
	keys        string
	clicks      string
	pageErrors  []string
	consoleErrs []string
}

func (o observation) String() string {
	return fmt.Sprintf("%-52s hasFocus=%-5v keys=%-3s clicks=%-3s pageErrors=%v consoleErrors=%v",
		o.label, o.hasFocus, o.keys, o.clicks, o.pageErrors, o.consoleErrs)
}

// newPage opens a page and wires error/console listeners BEFORE navigation.
func newPage(ctx pw.BrowserContext, url string) (pw.Page, *[]string, *[]string, error) {
	page, err := ctx.NewPage()
	if err != nil {
		return nil, nil, nil, err
	}
	var errs, cons []string
	page.On("pageerror", func(err error) { errs = append(errs, err.Error()) })
	page.On("console", func(msg pw.ConsoleMessage) {
		if msg.Type() == "error" {
			cons = append(cons, msg.Text())
		}
	})
	if _, err := page.Goto(url, pw.PageGotoOptions{WaitUntil: pw.WaitUntilStateLoad}); err != nil {
		return nil, nil, nil, err
	}
	return page, &errs, &cons, nil
}

func observe(label string, page pw.Page, errs, cons *[]string) observation {
	time.Sleep(400 * time.Millisecond)
	raw, _ := page.Evaluate(`(() => {
	  const a = document.documentElement;
	  return {focus: document.hasFocus(), keys: a.getAttribute('data-keys') || '0', clicks: a.getAttribute('data-clicks') || '0'};
	})()`)
	m, _ := raw.(map[string]any)
	o := observation{label: label, pageErrors: append([]string(nil), *errs...), consoleErrs: append([]string(nil), *cons...)}
	if m != nil {
		o.hasFocus, _ = m["focus"].(bool)
		o.keys, _ = m["keys"].(string)
		o.clicks, _ = m["clicks"].(string)
	}
	return o
}

func clickBody(page pw.Page) error {
	raw, err := page.Evaluate(`(() => { const r = document.body.getBoundingClientRect(); return {x: r.x + 5, y: r.y + 5}; })()`)
	if err != nil {
		return err
	}
	m, _ := raw.(map[string]any)
	x, _ := m["x"].(float64)
	y, _ := m["y"].(float64)
	return page.Mouse().Click(x, y)
}

const counters = `<script>
(function(){
  function bump(a){var n=parseInt(document.documentElement.getAttribute(a)||"0",10)+1;document.documentElement.setAttribute(a,String(n));}
  document.addEventListener('keydown',function(e){if(e.altKey&&e.shiftKey&&e.key&&e.key.toLowerCase()==='x')bump('data-keys');},true);
  document.addEventListener('click',function(){bump('data-clicks');},true);
})();
</script>`

func main() {
	pwRun, err := pw.Run()
	if err != nil {
		panic(err)
	}
	defer pwRun.Stop()
	exe := os.Getenv("AK_CHROME")
	if exe == "" {
		exe = "/home/udalah/.cache/ms-playwright/chromium-1234/chrome-linux64/chrome"
	}
	browser, err := pwRun.Chromium.Launch(pw.BrowserTypeLaunchOptions{
		Headless:        pw.Bool(true),
		ChromiumSandbox: pw.Bool(false),
		ExecutablePath:  pw.String(exe),
	})
	if err != nil {
		panic(err)
	}
	defer browser.Close()

	valued := `'accesskey='x' onclick='` + marker + `' x='`
	echo := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		q := r.URL.Query().Get("q")
		tmpl := r.URL.Query().Get("t")
		switch tmpl {
		case "head":
			fmt.Fprintf(w, `<!doctype html><html><head><link rel="canonical" href='https://example/?x=%s'>%s</head><body>ok</body></html>`, q, counters)
		default:
			fmt.Fprintf(w, `<!doctype html><html><head>%s</head><body>ok<a href='#?x=%s' id='ctl'>go</a></body></html>`, counters, q)
		}
	}
	srv := httptest.NewServer(http.HandlerFunc(echo))
	defer srv.Close()
	urlFor := func(tmpl string) string {
		return srv.URL + "/?t=" + tmpl + "&q=" + escape(valued)
	}

	var out []observation

	// A — exactly what production does: one page, no focus help.
	{
		ctx, _ := browser.NewContext()
		page, errs, cons, err := newPage(ctx, urlFor("head"))
		if err != nil {
			panic(err)
		}
		out = append(out, observe("before press (A)", page, errs, cons))
		if err := pressChord(ctx, page, "Alt+Shift+x"); err != nil {
			panic(err)
		}
		out = append(out, observe("A  link-in-head, press only (production path)", page, errs, cons))
		ctx.Close()
	}

	// B — BringToFront + one real mouse click on the body, then the press.
	{
		ctx, _ := browser.NewContext()
		page, errs, cons, err := newPage(ctx, urlFor("head"))
		if err != nil {
			panic(err)
		}
		if err := page.BringToFront(); err != nil {
			panic(err)
		}
		if err := clickBody(page); err != nil {
			panic(err)
		}
		out = append(out, observe("after bringToFront+click (B)", page, errs, cons))
		if err := pressChord(ctx, page, "Alt+Shift+x"); err != nil {
			panic(err)
		}
		out = append(out, observe("B  link-in-head, bringToFront+click, then press", page, errs, cons))
		ctx.Close()
	}

	// B2 — page A is a BACKGROUND tab (another page is in front), press only.
	// This is the focus disadvantage a scan with concurrent pages produces.
	{
		ctx, _ := browser.NewContext()
		pageA, errsA, consA, err := newPage(ctx, urlFor("head"))
		if err != nil {
			panic(err)
		}
		pageB, err := ctx.NewPage()
		if err != nil {
			panic(err)
		}
		if _, err := pageB.Goto("about:blank"); err != nil {
			panic(err)
		}
		if err := pageB.BringToFront(); err != nil {
			panic(err)
		}
		out = append(out, observe("B2 before press (A is background)", pageA, errsA, consA))
		if err := pressChord(ctx, pageA, "Alt+Shift+x"); err != nil {
			panic(err)
		}
		out = append(out, observe("B2 link-in-head, BACKGROUND tab, press only", pageA, errsA, consA))
		ctx.Close()
	}

	// B3 — page A was a background tab: BringToFront + click body, then press.
	{
		ctx, _ := browser.NewContext()
		pageA, errsA, consA, err := newPage(ctx, urlFor("head"))
		if err != nil {
			panic(err)
		}
		pageB, err := ctx.NewPage()
		if err != nil {
			panic(err)
		}
		if _, err := pageB.Goto("about:blank"); err != nil {
			panic(err)
		}
		if err := pageB.BringToFront(); err != nil {
			panic(err)
		}
		if err := pageA.BringToFront(); err != nil {
			panic(err)
		}
		if err := clickBody(pageA); err != nil {
			panic(err)
		}
		out = append(out, observe("B3 after bringToFront+click (was background)", pageA, errsA, consA))
		if err := pressChord(ctx, pageA, "Alt+Shift+x"); err != nil {
			panic(err)
		}
		out = append(out, observe("B3 link-in-head, was background, bringToFront+click, press", pageA, errsA, consA))
		ctx.Close()
	}

	// C — the control: the same payload on a RENDERED <a> in body, press only.
	{
		ctx, _ := browser.NewContext()
		page, errs, cons, err := newPage(ctx, urlFor("body"))
		if err != nil {
			panic(err)
		}
		if err := pressChord(ctx, page, "Alt+Shift+x"); err != nil {
			panic(err)
		}
		out = append(out, observe("C  rendered <a> in body, press only", page, errs, cons))
		ctx.Close()
	}

	fmt.Println("marker =", marker)
	for _, o := range out {
		fmt.Println(o)
	}
}

func escape(s string) string {
	out := ""
	for _, r := range s {
		if r == '\'' || r == '&' || r == '?' || r == '=' {
			out += fmt.Sprintf("%%%02X", r)
			continue
		}
		out += string(r)
	}
	return out
}
