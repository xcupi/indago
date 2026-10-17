package web_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/indago/indago/internal/browser"
)

// The report list is visible on BOTH Findings (Generate report) and Reports.
// DejaVu Sans exposes the six nowrap headers' min-content overflow at 420px;
// the developer machine's default Noto Sans fits and masked this bug.
func TestUILayoutReportsWrapAtPhoneWidth(t *testing.T) {
	u := newUIHarness(t)
	u.eval(layoutJS)
	scanID, _ := layoutScan(t, u)
	u.eval(`document.body.style.fontFamily='"DejaVu Sans", sans-serif'`)
	u.eval(`(function(){var f=document.createElement('iframe');f.id='narrow';
	  f.style.cssText='position:fixed;left:0;top:0;width:420px;height:700px;border:0;z-index:99999';
	  document.body.appendChild(f);return true;})()`)

	for _, populated := range []bool{false, true} {
		state := "empty"
		if populated {
			state = "populated"
			// Generate through the real API, not a synthetic DOM row.
			u.eval(fmt.Sprintf(`mutate('POST', api.scan(%q)+'/reports', {format:'html',mode:'confirmed',ai_summary:false}).then(r=>{if(!r.ok)throw new Error('report generation failed');return true;})`, scanID))
		}
		for _, tab := range []string{"findings", "reports"} {
			for _, frame := range []string{"", "narrow"} {
				label := state + " " + tab + " desktop"
				doc := "document"
				if frame == "" {
					u.openScanTab(scanID, tab)
				} else {
					label = state + " " + tab + " 420px"
					doc = `document.getElementById('narrow').contentDocument`
					u.eval(fmt.Sprintf(`document.getElementById('narrow').src=%q`, u.url+"/#/scans/"+string(scanID)+"/"+tab))
				}
				ready := `.getElementById('reportsBody').textContent==='No reports yet.'`
				if populated {
					ready = `.querySelectorAll('#reportsBody a.act').length===2`
				}
				u.waitUI(label+" list ready", doc+ready)
				u.waitUI(label+" preview ready", doc+`.getElementById('reportPreview').textContent.includes('Will include 31 of 31')`)
				if !populated && frame != "" && tab == "findings" {
					t.Logf("default system font widths: %v", u.eval(`(()=>{let d=`+doc+`, c=d.createElement('canvas').getContext('2d');return ['system-ui','DejaVu Sans','Noto Sans'].map(f=>{c.font='600 12px "'+f+'"';return [f,c.measureText('Created Format Selection Findings Verdicts Open').width]})})()`))
				}
				u.eval(doc + `.body.style.fontFamily='"DejaVu Sans", sans-serif'`)
				if !u.evalBool(doc + `.getElementById('reportsBody').closest('table').getBoundingClientRect().width>0`) {
					t.Fatal(label + ": report list must actually be visible")
				}
				if frame != "" && !u.evalBool(`document.getElementById('narrow').contentWindow.innerWidth===420`) {
					t.Fatal("phone viewport must be 420px")
				}
				t.Logf("%s: %v", label, u.eval(`(()=>{let d=`+doc+`, t=d.getElementById('reportsBody').closest('table'), c=t.closest('.card');return {tableWidth:t.getBoundingClientRect().width,cardWidth:c.clientWidth,cardScrollWidth:c.scrollWidth,headers:[...t.querySelectorAll('th')].map(e=>[e.textContent,e.getBoundingClientRect().width])}})()`))
				if populated && frame != "" && !u.evalBool(`(()=>{let d=`+doc+`;return [...d.querySelectorAll('#reportsBody td')].every((e,i)=>e.dataset.label===['Created','Format','Selection','Findings','Verdicts','Open'][i] && d.defaultView.getComputedStyle(e,'::before').content===JSON.stringify(e.dataset.label))})()`) {
					t.Fatal(label + ": each stacked report value must retain its visible column label")
				}
				if frame == "" && !u.evalBool(`document.querySelector('#reportsBody').closest('table').querySelector('thead').getBoundingClientRect().width>0`) {
					t.Fatal(label + ": desktop column headings must remain visible")
				}
				// Optional safe evidence capture: no server credentials or production data.
				if dir := os.Getenv("INDAGO_LAYOUT_EVIDENCE_DIR"); dir != "" {
					if frame == "" {
						u.eval(`document.getElementById('narrow').style.visibility='hidden'`)
					}
					u.eval(doc + `.getElementById('reportsBody').closest('.card').scrollIntoView()`)
					shot, err := u.page.Screenshot(u.ctx, browser.ScreenshotOptions{})
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(dir, strings.ReplaceAll(label, " ", "-")+".png"), shot, 0600); err != nil {
						t.Fatal(err)
					}
					u.eval(`document.getElementById('narrow').style.visibility='visible'`)
				}
				if v := u.violations(frame); len(v) > 0 {
					t.Fatalf("%s:\n  %s", label, strings.Join(v, "\n  "))
				}
				if populated && !u.evalBool(`(()=>{let d=`+doc+`;return [...d.querySelectorAll('#reportsBody a.act')].every(e=>e.getBoundingClientRect().width>0 && e.scrollWidth<=e.clientWidth+1)})()`) {
					t.Fatal(label + ": report actions must stay readable")
				}
			}
		}
	}
	if errs := u.page.PageErrors(); len(errs) > 0 {
		t.Fatalf("dashboard JS errors: %v", errs)
	}
}
