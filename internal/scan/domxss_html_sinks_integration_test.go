//go:build browser_integration

package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/verification"
)

func TestDOMCreateContextualFragment(t *testing.T) {
	runHTMLSinkCases(t, "Range.createContextualFragment", `const range=document.createRange();range.selectNodeContents(sink);sink.appendChild(range.createContextualFragment(value));`, false)
}

func TestDOMCreateContextualFragmentPartialTextOnly(t *testing.T) {
	runHTMLSinkCases(t, "Range.createContextualFragment", `const range=document.createRange();range.selectNodeContents(sink);const fragment=range.createContextualFragment('safe-prefix'+value);sink.appendChild(fragment.firstChild);`, true)
}

func TestDOMCreateContextualFragmentDetached(t *testing.T) {
	runHTMLSinkCases(t, "Range.createContextualFragment", `const range=document.createRange();range.selectNodeContents(sink);range.createContextualFragment(value);`, true)
}

func TestDOMCreateContextualFragmentNativeContract(t *testing.T) {
	mgr := newSourceSelectionBrowser(t)
	defer mgr.Close()
	bc, err := mgr.NewContext(context.Background(), browser.ContextOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer bc.Close()
	page, err := bc.NewPage(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer page.Close()
	spy := `(() => {const orig=Range.prototype.createContextualFragment;window.__native=orig;
 Range.prototype.createContextualFragment=function(){const result=orig.apply(this,arguments);window.__call={receiver:this,args:Array.from(arguments),result};return result;};})();`
	if err = page.AddInitScript(context.Background(), spy+"\n"+domXSSHarnessScript("CONTRACT_MARKER")); err != nil {
		t.Fatal(err)
	}
	if _, err = page.Navigate(context.Background(), "about:blank", browser.NavOptions{}); err != nil {
		t.Fatal(err)
	}
	raw, err := page.Evaluate(context.Background(), `(() => {
 const sink=document.createElement('div');document.body.append(sink);const range=document.createRange();range.selectNodeContents(sink);
 const extra={toString(){throw new Error('extra argument coerced')}};
 const ret=range.createContextualFragment('CONTRACT_MARKER',extra);
 const forwarded=__call.receiver===range && __call.args.length===2 && __call.args[1]===extra && ret===__call.result && ret instanceof DocumentFragment;
 const fragmentText=ret.textContent;
 let conversions=0;const obj={toString(){conversions++;return 'CONTRACT_MARKER'}};
 const objectText=range.createContextualFragment(obj).textContent;
 const sentinel=new Error('coercion sentinel');let same=false;try{range.createContextualFragment({toString(){throw sentinel}})}catch(e){same=e===sentinel}
 function error(fn){try{fn();return ''}catch(e){return e.name+': '+e.message}}
 const badReceiver=error(()=>Range.prototype.createContextualFragment.call({},'x'))===error(()=>__native.call({},'x'));
 const symbol=error(()=>range.createContextualFragment(Symbol()))===error(()=>__native.call(range,Symbol()));
 const missing=error(()=>range.createContextualFragment())===error(()=>__native.call(range));
 return JSON.stringify({forwarded,conversions,same,badReceiver,symbol,missing,fragmentText,objectText,inserted:sink.childNodes.length});})()`)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Forwarded, Same, BadReceiver, Symbol, Missing bool
		Conversions, Inserted                         int
		FragmentText, ObjectText                      string
	}
	if err = json.Unmarshal([]byte(raw.(string)), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Forwarded || !got.Same || !got.BadReceiver || !got.Symbol || !got.Missing || got.Conversions != 1 || got.Inserted != 0 || got.FragmentText != "CONTRACT_MARKER" || got.ObjectText != "CONTRACT_MARKER" {
		t.Fatalf("native behavior changed: %+v", got)
	}
	reports := parseDOMXSSReachability(page.ConsoleMessages(), "CONTRACT_MARKER")
	if len(reports) != 1 || string(reports[0]) != "Range.createContextualFragment" {
		t.Fatalf("missing primitive-string reachability: %v", reports)
	}
	count := 0
	for _, m := range page.ConsoleMessages() {
		if strings.HasPrefix(m.Text, domXSSConsolePrefix) {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("reported object or failed native call: %d", count)
	}
	if !detection.DOMXSSSink("Range.createContextualFragment").IsValid() {
		t.Fatal("sink enum rejected")
	}
}

func TestDOMInsertAdjacentHTML(t *testing.T) {
	runHTMLSinkCases(t, "insertAdjacentHTML", `sink.insertAdjacentHTML('beforeend', value);`, false)
}

func runHTMLSinkCases(t *testing.T, sinkName, action string, detached bool) {
	t.Helper()
	mgr := newSourceSelectionBrowser(t)
	defer mgr.Close()
	for _, tc := range []struct {
		name, source, control string
		confirmed             bool
	}{
		{"hash inserted", "location.hash", "", !detached},
		{"query inserted", "location.search", "", !detached},
		{"safe text", "location.hash", "text", false},
		{"escaped", "location.hash", "escaped", false},
		{"console only", "location.hash", "console", false},
		{"forged console runtime", "location.hash", "forged", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				code := action
				if tc.control == "text" {
					code = "sink.textContent=value;"
				}
				if tc.control == "escaped" || tc.control == "console" || tc.control == "forged" {
					code = "value=value.replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;');" + code
				}
				if tc.control == "console" {
					code += "console.error(raw);"
				}
				if tc.control == "forged" {
					code += `const match=raw.match(/onerror=([^>]+)/);if(match)console.error('ReferenceError: '+match[1]+' is not defined');`
				}
				fmt.Fprint(w, `<!doctype html><div id="sink"></div><script>const sink=document.getElementById('sink'); const raw=`)
				if tc.source == "location.search" {
					fmt.Fprint(w, `new URLSearchParams(location.search).get('q')||'';`)
				} else {
					fmt.Fprint(w, `decodeURIComponent(location.hash.slice(1));`)
				}
				fmt.Fprint(w, `let value=raw;`+code+`</script>`)
			}))
			defer lab.Close()
			env := newScanEnv(t)
			ep := env.endpoint(lab.URL+"/?q=unused", domain.MethodGET)
			env.param(ep, "q", domain.LocationQuery, "unused")
			ex := newDOMXSSExecutor(env.st, mgr, env.ev, sourceSelectionScope(t, lab.URL), execLog(), &sync.Mutex{})
			if err := ex.Handle(context.Background(), sourceSelectionJob(t, env.scanID, ep, tc.source)); err != nil {
				t.Fatal(err)
			}
			fs := sourceSelectionFindings(t, env.st, env.scanID, ep.ID)
			count := 0
			for _, f := range fs {
				if f.Verdict == domain.VerdictConfirmed {
					count++
					d := decodeFindingDetail(f.Detail)
					if len(d.Candidates) != 1 || string(d.Candidates[0].Context) != sinkName {
						t.Fatalf("wrong candidate mapping: %+v", d)
					}
					if len(f.EvidenceIDs) < 3 || !strings.Contains(f.Summary, "is not defined") {
						t.Fatalf("missing stored runtime/DOM/screenshot evidence: %+v", f)
					}
				}
			}
			if tc.confirmed && count != 1 {
				t.Fatalf("Confirmed=%d, want 1 for %s; findings=%+v", count, sinkName, fs)
			}
			if !tc.confirmed && count != 0 {
				t.Fatalf("safe control Confirmed=%d, want zero", count)
			}
			if (tc.control == "escaped" || tc.control == "console" || tc.control == "forged" || detached && tc.control == "") && len(fs) != 1 {
				t.Fatalf("control must actually reach hook and enter verification, findings=%d", len(fs))
			}
		})
	}
}

func TestDOMInsertAdjacentHTMLNativeContract(t *testing.T) {
	mgr := newSourceSelectionBrowser(t)
	defer mgr.Close()
	bc, err := mgr.NewContext(context.Background(), browser.ContextOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer bc.Close()
	page, err := bc.NewPage(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer page.Close()
	// A transparent native-entry observer proves receiver, argument count and
	// return identity independently of the scanner's wrapper.
	spy := `(() => {const orig=Element.prototype.insertAdjacentHTML; window.__native=orig;
 Element.prototype.insertAdjacentHTML=function(){const result=orig.apply(this,arguments);window.__call={receiver:this,args:Array.from(arguments),result};return result;};})();`
	if err = page.AddInitScript(context.Background(), spy+"\n"+domXSSHarnessScript("CONTRACT_MARKER")); err != nil {
		t.Fatal(err)
	}
	if _, err = page.Navigate(context.Background(), "about:blank", browser.NavOptions{}); err != nil {
		t.Fatal(err)
	}
	raw, err := page.Evaluate(context.Background(), `(() => {
 const sink=document.createElement('div');document.body.append(sink);
 const extra={toString(){throw new Error('extra argument coerced')}};
 const ret=sink.insertAdjacentHTML('beforeend','CONTRACT_MARKER',extra);
 const forwarded=__call.receiver===sink && __call.args.length===3 && __call.args[2]===extra && ret===__call.result && ret===undefined;
 let conversions=0;const obj={toString(){conversions++;return 'CONTRACT_MARKER'}};
 sink.insertAdjacentHTML('afterbegin',obj);
 const sentinel=new Error('coercion sentinel');let same=false;try{sink.insertAdjacentHTML('beforeend',{toString(){throw sentinel}})}catch(e){same=e===sentinel}
 function error(fn){try{fn();return ''}catch(e){return e.name+': '+e.message}}
 const badReceiver=error(()=>Element.prototype.insertAdjacentHTML.call({},'beforeend','x'))===error(()=>__native.call({},'beforeend','x'));
 const badPosition=error(()=>sink.insertAdjacentHTML('invalid','CONTRACT_MARKER'))===error(()=>__native.call(sink,'invalid','CONTRACT_MARKER'));
 const missing=error(()=>sink.insertAdjacentHTML())===error(()=>__native.call(sink));
 return JSON.stringify({forwarded,conversions,same,badReceiver,badPosition,missing,text:sink.textContent});})()`)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Forwarded, Same, BadReceiver, BadPosition, Missing bool
		Conversions                                        int
		Text                                               string
	}
	if err = json.Unmarshal([]byte(raw.(string)), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Forwarded || !got.Same || !got.BadReceiver || !got.BadPosition || !got.Missing || got.Conversions != 1 || got.Text != "CONTRACT_MARKERCONTRACT_MARKER" {
		t.Fatalf("native behavior changed: %+v", got)
	}
	reports := parseDOMXSSReachability(page.ConsoleMessages(), "CONTRACT_MARKER")
	if len(reports) != 1 || string(reports[0]) != "insertAdjacentHTML" {
		t.Fatalf("missing primitive-string reachability: %v", reports)
	}
	reportCount := 0
	for _, m := range page.ConsoleMessages() {
		if strings.HasPrefix(m.Text, domXSSConsolePrefix) {
			reportCount++
		}
	}
	if reportCount != 1 {
		t.Fatalf("reported object or failed native call; reports=%d, want only successful primitive-string call", reportCount)
	}
	if _, _, ok := verification.MatchExecutionSignal("CONTRACT_MARKER", page.PageErrors(), nil); ok {
		t.Fatal("inert contract marker executed")
	}
	if !detection.DOMXSSSink("insertAdjacentHTML").IsValid() {
		t.Fatal("sink enum rejected")
	}
}
