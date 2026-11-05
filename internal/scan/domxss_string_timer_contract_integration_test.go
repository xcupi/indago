//go:build browser_integration

package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/indago/indago/internal/browser"
)

// Fifteen native contracts for each timer, thirty cases total. Each case runs
// on fresh comparable documents with one ordered init script (spy, then optional
// harness), not unspecified ordering between independent AddInitScript calls.
func TestDOMStringTimerNativeContract(t *testing.T) {
	mgr := newSourceSelectionBrowser(t)
	defer mgr.Close()
	cases := []struct {
		name, code string
		reports    int
	}{
		{"receiver-all-arguments-return-id-reporting-failure", `String.prototype.indexOf=function(){throw new Error('reporting sentinel')};const extra={toString(){throw Error('extra coerced')}};const delay=60000;const id=timer.call(window,"void 'TIMER_MARKER'",delay,extra,17);clearTimeout(id);const c=__calls[0];return {ok:c.receiver===window&&c.args.length===4&&c.args[0]==="void 'TIMER_MARKER'"&&c.args[1]===delay&&c.args[2]===extra&&c.args[3]===17&&c.result===id&&typeof id==='number',calls:__calls.length};`, 0},
		{"callback-identity-extra-args-native-execution", `return await new Promise(resolve=>{const obj={};let id;function callback(a,b){clearInterval(id);const c=__calls[0];resolve({ok:this===window&&a===obj&&b===37&&c.args[0]===callback&&c.args[2]===obj&&c.args[3]===37&&c.result===id,calls:__calls.length});}id=timer.call(window,callback,0,obj,37);});`, 0},
		{"delay-coercion-once", `let conversions=0;const delay={valueOf(){conversions++;return 60000}};const id=timer.call(window,"void 'TIMER_MARKER'",delay);clearInterval(id);return {ok:conversions===1&&__calls[0].args[1]===delay&&__calls[0].result===id,calls:__calls.length};`, 1},
		{"object-handler-coercion-once-unobserved", `let conversions=0;const obj={toString(){conversions++;return "void 'TIMER_MARKER'"}};const id=timer.call(window,obj,60000);clearTimeout(id);return {ok:conversions===1&&__calls[0].args[0]===obj,calls:__calls.length};`, 0},
		{"boxed-string-unobserved", `const obj=new String("void 'TIMER_MARKER'");let conversions=0;obj.toString=function(){conversions++;return "void 'TIMER_MARKER'"};const id=timer.call(window,obj,60000);clearInterval(id);return {ok:conversions===1&&__calls[0].args[0]===obj,calls:__calls.length};`, 0},
		{"throwing-handler-exact-error", `const sentinel=new Error('handler sentinel');let count=0,same=false;try{timer.call(window,{toString(){count++;throw sentinel}},0)}catch(e){same=e===sentinel&&__calls[0].error===e}return {ok:same&&count===1,calls:__calls.length};`, 0},
		{"throwing-delay-exact-error", `const sentinel=new Error('delay sentinel');let count=0,same=false;try{timer.call(window,'TIMER_MARKER',{valueOf(){count++;throw sentinel}})}catch(e){same=e===sentinel&&__calls[0].error===e}return {ok:same&&count===1,calls:__calls.length};`, 0},
		{"invalid-receiver", `function error(fn){try{const id=fn();clearTimeout(id);return ''}catch(e){return e.name+': '+e.message}}const hooked=error(()=>timer.call({},'TIMER_MARKER',60000));const native=error(()=>__native.call({},'TIMER_MARKER',60000));return {ok:hooked!==''&&hooked===native&&__calls[0].receiver!==window,calls:__calls.length};`, 0},
		{"missing-handler", `function error(fn){try{const id=fn();clearTimeout(id);return ''}catch(e){return e.name+': '+e.message}}const got=error(()=>timer.call(window));return {ok:got!==''&&got===error(()=>__native.call(window))&&__calls[0].args.length===0,calls:__calls.length};`, 0},
		{"null-undefined-receivers", `let ok=true;for(const receiver of [null,undefined]){const id=timer.call(receiver,"void 'TIMER_MARKER'",60000);clearTimeout(id);const c=__calls[__calls.length-1];ok=ok&&c.receiver===receiver&&c.result===id;}return {ok,calls:__calls.length};`, 2},
		{"clearTimeout-cancels-shared-id", `window.__fired=0;const id=timer.call(window,'window.__fired++ /* TIMER_MARKER */',0);clearTimeout(id);await new Promise(resolve=>__checkpoint.call(window,resolve,0));return {ok:__fired===0&&__calls[0].result===id,calls:__calls.length};`, 1},
		{"clearInterval-cancels-shared-id", `window.__fired=0;const id=timer.call(window,'window.__fired++ /* TIMER_MARKER */',0);clearInterval(id);await new Promise(resolve=>__checkpoint.call(window,resolve,0));return {ok:__fired===0&&__calls[0].result===id,calls:__calls.length};`, 1},
		{"function-cancellation-unobserved", `let fired=0;function TIMER_MARKER(){fired++}const id=timer.call(window,TIMER_MARKER,0);clearTimeout(id);await new Promise(resolve=>__checkpoint.call(window,resolve,0));return {ok:fired===0&&__calls[0].args[0]===TIMER_MARKER,calls:__calls.length};`, 0},
		{"TrustedScript-native-unobserved", `const policy=trustedTypes.createPolicy('timer-contract',{createScript:s=>s});const value=policy.createScript("void 'TIMER_MARKER'");const id=timer.call(window,value,60000);clearInterval(id);return {ok:__calls[0].args[0]===value&&__calls[0].result===id,calls:__calls.length};`, 0},
		{"symbol-handler-native-error", `function error(fn){try{const id=fn();clearTimeout(id);return ''}catch(e){return e.name+': '+e.message}}const got=error(()=>timer.call(window,Symbol('TIMER_MARKER'),0));return {ok:got!==''&&got===error(()=>__native.call(window,Symbol('TIMER_MARKER'),0)),calls:__calls.length};`, 0},
	}
	if len(cases)*2 != 30 {
		t.Fatalf("native contract ceiling/inventory changed: %d", len(cases)*2)
	}
	for _, name := range []string{"setTimeout", "setInterval"} {
		for _, tc := range cases {
			t.Run(name+"/"+tc.name, func(t *testing.T) {
				var baseline map[string]any
				for _, hooked := range []bool{false, true} {
					ctx := context.Background()
					bc, err := mgr.NewContext(ctx, browser.ContextOptions{})
					if err != nil {
						t.Fatal(err)
					}
					page, err := bc.NewPage(ctx)
					if err != nil {
						bc.Close()
						t.Fatal(err)
					}
					spy := fmt.Sprintf(`(() => {window.__calls=[];window.__checkpoint=window.setTimeout;const name=%s;const orig=window[name];window.__native=orig;window[name]=function(){'use strict';const c={receiver:this,args:Array.from(arguments)};__calls.push(c);try{c.result=orig.apply(this,arguments);return c.result}catch(e){c.error=e;throw e}};})();`, goQuoteJS(name))
					init := spy
					if hooked {
						init += "\n" + domXSSHarnessScript("TIMER_MARKER")
					}
					if err = page.AddInitScript(ctx, init); err != nil {
						t.Fatal(err)
					}
					if _, err = page.Navigate(ctx, "about:blank", browser.NavOptions{}); err != nil {
						t.Fatal(err)
					}
					raw, err := page.Evaluate(ctx, `(async()=>{const timer=window[`+goQuoteJS(name)+`];`+tc.code+`})().then(result=>JSON.stringify(result))`)
					if err != nil {
						page.Close()
						bc.Close()
						t.Fatal(err)
					}
					var got map[string]any
					if err = json.Unmarshal([]byte(raw.(string)), &got); err != nil {
						t.Fatal(err)
					}
					count := 0
					for _, msg := range page.ConsoleMessages() {
						if strings.HasPrefix(msg.Text, domXSSConsolePrefix) {
							count++
						}
					}
					page.Close()
					bc.Close()
					if got["ok"] != true {
						t.Fatalf("hooked=%v native contract violated: %+v", hooked, got)
					}
					expectedCalls := float64(1)
					if tc.name == "null-undefined-receivers" {
						expectedCalls = 2
					}
					if got["calls"] != expectedCalls {
						t.Fatalf("duplicate scheduling or native bypass: %+v", got)
					}
					if !hooked {
						baseline = got
						if count != 0 {
							t.Fatal("native baseline logged scanner reports")
						}
					} else {
						if !reflect.DeepEqual(got, baseline) {
							t.Fatalf("native differential: baseline=%+v hooked=%+v", baseline, got)
						}
						if count != tc.reports {
							t.Fatalf("string-only successful-call observation: reports=%d want %d", count, tc.reports)
						}
					}
				}
			})
		}
	}
}
