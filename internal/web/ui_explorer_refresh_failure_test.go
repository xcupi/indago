package web_test

import (
	"testing"
	"time"

	"github.com/indago/indago/internal/web"
)

// "an expanded endpoint collapsed on refresh" has now failed twice on hosted
// runners. The endpoint explorer's load() replaced the whole list with
// "Could not load endpoints." on ANY failure, including a live refresh — so one
// transient error destroyed the table and the row the operator had opened.
//
// A live refresh that fails must keep the rows it already has and say so. Only
// a first load has nothing worth preserving.
func TestUIEndpointsKeepRowsWhenARefreshFails(t *testing.T) {
	u, w := explorerUIWorld(t, web.Capabilities{})
	u.openScanTab(w.scan, "endpoints")
	u.waitUI("endpoint rows", `document.querySelectorAll('#endpointsBody > tr[data-endpoint-id]').length===3`)

	sel := `#endpointsBody > tr[data-endpoint-id="` + string(w.search) + `"] button.row-toggle`
	u.eval(`document.querySelector('` + sel + `').click(); true`)
	u.waitUI("detail open", `document.querySelector('#endpointsBody tr.detail-row .endpoint-detail')`)

	// The first paint can happen before route() has installed the live
	// refresh callback. Firing refreshNow() in that window falls back to a
	// full route render (load(false)), which is not the behavior under test.
	// Let the route settle, then simulate a transient explorer failure.
	time.Sleep(time.Second)
	// Make the NEXT explorer read fail, the way a transient network error would.
	u.eval(`window.__origFetch = window.fetch;
	  window.fetch = function (u, o) {
	    return String(u).indexOf('/explorer') >= 0 ? Promise.reject(new Error('network down')) : window.__origFetch(u, o);
	  }; refreshNow(); true`)
	u.waitUI("refresh failure banner", `/Could not refresh/.test((document.querySelector('.list-err')||{}).textContent||'')`)

	if got := u.evalStr(`String(document.querySelectorAll('#endpointsBody > tr[data-endpoint-id]').length)`); got != "3" {
		t.Fatalf("a failed refresh removed the table: %s row(s) remain, want 3", got)
	}
	if !u.evalBool(`!!document.querySelector('#endpointsBody tr.detail-row .endpoint-detail')`) {
		t.Fatal("a failed refresh collapsed the expanded endpoint")
	}
	if !u.evalBool(`/Could not refresh/.test((document.querySelector('.list-err')||{}).textContent||'')`) {
		t.Fatal("a failed refresh must say so instead of silently showing the last list")
	}
}
