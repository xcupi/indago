package browser_test

// Navigation and fetch surfaces other than a 3xx Location header: Refresh
// header, <meta http-equiv=refresh>, iframes (same-site and CROSS-SITE, which
// Chromium isolates in a separate process), and dedicated/shared/blob workers.
// docs/browser-scope-boundary.md listed these as unverified.
//
// Every shape is measured twice against a SECOND host name (localhost vs the
// in-scope loopback addresses):
//   - control, NO gate: the second host must be reached, otherwise a zero below
//     could mean "the shape never ran" rather than "the gate stopped it";
//   - gated: the second host must see no request and no connection.
// The cross-site frames are served from 127.0.0.2, which is in scope and a
// different site from 127.0.0.1.

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/domain"
)

type surfaceShape struct {
	name          string
	main          string // body of the main page
	refreshHeader string // value of a Refresh response header on the main page
	frame         string // body served at /frame (on either in-scope host)
	worker        string // source served at /w.js
	// navigation marks shapes that make the browser START a navigation to the
	// out-of-scope URL (page or frame). Chromium preconnects to a navigation
	// target before the request reaches the scope gate, so these leave a
	// connection behind even though the request itself is refused. See the
	// "Known gap" note in docs/browser-scope-boundary.md.
	navigation bool
	// plainControl: the shape cannot run inside Indago any more because the
	// surface is switched off at launch (SharedWorker), so its control runs in a
	// plain Chrome instead, the same way the preconnect control does.
	plainControl bool
}

const (
	fetchOut = `fetch("http://OUT/f",{mode:"no-cors"}).catch(function(){});`
)

var surfaceShapes = []surfaceShape{
	{name: "meta-refresh", main: `<meta http-equiv="refresh" content="0;url=http://OUT/hit">`, navigation: true},
	{name: "refresh-header", main: `ok`, refreshHeader: `0; url=http://OUT/hit`, navigation: true},
	{name: "location-assign", main: `<script>location.href="http://OUT/hit"</script>`, navigation: true},
	{name: "iframe-outside", main: `<iframe src="http://OUT/hit"></iframe>`, navigation: true},
	{name: "iframe-srcdoc-subresource", main: `<iframe srcdoc="&lt;img src='http://OUT/img'&gt;"></iframe>`},
	{name: "iframe-redirect", main: `<iframe src="/bounce"></iframe>`},
	{name: "iframe-meta-refresh", main: `<iframe src="/frame"></iframe>`, frame: `<meta http-equiv="refresh" content="0;url=http://OUT/hit">`, navigation: true},
	{name: "oopif-meta-refresh", main: `<iframe src="http://OTHER/frame"></iframe>`, frame: `<meta http-equiv="refresh" content="0;url=http://OUT/hit">`, navigation: true},
	{name: "oopif-fetch", main: `<iframe src="http://OTHER/frame"></iframe>`, frame: `<script>` + fetchOut + `</script>`},
	{name: "oopif-redirect", main: `<iframe src="http://OTHER/bounce"></iframe>`},
	{name: "oopif-worker", main: `<iframe src="http://OTHER/frame"></iframe>`, frame: `<script>new Worker("/w.js")</script>`, worker: fetchOut},
	{name: "worker-fetch", main: `<script>new Worker("/w.js")</script>`, worker: fetchOut},
	{name: "worker-importscripts", main: `<script>new Worker("/w.js")</script>`, worker: `try{importScripts("http://OUT/i.js")}catch(e){}`},
	{name: "blob-worker", main: `<script>new Worker(URL.createObjectURL(new Blob(['` + strings.ReplaceAll(fetchOut, `'`, `\'`) + `'])))</script>`},
	{name: "shared-worker", main: `<script>new SharedWorker("/w.js")</script>`, worker: fetchOut, plainControl: true},
}

type surfaceWorld struct {
	out     *hintWorld
	inside  *httptest.Server
	other   *httptest.Server // 127.0.0.2: in scope, a different site
	inHits  atomic.Int64
	otherOK bool
}

func newSurfaceWorld(t *testing.T, s surfaceShape) *surfaceWorld {
	t.Helper()
	w := &surfaceWorld{out: newHintWorld(t)}
	otherLn, err := net.Listen("tcp", "127.0.0.2:0")
	if err != nil {
		t.Skipf("cannot listen on 127.0.0.2 for the cross-site frame: %v", err)
	}
	other := "127.0.0.2:" + strings.TrimPrefix(otherLn.Addr().String(), "127.0.0.2:")
	repl := strings.NewReplacer("OUT", w.out.outHost, "OTHER", other)
	handler := http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.inHits.Add(1)
			if s.refreshHeader != "" {
				rw.Header().Set("Refresh", repl.Replace(s.refreshHeader))
			}
			rw.Header().Set("Content-Type", "text/html")
			fmt.Fprint(rw, "<!doctype html><html><head></head><body>"+repl.Replace(s.main)+`<img src="/slow" width=1 height=1>`+"</body></html>")
		case "/slow":
			time.Sleep(2 * time.Second) // keeps the load event pending, so the context outlives async work
			rw.Header().Set("Content-Type", "image/gif")
		case "/frame":
			rw.Header().Set("Content-Type", "text/html")
			fmt.Fprint(rw, "<!doctype html><html><head></head><body>"+repl.Replace(s.frame)+"</body></html>")
		case "/w.js":
			rw.Header().Set("Content-Type", "text/javascript")
			fmt.Fprint(rw, repl.Replace(s.worker))
		case "/bounce":
			http.Redirect(rw, r, repl.Replace("http://OUT/hit"), http.StatusFound)
		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	})
	w.inside = httptest.NewServer(handler)
	t.Cleanup(w.inside.Close)
	w.other = httptest.NewUnstartedServer(handler)
	w.other.Listener.Close()
	w.other.Listener = otherLn
	w.other.Start()
	t.Cleanup(w.other.Close)
	return w
}

func (w *surfaceWorld) reached() int64 { return w.out.reqs.Load() + w.out.conns.Load() }

func TestIntegrationRedirectSurfacesControlReachesTheSecondHost(t *testing.T) {
	for _, s := range surfaceShapes {
		t.Run(s.name, func(t *testing.T) {
			w := newSurfaceWorld(t, s)
			if s.plainControl {
				plainChrome(t, w.inside.URL+"/")
			} else {
				m := newManagerOrSkip(t, browser.DefaultConfig())
				defer m.Close()
				_, _ = m.Render(context.Background(), w.inside.URL+"/", browser.RenderOptions{}) // NO gate
			}
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) && w.reached() == 0 {
				time.Sleep(50 * time.Millisecond)
			}
			if w.inHits.Load() == 0 {
				t.Fatal("the in-scope page was never fetched; the control proves nothing")
			}
			if w.reached() == 0 {
				t.Fatalf("control: %s never reached the second host even without a gate; the gated test cannot discriminate", s.name)
			}
		})
	}
}

func TestIntegrationScopeGateStopsRedirectSurfaces(t *testing.T) {
	for _, s := range surfaceShapes {
		t.Run(s.name, func(t *testing.T) {
			w := newSurfaceWorld(t, s)
			scope := domain.Scope{IncludeHosts: []string{"127.0.0.1", "127.0.0.2"}}
			m := newManagerOrSkip(t, browser.DefaultConfig())
			defer m.Close()
			_, _ = m.Render(context.Background(), w.inside.URL+"/", browser.RenderOptions{
				AllowRequest: func(raw string) bool { return scope.Permits(raw).Allowed },
			})
			time.Sleep(2 * time.Second) // refreshes, frames and workers are asynchronous
			if w.inHits.Load() == 0 {
				t.Fatal("the in-scope page was never fetched; the test proves nothing")
			}
			// The safety property: the out-of-scope host never receives a request.
			if n := w.out.reqs.Load(); n != 0 {
				t.Fatalf("%s sent %d HTTP request(s) to the out-of-scope host", s.name, n)
			}
			// No connection either, except for navigations, where Chromium preconnects
			// before the gate can refuse (a known gap, recorded rather than asserted).
			if s.navigation {
				t.Logf("KNOWN GAP %s: %d connection(s) to the out-of-scope host, 0 requests", s.name, w.out.conns.Load())
				return
			}
			if n := w.out.conns.Load(); n != 0 {
				t.Fatalf("%s opened %d connection(s) to the out-of-scope host", s.name, n)
			}
		})
	}
}
