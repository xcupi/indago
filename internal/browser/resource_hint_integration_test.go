package browser_test

// Resource hints (preconnect, prefetch) can contact a host without the page
// ever issuing a request the scope gate would see. Assertions are server-side
// counts of NEW TCP CONNECTIONS (net/http ConnState) on a second host name
// (localhost vs the in-scope 127.0.0.1).
//
// What these tests establish, and what they do not:
//
//   - prefetch is a real request; the scope gate is what stops it. The ungated
//     run proves it would connect, the gated run proves it does not.
//   - preconnect is NOT stopped by the gate. Indago's browser contexts are fresh
//     and off-the-record, and Chromium does not preconnect there. That is an
//     implicit property of the browser, not something Indago enforces. A plain
//     (non-incognito) Chrome run is the control that proves preconnect would
//     open a connection in this very environment, so a zero from Indago's
//     contexts is meaningful and a future change that loses the property fails.
//   - dns-prefetch opens no TCP connection and so cannot be seen here; see
//     docs/scope-semantics.md for how it was measured.

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/domain"
)

type hintWorld struct {
	conns, reqs atomic.Int64
	outside     *httptest.Server
	outHost     string // localhost:PORT, out of scope
}

func newHintWorld(t *testing.T) *hintWorld {
	t.Helper()
	w := &hintWorld{}
	w.outside = httptest.NewUnstartedServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		w.reqs.Add(1)
		fmt.Fprint(rw, "outside")
	}))
	w.outside.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			w.conns.Add(1)
		}
	}
	w.outside.Start()
	t.Cleanup(w.outside.Close)
	w.outHost = "localhost:" + strings.TrimPrefix(w.outside.URL, "http://127.0.0.1:")
	return w
}

type hintShape struct {
	name       string
	preconnect bool // true: a plain Chrome opens a connection, a gate cannot see it
	head       func(out string) string
	linkHeader func(out string) string
}

var hintShapes = []hintShape{
	{name: "preconnect-tag", preconnect: true, head: func(o string) string { return `<link rel="preconnect" href="http://` + o + `/">` }},
	{name: "preconnect-crossorigin", preconnect: true, head: func(o string) string { return `<link rel="preconnect" href="http://` + o + `/" crossorigin>` }},
	{name: "preconnect-link-header", preconnect: true, head: func(string) string { return "" }, linkHeader: func(o string) string { return `<http://` + o + `/>; rel=preconnect` }},
	{name: "prefetch-tag", head: func(o string) string { return `<link rel="prefetch" href="http://` + o + `/pf">` }},
}

func (s hintShape) page(t *testing.T, outHost string, inHits *atomic.Int64) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		inHits.Add(1)
		if s.linkHeader != nil {
			rw.Header().Set("Link", s.linkHeader(outHost))
		}
		rw.Header().Set("Content-Type", "text/html")
		fmt.Fprint(rw, "<!doctype html><html><head>"+s.head(outHost)+"</head><body>hint page</body></html>")
	}))
	t.Cleanup(srv.Close)
	return srv
}

func waitForConns(w *hintWorld, want int64, d time.Duration) {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) && w.conns.Load() < want {
		time.Sleep(50 * time.Millisecond)
	}
}

// plainChrome loads url in an ordinary (non-incognito) headless Chrome, outside
// Indago, as the control that shows preconnect opens a connection in this
// environment.
func plainChrome(t *testing.T, url string) {
	t.Helper()
	exe := findChromium()
	if exe == "" {
		t.Skip("no Chromium found (set INDAGO_CHROMIUM_PATH)")
	}
	prof, err := os.MkdirTemp(os.Getenv("TMPDIR"), "hint-control-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(prof)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "--headless=new", "--no-sandbox", "--disable-gpu", "--user-data-dir="+prof, url)
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start a plain Chrome control: %v", err)
	}
	<-ctx.Done() // let the hint fire, then the context kills the process
	_ = cmd.Wait()
}

func TestIntegrationResourceHintControlsOpenConnectionsWhereExpected(t *testing.T) {
	for _, shape := range hintShapes {
		t.Run(shape.name, func(t *testing.T) {
			w := newHintWorld(t)
			var inHits atomic.Int64
			inside := shape.page(t, w.outHost, &inHits)
			if shape.preconnect {
				plainChrome(t, inside.URL+"/")
			} else {
				m := newManagerOrSkip(t, browser.DefaultConfig())
				defer m.Close()
				_, _ = m.Render(context.Background(), inside.URL+"/", browser.RenderOptions{}) // NO gate
				waitForConns(w, 1, 3*time.Second)
			}
			if inHits.Load() == 0 {
				t.Fatal("the in-scope page was never fetched; the control proves nothing")
			}
			if w.conns.Load() == 0 {
				t.Fatalf("control: %s opened no connection to the second host even without a gate or in a plain Chrome; the gated test below cannot discriminate", shape.name)
			}
		})
	}
}

func TestIntegrationResourceHintsDoNotReachAnOutOfScopeHost(t *testing.T) {
	for _, shape := range hintShapes {
		t.Run(shape.name, func(t *testing.T) {
			w := newHintWorld(t)
			var inHits atomic.Int64
			inside := shape.page(t, w.outHost, &inHits)
			scope := domain.Scope{IncludeHosts: []string{"127.0.0.1"}}
			m := newManagerOrSkip(t, browser.DefaultConfig())
			defer m.Close()
			_, _ = m.Render(context.Background(), inside.URL+"/", browser.RenderOptions{
				AllowRequest: func(raw string) bool { return scope.Permits(raw).Allowed },
			})
			time.Sleep(1500 * time.Millisecond) // hints are asynchronous
			if inHits.Load() == 0 {
				t.Fatal("the in-scope page was never fetched; the test proves nothing")
			}
			if n := w.conns.Load(); n != 0 {
				t.Fatalf("%s opened %d connection(s) to the out-of-scope host (%d request(s))", shape.name, n, w.reqs.Load())
			}
		})
	}
}
