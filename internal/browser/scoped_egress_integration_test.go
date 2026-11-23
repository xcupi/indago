package browser_test

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/domain"
)

func TestIntegrationScopedEgressBlocksOtherPortBeforeTCP(t *testing.T) {
	if testing.Short() {
		t.Skip("real-browser test")
	}
	exe := findChromium()
	if exe == "" {
		t.Skip("Chromium not installed")
	}
	outside, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer outside.Close()
	dialed := make(chan struct{})
	go func() {
		if conn, err := outside.Accept(); err == nil {
			_ = conn.Close()
			close(dialed)
		}
	}()

	for _, tls := range []bool{false, true} {
		scheme := "http"
		if tls {
			scheme = "https"
		}
		t.Run(scheme, func(t *testing.T) {
			var forbiddenPath atomic.Int32
			target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/app/":
					w.Header().Set("Content-Type", "text/html")
					fmt.Fprintf(w, `<title>Scoped home</title><iframe src="%s://%s/"></iframe><img src="/private">`, scheme, outside.Addr())
				default:
					forbiddenPath.Add(1)
					http.NotFound(w, r)
				}
			}))
			if tls {
				target.StartTLS()
			} else {
				target.Start()
			}
			defer target.Close()
			scope := domain.Scope{
				IncludeHosts:        []string{"127.0.0.1"},
				AllowedOrigins:      []string{target.URL},
				IncludePathPrefixes: []string{"/app"},
			}
			mgr, err := browser.NewManager(browser.Config{
				Headless: true, ExecutablePath: exe, EnforceScopeEgress: true,
				DisableSandbox: os.Getenv("INDAGO_TEST_BROWSER_NO_SANDBOX") == "1",
			}, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer mgr.Close()

			allow := func(raw string) bool { return scope.Permits(raw).Allowed }
			if ctx, err := mgr.NewContext(t.Context(), browser.ContextOptions{AllowRequest: allow}); err == nil {
				_ = ctx.Close()
				t.Fatal("accepted a context with no authority gate")
			}
			opts := browser.RenderOptions{
				AllowRequest: allow, AllowAuthority: scope.PermitsHost,
				IgnoreHTTPSErrors: tls, ObservationWindow: 250 * time.Millisecond,
			}
			got, err := mgr.Render(t.Context(), target.URL+"/app/", opts)
			if err != nil {
				t.Fatal(err)
			}
			if got.Status != 200 || !strings.Contains(got.HTML, "<title>Scoped home</title>") {
				t.Fatalf("in-scope navigation failed through proxy: HTTP %d", got.Status)
			}
			if n := forbiddenPath.Load(); n != 0 {
				t.Fatalf("received %d requests to the excluded path", n)
			}
			select {
			case <-dialed:
				t.Fatal("Chromium opened a TCP connection to the unauthorized port")
			default:
			}
		})
	}
}
