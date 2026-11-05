package scan_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/scan"
	"github.com/indago/indago/internal/store/memory"
)

func TestIntegrationCreateScanLoginScope(t *testing.T) {
	t.Setenv("INDAGO_AUTH_USER", "loopback-dummy-user")
	t.Setenv("INDAGO_AUTH_PASS", "loopback-dummy-pass")
	var outsideHits, submissions atomic.Int64
	outside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { outsideHits.Add(1) }))
	defer outside.Close()
	outsideURL := strings.Replace(outside.URL, "127.0.0.1", "localhost", 1)
	inside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/done" {
			_ = r.ParseForm()
			if r.FormValue("username") == os.Getenv("INDAGO_AUTH_USER") && r.FormValue("password") == os.Getenv("INDAGO_AUTH_PASS") {
				submissions.Add(1)
			}
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<img src="%s/pixel"><form method="post" action="/done"><input name="username"><input name="password" type="password"><button type="submit">Login</button></form>`, outsideURL)
	}))
	defer inside.Close()
	mgr := newBrowserManagerOrSkip(t, 1)
	defer mgr.Close()
	st := memory.New()
	proj, tgt := seedProject(t, st, inside.URL, hostScope())
	ctrl := newCtrl(t, st, queue.NewMemory(), scan.Options{Browser: mgr, SessionsDir: t.TempDir()})
	sc, err := ctrl.CreateScan(context.Background(), scan.CreateScanParams{ProjectID: proj, TargetID: tgt, AuthMode: domain.AuthPassword, LoginURL: inside.URL + "/login", SuccessURL: "**/done"})
	if err != nil {
		t.Fatal(err)
	}
	if sc.State != domain.ScanCreated || submissions.Load() != 1 || outsideHits.Load() != 0 {
		t.Fatalf("state=%s scoped_submissions=%d outside_hits=%d", sc.State, submissions.Load(), outsideHits.Load())
	}
	// Creation establishes login only; never start a target scan.
	t.Logf("scoped_submissions=%d outside_hits=%d scan_state=%s", submissions.Load(), outsideHits.Load(), sc.State)
}
