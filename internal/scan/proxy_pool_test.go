package scan_test

// ProxyPool is validated when the scan is created, stored in the scan's
// config, and actually changes which HTTP engine the scan's raw traffic uses
// (see scan_http_engine_test.go for the white-box half of that last claim).

import (
	"context"
	"errors"
	"testing"

	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/scan"
	"github.com/indago/indago/internal/store/memory"
)

func TestCreateScanProxyPoolValidationAndPersistence(t *testing.T) {
	st, q := memory.New(), queue.NewMemory()
	site := standardSite(t)
	proj, tgt := seedProject(t, st, site.URL, hostScope())
	ctrl := newCtrl(t, st, q, scan.Options{})
	ctx := context.Background()
	base := scan.CreateScanParams{ProjectID: proj, TargetID: tgt, Name: "p"}

	for _, bad := range [][]string{
		{"not a url at all"},
		{"host:1080"},                  // no scheme -> url.Parse gives an empty Host
		{"ftp://proxy.example.com:21"}, // unsupported scheme
		{"http://ok:8080", "ftp://bad"},
	} {
		p := base
		p.ProxyPool = bad
		if _, err := ctrl.CreateScan(ctx, p); !errors.Is(err, scan.ErrBadConfig) {
			t.Fatalf("proxy_pool=%v: err = %v, want ErrBadConfig", bad, err)
		}
	}

	p := base
	p.ProxyPool = []string{"http://proxy1:8080", "socks5://user:pass@proxy2:1080"}
	sc, err := ctrl.CreateScan(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := st.Scans().Get(ctx, sc.ID)
	if len(got.Config.ProxyPool) != 2 || got.Config.ProxyPool[0] != "http://proxy1:8080" {
		t.Fatalf("persisted config = %+v", got.Config)
	}

	// Default: no proxy pool configured means none is stored.
	def, err := ctrl.CreateScan(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	if d, _ := st.Scans().Get(ctx, def.ID); len(d.Config.ProxyPool) != 0 {
		t.Fatalf("default config = %+v", d.Config)
	}
}
