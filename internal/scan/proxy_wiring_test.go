package scan

import (
	"context"
	"errors"
	"testing"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/ratelimit"
)

// wiringFakeBrowser stands in for the process-wide Browser in wiring tests.
// It must never be rendered when a scan configured a proxy pool: a render here
// would be a direct, unproxied request.
type wiringFakeBrowser struct {
	renders int
}

func (b *wiringFakeBrowser) Render(context.Context, string, browser.RenderOptions) (*browser.RenderResult, error) {
	b.renders++
	return &browser.RenderResult{Status: 200}, nil
}

func (b *wiringFakeBrowser) Close() error { return nil }

// A scan with a ProxyPool must get a per-scan, proxy-carrying Browser for
// discovery; a scan without one must keep exactly the shared Browser.
func TestDiscoveryBrowserIsPerScanAndFailsClosed(t *testing.T) {
	raw := &wiringFakeBrowser{}
	c := &Controller{log: execLog(), opts: Options{Browser: raw}}

	sc := &domain.Scan{Config: domain.ScanConfig{ProxyPool: []string{"http://127.0.0.1:3128"}}}
	proxied := c.discoveryBrowser(sc)
	if proxied == nil || proxied == raw {
		t.Fatalf("discoveryBrowser returned %T; a scan with a proxy pool must get a per-scan decorator, not the shared Browser", proxied)
	}
	// The decorator cannot proxy a non-Manager Browser, and must refuse rather
	// than render directly.
	if _, err := proxied.Render(context.Background(), "http://127.0.0.1:9/", browser.RenderOptions{}); !errors.Is(err, browser.ErrProxyUnsupported) {
		t.Fatalf("Render through the pool decorator = %v, want ErrProxyUnsupported", err)
	}
	if raw.renders != 0 {
		t.Fatalf("the shared Browser rendered directly despite the scan's proxy pool")
	}

	plain := c.discoveryBrowser(&domain.Scan{})
	if plain != raw {
		t.Fatalf("a scan without a proxy pool must use the shared Browser unchanged, got %T", plain)
	}
	if _, err := plain.Render(context.Background(), "http://127.0.0.1:9/", browser.RenderOptions{}); err != nil {
		t.Fatalf("direct render: %v", err)
	}
	if raw.renders != 1 {
		t.Fatalf("direct render count = %d, want 1", raw.renders)
	}
}

func TestDiscoveryBrowserStaysNilWithoutABrowser(t *testing.T) {
	c := &Controller{log: execLog()}
	if got := c.discoveryBrowser(&domain.Scan{Config: domain.ScanConfig{ProxyPool: []string{"http://127.0.0.1:3128"}}}); got != nil {
		t.Fatalf("discoveryBrowser with no configured browser = %T, want nil (discovery's browser source is inert)", got)
	}
}

// DOM XSS browser contexts take their proxy from domXSSExecutor.nextProxy, which
// is fed by defaultHandlers. This pins that wiring (it exists in handlers.go)
// so a future refactor cannot silently drop the pool and go direct.
func TestDefaultHandlersGiveDOMXSSTheScanProxyPool(t *testing.T) {
	env := newScanEnv(t)
	c := &Controller{store: env.st, log: execLog(), opts: Options{Evidence: env.ev}}
	pool := []string{"http://127.0.0.1:3128", "http://127.0.0.1:3129"}

	h := c.defaultHandlers(env.sc, nil, openScope(), pool, ratelimit.New(0), nil)
	dom, ok := h[domain.JobDOMXSS].(*domXSSExecutor)
	if !ok {
		t.Fatalf("JobDOMXSS handler is %T, want *domXSSExecutor", h[domain.JobDOMXSS])
	}
	// The executor must own a COPY: a later mutation of the caller's slice must
	// not change where this scan's browser traffic goes.
	pool[0] = "http://127.0.0.1:9999"
	for i, want := range []string{"http://127.0.0.1:3128", "http://127.0.0.1:3129", "http://127.0.0.1:3128"} {
		if got := dom.nextProxy(); got != want {
			t.Fatalf("nextProxy #%d = %q, want %q (pool must be copied per scan and round-robin)", i, got, want)
		}
	}

	// And a scan with no pool must keep the direct path.
	plain := c.defaultHandlers(env.sc, nil, openScope(), nil, ratelimit.New(0), nil)[domain.JobDOMXSS].(*domXSSExecutor)
	if got := plain.nextProxy(); got != "" {
		t.Fatalf("nextProxy without a pool = %q, want an empty (direct) proxy", got)
	}
}
