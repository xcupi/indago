package discovery_test

import (
	"context"
	"sync"
	"testing"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/discovery"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/ratelimit"
)

// limiterSpyBrowser records the limiter each render was handed.
type limiterSpyBrowser struct {
	mu       sync.Mutex
	limiters []*ratelimit.Limiter
}

func (b *limiterSpyBrowser) Render(_ context.Context, _ string, opts browser.RenderOptions) (*browser.RenderResult, error) {
	b.mu.Lock()
	b.limiters = append(b.limiters, opts.Limiter)
	b.mu.Unlock()
	return &browser.RenderResult{}, nil
}

func (b *limiterSpyBrowser) Close() error { return nil }

// Browser discovery navigations take the scan's shared limiter, not an
// unpaced path.
func TestNetworkSourcePacesNavigationsWithScanLimiter(t *testing.T) {
	sb := &limiterSpyBrowser{}
	lim := ratelimit.New(2)
	cfg := discovery.DefaultConfig()
	cfg.Limiter = lim
	src := discovery.NewNetworkSource(sb, cfg)
	in := discovery.Input{
		Scope:    domain.Scope{IncludeHosts: []string{"in.example"}},
		SeedURLs: []string{"http://in.example/"},
	}
	if err := src.Run(context.Background(), in, &spySink{}); err != nil {
		t.Fatal(err)
	}
	sb.mu.Lock()
	defer sb.mu.Unlock()
	if len(sb.limiters) != 1 || sb.limiters[0] != lim {
		t.Fatalf("browser navigation limiter = %v, want the scan's limiter", sb.limiters)
	}
}
