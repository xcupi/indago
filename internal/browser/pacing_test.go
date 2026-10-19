package browser

// Navigations are paced by the scan's shared limiter, passed per call (the
// Manager is shared across scans, so it cannot own a per-scan limiter).

import (
	"context"
	"testing"
	"time"

	"github.com/indago/indago/internal/ratelimit"
)

func (p *fakePage) GotoJSON(rawURL string, body []byte, contentType, waitUntil string, timeout time.Duration) (int, string, error) {
	return 200, rawURL, nil
}

func TestPageNavigateJSONHonoursLimiter(t *testing.T) {
	d := &fakeDriver{}
	m := newFakeManager(t, Config{PoolSize: 1}, d)
	defer m.Close()
	ctx := context.Background()
	c, err := m.NewContext(ctx, ContextOptions{AllowRequest: func(string) bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	page, err := c.NewPage(ctx)
	if err != nil {
		t.Fatal(err)
	}

	l := ratelimit.New(2) // 500ms interval; consume the first permit.
	if err := l.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := page.NavigateJSON(ctx, "https://target.example/api", []byte(`{"q":"x"}`), "application/json", NavOptions{Limiter: l}); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed < 450*time.Millisecond {
		t.Fatalf("JSON navigation took %v after reserving the previous permit; want limiter delay near 500ms", elapsed)
	}
}

func TestPageNavigateHonoursLimiter(t *testing.T) {
	d := &fakeDriver{}
	m := newFakeManager(t, Config{PoolSize: 1}, d)
	defer m.Close()
	ctx := context.Background()
	c, err := m.NewContext(ctx, ContextOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	page, err := c.NewPage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	l := ratelimit.New(10) // 100ms interval: navigations at 0, 100ms, 200ms
	start := time.Now()
	for i := 0; i < 3; i++ {
		if _, err := page.Navigate(ctx, "https://target.example/p", NavOptions{Limiter: l}); err != nil {
			t.Fatal(err)
		}
	}
	if el := time.Since(start); el < 190*time.Millisecond {
		t.Fatalf("3 paced navigations took %v, want >= 190ms at 10 rps", el)
	}
}

func TestRenderHonoursLimiter(t *testing.T) {
	d := &fakeDriver{}
	m := newFakeManager(t, Config{PoolSize: 1}, d)
	defer m.Close()
	l := ratelimit.New(10)
	start := time.Now()
	for i := 0; i < 3; i++ {
		if _, err := m.Render(context.Background(), "https://target.example/p", RenderOptions{Limiter: l}); err != nil {
			t.Fatal(err)
		}
	}
	if el := time.Since(start); el < 190*time.Millisecond {
		t.Fatalf("3 paced renders took %v, want >= 190ms at 10 rps", el)
	}
}
