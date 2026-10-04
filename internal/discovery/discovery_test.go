package discovery_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/discovery"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/httpengine"
)

func TestRealRegistrySources(t *testing.T) {
	eng := httpengine.NewDefault()

	// Without a browser: seed, crawl, sitemap, robots, content = 5.
	r := discovery.NewRealRegistry(eng, nil, discovery.DefaultConfig())
	if len(r.Names()) != 5 {
		t.Fatalf("expected 5 sources without browser, got %d: %v", len(r.Names()), r.Names())
	}
	if _, ok := r.Get(domain.SourceCrawler); !ok {
		t.Fatal("crawler source missing")
	}

	// With a browser: + network = 6.
	rb := discovery.NewRealRegistry(eng, browser.Stub{}, discovery.DefaultConfig())
	if len(rb.Names()) != 6 {
		t.Fatalf("expected 6 sources with browser, got %d", len(rb.Names()))
	}
	if _, ok := rb.Get(domain.SourceBrowserNetwork); !ok {
		t.Fatal("network source missing")
	}
}

func TestStubSource(t *testing.T) {
	s := discovery.NewStub(domain.SourceSitemap)
	if s.Name() != domain.SourceSitemap {
		t.Fatalf("name = %s", s.Name())
	}
	if err := s.Run(context.Background(), discovery.Input{}, nil); !errors.Is(err, discovery.ErrNotImplemented) {
		t.Fatalf("expected ErrNotImplemented, got %v", err)
	}
}

func TestGate(t *testing.T) {
	g := discovery.NewGate()
	if g.Paused() {
		t.Fatal("gate should start resumed")
	}
	if err := g.Wait(context.Background()); err != nil {
		t.Fatalf("resumed gate should not block: %v", err)
	}

	// Paused gate blocks until resumed.
	g.Pause()
	if !g.Paused() {
		t.Fatal("gate should be paused")
	}
	done := make(chan error, 1)
	go func() { done <- g.Wait(context.Background()) }()
	select {
	case <-done:
		t.Fatal("Wait returned while paused")
	case <-time.After(40 * time.Millisecond):
	}
	g.Resume()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Wait after resume: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Wait did not return after resume")
	}

	// Cancellation while paused.
	g.Pause()
	ctx, cancel := context.WithCancel(context.Background())
	go func() { done <- g.Wait(ctx) }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected Canceled, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Wait did not observe cancellation")
	}
}
