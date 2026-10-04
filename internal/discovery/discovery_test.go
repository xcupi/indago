package discovery_test

import (
	"context"
	"errors"
	"testing"

	"github.com/indago/indago/internal/discovery"
	"github.com/indago/indago/internal/domain"
)

func TestDefaultRegistryHasAllSources(t *testing.T) {
	r := discovery.DefaultRegistry()
	if len(r.Names()) != 8 {
		t.Fatalf("expected 8 discovery sources, got %d", len(r.Names()))
	}
	if _, ok := r.Get(domain.SourceCrawler); !ok {
		t.Fatal("crawler source missing")
	}
}

func TestStubSourceNotImplemented(t *testing.T) {
	s := discovery.NewStub(domain.SourceSitemap)
	if s.Name() != domain.SourceSitemap {
		t.Fatalf("name = %s", s.Name())
	}
	err := s.Run(context.Background(), discovery.Input{}, nil)
	if !errors.Is(err, discovery.ErrNotImplemented) {
		t.Fatalf("expected ErrNotImplemented, got %v", err)
	}
}
