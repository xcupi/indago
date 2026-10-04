package detection_test

import (
	"context"
	"errors"
	"testing"

	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
)

func TestDefaultRegistryHasReflectedXSSOnly(t *testing.T) {
	r := detection.DefaultRegistry()
	if _, ok := r.Get(domain.VulnReflectedXSS); !ok {
		t.Fatal("reflected_xss engine should be registered")
	}
	// Stored/DOM must NOT be present until their phases.
	if _, ok := r.Get(domain.VulnStoredXSS); ok {
		t.Fatal("stored_xss must not be registered in Phase 0/1")
	}
	if _, ok := r.Get(domain.VulnDOMXSS); ok {
		t.Fatal("dom_xss must not be registered in Phase 0/1")
	}
}

func TestStubEngineNotImplemented(t *testing.T) {
	e := detection.NewStub("reflected-xss", domain.VulnReflectedXSS)
	if e.VulnClass() != domain.VulnReflectedXSS {
		t.Fatalf("class = %s", e.VulnClass())
	}
	_, err := e.Detect(context.Background(), detection.Input{})
	if !errors.Is(err, detection.ErrNotImplemented) {
		t.Fatalf("expected ErrNotImplemented, got %v", err)
	}
}
