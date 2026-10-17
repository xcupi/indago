package detection_test

import (
	"context"
	"errors"
	"testing"

	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
)

func TestDefaultRegistryHasReflectedXSSAndDOMXSS(t *testing.T) {
	r := detection.DefaultRegistry()
	if _, ok := r.Get(domain.VulnReflectedXSS); !ok {
		t.Fatal("reflected_xss engine should be registered")
	}
	// Stored XSS remains absent until its own phase.
	if _, ok := r.Get(domain.VulnStoredXSS); ok {
		t.Fatal("stored_xss must not be registered yet")
	}
	// DOM XSS is now registered (first slice implemented — see
	// internal/scan/domxss.go for the real, non-Registry pipeline).
	e, ok := r.Get(domain.VulnDOMXSS)
	if !ok {
		t.Fatal("dom_xss engine should be registered now that its first slice is implemented")
	}
	if e.Name() != "dom-xss" {
		t.Fatalf("dom-xss engine name = %q", e.Name())
	}
	if e.VulnClass() != domain.VulnDOMXSS {
		t.Fatalf("dom-xss engine class = %s", e.VulnClass())
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

// The DOM XSS Registry entry's Detect is also never implemented — see
// domxssEngine's doc comment: this generic Input shape cannot express
// what DOM XSS needs, and nothing in the running product ever calls it.
func TestDOMXSSEngineDetectNotImplemented(t *testing.T) {
	e, ok := detection.DefaultRegistry().Get(domain.VulnDOMXSS)
	if !ok {
		t.Fatal("dom-xss engine should be registered")
	}
	_, err := e.Detect(context.Background(), detection.Input{})
	if !errors.Is(err, detection.ErrNotImplemented) {
		t.Fatalf("expected ErrNotImplemented, got %v", err)
	}
}
