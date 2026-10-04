// Package detection defines the detection-engine interface and a registry keyed
// by vulnerability class. A detection engine analyzes test context and proposes
// *candidates* — it never confirms a vulnerability. Confirmation is the job of
// package verification.
//
// Phase 0 contains NO detection logic. It provides the interface, a registry,
// and a stub engine for Reflected XSS so wiring and the UI can enumerate engines
// today. The Reflected XSS pipeline (baseline → marker → reflection → context →
// candidates → verification) is implemented in Phase 1.
package detection

import (
	"context"
	"errors"

	"github.com/indago/indago/internal/domain"
)

// ErrNotImplemented indicates a Phase 0 stub with no behavior yet.
var ErrNotImplemented = errors.New("detection: not implemented in Phase 0")

// Input is the generic context handed to a detection engine. Phase 1 extends it
// with baseline, unique marker, and response references; it is intentionally
// minimal here to avoid coupling the model to any one vulnerability class.
type Input struct {
	ScanID         domain.ID
	InjectionPoint domain.InjectionPoint
}

// Outcome is an engine's proposal. Candidate==true means "worth verifying", and
// is never, by itself, a confirmation.
type Outcome struct {
	Candidate bool
	// Suggested severity/confidence for a resulting finding (advisory).
	Severity   domain.Severity
	Confidence domain.Confidence
	Notes      string
}

// Engine analyzes an injection point for a single vulnerability class.
type Engine interface {
	Name() string
	VulnClass() domain.VulnClass
	// Detect runs detection and proposes a candidate. Phase 0: not implemented.
	Detect(ctx context.Context, in Input) (*Outcome, error)
}

// Registry holds detection engines keyed by vulnerability class.
type Registry struct {
	engines map[domain.VulnClass]Engine
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{engines: make(map[domain.VulnClass]Engine)}
}

// Register adds or replaces an engine.
func (r *Registry) Register(e Engine) { r.engines[e.VulnClass()] = e }

// Get returns the engine for a vulnerability class.
func (r *Registry) Get(class domain.VulnClass) (Engine, bool) {
	e, ok := r.engines[class]
	return e, ok
}

// Classes returns the registered vulnerability classes.
func (r *Registry) Classes() []domain.VulnClass {
	out := make([]domain.VulnClass, 0, len(r.engines))
	for c := range r.engines {
		out = append(out, c)
	}
	return out
}

// stubEngine is a Phase 0 no-op engine for a given class.
type stubEngine struct {
	name  string
	class domain.VulnClass
}

func (s stubEngine) Name() string                { return s.name }
func (s stubEngine) VulnClass() domain.VulnClass { return s.class }
func (s stubEngine) Detect(context.Context, Input) (*Outcome, error) {
	return nil, ErrNotImplemented
}

// NewStub returns a no-op engine for the given class.
func NewStub(name string, class domain.VulnClass) Engine {
	return stubEngine{name: name, class: class}
}

// DefaultRegistry returns a registry containing the Phase 1 target engine
// (Reflected XSS) as a stub. Stored/DOM XSS are intentionally absent until their
// phases.
func DefaultRegistry() *Registry {
	r := NewRegistry()
	r.Register(NewStub("reflected-xss", domain.VulnReflectedXSS))
	return r
}
