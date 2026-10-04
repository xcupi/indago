// Package discovery defines the discovery abstraction: pluggable Sources that
// find endpoints and parameters, emitting them continuously so that testing can
// begin immediately rather than waiting for discovery to finish.
//
// Phase 0 provides the Source interface, a Sink for emission, a Registry, and
// stub Sources for every planned discovery method. No Source performs network
// activity yet — each returns ErrNotImplemented.
package discovery

import (
	"context"
	"errors"

	"github.com/indago/indago/internal/domain"
)

// ErrNotImplemented indicates a Phase 0 stub with no behavior yet.
var ErrNotImplemented = errors.New("discovery: not implemented in Phase 0")

// Sink receives discovered items as they are found. Implementations typically
// de-duplicate and persist, then enqueue test jobs for new injection points.
// A Sink must be safe for concurrent use.
type Sink interface {
	AddEndpoint(ctx context.Context, e domain.Endpoint) error
	AddParameter(ctx context.Context, p domain.Parameter) error
}

// Input is the context a Source runs within.
type Input struct {
	ScanID    domain.ID
	Scope     domain.Scope
	SeedURLs  []string
	SessionID domain.ID
	// Wordlist is an optional path for content/parameter discovery sources.
	Wordlist string
}

// Source is a single discovery method (crawler, forms, sitemap, …). Run should
// stream results to the Sink and return when complete or ctx is canceled.
type Source interface {
	// Name is a stable identifier (also the DiscoverySource value it emits).
	Name() domain.DiscoverySource
	// Run executes discovery within scope, emitting to sink as items are found.
	Run(ctx context.Context, in Input, sink Sink) error
}

// Registry holds the available discovery sources by name.
type Registry struct {
	sources map[domain.DiscoverySource]Source
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{sources: make(map[domain.DiscoverySource]Source)}
}

// Register adds or replaces a source.
func (r *Registry) Register(s Source) { r.sources[s.Name()] = s }

// Get returns a source by name.
func (r *Registry) Get(name domain.DiscoverySource) (Source, bool) {
	s, ok := r.sources[name]
	return s, ok
}

// Names returns the registered source names.
func (r *Registry) Names() []domain.DiscoverySource {
	out := make([]domain.DiscoverySource, 0, len(r.sources))
	for n := range r.sources {
		out = append(out, n)
	}
	return out
}

// stubSource is a Phase 0 no-op source.
type stubSource struct{ name domain.DiscoverySource }

func (s stubSource) Name() domain.DiscoverySource { return s.name }
func (s stubSource) Run(context.Context, Input, Sink) error {
	return ErrNotImplemented
}

// NewStub returns a no-op source with the given name, for Phase 0 wiring.
func NewStub(name domain.DiscoverySource) Source { return stubSource{name: name} }

// DefaultRegistry returns a registry pre-populated with a stub for every planned
// discovery method, so the wiring and UI can enumerate sources today.
func DefaultRegistry() *Registry {
	r := NewRegistry()
	for _, n := range []domain.DiscoverySource{
		domain.SourceUserProvided,
		domain.SourceCrawler,
		domain.SourceForm,
		domain.SourceBrowserNetwork,
		domain.SourceSitemap,
		domain.SourceRobots,
		domain.SourceContentDiscovery,
		domain.SourceParamDiscovery,
	} {
		r.Register(NewStub(n))
	}
	return r
}
