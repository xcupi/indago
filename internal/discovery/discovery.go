// Package discovery is Indago's discovery layer. Pluggable Sources find
// endpoints and parameters (seed URLs, crawling/link extraction, forms,
// sitemap.xml, robots.txt, browser network observation, content and parameter
// wordlists) and stream them to a Sink that normalizes, scope-checks, and
// deduplicates them, persists survivors, and immediately enqueues test jobs.
//
// Discovery runs continuously and in parallel with testing: every new in-scope
// endpoint/parameter creates a test job as soon as it is found, so testing never
// waits for discovery to finish. Provenance (the discovery Source) is preserved.
//
// Boundaries: scope enforcement happens here (fail closed) before anything is
// persisted or enqueued; this package performs NO XSS detection, payload
// generation, or anti-bot/WAF evasion.
package discovery

import (
	"context"
	"errors"

	"github.com/indago/indago/internal/domain"
)

// Errors.
var (
	// ErrNotImplemented is returned by stub sources.
	ErrNotImplemented = errors.New("discovery: not implemented")
	// ErrLimitReached signals that a discovery limit (e.g. MaxEndpoints) was hit.
	// Sources treat it as a normal stop, not a failure.
	ErrLimitReached = errors.New("discovery: limit reached")

	errNonHTTP = errors.New("discovery: non-http(s) URL")
	errNoHost  = errors.New("discovery: URL has no host")
)

// EndpointCandidate is a discovered endpoint proposed to the Sink. The Sink owns
// normalization, scope checking, dedup, and ID assignment, so sources need not
// manage identity.
type EndpointCandidate struct {
	URL         string
	Method      domain.HTTPMethod
	Source      domain.DiscoverySource
	ContentType string
}

// ParamCandidate is a discovered parameter proposed to the Sink. The endpoint is
// identified by its URL+method so the Sink can resolve the canonical endpoint
// even after deduplication.
type ParamCandidate struct {
	EndpointURL    string
	EndpointMethod domain.HTTPMethod
	Name           string
	Location       domain.ParamLocation
	Example        string
	Source         domain.DiscoverySource
}

// Sink receives discovered items. Implementations normalize, scope-check,
// deduplicate, persist, and enqueue. A Sink must be safe for concurrent use.
type Sink interface {
	// AddEndpoint registers an endpoint and returns the canonical endpoint ID
	// (the existing one when a duplicate). An out-of-scope or duplicate endpoint
	// is skipped and reported via the returned ID being empty with a nil error.
	AddEndpoint(ctx context.Context, ep EndpointCandidate) (domain.ID, error)
	// AddParameter registers a parameter on an endpoint (resolved by URL+method).
	AddParameter(ctx context.Context, param ParamCandidate) error
}

// Input is the per-scan context a Source runs within.
type Input struct {
	ScanID    domain.ID
	Scope     domain.Scope
	SeedURLs  []string
	SessionID domain.ID
	// Wordlist is an optional file path for content/parameter discovery (used
	// when the Config wordlists are empty).
	Wordlist string
	// Gate lets a Source cooperatively pause before network work. It is nil when
	// pausing is not wired; sources must tolerate that.
	Gate *Gate
}

// wait blocks on the gate (if any) and returns ctx errors promptly.
func (in Input) wait(ctx context.Context) error {
	if in.Gate == nil {
		return ctx.Err()
	}
	return in.Gate.Wait(ctx)
}

// Source is a single discovery method. Run streams results to sink and returns
// when complete or ctx is canceled.
type Source interface {
	Name() domain.DiscoverySource
	Run(ctx context.Context, in Input, sink Sink) error
}

// Config tunes discovery behavior. Zero values get sensible defaults via
// withDefaults.
type Config struct {
	MaxDepth            int      // crawl depth (0 = seeds only)
	MaxEndpoints        int      // cap on endpoints discovered (0 → default)
	MaxPages            int      // cap on pages fetched by the crawler (0 → default)
	Concurrency         int      // crawl fetch concurrency (0 → default)
	Wordlist            []string // content-discovery words
	ParamWordlist       []string // parameter-name guesses applied to endpoints
	EnqueueEndpointJobs bool     // enqueue a test job per endpoint (not just per param)
}

// DefaultConfig returns conservative discovery defaults.
func DefaultConfig() Config {
	return Config{
		MaxDepth:            3,
		MaxEndpoints:        1000,
		MaxPages:            500,
		Concurrency:         4,
		EnqueueEndpointJobs: true,
	}
}

func (c Config) withDefaults() Config {
	if c.MaxDepth < 0 {
		c.MaxDepth = 0
	}
	if c.MaxEndpoints <= 0 {
		c.MaxEndpoints = 1000
	}
	if c.MaxPages <= 0 {
		c.MaxPages = 500
	}
	if c.Concurrency <= 0 {
		c.Concurrency = 4
	}
	return c
}

// Registry holds discovery sources by name.
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

// Sources returns all registered sources.
func (r *Registry) Sources() []Source {
	out := make([]Source, 0, len(r.sources))
	for _, s := range r.sources {
		out = append(out, s)
	}
	return out
}

// Names returns the registered source names.
func (r *Registry) Names() []domain.DiscoverySource {
	out := make([]domain.DiscoverySource, 0, len(r.sources))
	for n := range r.sources {
		out = append(out, n)
	}
	return out
}

// stubSource is a no-op source (used where a real source is not applicable).
type stubSource struct{ name domain.DiscoverySource }

func (s stubSource) Name() domain.DiscoverySource           { return s.name }
func (s stubSource) Run(context.Context, Input, Sink) error { return ErrNotImplemented }

// NewStub returns a no-op source with the given name.
func NewStub(name domain.DiscoverySource) Source { return stubSource{name: name} }
