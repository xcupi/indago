// Package ai defines the optional AI Gateway: a provider-agnostic abstraction
// for LLM assistance (prioritization, triage, context interpretation, payload
// suggestions, JS analysis, report drafting).
//
// Hard invariants:
//
//   - The scanner MUST work with AI disabled. The zero-value / default gateway
//     is Disabled.
//   - AI output is ADVISORY ONLY. It must never be the final authority for
//     scope, XSS confirmation, evidence, or any security verdict. To reinforce
//     this the method is named Advise (not Decide) and every Response is marked
//     Advisory.
//
// Phase 0 implements the gateway plumbing and the Disabled gateway. Concrete
// providers (OpenAI, Anthropic, OpenRouter, Ollama, vLLM) are stubs returning
// ErrNotImplemented; wiring real providers is a later phase.
package ai

import (
	"context"
	"errors"

	"github.com/indago/indago/internal/domain"
)

// ErrDisabled is returned when an advisory call is made while AI is disabled.
var ErrDisabled = errors.New("ai: gateway disabled")

// ErrNotImplemented indicates a provider stub with no behavior yet.
var ErrNotImplemented = errors.New("ai: provider not implemented")

// Request is an advisory request to the gateway.
type Request struct {
	Kind    domain.AITaskKind
	Prompt  string
	Context map[string]any
}

// Response is an advisory result. Advisory is always true: consumers must treat
// it as a suggestion, never as an authoritative decision.
type Response struct {
	Text     string
	Model    string
	Provider string
	Advisory bool
}

// Provider is a concrete LLM backend.
type Provider interface {
	Name() string
	Complete(ctx context.Context, req Request) (*Response, error)
}

// Gateway is the advisory entry point used by the rest of the system.
type Gateway interface {
	Enabled() bool
	// Advise runs an advisory task. Returns ErrDisabled when AI is off.
	Advise(ctx context.Context, req Request) (*Response, error)
}

// Disabled is the default gateway: AI is off and the scanner is fully functional.
type Disabled struct{}

// Enabled implements Gateway.
func (Disabled) Enabled() bool { return false }

// Advise implements Gateway.
func (Disabled) Advise(context.Context, Request) (*Response, error) { return nil, ErrDisabled }

var _ Gateway = Disabled{}

// enabledGateway wraps a Provider and enforces the advisory invariant.
type enabledGateway struct {
	provider Provider
	model    string
}

// Enabled implements Gateway.
func (g *enabledGateway) Enabled() bool { return true }

// Advise implements Gateway, stamping every response as advisory.
func (g *enabledGateway) Advise(ctx context.Context, req Request) (*Response, error) {
	resp, err := g.provider.Complete(ctx, req)
	if err != nil {
		return nil, err
	}
	if resp != nil {
		resp.Advisory = true // invariant: AI output is never authoritative
		if resp.Model == "" {
			resp.Model = g.model
		}
		resp.Provider = g.provider.Name()
	}
	return resp, nil
}

var _ Gateway = (*enabledGateway)(nil)

// Settings configures the gateway. The caller is responsible for reading the API
// key (e.g. from an environment variable); this package never touches secrets
// storage directly.
type Settings struct {
	Enabled  bool
	Provider string
	Model    string
	BaseURL  string
	APIKey   string
}

// New returns a gateway from settings. When disabled (or provider empty) it
// returns Disabled, guaranteeing the scanner works without AI.
func New(s Settings) (Gateway, error) {
	if !s.Enabled || s.Provider == "" {
		return Disabled{}, nil
	}
	p, err := NewProvider(s)
	if err != nil {
		return nil, err
	}
	return &enabledGateway{provider: p, model: s.Model}, nil
}
