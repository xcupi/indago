package ai

import (
	"context"
	"fmt"
	"strings"
)

// Supported provider identifiers. These are recognized for configuration and
// enumeration; their implementations are stubs in Phase 0.
const (
	ProviderOpenAI     = "openai"
	ProviderAnthropic  = "anthropic"
	ProviderOpenRouter = "openrouter"
	ProviderOllama     = "ollama"
	ProviderVLLM       = "vllm"
)

// Providers lists the recognized provider identifiers.
func Providers() []string {
	return []string{ProviderOpenAI, ProviderAnthropic, ProviderOpenRouter, ProviderOllama, ProviderVLLM}
}

// stubProvider is a Phase 0 placeholder that implements Provider but performs no
// network calls.
type stubProvider struct {
	name     string
	settings Settings
}

func (p stubProvider) Name() string { return p.name }

func (p stubProvider) Complete(context.Context, Request) (*Response, error) {
	return nil, fmt.Errorf("%w: %s", ErrNotImplemented, p.name)
}

// NewProvider constructs a provider from settings. In Phase 0 every recognized
// provider yields a stub; an unrecognized provider is an error.
func NewProvider(s Settings) (Provider, error) {
	name := strings.ToLower(strings.TrimSpace(s.Provider))
	switch name {
	case ProviderOpenAI, ProviderAnthropic, ProviderOpenRouter, ProviderOllama, ProviderVLLM:
		return stubProvider{name: name, settings: s}, nil
	default:
		return nil, fmt.Errorf("ai: unknown provider %q", s.Provider)
	}
}
