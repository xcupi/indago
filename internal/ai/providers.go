package ai

import (
	"fmt"
	"strings"
)

// Supported provider identifiers.
const (
	ProviderOpenAI     = "openai"
	ProviderAnthropic  = "anthropic"
	ProviderOpenRouter = "openrouter"
	ProviderGoogle     = "google"
	ProviderOllama     = "ollama"
	ProviderVLLM       = "vllm"
	// ProviderDeepSeek speaks the OpenAI Chat Completions shape at its own
	// endpoint (used by the LLM settings screen).
	ProviderDeepSeek = "deepseek"
	// ProviderCustom is any OpenAI-compatible endpoint (a gateway, a proxy)
	// whose base URL the operator supplies.
	ProviderCustom = "custom"
	// ProviderClaude is Anthropic's Claude through the Messages API. It is the
	// same wire protocol as ProviderAnthropic; the separate id exists because
	// users pick "Claude", and the model names are the claude-* family.
	ProviderClaude = "claude"
)

// Providers lists the recognized provider identifiers.
func Providers() []string {
	return []string{ProviderOpenAI, ProviderAnthropic, ProviderClaude, ProviderOpenRouter, ProviderGoogle, ProviderOllama, ProviderVLLM, ProviderDeepSeek, ProviderCustom}
}

// defaultBaseURL returns the conventional base URL for a provider when the
// operator didn't set one explicitly. OpenAI/Anthropic/OpenRouter are
// hosted services with one well-known endpoint; Ollama/vLLM are
// self-hosted, so their "default" is just the common localhost dev port —
// an operator pointing at a real deployment MUST still set -ai-base-url.
func defaultBaseURL(name string) string {
	switch name {
	case ProviderOpenAI:
		return "https://api.openai.com/v1"
	case ProviderAnthropic, ProviderClaude:
		return "https://api.anthropic.com/v1"
	case ProviderOpenRouter:
		return "https://openrouter.ai/api/v1"
	case ProviderGoogle:
		return "https://generativelanguage.googleapis.com/v1beta/openai"
	case ProviderOllama:
		return "http://127.0.0.1:11434/v1"
	case ProviderVLLM:
		return "http://127.0.0.1:8000/v1"
	case ProviderDeepSeek:
		return "https://api.deepseek.com"
	case ProviderCustom:
		// No default: the operator must say where the gateway is.
		return ""
	default:
		return ""
	}
}

// requiresAPIKey reports whether a provider is a hosted service that will
// reject requests with no credential. Ollama and vLLM are typically
// self-hosted with no auth in front of them by default — requiring a key
// for those would make the common local-dev case impossible to configure.
func requiresAPIKey(name string) bool {
	switch name {
	case ProviderOpenAI, ProviderAnthropic, ProviderClaude, ProviderOpenRouter, ProviderGoogle, ProviderDeepSeek:
		return true
	default:
		return false
	}
}

// NewProvider constructs a real provider from settings: an
// openAICompatProvider for Chat Completions or anthropicProvider for Anthropic
// (its own, differently-shaped Messages API). An unrecognized provider, or
// a hosted provider missing its required API key, is a config error — the
// gateway must fail closed at construction time, not on the first advisory
// call deep inside a scan.
func NewProvider(s Settings) (Provider, error) {
	name := strings.ToLower(strings.TrimSpace(s.Provider))
	if requiresAPIKey(name) && strings.TrimSpace(s.APIKey) == "" {
		return nil, fmt.Errorf("ai: provider %q requires an API key", name)
	}
	baseURL := strings.TrimSpace(s.BaseURL)
	if baseURL == "" {
		baseURL = defaultBaseURL(name)
	}
	model := strings.TrimSpace(s.Model)
	switch name {
	case ProviderOpenAI, ProviderOpenRouter, ProviderGoogle, ProviderOllama, ProviderVLLM, ProviderDeepSeek, ProviderCustom:
		return &openAICompatProvider{name: name, baseURL: baseURL, apiKey: s.APIKey, model: model}, nil
	case ProviderAnthropic, ProviderClaude:
		return &anthropicProvider{baseURL: baseURL, apiKey: strings.TrimSpace(s.APIKey), model: model}, nil
	default:
		return nil, fmt.Errorf("ai: unknown provider %q", s.Provider)
	}
}
