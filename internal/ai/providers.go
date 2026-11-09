package ai

import (
	"fmt"
	"os"
	"strings"
)

// Supported provider identifiers.
const (
	ProviderOpenAI     = "openai"
	ProviderAnthropic  = "anthropic"
	ProviderOpenRouter = "openrouter"
	ProviderOllama     = "ollama"
	ProviderVLLM       = "vllm"
	// ProviderDeepSeek speaks the OpenAI Chat Completions shape at its own
	// endpoint (used by the LLM settings screen).
	ProviderDeepSeek = "deepseek"
	// ProviderCustom is any OpenAI-compatible endpoint (a gateway, a proxy)
	// whose base URL the operator supplies.
	ProviderCustom = "custom"
	// ProviderChatGPT uses the ChatGPT/Codex OAuth session (no API key) and
	// the Responses API at chatgpt.com/backend-api/codex.
	ProviderChatGPT = "chatgpt"
)

// Providers lists the recognized provider identifiers.
func Providers() []string {
	return []string{ProviderOpenAI, ProviderAnthropic, ProviderOpenRouter, ProviderOllama, ProviderVLLM, ProviderDeepSeek, ProviderCustom, ProviderChatGPT}
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
	case ProviderAnthropic:
		return "https://api.anthropic.com/v1"
	case ProviderOpenRouter:
		return "https://openrouter.ai/api/v1"
	case ProviderOllama:
		return "http://127.0.0.1:11434/v1"
	case ProviderVLLM:
		return "http://127.0.0.1:8000/v1"
	case ProviderDeepSeek:
		return "https://api.deepseek.com"
	case ProviderCustom:
		// No default: the operator must say where the gateway is.
		return ""
	case ProviderChatGPT:
		return "https://chatgpt.com/backend-api/codex"
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
	case ProviderOpenAI, ProviderAnthropic, ProviderOpenRouter, ProviderDeepSeek:
		return true
	default:
		return false
	}
}

// NewProvider constructs a real provider from settings: an
// openAICompatProvider for OpenAI/OpenRouter/Ollama/vLLM (all four speak the
// same Chat Completions API shape), or anthropicProvider for Anthropic
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
	case ProviderOpenAI, ProviderOpenRouter, ProviderOllama, ProviderVLLM, ProviderDeepSeek, ProviderCustom:
		return &openAICompatProvider{name: name, baseURL: baseURL, apiKey: s.APIKey, model: model}, nil
	case ProviderAnthropic:
		return &anthropicProvider{baseURL: baseURL, apiKey: s.APIKey, model: model}, nil
	case ProviderChatGPT:
		// No API key: the OAuth session is read from Indago's store, falling
		// back to the borrowed Hermes session.
		return &chatgptProvider{credPath: os.Getenv("INDAGO_CHATGPT_AUTH"), credDir: s.CredentialsDir, model: model}, nil
	default:
		return nil, fmt.Errorf("ai: unknown provider %q", s.Provider)
	}
}
