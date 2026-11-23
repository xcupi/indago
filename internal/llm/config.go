// Package llm holds Indago's LLM provider configuration and the single
// bounded connection probe used by the CLI and the web settings screen.
//
// This package is configuration-only. It builds no prompts from assessment
// data, reads no findings, and never contacts a provider on its own: the only
// outbound calls are Prober.Test (one small chat-completions request) and
// Prober.Models (one GET /models), and both run only when the operator
// explicitly asks for them.
//
// Secret handling is structural, not advisory:
//
//   - The API key is an unexported field of Config. encoding/json cannot
//     serialize it, and code outside this package cannot read it at all.
//   - The non-secret settings live in <dir>/config.json, with credentials
//     stored in separate files. Files are mode 0600 inside a 0700 directory.
//   - Every error and log string derived from an upstream response passes
//     through Redact (redact.go) before it leaves this package.
package llm

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Recognized provider identifiers.
const (
	ProviderDeepSeek   = "deepseek"
	ProviderOpenAI     = "openai"
	ProviderAnthropic  = "anthropic"
	ProviderOpenRouter = "openrouter"
	ProviderGoogle     = "google"
	ProviderOllama     = "ollama"
	ProviderVLLM       = "vllm"
	ProviderCustom     = "custom"
	// ProviderChatGPT identifies legacy settings on disk.
	ProviderChatGPT = "chatgpt"
	// ProviderClaude is Anthropic's Claude (Messages API). It is the same
	// protocol as the anthropic id; the separate name is what users pick.
	ProviderClaude = "claude"

	// DefaultProvider is the provider a fresh configuration starts from.
	DefaultProvider = ProviderDeepSeek
)

var (
	// ErrNotConfigured means no LLM provider has been configured yet. It is a
	// normal state, not a failure: Indago works fully without an LLM.
	ErrNotConfigured = errors.New("llm: not configured")
	// ErrInvalid wraps a rejected configuration value. The message never
	// contains a submitted secret.
	ErrInvalid = errors.New("llm: invalid configuration")
)

// Provider describes a supported backend and its optional default model.
// The provider supplies its full model catalog at runtime.
type Provider struct {
	ID             string `json:"id"`
	Label          string `json:"label"`
	DefaultBaseURL string `json:"default_base_url"`
	DefaultModel   string `json:"default_model"`
	RequiresKey    bool   `json:"requires_key"`
	// Default marks the provider the UI starts from when nothing is configured.
	Default bool `json:"default,omitempty"`
	// Hidden keeps a provider resolvable for existing configs but excludes it
	// from the operator-facing provider list.
	Hidden bool `json:"-"`
}

var providerList = []Provider{
	{
		ID:             ProviderDeepSeek,
		Label:          "DeepSeek",
		DefaultBaseURL: "https://api.deepseek.com",
		DefaultModel:   "deepseek-chat",
		RequiresKey:    true,
		Default:        true,
	},
	{
		ID:             ProviderClaude,
		Label:          "Claude (Anthropic API)",
		DefaultBaseURL: "https://api.anthropic.com/v1",
		DefaultModel:   "claude-sonnet-5-5",
		RequiresKey:    true,
	},
	{
		// Same Messages API as Claude; the id stays separate because the
		// gateway has always accepted "anthropic" for direct API keys.
		ID:             ProviderAnthropic,
		Label:          "Anthropic (Messages API)",
		DefaultBaseURL: "https://api.anthropic.com/v1",
		RequiresKey:    true,
		Hidden:         true,
	},
	{
		ID:             ProviderOllama,
		Label:          "Ollama (local)",
		DefaultBaseURL: "http://127.0.0.1:11434/v1",
		RequiresKey:    false,
		Hidden:         true,
	},
	{
		ID:             ProviderVLLM,
		Label:          "vLLM (local)",
		DefaultBaseURL: "http://127.0.0.1:8000/v1",
		RequiresKey:    false,
		Hidden:         true,
	},
	{
		ID:             ProviderOpenAI,
		Label:          "OpenAI",
		DefaultBaseURL: "https://api.openai.com/v1",
		DefaultModel:   "gpt-4o-mini",
		RequiresKey:    true,
	},
	{
		ID:             ProviderOpenRouter,
		Label:          "OpenRouter",
		DefaultBaseURL: "https://openrouter.ai/api/v1",
		DefaultModel:   "openai/gpt-4o-mini",
		RequiresKey:    true,
	},
	{
		ID:             ProviderGoogle,
		Label:          "Google AI (Gemini)",
		DefaultBaseURL: "https://generativelanguage.googleapis.com/v1beta/openai",
		DefaultModel:   "gemini-3.5-flash-lite",
		RequiresKey:    true,
	},
	{
		// Any OpenAI-compatible endpoint: local vLLM/Ollama, OpenRouter, a
		// gateway. No default base URL or model exists for it, and the key is
		// optional because local endpoints commonly run without auth.
		ID:          ProviderCustom,
		Label:       "Custom (OpenAI-compatible)",
		RequiresKey: false,
	},
}

// Providers returns a copy of the supported provider definitions.
func Providers() []Provider {
	out := make([]Provider, 0, len(providerList))
	for _, p := range providerList {
		if !p.Hidden {
			out = append(out, p)
		}
	}
	return out
}

// LookupProvider resolves a provider id (case-insensitively). It is exported
// so callers can describe a stored provider without re-deriving its rules.
func LookupProvider(id string) (Provider, bool) {
	id = strings.ToLower(strings.TrimSpace(id))
	for _, p := range providerList {
		if p.ID == id {
			return p, true
		}
	}
	return Provider{}, false
}

func providerIDs() string {
	providers := Providers()
	ids := make([]string, 0, len(providers))
	for _, p := range providers {
		ids = append(ids, p.ID)
	}
	return strings.Join(ids, ", ")
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// Config is one provider configuration. Provider, Model and BaseURL are safe
// to display; the API key is deliberately unexported so it cannot be
// marshalled into a response or read by another package.
type Config struct {
	Provider string `json:"provider"`
	Model    string `json:"model"`
	BaseURL  string `json:"base_url"`
	// MaxAttempts is the advisory budget per parameter: after this many
	// failed model calls for the same parameter, Indago stops asking and
	// carries on with its own deterministic testing. 0 means DefaultMaxAttempts.
	MaxAttempts int `json:"max_attempts,omitempty"`
	// Enabled is the advisory master switch. Nil (a config written before the
	// switch existed) means enabled: upgrading must not silently turn AI off.
	Enabled *bool `json:"enabled,omitempty"`

	apiKey string
}

// AIEnabled reports whether the operator allows advisory calls. A nil switch
// (older config) is enabled.
func (c Config) AIEnabled() bool {
	if c.Enabled == nil {
		return true
	}
	return *c.Enabled
}

// DefaultMaxAttempts is the advisory budget when none is configured.
const DefaultMaxAttempts = 10

// AttemptBudget returns the effective per-parameter budget.
func (c Config) AttemptBudget() int {
	if c.MaxAttempts > 0 {
		return c.MaxAttempts
	}
	return DefaultMaxAttempts
}

// Configured reports whether a provider has been saved.
func (c Config) Configured() bool { return c.Provider != "" }

// HasKey reports whether a key is stored. It reveals only presence.
func (c Config) HasKey() bool { return c.apiKey != "" }

// MaskedKey is the only representation of the key that may leave this
// package: an empty string, or the last four characters behind a mask.
func (c Config) MaskedKey() string { return maskKey(c.apiKey) }

// Redact scrubs this configuration's exact key plus common credential shapes
// from s. Callers use it on upstream error text before returning or logging it.
func (c Config) Redact(s string) string { return Redact(s, c.apiKey) }

// String implements fmt.Stringer so a Config logged with %v or a slog
// attribute never prints the key.
func (c Config) String() string {
	state := "unset"
	if c.apiKey != "" {
		state = "set"
	}
	return fmt.Sprintf("llm.Config{provider: %q, model: %q, base_url: %q, api_key: %s}",
		c.Provider, c.Model, c.BaseURL, state)
}

// Status is the public, serializable view of a configuration. It is what
// GET /api/llm/config returns: no key, only a masked hint.
type Status struct {
	Configured  bool       `json:"configured"`
	Enabled     bool       `json:"enabled"`
	MaxAttempts int        `json:"max_attempts"`
	Provider    string     `json:"provider"`
	Model       string     `json:"model"`
	BaseURL     string     `json:"base_url"`
	KeyHint     string     `json:"key_hint"`
	KeySet      bool       `json:"key_set"`
	Providers   []Provider `json:"providers"`
}

// Status renders the configuration for an API response.
func (c Config) Status() Status {
	return Status{
		Configured:  c.Configured(),
		Provider:    c.Provider,
		Model:       c.Model,
		BaseURL:     c.BaseURL,
		KeyHint:     c.MaskedKey(),
		KeySet:      c.HasKey(),
		Enabled:     c.AIEnabled(),
		MaxAttempts: c.AttemptBudget(),
		Providers:   Providers(),
	}
}

// maskKey never reveals more than the last four characters, and reveals
// nothing at all for a key short enough that four characters would be a
// meaningful fraction of it.
func maskKey(k string) string {
	if k == "" {
		return ""
	}
	if len(k) < 12 {
		return "****"
	}
	return "****" + k[len(k)-4:]
}

// SetRequest updates and selects a provider profile. A blank key keeps that
// profile's credential or uses its environment key at runtime.
type SetRequest struct {
	// Enabled toggles advisory calls; nil keeps the current value.
	Enabled *bool `json:"enabled,omitempty"`
	// MaxAttempts is optional; 0 keeps the current/default budget.
	MaxAttempts int    `json:"max_attempts,omitempty"`
	Provider    string `json:"provider"`
	Model       string `json:"model"`
	BaseURL     string `json:"base_url"`
	APIKey      string `json:"api_key"`
}

// normalize validates and fills a SetRequest. It never includes any submitted
// value in an error: a secret pasted into the wrong field must not be echoed.
func normalize(req SetRequest, existing Config, existingAttempts int, existingEnabled *bool) (Config, error) {
	def, ok := LookupProvider(req.Provider)
	if !ok {
		return Config{}, invalid("unknown provider; valid providers are %s", providerIDs())
	}

	env := providerEnvironment(def.ID)
	model := strings.TrimSpace(req.Model)
	if model == "" {
		model = firstConfiguredValue(existing.Model, env.Model, def.DefaultModel)
	}
	if model == "" {
		return Config{}, invalid("model is required for the custom provider")
	}

	base := strings.TrimRight(strings.TrimSpace(req.BaseURL), "/")
	if base == "" {
		base = firstConfiguredValue(existing.BaseURL, env.BaseURL, def.DefaultBaseURL)
	}
	if base == "" {
		return Config{}, invalid("base_url is required for the custom provider")
	}
	if err := validateBaseURL(base); err != nil {
		return Config{}, err
	}

	key := firstConfiguredValue(strings.TrimSpace(req.APIKey), existing.apiKey)
	effectiveKey := firstConfiguredValue(key, env.apiKey)
	if !validKey(effectiveKey) {
		return Config{}, invalid("api key contains whitespace or control characters")
	}
	if def.RequiresKey && effectiveKey == "" {
		return Config{}, invalid("%s requires an API key", def.ID)
	}

	attempts := req.MaxAttempts
	if attempts < 0 || attempts > 50 {
		return Config{}, invalid("max_attempts must be between 1 and 50")
	}
	if attempts == 0 {
		attempts = existingAttempts
	}
	if attempts == 0 {
		attempts = DefaultMaxAttempts
	}
	enabled := req.Enabled
	if enabled == nil {
		enabled = existingEnabled
	}
	return Config{Provider: def.ID, Model: model, BaseURL: base, MaxAttempts: attempts, Enabled: enabled, apiKey: key}, nil
}

// validateBaseURL accepts only an absolute http(s) URL with no embedded
// credentials, query or fragment. Credentials in the URL would be a second,
// unmanaged copy of a secret (and would end up in error text), so they are
// rejected outright rather than silently tolerated.
func validateBaseURL(base string) error {
	if strings.ContainsAny(base, " \t\r\n") {
		return invalid("base_url must not contain whitespace")
	}
	u, err := url.Parse(base)
	if err != nil {
		return invalid("base_url is not a valid URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return invalid("base_url must use http or https")
	}
	if u.Host == "" {
		return invalid("base_url must include a host")
	}
	if u.User != nil {
		return invalid("base_url must not contain credentials")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return invalid("base_url must not contain a query or fragment")
	}
	return nil
}

// validKey rejects characters that HTTP header parsers would strip or refuse.
func validKey(key string) bool {
	for _, r := range key {
		if r <= 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func firstConfiguredValue(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
