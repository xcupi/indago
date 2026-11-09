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
//   - The non-secret settings live in <dir>/config.json; the key lives in a
//     separate <dir>/api_key file. Both are mode 0600 inside a 0700 directory.
//     A config file can therefore be copied or attached to a bug report
//     without carrying the credential with it.
//   - Every error and log string derived from an upstream response passes
//     through Redact (redact.go) before it leaves this package.
package llm

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Recognized provider identifiers.
const (
	ProviderDeepSeek = "deepseek"
	ProviderOpenAI   = "openai"
	ProviderCustom   = "custom"
	// ProviderChatGPT is the OAuth (Codex) provider: no API key, the session
	// comes from the Hermes auth store.
	ProviderChatGPT = "chatgpt"
	// ProviderClaude is Anthropic's Claude (Messages API). It is the same
	// protocol as the anthropic id; the separate name is what users pick.
	ProviderClaude = "claude"

	// DefaultProvider is the provider a fresh configuration starts from.
	DefaultProvider = ProviderDeepSeek
)

const (
	configFileName = "config.json"
	keyFileName    = "api_key"
	configVersion  = 1
)

var (
	// ErrNotConfigured means no LLM provider has been configured yet. It is a
	// normal state, not a failure: Indago works fully without an LLM.
	ErrNotConfigured = errors.New("llm: not configured")
	// ErrInvalid wraps a rejected configuration value. The message never
	// contains a submitted secret.
	ErrInvalid = errors.New("llm: invalid configuration")
)

// Provider describes a supported backend. The three providers are fixed
// because they are three distinct endpoint/auth conventions; model names are
// NOT enumerated here (a hardcoded model list goes stale immediately), only a
// per-provider default that the operator can override with free text.
type Provider struct {
	ID             string `json:"id"`
	Label          string `json:"label"`
	DefaultBaseURL string `json:"default_base_url"`
	DefaultModel   string `json:"default_model"`
	RequiresKey    bool   `json:"requires_key"`
	// Default marks the provider the UI starts from when nothing is configured.
	Default bool `json:"default,omitempty"`
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
		Label:          "Claude (Anthropic)",
		DefaultBaseURL: "https://api.anthropic.com/v1",
		RequiresKey:    true,
	},
	{
		ID:             ProviderOpenAI,
		Label:          "OpenAI",
		DefaultBaseURL: "https://api.openai.com/v1",
		DefaultModel:   "gpt-4o-mini",
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
	{
		// ChatGPT through the Codex OAuth session (no API key). The model is
		// discovered from the account's own model list at call time.
		ID:          ProviderChatGPT,
		Label:       "ChatGPT (OAuth)",
		RequiresKey: false,
	},
}

// Providers returns a copy of the supported provider definitions.
func Providers() []Provider {
	out := make([]Provider, len(providerList))
	copy(out, providerList)
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
	ids := make([]string, 0, len(providerList))
	for _, p := range providerList {
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

// SetRequest is a configuration update. APIKey is empty on update to mean
// "keep the stored key"; there is deliberately no way to clear only the key
// (DELETE /api/llm/config clears the whole configuration).
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
func normalize(req SetRequest, existingKey string, existingAttempts int, existingEnabled *bool) (Config, error) {
	def, ok := LookupProvider(req.Provider)
	if !ok {
		return Config{}, invalid("unknown provider; valid providers are %s", providerIDs())
	}

	model := strings.TrimSpace(req.Model)
	if model == "" {
		model = def.DefaultModel
	}
	if model == "" {
		return Config{}, invalid("model is required for the custom provider")
	}

	base := strings.TrimRight(strings.TrimSpace(req.BaseURL), "/")
	if base == "" {
		base = def.DefaultBaseURL
	}
	if base == "" {
		return Config{}, invalid("base_url is required for the custom provider")
	}
	if err := validateBaseURL(base); err != nil {
		return Config{}, err
	}

	key := strings.TrimSpace(req.APIKey)
	if key == "" {
		key = existingKey
	}
	if key != "" {
		for _, r := range key {
			// A key is a single header token: any whitespace or control
			// character would either be silently stripped by the HTTP layer or
			// produce an opaque provider error, so reject it here.
			if r <= 0x20 || r == 0x7f {
				return Config{}, invalid("api key contains whitespace or control characters")
			}
		}
	}
	if def.RequiresKey && key == "" {
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

// diskConfig is the exact on-disk shape of config.json. It has no API key
// field at all: the secret lives in the separate api_key file, so this file
// can never accidentally persist one.
type diskConfig struct {
	Version  int    `json:"version"`
	Provider string `json:"provider"`
	Model    string `json:"model"`
	BaseURL  string `json:"base_url"`
	// MaxAttempts and Enabled are operator policy, not secrets, so they live
	// in the config file next to the provider choice.
	MaxAttempts int   `json:"max_attempts,omitempty"`
	Enabled     *bool `json:"enabled,omitempty"`
}

// Store reads and writes one LLM configuration under a dedicated directory.
// It performs no network I/O.
//
// On disk:
//
//	<dir>/               mode 0700
//	<dir>/config.json    mode 0600   provider, model, base_url (no key)
//	<dir>/api_key        mode 0600   the API key, plain text, owner-only
//
// The key is intentionally not encrypted: there is no unattended secret with
// which to encrypt it, and obfuscation would only hide the real control, which
// is filesystem ownership (0600/0700). The API never returns it.
type Store struct {
	dir string
	mu  sync.Mutex
}

// NewStore returns a store rooted at dir. The directory is created on the
// first successful save.
func NewStore(dir string) *Store { return &Store{dir: dir} }

// Dir is the configuration directory.
func (s *Store) Dir() string { return s.dir }

// Path is the non-secret config.json path.
func (s *Store) Path() string { return filepath.Join(s.dir, configFileName) }

// KeyPath is the secret file path.
func (s *Store) KeyPath() string { return filepath.Join(s.dir, keyFileName) }

// Load reads the stored configuration. A missing file is ErrNotConfigured,
// not a failure.
func (s *Store) Load() (Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadLocked()
}

func (s *Store) loadLocked() (Config, error) {
	b, err := os.ReadFile(s.Path())
	if err != nil {
		if os.IsNotExist(err) {
			return Config{}, ErrNotConfigured
		}
		return Config{}, fmt.Errorf("llm: read config %s: %w", s.Path(), err)
	}
	var d diskConfig
	if err := json.Unmarshal(b, &d); err != nil {
		return Config{}, fmt.Errorf("llm: parse config %s: %w", s.Path(), err)
	}
	if d.Version > configVersion {
		return Config{}, fmt.Errorf("llm: config %s has unsupported version %d", s.Path(), d.Version)
	}
	if d.Provider == "" {
		return Config{}, ErrNotConfigured
	}
	key, err := s.readKeyLocked()
	if err != nil {
		return Config{}, err
	}
	return Config{Provider: d.Provider, Model: d.Model, BaseURL: d.BaseURL,
		MaxAttempts: d.MaxAttempts, Enabled: d.Enabled, apiKey: key}, nil
}

func (s *Store) readKeyLocked() (string, error) {
	b, err := os.ReadFile(s.KeyPath())
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("llm: read API key file %s: %w", s.KeyPath(), err)
	}
	return strings.TrimSpace(string(b)), nil
}

// Set validates req against any stored configuration and persists the result.
// An empty req.APIKey keeps the stored key.
func (s *Store) Set(req SetRequest) (Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cur, err := s.loadLocked()
	if err != nil && !errors.Is(err, ErrNotConfigured) {
		// A config we cannot read (permissions, corruption) must not be
		// silently overwritten — and its key, if any, must not be lost.
		return Config{}, err
	}
	cfg, err := normalize(req, cur.apiKey, cur.AttemptBudget(), cur.Enabled)
	if err != nil {
		return Config{}, err
	}
	if err := s.saveLocked(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (s *Store) saveLocked(cfg Config) error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return fmt.Errorf("llm: create config directory: %w", err)
	}
	// MkdirAll keeps an existing directory's mode, so tighten it explicitly:
	// a directory created by an older version or by hand must not stay open.
	if err := os.Chmod(s.dir, 0o700); err != nil {
		return fmt.Errorf("llm: secure config directory: %w", err)
	}

	// Secret first: if writing it fails, the previous config is untouched.
	if cfg.apiKey == "" {
		if err := os.Remove(s.KeyPath()); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("llm: remove API key file: %w", err)
		}
	} else if err := writeFile0600(s.KeyPath(), []byte(cfg.apiKey)); err != nil {
		return err
	}

	b, err := json.MarshalIndent(diskConfig{
		Version:     configVersion,
		Provider:    cfg.Provider,
		Model:       cfg.Model,
		BaseURL:     cfg.BaseURL,
		MaxAttempts: cfg.MaxAttempts,
		Enabled:     cfg.Enabled,
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("llm: encode config: %w", err)
	}
	b = append(b, '\n')
	return writeFile0600(s.Path(), b)
}

// writeFile0600 writes b atomically with owner-only permissions. The
// temporary file is created inside the (0700) destination directory, so no
// other user can open it while it is being written.
func writeFile0600(path string, b []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return fmt.Errorf("llm: create temporary file: %w", err)
	}
	name := tmp.Name()
	discard := func() { _ = os.Remove(name) }

	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		discard()
		return fmt.Errorf("llm: write %s: %w", filepath.Base(path), err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		discard()
		return fmt.Errorf("llm: sync %s: %w", filepath.Base(path), err)
	}
	if err := tmp.Close(); err != nil {
		discard()
		return fmt.Errorf("llm: close %s: %w", filepath.Base(path), err)
	}
	// os.CreateTemp already uses 0600; this also covers a filesystem or umask
	// that surprised us, and rename would otherwise replace the old file's
	// mode with the temp file's.
	if err := os.Chmod(name, 0o600); err != nil {
		discard()
		return fmt.Errorf("llm: set mode on %s: %w", filepath.Base(path), err)
	}
	if err := os.Rename(name, path); err != nil {
		discard()
		return fmt.Errorf("llm: replace %s: %w", filepath.Base(path), err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("llm: set mode on %s: %w", filepath.Base(path), err)
	}
	return nil
}

// Clear removes the stored configuration and key. It is idempotent.
func (s *Store) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range []string{s.KeyPath(), s.Path()} {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("llm: remove %s: %w", filepath.Base(p), err)
		}
	}
	return nil
}
