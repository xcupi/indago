package llm

// Provider registry: resolve the credential and endpoint for any supported
// provider, whether it comes from the Settings screen (one stored provider) or
// from the environment (one key per provider).
//
// The env path exists so an operator can offer more than one provider to a
// scan or a report without putting several secrets in a file the API can read:
//
//	INDAGO_LLM_KEY_DEEPSEEK=...      INDAGO_LLM_KEY_OPENAI=...
//	INDAGO_LLM_MODEL_OPENAI=gpt-4o-mini   INDAGO_LLM_BASE_URL_CUSTOM=...
//
// A stored configuration always wins for its own provider; env only fills the
// providers the store does not cover.

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// ErrNoCredential means the provider is known but no key is available for it.
// Callers turn this into a 400 naming the env var to set.
var ErrNoCredential = errors.New("llm: no credential for provider")

// Credential is one resolved provider configuration.
type Credential struct {
	Provider string
	Model    string
	BaseURL  string

	apiKey string
}

// HasKey reports whether a key is available. It reveals only presence.
func (c Credential) HasKey() bool { return c.apiKey != "" }

// APIKey returns the key so an outbound client can be constructed. It exists
// only for that purpose: never log, serialize or return this value.
func (c Credential) APIKey() string { return c.apiKey }

// Redact scrubs this credential's key from s.
func (c Credential) Redact(s string) string { return Redact(s, c.apiKey) }

// String implements fmt.Stringer without the key.
func (c Credential) String() string {
	state := "unset"
	if c.apiKey != "" {
		state = "set"
	}
	return fmt.Sprintf("llm.Credential{provider: %q, model: %q, base_url: %q, api_key: %s}",
		c.Provider, c.Model, c.BaseURL, state)
}

// Availability is the public view of one provider: what the UI needs to show
// which providers are usable without revealing any secret.
type Availability struct {
	Provider   string `json:"provider"`
	Label      string `json:"label"`
	Configured bool   `json:"configured"`
	Model      string `json:"model,omitempty"`
	BaseURL    string `json:"base_url,omitempty"`
	KeyHint    string `json:"key_hint,omitempty"`
	// Source is "settings" when the stored configuration supplies this
	// provider, "environment" when only env vars do, "" when neither.
	Source string `json:"source"`
}

// Registry resolves provider credentials from the stored configuration plus
// the environment. It performs no I/O beyond reading local files/env.
type Registry struct {
	store *Store
}

// NewRegistry wraps a store. A nil store is allowed: only env-provided
// providers resolve then.
func NewRegistry(st *Store) *Registry { return &Registry{store: st} }

func envName(provider, suffix string) string {
	p := strings.ToUpper(provider)
	var b strings.Builder
	for _, r := range p {
		switch {
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return "INDAGO_LLM_" + suffix + "_" + b.String()
}

// Resolve returns the credential for provider (default: the stored provider,
// else DefaultProvider) with an optional model override. It returns
// ErrNoCredential when a hosted provider has no key anywhere.
func (r *Registry) Resolve(provider, model string) (Credential, error) {
	var stored Config
	if r != nil && r.store != nil {
		if c, err := r.store.Load(); err == nil {
			stored = c
		} else if !errors.Is(err, ErrNotConfigured) {
			return Credential{}, err
		}
	}

	provider = strings.ToLower(strings.TrimSpace(provider))
	if provider == "" {
		provider = stored.Provider
	}
	if provider == "" {
		provider = DefaultProvider
	}
	def, ok := LookupProvider(provider)
	if !ok {
		return Credential{}, fmt.Errorf("%w: %q", ErrInvalid, provider)
	}

	cred := Credential{Provider: provider, Model: def.DefaultModel, BaseURL: def.DefaultBaseURL}
	source := ""
	if stored.Configured() && stored.Provider == provider {
		cred.Model = stored.Model
		cred.BaseURL = stored.BaseURL
		cred.apiKey = stored.apiKey
		source = "settings"
	}
	if v := strings.TrimSpace(os.Getenv(envName(provider, "MODEL"))); v != "" {
		cred.Model = v
	}
	if v := strings.TrimSpace(os.Getenv(envName(provider, "BASE_URL"))); v != "" {
		cred.BaseURL = v
	}
	if v := strings.TrimSpace(os.Getenv(envName(provider, "KEY"))); v != "" {
		cred.apiKey = v
		source = "environment"
	}
	if strings.TrimSpace(model) != "" {
		cred.Model = strings.TrimSpace(model)
	}
	if cred.BaseURL == "" {
		return Credential{}, fmt.Errorf("%w: provider %q needs a base_url", ErrInvalid, provider)
	}
	if def.RequiresKey && cred.apiKey == "" {
		return Credential{}, fmt.Errorf("%w %q: set INDAGO_LLM_KEY_%s or save it in Settings",
			ErrNoCredential, provider, strings.ToUpper(strings.ReplaceAll(provider, "-", "_")))
	}
	_ = source
	return cred, nil
}

// List reports every supported provider with its availability.
func (r *Registry) List() []Availability {
	out := make([]Availability, 0, len(providerList))
	for _, p := range providerList {
		cred, err := r.Resolve(p.ID, "")
		av := Availability{Provider: p.ID, Label: p.Label}
		if err == nil {
			av.Configured = true
			av.Model = cred.Model
			av.BaseURL = cred.BaseURL
			av.KeyHint = maskKey(cred.apiKey)
			av.Source = "environment"
			if r != nil && r.store != nil {
				if stored, e := r.store.Load(); e == nil && stored.Provider == p.ID {
					av.Source = "settings"
				}
			}
		}
		out = append(out, av)
	}
	return out
}
