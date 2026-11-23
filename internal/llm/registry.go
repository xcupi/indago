package llm

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
	source string
}

// HasKey reports whether a key is available. It reveals only presence.
func (c Credential) HasKey() bool { return c.apiKey != "" }

// APIKey returns the key so an outbound client can be constructed. It exists
// only for that purpose: never log, serialize or return this value.
func (c Credential) APIKey() string { return c.apiKey }

// Config returns the resolved settings for a connection or catalog probe.
func (c Credential) Config() Config {
	return Config{Provider: c.Provider, Model: c.Model, BaseURL: c.BaseURL, apiKey: c.apiKey}
}

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
	ReportOnly bool   `json:"report_only,omitempty"`
	Model      string `json:"model,omitempty"`
	BaseURL    string `json:"base_url,omitempty"`
	KeyHint    string `json:"key_hint,omitempty"`
	Saved      bool   `json:"saved,omitempty"`
	// Source identifies where the effective credential came from.
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

// KeyEnvName returns the environment variable for a provider credential.
func KeyEnvName(provider string) string { return envName(strings.TrimSpace(provider), "KEY") }

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

func providerEnvironment(provider string) Config {
	return Config{
		Model:   strings.TrimSpace(os.Getenv(envName(provider, "MODEL"))),
		BaseURL: strings.TrimRight(strings.TrimSpace(os.Getenv(envName(provider, "BASE_URL"))), "/"),
		apiKey:  strings.TrimSpace(os.Getenv(KeyEnvName(provider))),
	}
}

func (r *Registry) snapshot() (diskConfig, map[string]Config, error) {
	if r != nil && r.store != nil {
		d, profiles, err := r.store.snapshot()
		if !errors.Is(err, ErrNotConfigured) {
			return d, profiles, err
		}
	}
	return diskConfig{}, nil, nil
}

// Resolve uses the selected provider, or the stored default when omitted.
// An explicit model overrides the saved and environment model.
func (r *Registry) Resolve(provider, model string) (Credential, error) {
	d, profiles, err := r.snapshot()
	if err != nil {
		return Credential{}, err
	}
	provider = firstConfiguredValue(strings.ToLower(strings.TrimSpace(provider)), d.Provider, DefaultProvider)
	return resolveProvider(provider, model, profiles[provider])
}

func resolveProvider(provider, model string, stored Config) (Credential, error) {
	def, ok := LookupProvider(provider)
	if !ok {
		return Credential{}, invalid("unknown provider")
	}
	env := providerEnvironment(provider)
	cred := Credential{
		Provider: def.ID,
		Model:    firstConfiguredValue(strings.TrimSpace(model), stored.Model, env.Model, def.DefaultModel),
		BaseURL:  firstConfiguredValue(stored.BaseURL, env.BaseURL, def.DefaultBaseURL),
		apiKey:   firstConfiguredValue(stored.apiKey, env.apiKey),
	}
	if stored.HasKey() || (env.apiKey == "" && stored.Configured()) {
		cred.source = "settings"
	} else if env.apiKey != "" || env.BaseURL != "" {
		cred.source = "environment"
	}
	if cred.BaseURL == "" {
		return cred, invalid("provider %q needs a base_url", def.ID)
	}
	if validateBaseURL(cred.BaseURL) != nil {
		return cred, invalid("provider %q has an invalid base_url", def.ID)
	}
	if def.RequiresKey && !cred.HasKey() {
		return cred, fmt.Errorf("%w %q: set %s or save it in Settings", ErrNoCredential, def.ID, KeyEnvName(def.ID))
	}
	if !validKey(cred.apiKey) {
		return cred, invalid("provider %q has an invalid API key", def.ID)
	}
	return cred, nil
}

// List reports provider availability and the default selection from one
// snapshot. Model and endpoint metadata are useful even for a saved profile
// whose environment key is temporarily unavailable.
func (r *Registry) List() ([]Availability, string, error) {
	d, profiles, err := r.snapshot()
	if err != nil {
		return nil, "", err
	}
	definitions := Providers()
	out := make([]Availability, 0, len(definitions))
	for _, p := range definitions {
		profile := profiles[p.ID]
		cred, err := resolveProvider(p.ID, "", profile)
		av := Availability{
			Provider: p.ID, Label: p.Label, Configured: err == nil, Saved: profile.Configured(),
			Model: cred.Model, BaseURL: cred.BaseURL, Source: cred.source, KeyHint: profile.MaskedKey(),
		}
		out = append(out, av)
	}
	return out, d.Provider, nil
}
