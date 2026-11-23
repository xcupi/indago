package llm

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	configFileName = "config.json"
	keyFileName    = "api_key" // Legacy v1 credential.
	configVersion  = 2
)

// The manifest has no credential values. Each key file is immutable and is
// named for its provider. A manifest rename publishes the selection, options,
// and matching credentials together.
type diskConfig struct {
	Version     int                    `json:"version"`
	Provider    string                 `json:"provider"`
	MaxAttempts int                    `json:"max_attempts,omitempty"`
	Enabled     *bool                  `json:"enabled,omitempty"`
	Profiles    map[string]diskProfile `json:"profiles,omitempty"`
	Model       string                 `json:"model,omitempty"`    // v1
	BaseURL     string                 `json:"base_url,omitempty"` // v1
}

type diskProfile struct {
	Model   string `json:"model"`
	BaseURL string `json:"base_url"`
	KeyFile string `json:"key_file,omitempty"`
}

// Store keeps the default selection, global policy and provider profiles.
type Store struct {
	dir string
}

// NewStore returns a local store rooted at dir.
func NewStore(dir string) *Store { return &Store{dir: dir} }

func (s *Store) Dir() string { return s.dir }

func (s *Store) Path() string { return filepath.Join(s.dir, configFileName) }

func (d diskConfig) policy() Config {
	return Config{MaxAttempts: d.MaxAttempts, Enabled: d.Enabled}
}

// Load reads the default provider with its stored options and key. A missing
// configuration is ErrNotConfigured.
func (s *Store) Load() (Config, error) {
	d, profiles, err := s.snapshot()
	if err != nil {
		return Config{}, err
	}
	return profiles[d.Provider], nil
}

// snapshot holds the directory lock until all referenced keys are read, so
// resolving a credential cannot race with key rotation or cleanup.
func (s *Store) snapshot() (diskConfig, map[string]Config, error) {
	unlock, err := lockStore(s.dir)
	if errors.Is(err, os.ErrNotExist) {
		return diskConfig{}, nil, ErrNotConfigured
	}
	if err != nil {
		return diskConfig{}, nil, err
	}
	defer unlock()
	d, err := s.loadLocked()
	if err != nil {
		return diskConfig{}, nil, err
	}
	profiles := make(map[string]Config, len(d.Profiles))
	for id, profile := range d.Profiles {
		key, err := s.readKey(d.Version, profile.KeyFile)
		if err != nil {
			return diskConfig{}, nil, err
		}
		cfg := d.policy()
		cfg.Provider, cfg.Model, cfg.BaseURL, cfg.apiKey = id, profile.Model, profile.BaseURL, key
		profiles[id] = cfg
	}
	return d, profiles, nil
}

func (s *Store) loadLocked() (diskConfig, error) {
	b, err := os.ReadFile(s.Path())
	if errors.Is(err, os.ErrNotExist) {
		return diskConfig{}, ErrNotConfigured
	}
	if err != nil {
		return diskConfig{}, fmt.Errorf("llm: read config: %w", err)
	}
	var d diskConfig
	if err := json.Unmarshal(b, &d); err != nil {
		return diskConfig{}, fmt.Errorf("llm: parse config: %w", err)
	}
	if d.Version < 0 || d.Version > configVersion {
		return diskConfig{}, fmt.Errorf("llm: config has unsupported version %d", d.Version)
	}
	if d.Provider == "" {
		if len(d.Profiles) > 0 {
			return diskConfig{}, errors.New("llm: configured providers have no default")
		}
		return diskConfig{}, ErrNotConfigured
	}
	if d.Version < configVersion {
		profile := diskProfile{Model: d.Model, BaseURL: d.BaseURL, KeyFile: keyFileName}
		d.Provider = strings.ToLower(strings.TrimSpace(d.Provider))
		if d.Provider == ProviderChatGPT {
			// OAuth subscription credentials and model IDs do not transfer to API keys.
			def, _ := LookupProvider(ProviderOpenAI)
			d.Provider = def.ID
			profile = diskProfile{Model: def.DefaultModel, BaseURL: def.DefaultBaseURL}
		}
		d.Profiles = map[string]diskProfile{d.Provider: profile}
	}
	if _, ok := d.Profiles[d.Provider]; !ok {
		return diskConfig{}, errors.New("llm: default profile is missing")
	}
	for id, profile := range d.Profiles {
		def, ok := LookupProvider(id)
		if !ok || def.ID != id || strings.TrimSpace(profile.Model) == "" || validateBaseURL(profile.BaseURL) != nil {
			return diskConfig{}, errors.New("llm: invalid saved provider profile")
		}
		if d.Version == configVersion && profile.KeyFile != "" && !isKeyFile(id, profile.KeyFile) {
			return diskConfig{}, errors.New("llm: saved key does not match its provider")
		}
	}
	return d, nil
}

func (s *Store) readKey(version int, name string) (string, error) {
	if name == "" {
		return "", nil
	}
	info, err := os.Lstat(filepath.Join(s.dir, name))
	if errors.Is(err, os.ErrNotExist) && version < configVersion {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("llm: access API key: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("llm: API key is not a regular file")
	}
	b, err := os.ReadFile(filepath.Join(s.dir, name))
	if err != nil {
		return "", fmt.Errorf("llm: read API key: %w", err)
	}
	key := strings.TrimSpace(string(b))
	if !validKey(key) || (key == "" && version == configVersion) {
		return "", errors.New("llm: malformed saved API key")
	}
	return key, nil
}

// Set saves one provider profile and makes it the default. Other provider
// profiles retain their parameters and credentials.
func (s *Store) Set(req SetRequest) (Config, error) {
	unlock, err := lockStore(s.dir)
	if errors.Is(err, os.ErrNotExist) {
		// Do not create an empty directory for a rejected first save.
		if _, err := normalize(req, Config{}, 0, nil); err != nil {
			return Config{}, err
		}
		if err := os.MkdirAll(s.dir, 0o700); err != nil {
			return Config{}, fmt.Errorf("llm: create config directory: %w", err)
		}
		unlock, err = lockStore(s.dir)
	}
	if err != nil {
		return Config{}, err
	}
	defer unlock()

	d, err := s.loadLocked()
	if err != nil && !errors.Is(err, ErrNotConfigured) {
		return Config{}, err
	}
	profile := d.Profiles[strings.ToLower(strings.TrimSpace(req.Provider))]
	key, err := s.readKey(d.Version, profile.KeyFile)
	if err != nil && strings.TrimSpace(req.APIKey) == "" {
		return Config{}, err
	}
	existing := Config{Model: profile.Model, BaseURL: profile.BaseURL, apiKey: key}
	cfg, err := normalize(req, existing, d.policy().AttemptBudget(), d.Enabled)
	if err != nil {
		return Config{}, err
	}
	if err := os.Chmod(s.dir, 0o700); err != nil {
		return Config{}, fmt.Errorf("llm: secure config directory: %w", err)
	}
	if err := s.saveLocked(d, cfg, key); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (s *Store) saveLocked(d diskConfig, cfg Config, previousKey string) error {
	if d.Profiles == nil {
		d.Profiles = make(map[string]diskProfile)
	}
	// Migration copies the single legacy credential into a new immutable
	// provider-specific file before publishing a v2 manifest.
	if d.Version < configVersion && d.Provider != "" && d.Provider != cfg.Provider {
		profile := d.Profiles[d.Provider]
		key, err := s.readKey(d.Version, profile.KeyFile)
		if err != nil {
			return err
		}
		profile.KeyFile, err = s.writeKey(d.Provider, key)
		if err != nil {
			return err
		}
		d.Profiles[d.Provider] = profile
	}
	profile := d.Profiles[cfg.Provider]
	if d.Version < configVersion || previousKey != cfg.apiKey {
		var err error
		profile.KeyFile, err = s.writeKey(cfg.Provider, cfg.apiKey)
		if err != nil {
			return err
		}
	}
	profile.Model, profile.BaseURL = cfg.Model, cfg.BaseURL
	d.Profiles[cfg.Provider] = profile
	d.Version, d.Provider, d.MaxAttempts, d.Enabled = configVersion, cfg.Provider, cfg.MaxAttempts, cfg.Enabled
	d.Model, d.BaseURL = "", ""
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return fmt.Errorf("llm: encode config: %w", err)
	}
	// Flush new key directory entries before the manifest can refer to them.
	if err := syncStoreDir(s.dir); err != nil {
		return err
	}
	manifest, err := writeTemp(s.dir, ".config-*", append(b, '\n'))
	if err != nil {
		return err
	}
	defer os.Remove(manifest)
	if err := os.Rename(manifest, s.Path()); err != nil {
		return fmt.Errorf("llm: publish config: %w", err)
	}
	if err := syncStoreDir(s.dir); err != nil {
		// Do not collect earlier keys until the new manifest is durable.
		return err
	}
	// A failure to collect old keys does not undo a published save. Retrying
	// a save or clearing the store will retry collection.
	_ = s.collectKeys(d.Profiles)
	return nil
}

func keyPrefix(provider string) string { return "api_key-" + provider + "-" }

func isKeyFile(provider, name string) bool {
	suffix, ok := strings.CutPrefix(name, keyPrefix(provider))
	if !ok {
		return false
	}
	_, err := strconv.ParseUint(suffix, 10, 64)
	return err == nil
}

func isCredentialFile(name string) bool {
	if name == keyFileName {
		return true
	}
	for _, provider := range providerList {
		if isKeyFile(provider.ID, name) {
			return true
		}
	}
	return false
}

func (s *Store) writeKey(provider, value string) (string, error) {
	if value == "" {
		return "", nil
	}
	path, err := writeTemp(s.dir, keyPrefix(provider)+"*", []byte(value))
	if err != nil {
		return "", err
	}
	return filepath.Base(path), nil
}

func writeTemp(dir, pattern string, contents []byte) (string, error) {
	f, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return "", fmt.Errorf("llm: create temporary file: %w", err)
	}
	name := f.Name()
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		_ = os.Remove(name)
		return "", fmt.Errorf("llm: secure temporary file: %w", err)
	}
	if _, err := f.Write(contents); err != nil {
		_ = f.Close()
		_ = os.Remove(name)
		return "", fmt.Errorf("llm: write temporary file: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(name)
		return "", fmt.Errorf("llm: sync temporary file: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(name)
		return "", fmt.Errorf("llm: close temporary file: %w", err)
	}
	return name, nil
}

func (s *Store) collectKeys(profiles map[string]diskProfile) error {
	active := make(map[string]bool, len(profiles))
	for _, profile := range profiles {
		active[profile.KeyFile] = true
	}
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return fmt.Errorf("llm: list credential files: %w", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || active[name] || !isCredentialFile(name) {
			continue
		}
		if err := os.Remove(filepath.Join(s.dir, name)); err != nil {
			return fmt.Errorf("llm: remove obsolete API key: %w", err)
		}
	}
	return nil
}

// Clear removes all saved profiles and their credentials. It is idempotent.
func (s *Store) Clear() error {
	unlock, err := lockStore(s.dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer unlock()
	if err := os.Remove(s.Path()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("llm: remove config: %w", err)
	}
	if err := syncStoreDir(s.dir); err != nil {
		return err
	}
	if err := s.collectKeys(nil); err != nil {
		return err
	}
	return syncStoreDir(s.dir)
}
