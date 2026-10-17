// Package config defines Indago's configuration: local data locations, the web
// server address, default scan profile, and the (disabled-by-default) AI
// gateway settings. Configuration is local-first and lives under the data dir.
package config

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"

	"github.com/indago/indago/internal/domain"
)

// Default locations and values.
const (
	DefaultDataDir    = "data"
	DefaultServerAddr = "127.0.0.1:8750"
	dbFileName        = "indago.db"
	evidenceDirName   = "evidence"
	reportsDirName    = "reports"
	sessionsDirName   = "sessions"
	configFileName    = "config.json"
)

// ServerConfig configures the web UI / API server.
type ServerConfig struct {
	Addr string `json:"addr"`
	// APIRate is the per-client-IP sustained request rate (requests/second)
	// allowed on /api/ and /metrics. 0 disables the limiter.
	APIRate float64 `json:"api_rate"`
	// APIBurst is the per-client-IP bucket size. Must be >= 1 when APIRate > 0.
	APIBurst int `json:"api_burst"`
}

// Default rate-limit values. 50 rps / 200 burst: the bundled UI's "1 second"
// live refresh issues about one request per scan per tick on the Scans and
// Dashboard views, so a 20 rps default would throttle the UI with ~20 scans.
const (
	DefaultAPIRate  = 50.0
	DefaultAPIBurst = 200
)

// Validate reports whether the server section is usable. A negative or
// non-finite rate is refused; a positive rate needs a burst of at least 1.
// Rate 0 disables rate limiting (any burst is then ignored).
func (s ServerConfig) Validate() error {
	if math.IsNaN(s.APIRate) || math.IsInf(s.APIRate, 0) || s.APIRate < 0 {
		return fmt.Errorf("config: server api_rate must be a finite number >= 0 (got %v)", s.APIRate)
	}
	if s.APIRate > 0 && s.APIBurst < 1 {
		return fmt.Errorf("config: server api_burst must be >= 1 when api_rate > 0 (got %d)", s.APIBurst)
	}
	return nil
}

// AIConfig configures the optional AI gateway. Disabled by default; even when
// enabled it is advisory only and never authoritative. The API key is read from
// an environment variable (APIKeyEnv), never stored in config.
type AIConfig struct {
	Enabled   bool   `json:"enabled"`
	Provider  string `json:"provider,omitempty"` // openai|anthropic|openrouter|ollama|vllm
	Model     string `json:"model,omitempty"`
	BaseURL   string `json:"base_url,omitempty"`
	APIKeyEnv string `json:"api_key_env,omitempty"` // name of env var holding the key
}

// Config is the top-level configuration.
type Config struct {
	DataDir        string             `json:"data_dir"`
	Server         ServerConfig       `json:"server"`
	DefaultProfile domain.ProfileName `json:"default_profile"`
	AI             AIConfig           `json:"ai"`
}

// Default returns a configuration with conservative, local-first defaults and
// AI disabled.
func Default() Config {
	return Config{
		DataDir:        DefaultDataDir,
		Server:         ServerConfig{Addr: DefaultServerAddr, APIRate: DefaultAPIRate, APIBurst: DefaultAPIBurst},
		DefaultProfile: domain.ProfileBalanced,
		AI:             AIConfig{Enabled: false},
	}
}

// DBPath returns the SQLite database path under the data dir.
func (c Config) DBPath() string { return filepath.Join(c.DataDir, dbFileName) }

// EvidenceDir returns the evidence root under the data dir.
func (c Config) EvidenceDir() string { return filepath.Join(c.DataDir, evidenceDirName) }

// ReportsDir returns the generated-report root under the data dir.
func (c Config) ReportsDir() string { return filepath.Join(c.DataDir, reportsDirName) }

// SessionsDir returns the root for saved interactive-login session material
// (cookies/storage state) under the data dir. These files are sensitive; the
// browser login writes them with 0600.
func (c Config) SessionsDir() string { return filepath.Join(c.DataDir, sessionsDirName) }

// ConfigPath returns the config file path under the data dir.
func (c Config) ConfigPath() string { return filepath.Join(c.DataDir, configFileName) }

// EnsureDirs creates the data and evidence directories if missing.
func (c Config) EnsureDirs() error {
	for _, d := range []string{c.DataDir, c.EvidenceDir(), c.ReportsDir(), c.SessionsDir()} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			return fmt.Errorf("config: create dir %s: %w", d, err)
		}
	}
	return nil
}

// Load reads configuration from path. A missing file is not an error: defaults
// (with DataDir set to the file's directory) are returned instead.
func Load(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			c := Default()
			c.DataDir = filepath.Dir(path)
			return c, nil
		}
		return Config{}, fmt.Errorf("config: read %s: %w", path, err)
	}
	c := Default()
	if err := json.Unmarshal(b, &c); err != nil {
		return Config{}, fmt.Errorf("config: parse %s: %w", path, err)
	}
	if c.DataDir == "" {
		c.DataDir = filepath.Dir(path)
	}
	if err := c.Server.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

// Save writes configuration to path (pretty-printed), creating parent dirs.
func (c Config) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("config: create dir: %w", err)
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("config: marshal: %w", err)
	}
	if err := os.WriteFile(path, b, 0o640); err != nil {
		return fmt.Errorf("config: write %s: %w", path, err)
	}
	return nil
}
