package config_test

import (
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/indago/indago/internal/config"
	"github.com/indago/indago/internal/domain"
)

func TestDefaultsAreConservativeAndAIDisabled(t *testing.T) {
	c := config.Default()
	if c.AI.Enabled {
		t.Fatal("AI must be disabled by default")
	}
	if c.DefaultProfile != domain.ProfileBalanced {
		t.Fatalf("default profile = %s", c.DefaultProfile)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	c := config.Default()
	c.DataDir = dir
	c.Server.Addr = "127.0.0.1:9999"
	if err := c.Save(path); err != nil {
		t.Fatal(err)
	}
	got, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Server.Addr != "127.0.0.1:9999" {
		t.Fatalf("addr = %s", got.Server.Addr)
	}
}

func TestLoadMissingReturnsDefaults(t *testing.T) {
	dir := t.TempDir()
	got, err := config.Load(filepath.Join(dir, "nope.json"))
	if err != nil {
		t.Fatalf("missing config should not error: %v", err)
	}
	if got.DataDir != dir {
		t.Fatalf("expected DataDir to default to file dir, got %s", got.DataDir)
	}
}

func TestDerivedPaths(t *testing.T) {
	c := config.Default()
	c.DataDir = "/var/indago"
	if c.DBPath() != "/var/indago/indago.db" {
		t.Fatalf("db path = %s", c.DBPath())
	}
	if c.EvidenceDir() != "/var/indago/evidence" {
		t.Fatalf("evidence dir = %s", c.EvidenceDir())
	}
	if c.ReportsDir() != "/var/indago/reports" {
		t.Fatalf("reports dir = %s", c.ReportsDir())
	}
}

func TestEnsureDirsCreatesReportsDir(t *testing.T) {
	c := config.Default()
	c.DataDir = t.TempDir()
	if err := c.EnsureDirs(); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(c.ReportsDir()); err != nil || !info.IsDir() {
		t.Fatalf("reports dir not created: %v", err)
	}
}

func TestServerRateLimitDefaultsAndValidation(t *testing.T) {
	d := config.Default()
	if d.Server.APIRate != config.DefaultAPIRate || d.Server.APIBurst != config.DefaultAPIBurst {
		t.Fatalf("Default() server rate limit = %v/%d, want %v/%d",
			d.Server.APIRate, d.Server.APIBurst, config.DefaultAPIRate, config.DefaultAPIBurst)
	}
	if err := d.Server.Validate(); err != nil {
		t.Fatalf("default server config must validate: %v", err)
	}
	cases := []struct {
		name  string
		rate  float64
		burst int
		ok    bool
	}{
		{"defaults", 50, 200, true},
		{"rate zero disables", 0, 0, true},
		{"rate zero ignores burst", 0, -5, true},
		{"negative rate", -1, 10, false},
		{"NaN rate", math.NaN(), 10, false},
		{"infinite rate", math.Inf(1), 10, false},
		{"burst zero with rate", 5, 0, false},
		{"negative burst with rate", 5, -3, false},
	}
	for _, c := range cases {
		err := config.ServerConfig{Addr: "127.0.0.1:8750", APIRate: c.rate, APIBurst: c.burst}.Validate()
		if (err == nil) != c.ok {
			t.Errorf("%s: Validate(rate=%v, burst=%d) err=%v, want ok=%v", c.name, c.rate, c.burst, err, c.ok)
		}
	}
}

func TestLoadRejectsInvalidRateLimitInConfigFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"server":{"addr":"127.0.0.1:8750","api_rate":-2,"api_burst":10}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(path); err == nil {
		t.Fatal("Load accepted a negative api_rate; want an error")
	}
	if err := os.WriteFile(path, []byte(`{"server":{"addr":"127.0.0.1:8750","api_rate":5,"api_burst":0}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(path); err == nil {
		t.Fatal("Load accepted api_burst 0 with api_rate 5; want an error")
	}
	// Missing keys fall back to the defaults, not to zero (which would disable).
	if err := os.WriteFile(path, []byte(`{"server":{"addr":"127.0.0.1:8750"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Server.APIRate != config.DefaultAPIRate || c.Server.APIBurst != config.DefaultAPIBurst {
		t.Fatalf("missing rate keys: got %v/%d, want defaults", c.Server.APIRate, c.Server.APIBurst)
	}
}
