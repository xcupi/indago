package config_test

import (
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
