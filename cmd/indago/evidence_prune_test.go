package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/indago/indago/internal/config"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/evidence"
	"github.com/indago/indago/internal/store/sqlite"
)

// seedPruneData builds a real on-disk data dir (SQLite + evidence) with one
// old completed scan holding a blob, and one old RUNNING scan holding a blob.
// The DB is closed before returning so the command can open it.
func seedPruneData(t *testing.T) (dir string, oldScan, runScan *domain.Scan, oldBlob, runBlob *domain.Evidence) {
	t.Helper()
	ctx := context.Background()
	dir = t.TempDir()
	cfg := config.Default()
	cfg.DataDir = dir
	if err := cfg.EnsureDirs(); err != nil {
		t.Fatal(err)
	}
	db, err := sqlite.Open(cfg.DBPath())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	ev, err := evidence.NewFS(cfg.EvidenceDir())
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	old := now.Add(-1000 * time.Hour)
	proj := &domain.Project{ID: domain.NewID(), Name: "p", CreatedAt: now, UpdatedAt: now}
	if err := db.Projects().Create(ctx, proj); err != nil {
		t.Fatal(err)
	}
	tgt := &domain.Target{ID: domain.NewID(), ProjectID: proj.ID, Name: "t", BaseURL: "http://127.0.0.1:1/", CreatedAt: now, UpdatedAt: now}
	if err := db.Targets().Create(ctx, tgt); err != nil {
		t.Fatal(err)
	}
	mkScan := func(state domain.ScanState) *domain.Scan {
		sc := &domain.Scan{
			ID: domain.NewID(), ProjectID: proj.ID, TargetID: tgt.ID, Name: string(state),
			State: state, Profile: "standard", Discovery: domain.DiscoveryComplete,
			CreatedAt: old, UpdatedAt: old,
		}
		if state.IsTerminal() {
			e := old
			sc.EndedAt = &e
		}
		if err := db.Scans().Create(ctx, sc); err != nil {
			t.Fatal(err)
		}
		return sc
	}
	mkBlob := func(sc *domain.Scan, body string) *domain.Evidence {
		ref, err := ev.Put(sc.ID, domain.EvidenceRequest, ".txt", []byte(body))
		if err != nil {
			t.Fatal(err)
		}
		e := &domain.Evidence{
			ID: domain.NewID(), ScanID: sc.ID, Kind: domain.EvidenceRequest,
			BlobPath: ref.BlobPath, Size: ref.Size, SHA256: ref.SHA256, CreatedAt: old,
		}
		if err := db.Evidence().Create(ctx, e); err != nil {
			t.Fatal(err)
		}
		return e
	}
	oldScan = mkScan(domain.ScanCompleted)
	runScan = mkScan(domain.ScanRunning)
	oldBlob = mkBlob(oldScan, "Cookie: SESSION=supersecret-cookie-value")
	runBlob = mkBlob(runScan, "Cookie: SESSION=running-cookie-value")
	return dir, oldScan, runScan, oldBlob, runBlob
}

func runPrune(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	var out, errb bytes.Buffer
	err = runEvidencePrune(args, &out, &errb)
	return out.String(), errb.String(), err
}

func TestEvidencePruneRequiresOlderThan(t *testing.T) {
	dir := t.TempDir()
	_, _, err := runPrune(t, "prune", "-data", dir)
	if err == nil || !strings.Contains(err.Error(), "-older-than") {
		t.Fatalf("missing -older-than: err = %v, want a message naming -older-than", err)
	}
}

func TestEvidencePruneRejectsShortOlderThan(t *testing.T) {
	dir := t.TempDir()
	for _, bad := range []string{"30m", "0s", "bogus"} {
		_, _, err := runPrune(t, "prune", "-data", dir, "-older-than", bad)
		if err == nil {
			t.Errorf("-older-than %q accepted, want error", bad)
		}
	}
}

// A data dir with no database is an error, and the command must not create one.
func TestEvidencePruneRefusesDataDirWithoutDatabase(t *testing.T) {
	dir := t.TempDir()
	_, _, err := runPrune(t, "prune", "-data", dir, "-older-than", "720h")
	if err == nil {
		t.Fatal("prune on a data dir without a database succeeded")
	}
	if _, statErr := os.Stat(filepath.Join(dir, "indago.db")); statErr == nil {
		t.Fatal("prune created a database file")
	}
}

// Dry run (default) deletes nothing and never prints blob content; -apply
// deletes the old terminal scan's blob and row and leaves the running scan alone.
func TestEvidencePruneDryRunThenApply(t *testing.T) {
	dir, oldScan, runScan, oldBlob, runBlob := seedPruneData(t)
	ev, err := evidence.NewFS(config.Config{DataDir: dir}.EvidenceDir())
	if err != nil {
		t.Fatal(err)
	}
	oldPath := ev.AbsPath(oldBlob.BlobPath)
	runPath := ev.AbsPath(runBlob.BlobPath)

	out, _, err := runPrune(t, "prune", "-data", dir, "-older-than", "720h")
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if !strings.Contains(out, "DRY RUN") {
		t.Fatalf("dry run output does not say so:\n%s", out)
	}
	if !strings.Contains(out, oldBlob.BlobPath) {
		t.Fatalf("dry run does not list the blob's relative path:\n%s", out)
	}
	if strings.Contains(out, "supersecret") || strings.Contains(out, "running-cookie") {
		t.Fatalf("output leaks blob content:\n%s", out)
	}
	if !exists(oldPath) || !exists(runPath) {
		t.Fatal("dry run removed blob files")
	}

	out, errOut, err := runPrune(t, "prune", "-data", dir, "-older-than", "720h", "-apply")
	if err != nil {
		t.Fatalf("apply: %v\n%s", err, out)
	}
	if exists(oldPath) {
		t.Fatalf("apply left the old scan's blob:\n%s", out)
	}
	if !exists(runPath) {
		t.Fatal("apply removed the running scan's blob")
	}
	if strings.Contains(out, "supersecret") || strings.Contains(errOut, "supersecret") {
		t.Fatalf("apply output leaks blob content:\n%s", out)
	}
	if !strings.Contains(errOut, "evidence pruned") || !strings.Contains(errOut, "scan_id="+string(oldScan.ID)) {
		t.Fatalf("no audit line for the deleted scan on stderr:\n%s", errOut)
	}
	if strings.Contains(errOut, string(runScan.ID)) {
		t.Fatalf("audit line mentions the untouched running scan:\n%s", errOut)
	}
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
