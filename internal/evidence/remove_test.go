package evidence_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/evidence"
)

// TestRemoveRefusesTraversalAndKeepsCanary: a blob path that escapes the root
// (relative or absolute), names the root itself, or is empty must be refused,
// and nothing outside the root may be deleted as a side effect.
func TestRemoveRefusesTraversalAndKeepsCanary(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "evidence")
	s, err := evidence.NewFS(root)
	if err != nil {
		t.Fatal(err)
	}
	canary := filepath.Join(base, "canary.txt")
	if err := os.WriteFile(canary, []byte("canary"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, bad := range []string{"../canary.txt", "scan/../../canary.txt", canary, "", "."} {
		if err := s.Remove(bad); !errors.Is(err, evidence.ErrRefused) {
			t.Errorf("Remove(%q) = %v, want ErrRefused", bad, err)
		}
	}
	if got, err := os.ReadFile(canary); err != nil || string(got) != "canary" {
		t.Fatalf("canary outside the root was touched: %q, %v", got, err)
	}
	if _, err := os.Stat(root); err != nil {
		t.Fatalf("evidence root removed: %v", err)
	}
}

// TestRemoveRefusesSymlinkedBlobAndParent: a symlink standing in for a blob,
// or a symlinked directory on the way to one, must not let Remove reach a
// file outside the root.
func TestRemoveRefusesSymlinkedBlobAndParent(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "evidence")
	s, err := evidence.NewFS(root)
	if err != nil {
		t.Fatal(err)
	}
	outsideDir := filepath.Join(base, "outside")
	if err := os.MkdirAll(outsideDir, 0o750); err != nil {
		t.Fatal(err)
	}
	outsideFile := filepath.Join(outsideDir, "secret.bin")
	if err := os.WriteFile(outsideFile, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideFile, filepath.Join(root, "link.bin")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideDir, filepath.Join(root, "linkdir")); err != nil {
		t.Fatal(err)
	}

	for _, bad := range []string{"link.bin", "linkdir/secret.bin"} {
		if err := s.Remove(bad); !errors.Is(err, evidence.ErrRefused) {
			t.Errorf("Remove(%q) = %v, want ErrRefused", bad, err)
		}
	}
	if got, err := os.ReadFile(outsideFile); err != nil || string(got) != "keep" {
		t.Fatalf("file behind symlink was removed: %q, %v", got, err)
	}
}

// TestRemoveRefusesDirectory: a row naming a directory is refused, not
// recursively deleted.
func TestRemoveRefusesDirectory(t *testing.T) {
	root := t.TempDir()
	s, err := evidence.NewFS(root)
	if err != nil {
		t.Fatal(err)
	}
	scan := domain.NewID()
	ref, err := s.Put(scan, domain.EvidenceResponse, ".bin", []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(s.AbsPath(ref.BlobPath))
	rel := filepath.ToSlash(filepath.Base(filepath.Dir(dir))) + "/" + filepath.Base(dir)
	if err := s.Remove(rel); !errors.Is(err, evidence.ErrRefused) {
		t.Fatalf("Remove(directory %q) = %v, want ErrRefused", rel, err)
	}
	if _, err := os.Stat(s.AbsPath(ref.BlobPath)); err != nil {
		t.Fatalf("blob inside refused directory was removed: %v", err)
	}
}

// TestRemoveAndStatMissingBlobIsNotExist: a blob already gone is reported with
// fs.ErrNotExist so callers can distinguish "already gone" from a failure.
func TestRemoveAndStatMissingBlobIsNotExist(t *testing.T) {
	s, err := evidence.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	const rel = "scan1/response/none.bin"
	if _, err := s.Stat(rel); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Stat(missing) = %v, want fs.ErrNotExist", err)
	}
	if err := s.Remove(rel); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Remove(missing) = %v, want fs.ErrNotExist", err)
	}
}

// TestRemoveDeletesOnlyTheNamedBlob: a valid Remove deletes exactly that blob.
func TestRemoveDeletesOnlyTheNamedBlob(t *testing.T) {
	s, err := evidence.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	scan := domain.NewID()
	a, _ := s.Put(scan, domain.EvidenceResponse, ".bin", []byte("aaa"))
	b, _ := s.Put(scan, domain.EvidenceResponse, ".bin", []byte("bbb"))
	if err := s.Remove(a.BlobPath); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := os.Stat(s.AbsPath(a.BlobPath)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("removed blob still present: %v", err)
	}
	if _, err := os.Stat(s.AbsPath(b.BlobPath)); err != nil {
		t.Fatalf("sibling blob removed: %v", err)
	}
}
