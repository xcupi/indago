package evidence_test

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/evidence"
)

func TestPutAndOpen(t *testing.T) {
	s, err := evidence.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	scan := domain.NewID()
	data := []byte("<html>response body</html>")

	ref, err := s.Put(scan, domain.EvidenceResponse, ".html", data)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	if ref.Size != int64(len(data)) || ref.SHA256 == "" {
		t.Fatalf("bad ref: %+v", ref)
	}

	rc, err := s.Open(ref.BlobPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer rc.Close()
	got, _ := io.ReadAll(rc)
	if string(got) != string(data) {
		t.Fatalf("round-trip mismatch: %q", got)
	}
}

func TestPutIsContentAddressedAndIdempotent(t *testing.T) {
	s, _ := evidence.NewFS(t.TempDir())
	scan := domain.NewID()
	data := []byte("same bytes")

	r1, _ := s.Put(scan, domain.EvidenceResponse, ".bin", data)
	r2, _ := s.Put(scan, domain.EvidenceResponse, ".bin", data)
	if r1.BlobPath != r2.BlobPath {
		t.Fatalf("identical content produced different paths: %s vs %s", r1.BlobPath, r2.BlobPath)
	}
	if r1.SHA256 != r2.SHA256 {
		t.Fatal("hash mismatch for identical content")
	}
}

// TestPutLeavesNoPartialBlobAfterInterruptedWrite simulates a process crash
// that killed a previous Put between creating its temp file and renaming it
// into place: a stray, incomplete temp file is left in the blob directory,
// but nothing has been renamed onto the final content-addressed path yet. A
// correct Put must still produce a complete, correct blob at that path (the
// leftover temp file must never be mistaken for it) — this is the crash-
// consistency property the atomic write in Put exists to guarantee.
func TestPutLeavesNoPartialBlobAfterInterruptedWrite(t *testing.T) {
	root := t.TempDir()
	s, err := evidence.NewFS(root)
	if err != nil {
		t.Fatal(err)
	}
	scan := domain.NewID()
	data := []byte("the full, correct evidence body")

	// Simulate the crash: drop a stray temp file (as os.CreateTemp would,
	// pre-rename) in the directory Put will use, containing truncated garbage.
	dir := filepath.Join(root, string(scan), string(domain.EvidenceResponse))
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	stray, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stray.WriteString("truncated garb"); err != nil {
		t.Fatal(err)
	}
	stray.Close()

	ref, err := s.Put(scan, domain.EvidenceResponse, ".bin", data)
	if err != nil {
		t.Fatalf("put: %v", err)
	}

	rc, err := s.Open(ref.BlobPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer rc.Close()
	got, _ := io.ReadAll(rc)
	if string(got) != string(data) {
		t.Fatalf("blob corrupted by stray temp file: got %q, want %q", got, data)
	}
}

func TestOpenRejectsTraversal(t *testing.T) {
	s, _ := evidence.NewFS(t.TempDir())
	for _, bad := range []string{"../escape", "/etc/passwd", "../../x"} {
		if _, err := s.Open(bad); err == nil {
			t.Errorf("expected error opening %q", bad)
		}
		if p := s.AbsPath(bad); p != "" {
			t.Errorf("AbsPath(%q) should be empty, got %q", bad, p)
		}
	}
}
