// Package evidence stores large evidence blobs (response bodies, screenshots,
// HARs) on the filesystem, keeping the database small. Blobs are content-
// addressed by SHA-256 for integrity and de-duplication; the returned relative
// path is what gets recorded in a domain.Evidence row.
package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/indago/indago/internal/domain"
)

// Ref is the result of storing a blob.
type Ref struct {
	BlobPath string // path relative to the evidence root (store this)
	Size     int64
	SHA256   string
}

// Store persists and retrieves evidence blobs.
type Store interface {
	// Put stores data for a scan under the given kind, returning a Ref. ext is a
	// filename extension including the dot (e.g. ".png", ".bin"); "" is allowed.
	Put(scanID domain.ID, kind domain.EvidenceKind, ext string, data []byte) (Ref, error)
	// Open opens a blob by its relative path.
	Open(relPath string) (io.ReadCloser, error)
	// AbsPath returns the absolute path for a relative blob path.
	AbsPath(relPath string) string
}

// FSStore is a filesystem-backed Store rooted at a directory.
type FSStore struct {
	root string
}

// NewFS returns a filesystem evidence store rooted at root, creating it if
// necessary.
func NewFS(root string) (*FSStore, error) {
	if err := os.MkdirAll(root, 0o750); err != nil {
		return nil, fmt.Errorf("evidence: create root: %w", err)
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("evidence: resolve root: %w", err)
	}
	return &FSStore{root: abs}, nil
}

var _ Store = (*FSStore)(nil)

// Put implements Store. Writing is idempotent: identical content maps to the
// same path and is not rewritten.
//
// The write is atomic (temp file in the same directory, then rename) so a
// crash mid-write can never leave a truncated blob at the final, content-
// addressed path. That matters specifically because of the existence check
// below: without an atomic write, a partial file left by a prior crash would
// be mistaken for "already written" and never get repaired.
func (s *FSStore) Put(scanID domain.ID, kind domain.EvidenceKind, ext string, data []byte) (Ref, error) {
	if scanID.Empty() {
		return Ref{}, errors.New("evidence: empty scan id")
	}
	sum := sha256.Sum256(data)
	hexsum := hex.EncodeToString(sum[:])
	ext = sanitizeExt(ext)

	rel := filepath.Join(string(scanID), string(kind), hexsum+ext)
	abs := filepath.Join(s.root, rel)
	dir := filepath.Dir(abs)

	if err := os.MkdirAll(dir, 0o750); err != nil {
		return Ref{}, fmt.Errorf("evidence: mkdir: %w", err)
	}
	if _, err := os.Stat(abs); errors.Is(err, os.ErrNotExist) {
		if err := writeFileAtomic(dir, abs, data); err != nil {
			return Ref{}, fmt.Errorf("evidence: write: %w", err)
		}
	} else if err != nil {
		return Ref{}, fmt.Errorf("evidence: stat: %w", err)
	}

	// Store the relative path with forward slashes for portability.
	return Ref{BlobPath: filepath.ToSlash(rel), Size: int64(len(data)), SHA256: hexsum}, nil
}

// writeFileAtomic writes data to a temp file in dir and renames it onto abs.
// Rename is atomic on the same filesystem, so readers (including a future
// Put's existence check) never observe a partially written file.
func writeFileAtomic(dir, abs string, data []byte) error {
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once renamed away

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o640); err != nil {
		return err
	}
	return os.Rename(tmpName, abs)
}

// Open implements Store, guarding against path traversal outside the root.
func (s *FSStore) Open(relPath string) (io.ReadCloser, error) {
	abs, err := s.safeAbs(relPath)
	if err != nil {
		return nil, err
	}
	return os.Open(abs)
}

// AbsPath implements Store. It returns an empty string for paths that would
// escape the root.
func (s *FSStore) AbsPath(relPath string) string {
	abs, err := s.safeAbs(relPath)
	if err != nil {
		return ""
	}
	return abs
}

func (s *FSStore) safeAbs(relPath string) (string, error) {
	clean := filepath.Clean(filepath.FromSlash(relPath))
	if filepath.IsAbs(clean) || strings.HasPrefix(clean, "..") {
		return "", fmt.Errorf("evidence: illegal path %q", relPath)
	}
	abs := filepath.Join(s.root, clean)
	if abs != s.root && !strings.HasPrefix(abs, s.root+string(os.PathSeparator)) {
		return "", fmt.Errorf("evidence: path escapes root: %q", relPath)
	}
	return abs, nil
}

func sanitizeExt(ext string) string {
	if ext == "" {
		return ""
	}
	if !strings.HasPrefix(ext, ".") {
		ext = "." + ext
	}
	// Drop anything suspicious; keep it simple and safe.
	ext = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.':
			return r
		default:
			return -1
		}
	}, ext)
	return ext
}
