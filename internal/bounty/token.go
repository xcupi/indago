package bounty

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Store keeps the provider token on disk: 0600 in a 0700 directory, the same
// policy as the LLM key. The token is never returned by the API — only whether
// one is configured.
type Store struct {
	dir string
	mu  sync.Mutex
}

// NewStore returns a token store rooted at dir.
func NewStore(dir string) *Store { return &Store{dir: dir} }

func (s *Store) path() string { return filepath.Join(s.dir, "yeswehack.token") }

// Set writes the token after trimming whitespace. An empty token is rejected:
// callers that want to remove one use Clear.
func (s *Store) Set(token string) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return errors.New("bounty: empty token")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(s.dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.dir, ".token-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.WriteString(token); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, s.path())
}

// Token returns the stored token, or "" when none is configured.
func (s *Store) Token() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := os.ReadFile(s.path())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// Configured reports whether a token is stored.
func (s *Store) Configured() bool { return s.Token() != "" }

// Clear removes the stored token.
func (s *Store) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := os.Remove(s.path())
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("bounty: clear token: %w", err)
	}
	return nil
}
