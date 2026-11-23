package bounty

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Supported bounty platform provider identifiers.
const (
	ProviderYesWeHack = "yeswehack"
	ProviderHackerOne = "hackerone"
	ProviderBugcrowd  = "bugcrowd"
	ProviderIntigriti = "intigriti"
)

// ErrUnsupportedProvider is returned when an unknown provider name is passed to Store.
var ErrUnsupportedProvider = errors.New("bounty: unsupported provider")

func normalizeProvider(provider string) (string, error) {
	p := strings.ToLower(strings.TrimSpace(provider))
	switch p {
	case ProviderYesWeHack, ProviderHackerOne, ProviderBugcrowd, ProviderIntigriti:
		return p, nil
	default:
		return "", fmt.Errorf("%w: %q", ErrUnsupportedProvider, provider)
	}
}

// Store keeps provider tokens on disk: 0600 in a 0700 directory, the same
// policy as the LLM key. Tokens are never returned by the API — only whether
// one is configured.
type Store struct {
	dir string
	mu  sync.Mutex
}

// NewStore returns a token store rooted at dir.
func NewStore(dir string) *Store { return &Store{dir: dir} }

func (s *Store) pathFor(provider string) (string, error) {
	p, err := normalizeProvider(provider)
	if err != nil {
		return "", err
	}
	return filepath.Join(s.dir, p+".token"), nil
}

// Set writes the YesWeHack token after trimming whitespace. An empty token is
// rejected: callers that want to remove one use Clear.
func (s *Store) Set(token string) error {
	return s.SetFor(ProviderYesWeHack, token)
}

// SetFor writes the token for provider after trimming whitespace.
func (s *Store) SetFor(provider, token string) error {
	p, err := s.pathFor(provider)
	if err != nil {
		return err
	}
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
	return os.Rename(tmpName, p)
}

// Token returns the stored YesWeHack token, or "" when none is configured.
func (s *Store) Token() string {
	return s.TokenFor(ProviderYesWeHack)
}

// TokenFor returns the stored token for provider, or "" when none is configured
// or the provider is invalid.
func (s *Store) TokenFor(provider string) string {
	p, err := s.pathFor(provider)
	if err != nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// Configured reports whether a YesWeHack token is stored.
func (s *Store) Configured() bool { return s.ConfiguredFor(ProviderYesWeHack) }

// ConfiguredFor reports whether a token is stored for provider.
func (s *Store) ConfiguredFor(provider string) bool { return s.TokenFor(provider) != "" }

// Clear removes the stored YesWeHack token.
func (s *Store) Clear() error {
	return s.ClearFor(ProviderYesWeHack)
}

// ClearFor removes the stored token for provider.
func (s *Store) ClearFor(provider string) error {
	p, err := s.pathFor(provider)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	err = os.Remove(p)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("bounty: clear token: %w", err)
	}
	return nil
}
