// Package claudeoauth implements Indago's own Claude OAuth (PKCE) session.
//
// Claude Code authenticates a subscription through an OAuth PKCE flow and then
// calls the Messages API with a Bearer token plus two beta headers. Indago
// mirrors that flow so a user can connect their own Claude account without an
// API key and without borrowing another tool's credential store.
//
// The flow is deliberately manual at one point: the redirect URI is Anthropic's
// own callback page, which displays a code for the user to copy. Indago opens
// the authorization URL, the user approves, pastes the code back, and Indago
// exchanges it. No password or code is ever logged.
package claudeoauth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	ClientID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
	// Claude Code v2.1.84 moved the claude.ai authorization endpoint from
	// claude.ai/oauth/authorize to claude.com/cai/oauth/authorize. The old
	// host still renders the consent page but the authorize step fails.
	AuthorizeURL = "https://claude.com/cai/oauth/authorize"
	// platform.claude.com is the live token host; the console host is kept as
	// a fallback. Both reject requests whose User-Agent looks like a browser
	// or like claude-code, so the exchange sends the bare axios UA the real
	// CLI uses.
	TokenURL = "https://platform.claude.com/v1/oauth/token"
	// Anthropic registers the callback on platform.claude.com. The old
	// console.anthropic.com path is rejected at authorize time with
	// "Authorization failed — Redirect URI is not supported by client".
	RedirectURI = "https://platform.claude.com/oauth/code/callback"
	// Scope for the headless/platform code flow. The CLI's localhost flow
	// also requests org:create_api_key, but the claude.ai subscription
	// authorize endpoint rejects that scope (Invalid OAuth Request / Missing
	// scope); the platform code flow uses this set instead.
	Scope = "user:profile user:inference user:sessions:claude_code user:mcp_servers"
	// Beta headers Claude Code sends with an OAuth token.
	BetaHeader = "oauth-2025-04-20,claude-code-20250219"
)

// Credentials is what Indago stores: the pair plus its expiry.
type Credentials struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// Store persists credentials at 0600 inside a 0700 directory.
type Store struct {
	dir string
	mu  sync.Mutex
}

func NewStore(dir string) *Store { return &Store{dir: dir} }

func (s *Store) path() string { return filepath.Join(s.dir, "credentials.json") }

// Load returns the stored credentials, or zero values when none exist.
func (s *Store) Load() (Credentials, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := os.ReadFile(s.path())
	if err != nil {
		if os.IsNotExist(err) {
			return Credentials{}, nil
		}
		return Credentials{}, err
	}
	var c Credentials
	if err := json.Unmarshal(b, &c); err != nil {
		return Credentials{}, err
	}
	return c, nil
}

// Save writes the credentials atomically with owner-only permissions.
func (s *Store) Save(c Credentials) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(s.dir, 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.dir, ".cred-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(b); err != nil {
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
	return os.Rename(name, s.path())
}

// Clear removes the stored credentials.
func (s *Store) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := os.Remove(s.path())
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// Configured reports whether an access token is stored.
func (s *Store) Configured() bool {
	c, err := s.Load()
	return err == nil && strings.TrimSpace(c.AccessToken) != ""
}

// Login manages one in-flight PKCE authorization.
type Login struct {
	store   *Store
	http    *http.Client
	mu      sync.Mutex
	pending map[string]string // state -> code verifier
}

func NewLogin(store *Store) *Login {
	return &Login{store: store, http: &http.Client{Timeout: 30 * time.Second}, pending: map[string]string{}}
}

// Start builds the authorization URL and remembers the verifier for Finish.
func (l *Login) Start() (authURL, state string, err error) {
	verifier, err := randomToken(32)
	if err != nil {
		return "", "", err
	}
	state, err = randomToken(16)
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	q := url.Values{
		"code":                  {"true"},
		"response_type":         {"code"},
		"client_id":             {ClientID},
		"redirect_uri":          {RedirectURI},
		"scope":                 {Scope},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"state":                 {state},
	}
	l.mu.Lock()
	l.pending[state] = verifier
	l.mu.Unlock()
	return AuthorizeURL + "?" + q.Encode(), state, nil
}

// Finish exchanges the pasted code for tokens. The pasted value may be
// "code#state" (the callback page shows both) or just the code, in which case
// the caller's state is used.
func (l *Login) Finish(ctx context.Context, codeOrPair, state string) (Credentials, error) {
	code := strings.TrimSpace(codeOrPair)
	if i := strings.Index(code, "#"); i >= 0 {
		if state == "" {
			state = code[i+1:]
		}
		code = code[:i]
	}
	l.mu.Lock()
	verifier, ok := l.pending[state]
	if ok {
		delete(l.pending, state)
	}
	l.mu.Unlock()
	if !ok || verifier == "" {
		return Credentials{}, errors.New("claude: unknown or expired login state; start the login again")
	}

	body := map[string]string{
		"grant_type":    "authorization_code",
		"code":          code,
		"redirect_uri":  RedirectURI,
		"client_id":     ClientID,
		"code_verifier": verifier,
	}
	cred, err := l.exchange(ctx, body)
	if err != nil {
		return Credentials{}, err
	}
	if err := l.store.Save(cred); err != nil {
		return Credentials{}, err
	}
	return cred, nil
}

// Token returns a valid access token, refreshing it when it expires within a
// minute. A missing credential returns ("", nil) so callers can fall back to an
// API key.
func (l *Login) Token(ctx context.Context) (string, error) {
	c, err := l.store.Load()
	if err != nil {
		return "", err
	}
	if c.AccessToken == "" {
		return "", nil
	}
	if time.Until(c.ExpiresAt) > time.Minute {
		return c.AccessToken, nil
	}
	if c.RefreshToken == "" {
		return "", errors.New("claude: session expired and no refresh token is stored; connect Claude again")
	}
	refreshed, err := l.exchange(ctx, map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": c.RefreshToken,
		"client_id":     ClientID,
	})
	if err != nil {
		return "", err
	}
	if refreshed.RefreshToken == "" {
		refreshed.RefreshToken = c.RefreshToken
	}
	if err := l.store.Save(refreshed); err != nil {
		return "", err
	}
	return refreshed.AccessToken, nil
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	Error        string `json:"error"`
	ErrorDesc    string `json:"error_description"`
}

func (l *Login) exchange(ctx context.Context, payload map[string]string) (Credentials, error) {
	b, _ := json.Marshal(payload)
	var lastErr error
	for _, endpoint := range []string{TokenURL, "https://console.anthropic.com/v1/oauth/token"} {
		req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(b))
		if err != nil {
			return Credentials{}, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "axios/1.7.9")
		resp, err := l.http.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		var out tokenResponse
		_ = json.Unmarshal(body, &out)
		if resp.StatusCode != 200 || out.AccessToken == "" {
			msg := out.ErrorDesc
			if msg == "" {
				msg = out.Error
			}
			if msg == "" {
				msg = fmt.Sprintf("status %d", resp.StatusCode)
			}
			lastErr = fmt.Errorf("claude: token endpoint rejected the request: %s", msg)
			// A 404/403 means this host is wrong or blocked; the other host
			// may work. Do not replay a refresh token on an auth rejection.
			if resp.StatusCode == 404 || resp.StatusCode == 403 {
				continue
			}
			return Credentials{}, lastErr
		}
		return credentialsFromToken(out), nil
	}
	if lastErr == nil {
		lastErr = errors.New("claude: no token endpoint reachable")
	}
	return Credentials{}, lastErr
}

func credentialsFromToken(out tokenResponse) Credentials {
	exp := time.Now().Add(time.Duration(out.ExpiresIn) * time.Second)
	if out.ExpiresIn == 0 {
		exp = time.Now().Add(time.Hour)
	}
	return Credentials{AccessToken: out.AccessToken, RefreshToken: out.RefreshToken, ExpiresAt: exp}
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ListModels asks Anthropic for the models this session can use. The OAuth
// token needs the same Bearer + beta headers as a Messages call.
func (l *Login) ListModels(ctx context.Context) ([]string, error) {
	tok, err := l.Token(ctx)
	if err != nil {
		return nil, err
	}
	if tok == "" {
		return nil, errors.New("claude: not connected")
	}
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.anthropic.com/v1/models", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("anthropic-beta", BetaHeader)
	req.Header.Set("Accept", "application/json")
	resp, err := l.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("claude: models returned %d", resp.StatusCode)
	}
	var out struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	models := make([]string, 0, len(out.Data))
	for _, m := range out.Data {
		models = append(models, m.ID)
	}
	return models, nil
}
