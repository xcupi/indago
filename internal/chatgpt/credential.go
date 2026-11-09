// Package chatgpt reads the ChatGPT/Codex OAuth credential that a Hermes
// install already holds and exposes it to Indago's advisory layer.
//
// It is read-only: Indago never writes, refreshes or rotates the token file, so
// a session used by the agent stays untouched. When the access token expires
// the error says so and points at re-authenticating in Hermes; refreshing here
// could rotate the refresh token out from under the other process.
package chatgpt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ErrNoCredential means no usable ChatGPT OAuth session was found.
var ErrNoCredential = errors.New("chatgpt: no OAuth credential")

// DefaultBaseURL is the Codex backend the OAuth session is valid for.
const DefaultBaseURL = "https://chatgpt.com/backend-api/codex"

// Credential is one usable OAuth session.
type Credential struct {
	AccessToken  string
	RefreshToken string
	BaseURL      string
	AccountID    string
	Plan         string
	ExpiresAt    time.Time
	Label        string
	// Owned is true when Indago itself obtained the credential (its own store),
	// which is what permits refreshing it. A borrowed Hermes session is
	// read-only.
	Owned bool
}

// Expired reports whether the access token is past its expiry.
func (c Credential) Expired() bool {
	return !c.ExpiresAt.IsZero() && time.Now().After(c.ExpiresAt.Add(-2*time.Minute))
}

// String implements fmt.Stringer without the tokens.
func (c Credential) String() string {
	return fmt.Sprintf("chatgpt.Credential{label: %q, account: %s, plan: %q, expires: %s}",
		c.Label, maskAccount(c.AccountID), c.Plan, c.ExpiresAt.Format(time.RFC3339))
}

func maskAccount(id string) string {
	if len(id) <= 6 {
		return "***"
	}
	return id[:4] + "…" + id[len(id)-2:]
}

// Path resolves the credential file: INDAGO_CHATGPT_AUTH when set, else the
// Hermes auth store. An explicit path keeps Indago usable on a machine that has
// Codex credentials somewhere else.
func Path() string {
	if v := strings.TrimSpace(os.Getenv("INDAGO_CHATGPT_AUTH")); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".hermes", "auth.json")
}

type authFile struct {
	CredentialPool struct {
		Entries []struct {
			Label          string  `json:"label"`
			AuthType       string  `json:"auth_type"`
			AccessToken    string  `json:"access_token"`
			RefreshToken   string  `json:"refresh_token"`
			BaseURL        string  `json:"base_url"`
			ExpiresAtMS    int64   `json:"expires_at_ms"`
			LastStatus     string  `json:"last_status"`
			LastErrorReset float64 `json:"last_error_reset_at"`
		} `json:"openai-codex"`
	} `json:"credential_pool"`
}

// Load returns the best usable Codex session from path ("" means Path()).
//
// Selection: a token that is not expired wins; among equals the first entry
// that is not marked exhausted. Rate-limit state is reported by the backend at
// call time — this function does not treat a stale "exhausted" flag as fatal,
// because the window may already have reset.
func Load(path string) (Credential, error) {
	if strings.TrimSpace(path) == "" {
		path = Path()
	}
	if path == "" {
		return Credential{}, ErrNoCredential
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Credential{}, fmt.Errorf("%w: %s not found", ErrNoCredential, path)
		}
		return Credential{}, fmt.Errorf("chatgpt: read credential: %w", err)
	}
	var af authFile
	if err := json.Unmarshal(raw, &af); err != nil {
		return Credential{}, fmt.Errorf("chatgpt: parse credential: %w", err)
	}
	var fallback *Credential
	for _, e := range af.CredentialPool.Entries {
		if strings.TrimSpace(e.AccessToken) == "" {
			continue
		}
		c := Credential{
			AccessToken: e.AccessToken, RefreshToken: e.RefreshToken,
			BaseURL: strings.TrimRight(strings.TrimSpace(e.BaseURL), "/"),
			Label:   e.Label,
		}
		if c.BaseURL == "" {
			c.BaseURL = DefaultBaseURL
		}
		c.AccountID, c.Plan, c.ExpiresAt = claims(e.AccessToken)
		if c.ExpiresAt.IsZero() && e.ExpiresAtMS > 0 {
			c.ExpiresAt = time.UnixMilli(e.ExpiresAtMS)
		}
		if fallback == nil {
			cp := c
			fallback = &cp
		}
		if !c.Expired() && e.LastStatus != "exhausted" {
			return c, nil
		}
	}
	if fallback != nil {
		return *fallback, nil
	}
	return Credential{}, fmt.Errorf("%w: no openai-codex entry in %s", ErrNoCredential, path)
}

// LoadPreferred returns Indago's own session when present, otherwise the
// borrowed Hermes session (read-only).
func LoadPreferred(storeDir string) (Credential, error) {
	if storeDir != "" {
		if c, err := NewStore(storeDir).Load(); err == nil {
			return c, nil
		} else if !errors.Is(err, ErrNoCredential) {
			return Credential{}, err
		}
	}
	return Load("")
}

// claims decodes the (unverified) JWT payload: it is used to read the account
// id, plan and expiry the backend itself will check. The signature is not
// validated here because the token is only ever presented to its issuer.
func claims(token string) (accountID, plan string, exp time.Time) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return "", "", time.Time{}
	}
	p := parts[1]
	if pad := len(p) % 4; pad != 0 {
		p += strings.Repeat("=", 4-pad)
	}
	raw, err := base64.URLEncoding.DecodeString(p)
	if err != nil {
		return "", "", time.Time{}
	}
	var payload struct {
		Exp  int64 `json:"exp"`
		Auth struct {
			AccountID string `json:"chatgpt_account_id"`
			PlanType  string `json:"chatgpt_plan_type"`
		} `json:"https://api.openai.com/auth"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return "", "", time.Time{}
	}
	if payload.Exp > 0 {
		exp = time.Unix(payload.Exp, 0)
	}
	return payload.Auth.AccountID, payload.Auth.PlanType, exp
}

// Redact scrubs the access and refresh tokens from s.
func (c Credential) Redact(s string) string {
	for _, tok := range []string{c.AccessToken, c.RefreshToken} {
		if len(tok) > 12 {
			s = strings.ReplaceAll(s, tok, "[REDACTED]")
		}
	}
	return s
}
