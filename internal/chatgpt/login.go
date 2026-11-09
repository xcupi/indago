package chatgpt

// Indago-owned ChatGPT credential: device-code login, token refresh and a
// private store under the data directory.
//
// This is the alternative to borrowing the Hermes session: the operator logs in
// once for Indago, the tokens live in <data>/chatgpt/credentials.json (0600 in a
// 0700 directory), and only Indago rotates them. Nothing else on the machine is
// touched.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// ClientID is the public Codex OAuth client used by the device flow.
	ClientID = "app_EMoamEEZ73f0CkXaXp7hrann"
	// Issuer is the OpenAI auth host.
	Issuer = "https://auth.openai.com"
	// DeviceURL is where the operator enters the user code.
	DeviceURL = Issuer + "/codex/device"
	// TokenURL exchanges the authorization code and refreshes tokens.
	TokenURL = Issuer + "/oauth/token"
)

// DeviceAuth is one in-flight device login.
type DeviceAuth struct {
	DeviceAuthID string    `json:"device_auth_id"`
	UserCode     string    `json:"user_code"`
	URL          string    `json:"url"`
	IntervalSec  int       `json:"interval_seconds"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// Store is Indago's own credential store.
type Store struct{ Dir string }

// NewStore returns a store rooted at dir (created on demand).
func NewStore(dir string) *Store { return &Store{Dir: dir} }

func (s *Store) path() string { return filepath.Join(s.Dir, "credentials.json") }

// Save writes the credential atomically with 0600 permissions.
func (s *Store) Save(c Credential) error {
	if s == nil || s.Dir == "" {
		return fmt.Errorf("chatgpt: no credential directory")
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return fmt.Errorf("chatgpt: create credential dir: %w", err)
	}
	doc := map[string]any{
		"access_token":  c.AccessToken,
		"refresh_token": c.RefreshToken,
		"base_url":      c.BaseURL,
		"account_id":    c.AccountID,
		"plan":          c.Plan,
		"expires_at":    c.ExpiresAt.UTC().Format(time.RFC3339),
		"label":         c.Label,
		"saved_at":      time.Now().UTC().Format(time.RFC3339),
	}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path() + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("chatgpt: write credential: %w", err)
	}
	return os.Rename(tmp, s.path())
}

// Load reads Indago's own credential. ErrNoCredential when absent.
func (s *Store) Load() (Credential, error) {
	if s == nil || s.Dir == "" {
		return Credential{}, ErrNoCredential
	}
	raw, err := os.ReadFile(s.path())
	if err != nil {
		if os.IsNotExist(err) {
			return Credential{}, ErrNoCredential
		}
		return Credential{}, fmt.Errorf("chatgpt: read credential: %w", err)
	}
	var doc struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		BaseURL      string `json:"base_url"`
		AccountID    string `json:"account_id"`
		Plan         string `json:"plan"`
		ExpiresAt    string `json:"expires_at"`
		Label        string `json:"label"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return Credential{}, fmt.Errorf("chatgpt: parse credential: %w", err)
	}
	if doc.AccessToken == "" {
		return Credential{}, ErrNoCredential
	}
	c := Credential{
		AccessToken: doc.AccessToken, RefreshToken: doc.RefreshToken,
		BaseURL: strings.TrimRight(doc.BaseURL, "/"), AccountID: doc.AccountID,
		Plan: doc.Plan, Label: doc.Label, Owned: true,
	}
	if c.BaseURL == "" {
		c.BaseURL = DefaultBaseURL
	}
	if t, err := time.Parse(time.RFC3339, doc.ExpiresAt); err == nil {
		c.ExpiresAt = t
	}
	if c.AccountID == "" {
		if id, plan, exp := claims(c.AccessToken); id != "" {
			c.AccountID, c.Plan = id, plan
			if c.ExpiresAt.IsZero() {
				c.ExpiresAt = exp
			}
		}
	}
	return c, nil
}

// Clear removes Indago's stored credential.
func (s *Store) Clear() error {
	if s == nil || s.Dir == "" {
		return nil
	}
	if err := os.Remove(s.path()); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// StartLogin requests a device code.
func StartLogin(ctx context.Context) (*DeviceAuth, error) {
	body := strings.NewReader(fmt.Sprintf(`{"client_id":%q}`, ClientID))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, Issuer+"/api/accounts/deviceauth/usercode", body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("chatgpt: device code request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("chatgpt: OpenAI is rate-limiting login requests; retry in a minute (HTTP 429)")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("chatgpt: device code request returned %s", resp.Status)
	}
	var out struct {
		DeviceAuthID string          `json:"device_auth_id"`
		UserCode     string          `json:"user_code"`
		Interval     json.RawMessage `json:"interval"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("chatgpt: decode device code: %w", err)
	}
	if out.DeviceAuthID == "" || out.UserCode == "" {
		return nil, fmt.Errorf("chatgpt: device code response is incomplete")
	}
	interval := 5
	if len(out.Interval) > 0 {
		var n int
		if json.Unmarshal(out.Interval, &n) == nil && n > 0 {
			interval = n
		}
	}
	if interval < 3 {
		interval = 3
	}
	return &DeviceAuth{
		DeviceAuthID: out.DeviceAuthID, UserCode: out.UserCode, URL: DeviceURL,
		IntervalSec: interval, ExpiresAt: time.Now().Add(15 * time.Minute),
	}, nil
}

// PollOnce asks whether the operator finished signing in. done=false means keep
// waiting (the backend answers 403/404 until then).
func PollOnce(ctx context.Context, d DeviceAuth) (cred *Credential, done bool, err error) {
	payload, _ := json.Marshal(map[string]string{
		"device_auth_id": d.DeviceAuthID, "user_code": d.UserCode,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		Issuer+"/api/accounts/deviceauth/token", strings.NewReader(string(payload)))
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("chatgpt: poll: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound {
		return nil, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("chatgpt: poll returned %s", resp.Status)
	}
	var out struct {
		AuthorizationCode string `json:"authorization_code"`
		CodeVerifier      string `json:"code_verifier"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, false, fmt.Errorf("chatgpt: decode poll: %w", err)
	}
	if out.AuthorizationCode == "" || out.CodeVerifier == "" {
		return nil, false, fmt.Errorf("chatgpt: poll response is incomplete")
	}
	c, err := exchange(ctx, out.AuthorizationCode, out.CodeVerifier)
	if err != nil {
		return nil, false, err
	}
	return &c, true, nil
}

// Wait polls until the login completes, the context ends or the device code
// expires.
func Wait(ctx context.Context, d DeviceAuth) (Credential, error) {
	interval := time.Duration(d.IntervalSec) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}
	deadline := d.ExpiresAt
	if deadline.IsZero() {
		deadline = time.Now().Add(15 * time.Minute)
	}
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return Credential{}, ctx.Err()
		case <-time.After(interval):
		}
		cred, done, err := PollOnce(ctx, d)
		if err != nil {
			return Credential{}, err
		}
		if done {
			return *cred, nil
		}
	}
	return Credential{}, fmt.Errorf("chatgpt: login timed out after 15 minutes")
}

func exchange(ctx context.Context, code, verifier string) (Credential, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {Issuer + "/deviceauth/callback"},
		"client_id":     {ClientID},
		"code_verifier": {verifier},
	}
	tokens, err := tokenRequest(ctx, form)
	if err != nil {
		return Credential{}, err
	}
	c := Credential{
		AccessToken: tokens.AccessToken, RefreshToken: tokens.RefreshToken,
		BaseURL: DefaultBaseURL, Label: "indago device-code", Owned: true,
	}
	c.AccountID, c.Plan, c.ExpiresAt = claims(c.AccessToken)
	if tokens.ExpiresIn > 0 {
		c.ExpiresAt = time.Now().Add(time.Duration(tokens.ExpiresIn) * time.Second)
	}
	if c.AccessToken == "" {
		return Credential{}, fmt.Errorf("chatgpt: token exchange returned no access_token")
	}
	return c, nil
}

// Refresh rotates an Indago-owned credential. Callers must only pass a
// credential Indago owns; a borrowed Hermes token must never be refreshed here.
func Refresh(ctx context.Context, c Credential) (Credential, error) {
	if !c.Owned {
		return Credential{}, fmt.Errorf("chatgpt: refusing to refresh a borrowed credential")
	}
	if c.RefreshToken == "" {
		return Credential{}, fmt.Errorf("chatgpt: no refresh_token stored — log in again")
	}
	tokens, err := tokenRequest(ctx, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {c.RefreshToken},
		"client_id":     {ClientID},
	})
	if err != nil {
		return Credential{}, err
	}
	c.AccessToken = tokens.AccessToken
	if tokens.RefreshToken != "" {
		c.RefreshToken = tokens.RefreshToken
	}
	c.AccountID, c.Plan, c.ExpiresAt = claims(c.AccessToken)
	if tokens.ExpiresIn > 0 {
		c.ExpiresAt = time.Now().Add(time.Duration(tokens.ExpiresIn) * time.Second)
	}
	return c, nil
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	Error        string `json:"error"`
	ErrorDesc    string `json:"error_description"`
}

func tokenRequest(ctx context.Context, form url.Values) (tokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return tokenResponse{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "indago")
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return tokenResponse{}, fmt.Errorf("chatgpt: token request: %w", err)
	}
	defer resp.Body.Close()
	var out tokenResponse
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode == http.StatusTooManyRequests {
		return tokenResponse{}, fmt.Errorf("chatgpt: OpenAI is rate-limiting token requests (HTTP 429); retry later")
	}
	if resp.StatusCode != http.StatusOK || out.Error != "" {
		msg := out.ErrorDesc
		if msg == "" {
			msg = out.Error
		}
		if msg == "" {
			msg = resp.Status
		}
		return tokenResponse{}, fmt.Errorf("chatgpt: token endpoint: %s", msg)
	}
	return out, nil
}
