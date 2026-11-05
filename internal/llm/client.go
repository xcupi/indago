package llm

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

const (
	// DefaultTimeout bounds one explicit probe. It is short because this is a
	// connection check, not a completion: a provider that cannot answer a
	// one-token prompt promptly is not usable for an assessment either.
	DefaultTimeout = 10 * time.Second

	// maxProbeTokens is the token cap for the probe. Enough for a provider to
	// accept the request; not enough to bill or stream a real completion.
	maxProbeTokens = 1

	// maxResponseBytes caps how much of an upstream body is buffered. A
	// provider error page is never worth more than this.
	maxResponseBytes = 1 << 20

	probePrompt    = "Reply with OK."
	probeUserAgent = "indago-llm-probe"
)

// ProbeResult is the outcome of one bounded connection test. It contains no
// secret: Error has already been redacted.
type ProbeResult struct {
	OK        bool   `json:"ok"`
	Provider  string `json:"provider"`
	Model     string `json:"model"`
	LatencyMS int64  `json:"latency_ms"`
	Error     string `json:"error,omitempty"`
}

// Prober performs the two explicit outbound operations this package allows:
// Test (one chat completion) and Models (one model list). It is stateless and
// safe for concurrent use. The zero value uses DefaultTimeout.
type Prober struct {
	Timeout time.Duration
}

// NewProber returns a prober with the given budget. A non-positive timeout
// means DefaultTimeout.
func NewProber(timeout time.Duration) *Prober { return &Prober{Timeout: timeout} }

func (p *Prober) timeout() time.Duration {
	if p.Timeout > 0 {
		return p.Timeout
	}
	return DefaultTimeout
}

// Test performs ONE bounded chat-completions request against cfg. It never
// retries, never streams, and asks for a single token. The returned Error is
// already redacted; callers may redact again at their own boundary.
func (p *Prober) Test(ctx context.Context, cfg Config) ProbeResult {
	res := ProbeResult{Provider: cfg.Provider, Model: cfg.Model}
	if !cfg.Configured() {
		res.Error = ErrNotConfigured.Error()
		return res
	}
	if cfg.BaseURL == "" || cfg.Model == "" {
		res.Error = "model and base_url are required"
		return res
	}

	start := time.Now()
	err := p.chat(ctx, cfg)
	res.LatencyMS = time.Since(start).Milliseconds()
	if err != nil {
		res.Error = RedactAndTrim(err.Error(), cfg.apiKey)
		return res
	}
	res.OK = true
	return res
}

func (p *Prober) chat(ctx context.Context, cfg Config) error {
	ctx, cancel := context.WithTimeout(ctx, p.timeout())
	defer cancel()

	payload, err := json.Marshal(chatRequest{
		Model:     cfg.Model,
		Messages:  []chatMessage{{Role: "user", Content: probePrompt}},
		MaxTokens: maxProbeTokens,
		Stream:    false,
	})
	if err != nil {
		return fmt.Errorf("encode request: %w", err)
	}

	endpoint := strings.TrimRight(cfg.BaseURL, "/") + "/chat/completions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	setHeaders(req, cfg)

	client := p.client()
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		// net/http error strings include the URL (never headers), so the key
		// cannot appear here — but redact anyway: the boundary is cheap.
		return fmt.Errorf("request failed: %s", RedactAndTrim(err.Error(), cfg.apiKey))
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("read response: %s", RedactAndTrim(err.Error(), cfg.apiKey))
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("provider returned %s: %s", resp.Status, RedactAndTrim(string(body), cfg.apiKey))
	}
	// Some gateways answer 200 with an error envelope. Treat that as a failed
	// probe rather than a successful connection.
	if msg := apiErrorMessage(body); msg != "" {
		return fmt.Errorf("provider error: %s", RedactAndTrim(msg, cfg.apiKey))
	}
	return nil
}

// Models asks the provider for its model list. It is one bounded GET, never a
// completion. A provider that does not implement /models (404/501) returns an
// error; the caller degrades to the free-text model field, which is the
// primary input either way.
func (p *Prober) Models(ctx context.Context, cfg Config) ([]string, error) {
	if !cfg.Configured() {
		return nil, ErrNotConfigured
	}
	if cfg.BaseURL == "" {
		return nil, invalid("base_url is required")
	}
	ctx, cancel := context.WithTimeout(ctx, p.timeout())
	defer cancel()

	endpoint := strings.TrimRight(cfg.BaseURL, "/") + "/models"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	setHeaders(req, cfg)

	client := p.client()
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %s", RedactAndTrim(err.Error(), cfg.apiKey))
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("read response: %s", RedactAndTrim(err.Error(), cfg.apiKey))
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("provider returned %s: %s", resp.Status, RedactAndTrim(string(body), cfg.apiKey))
	}

	// OpenAI-compatible: {"data":[{"id":"..."}]}. Ollama's native shape is
	// {"models":[{"name":"..."}]}; accept both rather than guessing the
	// backend from its base URL.
	var out struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, errors.New("provider returned an unreadable model list")
	}
	seen := make(map[string]bool)
	var ids []string
	add := func(id string) {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			return
		}
		seen[id] = true
		ids = append(ids, id)
	}
	for _, m := range out.Data {
		add(m.ID)
	}
	for _, m := range out.Models {
		add(m.Name)
	}
	if len(ids) == 0 {
		return nil, errors.New("provider returned no model list")
	}
	sort.Strings(ids)
	return ids, nil
}

type chatRequest struct {
	Model     string        `json:"model"`
	Messages  []chatMessage `json:"messages"`
	MaxTokens int           `json:"max_tokens"`
	Stream    bool          `json:"stream"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// setHeaders applies the provider's auth convention. The Authorization header
// is the only place the key is written; it is never logged.
func setHeaders(req *http.Request, cfg Config) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", probeUserAgent)
	if cfg.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.apiKey)
	}
}

// client builds a one-shot HTTP client: bounded total time, TLS >= 1.2, and no
// redirect following. A redirect is treated as an error rather than replaying
// a credentialed request against a target the operator did not configure.
func (p *Prober) client() *http.Client {
	tr := &http.Transport{Proxy: http.ProxyFromEnvironment}
	if base, ok := http.DefaultTransport.(*http.Transport); ok {
		tr = base.Clone()
	}
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return &http.Client{
		Timeout:   p.timeout(),
		Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// apiErrorMessage extracts an error message from a 2xx body that is really an
// error envelope. Empty when the body has no error object.
func apiErrorMessage(body []byte) string {
	var out struct {
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &out) != nil || out.Error == nil {
		return ""
	}
	return strings.TrimSpace(out.Error.Message)
}
