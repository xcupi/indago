package llm

// ChatGPT/Codex OAuth probe: a bounded GET /models against the Codex backend.
// It proves the stored session is accepted without spending a completion.

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/indago/indago/internal/chatgpt"
)

// chatgptClientVersion mirrors the Codex client the backend validates in the
// /models query.
const chatgptClientVersion = "0.153.0"

// TestChatGPT checks the OAuth session in the Hermes auth store.
func (p *Prober) TestChatGPT(ctx context.Context) ProbeResult {
	res := ProbeResult{Provider: ProviderChatGPT, Model: "oauth"}
	cred, err := chatgpt.Load("")
	if err != nil {
		res.Error = err.Error()
		return res
	}
	if cred.Expired() {
		res.Error = "OAuth session expired — re-authenticate in Hermes"
		return res
	}
	res.Model = cred.Plan
	ctx, cancel := context.WithTimeout(ctx, p.timeout())
	defer cancel()

	endpoint := strings.TrimRight(cred.BaseURL, "/") + "/models?client_version=" + chatgptClientVersion
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		res.Error = "build request: " + err.Error()
		return res
	}
	req.Header.Set("Authorization", "Bearer "+cred.AccessToken)
	req.Header.Set("originator", "codex_cli_rs")
	req.Header.Set("User-Agent", "codex_cli_rs/"+chatgptClientVersion)
	if cred.AccountID != "" {
		req.Header.Set("ChatGPT-Account-ID", cred.AccountID)
	}
	start := time.Now()
	resp, err := (&http.Client{Timeout: p.timeout()}).Do(req)
	res.LatencyMS = time.Since(start).Milliseconds()
	if err != nil {
		res.Error = cred.Redact(err.Error())
		return res
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		res.Error = fmt.Sprintf("provider returned %s", resp.Status)
		return res
	}
	res.OK = true
	return res
}

// Config returns the outbound settings for this credential (the key stays
// inside this package's type).
func (c Credential) Config() Config {
	return Config{Provider: c.Provider, Model: c.Model, BaseURL: c.BaseURL, apiKey: c.apiKey}
}

// ProbeChatGPT exposes the session probe for callers that hold no Config.
func (p *Prober) ProbeChatGPT(ctx context.Context) ProbeResult { return p.TestChatGPT(ctx) }
