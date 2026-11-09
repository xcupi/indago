package ai

// ChatGPT via OAuth: the Codex backend (chatgpt.com/backend-api/codex) speaks
// the Responses API and authenticates with the OAuth access token instead of an
// API key. The credential is the session a Hermes install already holds
// (internal/chatgpt), so no separate login is needed and no key is copied
// around.
//
// Protocol details that are easy to get wrong, all verified against the live
// endpoint:
//   - POST /responses, not /chat/completions.
//   - "store": false is required.
//   - "stream": true is required; the answer arrives as SSE events and the
//     text is the concatenation of response.output_text.delta.
//   - ChatGPT-Account-ID comes from the access-token claims.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/indago/indago/internal/chatgpt"
)

// chatgptClientVersion is sent as both User-Agent and the /models query the
// backend validates. The value mirrors the Codex client the endpoint expects.
const chatgptClientVersion = "0.153.0"

type chatgptProvider struct {
	credPath string
	model    string
}

// chatgptResponseRequest is the Responses API body. Only the fields Indago
// needs are set; store=false keeps the request out of the account's history.
type chatgptResponseRequest struct {
	Model        string                `json:"model"`
	Store        bool                  `json:"store"`
	Stream       bool                  `json:"stream"`
	Instructions string                `json:"instructions,omitempty"`
	Input        []chatgptResponseItem `json:"input"`
}

type chatgptResponseItem struct {
	Role    string               `json:"role"`
	Content []chatgptContentPart `json:"content"`
}

type chatgptContentPart struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type chatgptEvent struct {
	Type  string `json:"type"`
	Delta string `json:"delta"`
	Text  string `json:"text"`
	Error *struct {
		Message string `json:"message"`
		Code    string `json:"code"`
	} `json:"error"`
	Response *struct {
		Error *struct {
			Message string `json:"message"`
			Code    string `json:"code"`
		} `json:"error"`
	} `json:"response"`
}

func (p *chatgptProvider) Name() string { return ProviderChatGPT }

func (p *chatgptProvider) Complete(ctx context.Context, req Request) (*Response, error) {
	cred, err := chatgpt.Load(p.credPath)
	if err != nil {
		return nil, fmt.Errorf("ai: chatgpt: %w", err)
	}
	if cred.Expired() {
		return nil, fmt.Errorf("ai: chatgpt: OAuth session expired — re-authenticate in Hermes (codex login); Indago does not refresh the shared token")
	}
	model := strings.TrimSpace(p.model)
	if model == "" {
		model = p.discoverModel(ctx, cred)
	}

	body := chatgptResponseRequest{
		Model: model, Store: false, Stream: true, Instructions: systemPrompt,
		Input: []chatgptResponseItem{{
			Role:    "user",
			Content: []chatgptContentPart{{Type: "input_text", Text: userContent(req)}},
		}},
	}
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("ai: chatgpt: encode request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(cred.BaseURL, "/")+"/responses", bytes.NewReader(buf))
	if err != nil {
		return nil, fmt.Errorf("ai: chatgpt: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "text/event-stream")
	httpReq.Header.Set("Authorization", "Bearer "+cred.AccessToken)
	httpReq.Header.Set("originator", "codex_cli_rs")
	httpReq.Header.Set("User-Agent", "codex_cli_rs/"+chatgptClientVersion)
	if cred.AccountID != "" {
		httpReq.Header.Set("ChatGPT-Account-ID", cred.AccountID)
	}

	resp, err := (&http.Client{Timeout: defaultHTTPTimeout}).Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("ai: chatgpt: request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("ai: chatgpt: provider returned %s: %s",
			resp.Status, cred.Redact(truncate(string(msg), 400)))
	}

	text, err := readResponsesStream(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("ai: chatgpt: %w", err)
	}
	if strings.TrimSpace(text) == "" {
		return nil, fmt.Errorf("ai: chatgpt: empty response")
	}
	return &Response{Text: text, Model: model}, nil
}

// discoverModel asks the backend which models the account may use. The list is
// account-specific, so it is not hardcoded; the fallback only covers a backend
// that answers without the models payload.
func (p *chatgptProvider) discoverModel(ctx context.Context, cred chatgpt.Credential) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		strings.TrimRight(cred.BaseURL, "/")+"/models?client_version="+chatgptClientVersion, nil)
	if err != nil {
		return "gpt-5.6-luna"
	}
	req.Header.Set("Authorization", "Bearer "+cred.AccessToken)
	req.Header.Set("originator", "codex_cli_rs")
	req.Header.Set("User-Agent", "codex_cli_rs/"+chatgptClientVersion)
	resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		return "gpt-5.6-luna"
	}
	defer resp.Body.Close()
	var out struct {
		Models []struct {
			Slug       string `json:"slug"`
			Supported  bool   `json:"supported_in_api"`
			Visibility string `json:"visibility"`
			MinimalFor string `json:"minimal_client_version"`
		} `json:"models"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return "gpt-5.6-luna"
	}
	for _, m := range out.Models {
		if m.Slug != "" && m.Supported {
			return m.Slug
		}
	}
	return "gpt-5.6-luna"
}

// readResponsesStream accumulates the answer from Responses API SSE events:
// deltas while streaming, the final text as a fallback, and a provider error
// event as a failure. It stops at response.completed/failed or EOF.
func readResponsesStream(r io.Reader) (string, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	var b strings.Builder
	var done bool
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "" || payload == "[DONE]" {
			continue
		}
		var ev chatgptEvent
		if err := json.Unmarshal([]byte(payload), &ev); err != nil {
			continue
		}
		switch ev.Type {
		case "response.output_text.delta":
			b.WriteString(ev.Delta)
		case "response.output_text.done":
			if b.Len() == 0 {
				b.WriteString(ev.Text)
			}
		case "response.failed", "error":
			msg := "provider reported failure"
			if ev.Error != nil && ev.Error.Message != "" {
				msg = ev.Error.Message
			} else if ev.Response != nil && ev.Response.Error != nil && ev.Response.Error.Message != "" {
				msg = ev.Response.Error.Message
			}
			return "", fmt.Errorf("%s", msg)
		case "response.completed":
			done = true
		}
		if done {
			break
		}
	}
	if err := sc.Err(); err != nil {
		return "", fmt.Errorf("read stream: %w", err)
	}
	return b.String(), nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

var _ Provider = (*chatgptProvider)(nil)
