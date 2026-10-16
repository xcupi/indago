package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// defaultHTTPTimeout bounds how long a single advisory call may run. LLM
// completions are slower than ordinary API calls but a scan must never hang
// indefinitely because a provider stalled — the caller's ctx can still
// cancel sooner than this.
const defaultHTTPTimeout = 90 * time.Second

// newHTTPClient returns an http.Client shared by every provider in this
// package. No provider reuses net/http's DefaultClient (which has no
// timeout at all).
func newHTTPClient() *http.Client {
	return &http.Client{Timeout: defaultHTTPTimeout}
}

// systemPrompt frames every advisory call with the package's own hard
// invariant, in-band, so a provider that honors system messages reinforces
// it independently of anything the Go code does: this call is advisory only,
// never an authoritative security verdict.
const systemPrompt = "You are an advisory assistant embedded in Indago, a reflected-XSS scanner. " +
	"Your output is advisory only: it is never the final authority on scope, vulnerability confirmation, " +
	"evidence, or any security verdict — a human or the scanner's own deterministic verification decides that. " +
	"Be concise, factual, and avoid speculation beyond what the given context supports."

// userContent builds the user-role message from a Request: the prompt, plus
// its Context map (if any) rendered as a JSON block so structured data
// (finding fields, endpoint lists, etc.) survives rather than being
// flattened into prose by the caller.
func userContent(req Request) string {
	if len(req.Context) == 0 {
		return req.Prompt
	}
	ctxJSON, err := json.MarshalIndent(req.Context, "", "  ")
	if err != nil {
		return req.Prompt
	}
	return req.Prompt + "\n\nContext:\n" + string(ctxJSON)
}

// postJSON POSTs body as JSON to url with the given extra headers, decodes
// the JSON response into out, and turns a non-2xx status into an error that
// includes the response body (truncated) so a misconfigured provider fails
// with a readable message instead of a bare status code.
func postJSON(ctx context.Context, url string, headers map[string]string, body any, out any) error {
	buf, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("ai: encode request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return fmt.Errorf("ai: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := newHTTPClient().Do(req)
	if err != nil {
		return fmt.Errorf("ai: request failed: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB cap: never buffer an unbounded body
	if err != nil {
		return fmt.Errorf("ai: read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := string(respBody)
		if len(msg) > 500 {
			msg = msg[:500] + "..."
		}
		return fmt.Errorf("ai: provider returned %s: %s", resp.Status, msg)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(respBody, out); err != nil {
		return fmt.Errorf("ai: decode response: %w", err)
	}
	return nil
}
