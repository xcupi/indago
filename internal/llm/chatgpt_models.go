package llm

// ChatGPT model discovery. The OAuth session is valid for the Codex backend,
// whose /models response is richer than the OpenAI-compatible shape: it lists
// slug, visibility, and whether the model is usable through the API.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/indago/indago/internal/chatgpt"
)

// ChatGPTModels returns the model slugs the signed-in ChatGPT account exposes.
// Only models marked visible or usable through the API are returned; hidden
// internal models are deliberately omitted from the picker.
func (p *Prober) ChatGPTModels(ctx context.Context, dir string) ([]string, error) {
	cred, err := chatgpt.LoadPreferred(dir)
	if err != nil {
		return nil, err
	}
	if cred.Expired() {
		return nil, fmt.Errorf("ChatGPT OAuth session expired — log in again from Settings")
	}
	ctx, cancel := context.WithTimeout(ctx, p.timeout())
	defer cancel()

	endpoint := strings.TrimRight(cred.BaseURL, "/") + "/models?client_version=" + chatgptClientVersion
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+cred.AccessToken)
	req.Header.Set("originator", "codex_cli_rs")
	req.Header.Set("User-Agent", "codex_cli_rs/"+chatgptClientVersion)
	if cred.AccountID != "" {
		req.Header.Set("ChatGPT-Account-ID", cred.AccountID)
	}
	client := &http.Client{Timeout: p.timeout()}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %s", cred.Redact(err.Error()))
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("provider returned %s", resp.Status)
	}

	var out struct {
		Models []struct {
			Slug           string `json:"slug"`
			Visibility     string `json:"visibility"`
			SupportedInAPI bool   `json:"supported_in_api"`
		} `json:"models"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("provider returned an unreadable model list")
	}
	seen := map[string]bool{}
	models := make([]string, 0, len(out.Models))
	for _, m := range out.Models {
		slug := strings.TrimSpace(m.Slug)
		if slug == "" || seen[slug] || !m.SupportedInAPI || m.Visibility == "hide" {
			continue
		}
		seen[slug] = true
		models = append(models, slug)
	}
	if len(models) == 0 {
		return nil, fmt.Errorf("provider returned no selectable models")
	}
	return models, nil
}
