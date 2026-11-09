package ai_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/indago/indago/internal/ai"
)

func fakeJWT(t *testing.T, exp time.Time, account string) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload := map[string]any{
		"exp": exp.Unix(),
		"https://api.openai.com/auth": map[string]any{
			"chatgpt_account_id": account,
			"chatgpt_plan_type":  "plus",
		},
	}
	raw, _ := json.Marshal(payload)
	return header + "." + base64.RawURLEncoding.EncodeToString(raw) + ".sig"
}

func writeAuth(t *testing.T, baseURL, token string, expires time.Time) string {
	t.Helper()
	doc := map[string]any{"credential_pool": map[string]any{
		"openai-codex": []map[string]any{{
			"label": "test", "auth_type": "oauth", "access_token": token,
			"refresh_token": "refresh", "base_url": baseURL,
			"expires_at_ms": expires.UnixMilli(), "last_status": "ok",
		}},
	}}
	raw, _ := json.Marshal(doc)
	path := filepath.Join(t.TempDir(), "auth.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestChatGPTProviderUsesOAuthSession(t *testing.T) {
	token := fakeJWT(t, time.Now().Add(3*time.Hour), "acct-123456789")
	var gotAuth, gotAccount, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotAccount = r.Header.Get("ChatGPT-Account-ID")
		buf := make([]byte, 8192)
		n, _ := r.Body.Read(buf)
		gotBody = string(buf[:n])
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("event: response.output_text.delta\n" +
			`data: {"type":"response.output_text.delta","delta":"hello "}` + "\n\n" +
			"event: response.output_text.delta\n" +
			`data: {"type":"response.output_text.delta","delta":"world"}` + "\n\n" +
			"event: response.completed\n" +
			`data: {"type":"response.completed"}` + "\n\n"))
	}))
	defer srv.Close()
	t.Setenv("INDAGO_CHATGPT_AUTH", writeAuth(t, srv.URL, token, time.Now().Add(3*time.Hour)))

	p, err := ai.NewProvider(ai.Settings{Provider: ai.ProviderChatGPT, Model: "gpt-test"})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := p.Complete(context.Background(), ai.Request{Prompt: "hi"})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if resp.Text != "hello world" {
		t.Fatalf("text = %q", resp.Text)
	}
	if gotAuth != "Bearer "+token {
		t.Fatalf("authorization header not the OAuth token: %q", gotAuth)
	}
	if gotAccount != "acct-123456789" {
		t.Fatalf("account header = %q", gotAccount)
	}
	for _, want := range []string{`"store":false`, `"stream":true`, `"model":"gpt-test"`} {
		if !strings.Contains(gotBody, want) {
			t.Fatalf("request body missing %s: %s", want, gotBody)
		}
	}
}

func TestChatGPTProviderRejectsExpiredSession(t *testing.T) {
	token := fakeJWT(t, time.Now().Add(-time.Hour), "acct")
	t.Setenv("INDAGO_CHATGPT_AUTH", writeAuth(t, "https://example.invalid", token, time.Now().Add(-time.Hour)))
	p, err := ai.NewProvider(ai.Settings{Provider: ai.ProviderChatGPT, Model: "m"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Complete(context.Background(), ai.Request{Prompt: "hi"}); err == nil ||
		!strings.Contains(err.Error(), "expired") {
		t.Fatalf("err = %v, want an expired-session error", err)
	}
}
