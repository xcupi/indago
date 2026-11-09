package ai_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/indago/indago/internal/ai"
)

// Some OpenAI-compatible gateways stream by default: the body is one JSON
// completion followed by the SSE terminator, or a bare "data: {...}" frame.
// Both must decode; json.Unmarshal alone rejects them.
func TestCompleteToleratesSSEFraming(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"json_then_done", `{"choices":[{"message":{"role":"assistant","content":"hello"}}],"model":"m"}` + "\ndata: [DONE]"},
		{"sse_frame", "data: {\"choices\":[{\"message\":{\"role\":\"assistant\",\"content\":\"hello\"}}],\"model\":\"m\"}\n\ndata: [DONE]\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/chat/completions" {
					t.Errorf("unexpected path %s", r.URL.Path)
				}
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			p, err := ai.NewProvider(ai.Settings{
				Provider: ai.ProviderOpenAI, BaseURL: srv.URL, Model: "m", APIKey: "k",
			})
			if err != nil {
				t.Fatal(err)
			}
			resp, err := p.Complete(context.Background(), ai.Request{Prompt: "hi"})
			if err != nil {
				t.Fatalf("Complete: %v", err)
			}
			if !strings.Contains(resp.Text, "hello") {
				t.Fatalf("text = %q", resp.Text)
			}
		})
	}
}

// The request body must state stream:false — a gateway that defaults to SSE
// when the field is absent otherwise answers with an event stream.
func TestCompleteSendsStreamFalse(t *testing.T) {
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 4096)
		n, _ := r.Body.Read(buf)
		gotBody = string(buf[:n])
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"ok"}}]}`))
	}))
	defer srv.Close()

	p, err := ai.NewProvider(ai.Settings{Provider: ai.ProviderCustom, BaseURL: srv.URL, Model: "m"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Complete(context.Background(), ai.Request{Prompt: "hi"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(gotBody, `"stream":false`) {
		t.Fatalf("request body missing stream:false: %s", gotBody)
	}
}
