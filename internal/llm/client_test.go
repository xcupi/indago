package llm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testConfig(baseURL string) Config {
	return Config{Provider: ProviderCustom, Model: "test-model", BaseURL: baseURL, apiKey: testKey}
}

func TestProbeSendsOneBoundedRequest(t *testing.T) {
	var calls int32
	var path, auth string
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		path = r.URL.Path
		auth = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"OK"}}]}`)
	}))
	defer srv.Close()

	res := NewProber(2*time.Second).Test(context.Background(), testConfig(srv.URL))
	if !res.OK {
		t.Fatalf("probe failed: %+v", res)
	}
	if res.Error != "" {
		t.Fatalf("successful probe carries an error: %q", res.Error)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("probe made %d requests, want exactly 1", got)
	}
	if path != "/chat/completions" {
		t.Errorf("path = %q, want /chat/completions", path)
	}
	if auth != "Bearer "+testKey {
		t.Errorf("Authorization header = %q, want the bearer key", auth)
	}
	if body["model"] != "test-model" {
		t.Errorf("request model = %v", body["model"])
	}
	if mt, ok := body["max_tokens"].(float64); !ok || mt != 1 {
		t.Errorf("max_tokens = %v, want the small cap 1", body["max_tokens"])
	}
	if stream, ok := body["stream"].(bool); !ok || stream {
		t.Errorf("stream = %v, want false", body["stream"])
	}
}

func TestProbeRedactsAKeyEchoedByTheProvider(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, `{"error":{"message":"401 invalid key `+testKey+` (sent as Bearer `+testKey+`)"}}`)
	}))
	defer srv.Close()

	res := NewProber(2*time.Second).Test(context.Background(), testConfig(srv.URL))
	if res.OK {
		t.Fatal("a 401 was reported as a successful probe")
	}
	if strings.Contains(res.Error, testKey) {
		t.Fatalf("probe error contains the literal key: %s", res.Error)
	}
	if strings.Contains(res.Error, testKey[:12]) {
		t.Fatalf("probe error contains a key prefix: %s", res.Error)
	}
	if !strings.Contains(res.Error, Redacted) {
		t.Fatalf("probe error was not redacted: %s", res.Error)
	}
	if !strings.Contains(res.Error, "401") {
		t.Fatalf("probe error lost the upstream status: %s", res.Error)
	}
}

func TestProbeRedactsBeforeTruncating(t *testing.T) {
	// Put the key right at the old 300-byte truncation point: truncating
	// first would leave a recognisable key prefix behind.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, strings.Repeat("x", 280)+" "+testKey+" "+strings.Repeat("y", 200))
	}))
	defer srv.Close()

	res := NewProber(2*time.Second).Test(context.Background(), testConfig(srv.URL))
	if res.OK {
		t.Fatal("a 400 was reported as a successful probe")
	}
	if strings.Contains(res.Error, testKey) || strings.Contains(res.Error, testKey[:12]) {
		t.Fatalf("truncated error leaked the key: %s", res.Error)
	}
	if len(res.Error) > maxErrorBody+100 {
		t.Fatalf("error string is not bounded: %d bytes", len(res.Error))
	}
}

func TestProbeTimeoutFailsFast(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release: // test cleanup: let Close finish
		case <-r.Context().Done():
		}
	}))
	defer func() {
		close(release)
		srv.Close()
	}()

	start := time.Now()
	res := NewProber(120*time.Millisecond).Test(context.Background(), testConfig(srv.URL))
	elapsed := time.Since(start)
	if res.OK {
		t.Fatal("a stalled provider was reported as reachable")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("probe took %v with a 120ms budget", elapsed)
	}
	if res.Error == "" {
		t.Fatal("a timeout produced no error text")
	}
	if strings.Contains(res.Error, testKey) {
		t.Fatalf("timeout error leaked the key: %s", res.Error)
	}
}

func TestProbeUnreachableFailsFastAndDoesNotLeak(t *testing.T) {
	// Port 1 on loopback refuses immediately; this is the CLI/web "unreachable
	// base URL" case.
	start := time.Now()
	res := NewProber(0).Test(context.Background(), testConfig("http://127.0.0.1:1"))
	if res.OK {
		t.Fatal("an unreachable endpoint was reported as reachable")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("unreachable probe took %v, want a fast failure", elapsed)
	}
	if res.Error == "" || strings.Contains(res.Error, testKey) {
		t.Fatalf("unreachable error = %q", res.Error)
	}
}

func TestProbeDoesNotFollowRedirects(t *testing.T) {
	var redirected int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&redirected, 1)
		io.WriteString(w, `{"choices":[]}`)
	}))
	defer target.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/chat/completions", http.StatusTemporaryRedirect)
	}))
	defer srv.Close()

	res := NewProber(2*time.Second).Test(context.Background(), testConfig(srv.URL))
	if res.OK {
		t.Fatal("a redirect was followed and reported as success")
	}
	if got := atomic.LoadInt32(&redirected); got != 0 {
		t.Fatalf("the credentialed request was replayed at the redirect target %d time(s)", got)
	}
}

func TestProbeTreatsA200ErrorEnvelopeAsFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"error":{"message":"quota exceeded for key `+testKey+`"}}`)
	}))
	defer srv.Close()
	res := NewProber(2*time.Second).Test(context.Background(), testConfig(srv.URL))
	if res.OK {
		t.Fatal("a 200 error envelope was reported as success")
	}
	if strings.Contains(res.Error, testKey) {
		t.Fatalf("error envelope leaked the key: %s", res.Error)
	}
}

func TestModelsListsAndDeduplicates(t *testing.T) {
	var calls int32
	var path, auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		path, auth = r.URL.Path, r.Header.Get("Authorization")
		io.WriteString(w, `{"data":[{"id":"zeta"},{"id":"alpha"},{"id":"alpha"},{"id":""}]}`)
	}))
	defer srv.Close()

	models, err := NewProber(2*time.Second).Models(context.Background(), testConfig(srv.URL))
	if err != nil {
		t.Fatalf("Models: %v", err)
	}
	if got := strings.Join(models, ","); got != "alpha,zeta" {
		t.Fatalf("models = %q, want alpha,zeta", got)
	}
	if path != "/models" || auth != "Bearer "+testKey {
		t.Fatalf("models request path=%q auth set=%v", path, auth != "")
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("Models made %d requests, want exactly 1", got)
	}
}

func TestModelsAcceptsOllamaShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"models":[{"name":"llama3"},{"name":"qwen2.5"}]}`)
	}))
	defer srv.Close()
	models, err := NewProber(2*time.Second).Models(context.Background(), testConfig(srv.URL))
	if err != nil {
		t.Fatalf("Models: %v", err)
	}
	if got := strings.Join(models, ","); got != "llama3,qwen2.5" {
		t.Fatalf("models = %q", got)
	}
}

func TestModelsDegradesOnUnsupportedEndpointAndRedacts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		io.WriteString(w, "no such route for key "+testKey)
	}))
	defer srv.Close()
	_, err := NewProber(2*time.Second).Models(context.Background(), testConfig(srv.URL))
	if err == nil {
		t.Fatal("a 404 model endpoint returned no error")
	}
	if strings.Contains(err.Error(), testKey) {
		t.Fatalf("model-list error leaked the key: %v", err)
	}
	if !strings.Contains(err.Error(), "404") {
		t.Fatalf("model-list error lost the status: %v", err)
	}
}

func TestRedactShapes(t *testing.T) {
	const secret = "sk-live-ABCdef0123456789"
	cases := map[string]string{
		"exact":          "upstream said " + secret + " is invalid",
		"bearer":         "Authorization: Bearer " + secret,
		"generic bearer": "sent Bearer abcdefghijklmnop",
		"sk shape":       "invalid key sk-other-key-123456",
		"key assignment": `{"api_key":"somethinglongenough"}`,
	}
	for name, in := range cases {
		out := Redact(in, secret)
		if strings.Contains(out, secret) {
			t.Errorf("%s: redaction left the exact secret: %s", name, out)
		}
		if name == "exact" || name == "bearer" {
			if !strings.Contains(out, Redacted) {
				t.Errorf("%s: no redaction marker: %s", name, out)
			}
		}
	}
	if got := Redact("plain text, nothing secret", secret); got != "plain text, nothing secret" {
		t.Errorf("redaction changed unrelated text: %q", got)
	}
}
