package scan

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/indago/indago/internal/httpengine"
)

func writeAuthState(t *testing.T, origins any) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "state-*.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.NewEncoder(f).Encode(map[string]any{"cookies": []any{}, "origins": origins}); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return f.Name()
}

func TestSessionAuthHeadersReadsJWTFromLocalStorage(t *testing.T) {
	state := writeAuthState(t, []any{map[string]any{
		"origin": "https://app.example.test",
		"localStorage": []any{
			map[string]any{"name": "access_token", "value": "aaaaa.bbbbb.ccccc"},
			map[string]any{"name": "theme", "value": "aaaaa.bbbbb.ccccc"},
			map[string]any{"name": "token", "value": "not-a-jwt"},
		},
	}})
	headers := sessionAuthHeaders(state)
	if len(headers) != 1 {
		t.Fatalf("headers = %+v, want one recognized JWT", headers)
	}
	if headers[0].Origin != "https://app.example.test" || headers[0].Value != "Bearer aaaaa.bbbbb.ccccc" {
		t.Fatalf("unexpected header: %+v", headers[0])
	}
}

func TestScopedEngineAppliesAuthOnlyToExactOrigin(t *testing.T) {
	seen := make(chan string, 2)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get("Authorization")
		_, _ = w.Write([]byte("ok"))
	}))
	defer target.Close()

	eng := newScopedEngine(noFollowClient(t), openScope()).WithSessionAuthHeaders([]sessionAuthHeader{
		{Origin: target.URL, Value: "Bearer tested"},
	})
	resp, err := eng.Do(t.Context(), httpengine.GET(target.URL+"/api"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Fatalf("status = %d", resp.Status)
	}
	if got := <-seen; got != "Bearer tested" {
		t.Fatalf("Authorization = %q, want Bearer tested", got)
	}

	// Same host but a different scheme is a different origin: no token.
	eng = newScopedEngine(noFollowClient(t), openScope()).WithSessionAuthHeaders([]sessionAuthHeader{
		{Origin: strings.Replace(target.URL, "http://", "https://", 1), Value: "Bearer wrong"},
	})
	// The test server is HTTP, so use its actual origin with a different value
	// would still match; instead exercise the predicate directly.
	if sameURLOrigin(target.URL, strings.Replace(target.URL, "http://", "https://", 1)) {
		t.Fatal("http and https must not be considered the same origin")
	}
}
