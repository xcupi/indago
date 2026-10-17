package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
)

// CLI side of the optional bearer token: the CLI sends
// Authorization: Bearer <INDAGO_API_TOKEN> on every request when the variable
// is set, and never otherwise. The token is never a flag.

const cliTestToken = "indago-test-token-9f2c7d41a8e6b305c1d9e2f7a4b8c6d0" // dummy

// authRecorder is a fake server that records the Authorization header of each
// request and answers 200 with an empty JSON list (or 401 when requireTok is
// set and the header does not match).
type authRecorder struct {
	mu       sync.Mutex
	seen     []string // "METHOD <Authorization or ->"
	requireT string   // when non-empty, answer 401 unless the Bearer token matches
}

func (a *authRecorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	auth := r.Header.Get("Authorization")
	if auth == "" {
		auth = "-"
	}
	a.seen = append(a.seen, r.Method+" "+auth)
	if a.requireT != "" && auth != "Bearer "+a.requireT {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("WWW-Authenticate", "Bearer")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":"missing or invalid API token"}`)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `[]`)
}

func TestCLISendsBearerTokenOnlyWhenConfigured(t *testing.T) {
	rec := &authRecorder{}
	srv := httptest.NewServer(rec)
	defer srv.Close()

	// Configured: every request (GET, POST, and the raw GET) carries the header.
	t.Setenv("INDAGO_API_TOKEN", cliTestToken)
	c := newCLI(srv.URL, io.Discard)
	var list []any
	if err := c.call(http.MethodGet, "/api/projects", nil, &list); err != nil {
		t.Fatalf("GET with token: %v", err)
	}
	if err := c.call(http.MethodPost, "/api/projects", map[string]string{"name": "x"}, nil); err != nil {
		t.Fatalf("POST with token: %v", err)
	}
	if _, err := c.getRaw("/api/version"); err != nil {
		t.Fatalf("getRaw with token: %v", err)
	}

	// Unset: no Authorization header at all (behaviour as before).
	t.Setenv("INDAGO_API_TOKEN", "")
	os.Unsetenv("INDAGO_API_TOKEN")
	c = newCLI(srv.URL, io.Discard)
	if err := c.call(http.MethodGet, "/api/projects", nil, &list); err != nil {
		t.Fatalf("GET without token: %v", err)
	}

	want := []string{
		"GET Bearer " + cliTestToken,
		"POST Bearer " + cliTestToken,
		"GET Bearer " + cliTestToken,
		"GET -",
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if strings.Join(rec.seen, "\n") != strings.Join(want, "\n") {
		t.Fatalf("Authorization headers seen by server:\n%s\nwant:\n%s",
			strings.Join(rec.seen, "\n"), strings.Join(want, "\n"))
	}
}

func TestCLIAuthFailuresAreCleanAndNeverEchoTheToken(t *testing.T) {
	rec := &authRecorder{requireT: cliTestToken}
	srv := httptest.NewServer(rec)
	defer srv.Close()

	// No token configured on the client: a clean 401 that tells the operator
	// what to set.
	t.Setenv("INDAGO_API_TOKEN", "")
	os.Unsetenv("INDAGO_API_TOKEN")
	c := newCLI(srv.URL, io.Discard)
	err := c.call(http.MethodGet, "/api/projects", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "401") || !strings.Contains(err.Error(), "INDAGO_API_TOKEN") {
		t.Fatalf("no-token 401: want a clean error naming HTTP 401 and INDAGO_API_TOKEN, got %v", err)
	}

	// Wrong token configured: 401, and the error text must not contain the
	// token the client was given.
	const wrong = "wrong-token-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	t.Setenv("INDAGO_API_TOKEN", wrong)
	c = newCLI(srv.URL, io.Discard)
	err = c.call(http.MethodGet, "/api/projects", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("wrong-token 401: got %v", err)
	}
	if strings.Contains(err.Error(), wrong) {
		t.Fatalf("error text echoes the token: %v", err)
	}
	if _, err := c.getRaw("/api/version"); err == nil || strings.Contains(err.Error(), wrong) {
		t.Fatalf("getRaw wrong-token: got %v", err)
	}

	// Correct token: succeeds.
	t.Setenv("INDAGO_API_TOKEN", cliTestToken)
	c = newCLI(srv.URL, io.Discard)
	if err := c.call(http.MethodGet, "/api/projects", nil, nil); err != nil {
		t.Fatalf("correct token: %v", err)
	}
}
