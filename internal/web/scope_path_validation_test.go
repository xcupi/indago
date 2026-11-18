package web_test

// Save-time regression: a scope PUT must reject path prefixes whose
// decoding/segment boundary is ambiguous instead of storing a prefix that can
// never safely match (or, worse, matches after an intermediary normalises it).

import (
	"net/http"
	"strings"
	"testing"
)

func TestScopePUTRejectsAmbiguousPathPrefixes(t *testing.T) {
	a, pid := newScopeProject(t)
	for _, prefix := range []string{
		"/app/%2e%2e",
		"/app/%252e%252e",
		"/app/%2f",
		`/app\..\admin`,
		"/app//x",
		"/app/..;/x",
		"/app;v=1",
		"/app/%",
	} {
		t.Run(prefix, func(t *testing.T) {
			code, body := scopePut(a, pid, map[string]any{
				"include_hosts":         []string{"a.example"},
				"include_path_prefixes": []string{prefix},
			})
			if code != http.StatusBadRequest {
				t.Fatalf("scope PUT %q status = %d, want 400 (%s)", prefix, code, body)
			}
			if !strings.Contains(body, "include_path_prefixes") {
				t.Fatalf("scope PUT %q error should name include_path_prefixes, got %s", prefix, body)
			}
		})
	}
}
