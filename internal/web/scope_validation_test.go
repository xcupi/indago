package web_test

import (
	"encoding/json"
	"github.com/indago/indago/internal/web"
	"net/http"
	"strings"
	"testing"
)

// Scope entries that can never match used to be stored and then silently deny
// everything. Saving them is now a 400 that names the entry and how to write it.

func scopePut(a api, pid string, body map[string]any) (int, string) {
	rec := a.do("PUT", "/api/projects/"+pid+"/scope", body)
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(rec.Body.Bytes(), &e) == nil && e.Error != "" {
		return rec.Code, e.Error // the decoded message, not JSON-escaped text
	}
	return rec.Code, rec.Body.String()
}

func newScopeProject(t *testing.T) (api, string) {
	t.Helper()
	a, _ := coverageAPI(t, webCapsZero())
	var p map[string]any
	a.mustJSON(a.do("POST", "/api/projects", map[string]string{"name": "scope-validation"}), 201, &p)
	return a, p["id"].(string)
}

func TestScopeRejectsHostEntriesThatCanNeverMatch(t *testing.T) {
	a, pid := newScopeProject(t)
	for _, tc := range []struct{ entry, hint string }{
		{"https://example.com", `"example.com"`},
		{"example.com:8443", `"example.com"`},
		{"*.example.com", `".example.com"`},
		{"example.com/app", `"example.com"`},
		{"[::1]", `"::1"`},
		{"example.com.", "trailing dot"},
		{"bücher.example", "punycode"},
		{"2130706433", "dotted-quad"},
	} {
		code, body := scopePut(a, pid, map[string]any{"include_hosts": []string{"ok.example", tc.entry}})
		if code != http.StatusBadRequest {
			t.Errorf("include %q: status = %d, want 400 (%s)", tc.entry, code, body)
			continue
		}
		if !strings.Contains(body, "include_hosts") || !strings.Contains(body, tc.hint) {
			t.Errorf("include %q: message should name the field and mention %s, got %s", tc.entry, tc.hint, body)
		}
	}
	// Nothing was stored by any rejected attempt.
	if rec := a.do("GET", "/api/projects/"+pid+"/scope", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("a rejected scope must not be created, GET status = %d", rec.Code)
	}
}

func TestScopeRejectsBadExcludeAndPathEntriesToo(t *testing.T) {
	a, pid := newScopeProject(t)
	for _, tc := range []struct {
		field string
		body  map[string]any
	}{
		{"exclude_hosts", map[string]any{"include_hosts": []string{"a.example"}, "exclude_hosts": []string{"https://admin.a.example"}}},
		{"include_path_prefixes", map[string]any{"include_hosts": []string{"a.example"}, "include_path_prefixes": []string{"app"}}},
		{"exclude_path_prefixes", map[string]any{"include_hosts": []string{"a.example"}, "exclude_path_prefixes": []string{"/admin?x=1"}}},
	} {
		code, body := scopePut(a, pid, tc.body)
		if code != http.StatusBadRequest || !strings.Contains(body, tc.field) {
			t.Errorf("%s: status %d body %s", tc.field, code, body)
		}
	}
}

func TestScopeAcceptsRealEntriesAndKeepsEarlierScopeWhenAReplacementIsRejected(t *testing.T) {
	a, pid := newScopeProject(t)
	good := map[string]any{
		"include_hosts":         []string{"example.com", ".api.example.com", "127.0.0.1", "::1", "localhost"},
		"exclude_hosts":         []string{"admin.example.com"},
		"include_path_prefixes": []string{"/app/"},
		"exclude_path_prefixes": []string{"/app/private", "/app/private/"},
		"allow_subdomains":      true,
	}
	if code, body := scopePut(a, pid, good); code != http.StatusCreated {
		t.Fatalf("valid scope status %d: %s", code, body)
	}
	// A replacement with one bad entry changes nothing.
	code, _ := scopePut(a, pid, map[string]any{"include_hosts": []string{"other.example", "https://oops.example"}})
	if code != http.StatusBadRequest {
		t.Fatalf("replacement with a bad entry: status %d", code)
	}
	var got struct {
		IncludeHosts []string `json:"include_hosts"`
	}
	a.mustJSON(a.do("GET", "/api/projects/"+pid+"/scope", nil), 200, &got)
	if len(got.IncludeHosts) != 5 || got.IncludeHosts[0] != "example.com" {
		t.Fatalf("a rejected replacement must leave the stored scope alone, got %v", got.IncludeHosts)
	}
	// A valid replacement still works (200).
	if code, body := scopePut(a, pid, map[string]any{"include_hosts": []string{"other.example"}}); code != http.StatusOK {
		t.Fatalf("valid replacement: %d %s", code, body)
	}
}

func TestScopeEmptyIncludeIsStillRejected(t *testing.T) {
	a, pid := newScopeProject(t)
	if code, _ := scopePut(a, pid, map[string]any{"include_hosts": []string{"  "}}); code != http.StatusBadRequest {
		t.Fatalf("status = %d", code)
	}
}

func webCapsZero() web.Capabilities { return web.Capabilities{} }
