package web_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/httpengine"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/scan"
	"github.com/indago/indago/internal/store/memory"
	"github.com/indago/indago/internal/web"
)

func TestStrictTargetReadSnapshot(t *testing.T) {
	var calls, forbidden, authenticated atomic.Int32
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodGet || r.ContentLength != 0 ||
			(r.URL.Path != "/inventories" && r.URL.Path != "/status" && r.URL.Path != "/handoff") {
			forbidden.Add(1)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if r.URL.Path == "/handoff" {
			http.Redirect(w, r, "/unapproved", http.StatusFound)
			return
		}
		if cookie, err := r.Cookie("fixture_session"); err == nil && cookie.Value == "reader" {
			authenticated.Add(1)
		}
		w.Header().Set("Set-Cookie", "fixture_response=private")
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<main>Read-only inventory</main>"))
	}))
	defer site.Close()
	cfg := httpengine.DefaultConfig()
	cfg.FollowRedirects, cfg.DisableCookies = false, true
	eng, err := httpengine.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	st := memory.New()
	ctrl := scan.NewController(st, queue.NewMemory(), nil, "test", scan.Options{ReadOnlyTargets: true, HTTP: eng})
	defer ctrl.Shutdown()
	srv := web.NewServer(st, ctrl, "test", nil, nil, t.TempDir())
	srv.SetLoginFunc(func(context.Context, web.LoginParams) (string, string, error) {
		t.Error("blocked live login handler was called")
		return "", "", nil
	})
	a := api{t: t, st: st, h: srv.Handler()}

	// Version has a string value in the actual response; only assert the current policy fields.
	var state struct {
		ReadOnly bool `json:"target_read_only"`
		Login    bool `json:"interactive_login"`
		Writes   bool `json:"state_changing_allowed"`
	}
	a.mustJSON(a.do("GET", "/api/capabilities", nil), 200, &state)
	if !state.ReadOnly || state.Login || state.Writes {
		t.Fatalf("policy advertised unsafe capabilities: %+v", state)
	}
	var proj domain.Project
	a.mustJSON(a.do("POST", "/api/projects", map[string]string{"name": "Snapshot fixture"}), 201, &proj)
	root := "/api/projects/" + string(proj.ID)
	a.mustJSON(a.do("PUT", root+"/scope", map[string]any{
		"include_hosts": []string{"127.0.0.1"}, "allowed_origins": []string{site.URL},
	}), 201, nil)
	var target domain.Target
	a.mustJSON(a.do("POST", root+"/targets", map[string]string{"name": "Inventory", "base_url": site.URL}), 201, &target)
	var draft domain.Scan
	a.mustJSON(a.do("POST", "/api/scans", map[string]any{"project_id": proj.ID, "target_id": target.ID}), 201, &draft)
	scanPath := "/api/scans/" + string(draft.ID)
	for _, tc := range []struct{ method, path string }{
		{"POST", scanPath + "/start"}, {"POST", scanPath + "/resume"},
		{"POST", "/api/auth/login"}, {"POST", scanPath + "/bounty/yeswehack/draft"},
		{"GET", scanPath + "/findings/stored/poc"},
	} {
		a.mustJSON(a.do(tc.method, tc.path, map[string]string{}), http.StatusForbidden, nil)
	}
	a.mustJSON(a.do("POST", "/api/scans", map[string]any{
		"project_id": proj.ID, "target_id": target.ID, "auth_mode": "interactive", "login_url": site.URL + "/status",
	}), http.StatusForbidden, nil)
	a.mustJSON(a.do("POST", root+"/read-snapshot", map[string]any{"url": site.URL + "/status"}), 400, nil)
	a.mustJSON(a.do("POST", root+"/read-snapshot", map[string]any{
		"url": "https://outside.invalid/status", "approved_read_only": true,
	}), 400, nil)
	if calls.Load() != 0 {
		t.Fatal("blocked requests reached the target")
	}

	statePath := filepath.Join(t.TempDir(), "storage-state.json")
	stateJSON := `{"cookies":[{"name":"fixture_session","value":"reader","domain":"127.0.0.1","path":"/","expires":-1}],"origins":[]}`
	if err := os.WriteFile(statePath, []byte(stateJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	var profile domain.AuthProfile
	a.mustJSON(a.do("POST", root+"/auth-profiles", map[string]any{"name": "Reader", "state_path": statePath}), 201, &profile)

	approved := map[string]any{"url": site.URL + "/inventories", "approved_read_only": true, "auth_profile_id": profile.ID}
	var snapshot struct {
		Status int    `json:"status"`
		Body   string `json:"body_text"`
		SHA    string `json:"sha256"`
	}
	rec := a.do("POST", root+"/read-snapshot", approved)
	a.mustJSON(rec, 200, &snapshot)
	if snapshot.Status != 200 || snapshot.Body != "<main>Read-only inventory</main>" || len(snapshot.SHA) != 64 ||
		strings.Contains(rec.Body.String(), "fixture_response") || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("unexpected snapshot or header: %+v, %s", snapshot, rec.Header())
	}

	// The redirect is captured as status evidence and does not issue a second GET.
	var redirect struct {
		Status int  `json:"status"`
		Denied bool `json:"redirect_not_followed"`
	}
	a.mustJSON(a.do("POST", root+"/read-snapshot", map[string]any{
		"url": site.URL + "/handoff", "approved_read_only": true,
	}), 200, &redirect)
	if redirect.Status != 302 || !redirect.Denied || calls.Load() != 2 || forbidden.Load() != 0 || authenticated.Load() != 1 {
		t.Fatalf("unexpected traffic: redirect=%+v calls=%d forbidden=%d auth=%d", redirect, calls.Load(), forbidden.Load(), authenticated.Load())
	}
	a.mustJSON(a.do("DELETE", root+"/auth-profiles/"+string(profile.ID), nil), 204, nil)
	if _, err := os.Stat(statePath); err != nil {
		t.Fatalf("deleting a profile removed the operator's read-only session file: %v", err)
	}
}
