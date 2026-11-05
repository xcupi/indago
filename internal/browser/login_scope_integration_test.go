package browser_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/domain"
)

// Canonical absolute Locations isolate login policy plumbing from redirect parsing.
func TestIntegrationLoginScopeBoundary(t *testing.T) {
	t.Setenv("INDAGO_AUTH_USER", "loopback-dummy-user")
	t.Setenv("INDAGO_AUTH_PASS", "loopback-dummy-pass")
	for _, scenario := range []string{"initial", "redirect", "form", "subresource-popup", "scoped-control", "explicit-sso"} {
		t.Run(scenario, func(t *testing.T) {
			var outsideHits, credentialPosts, insidePosts atomic.Int64
			outside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				outsideHits.Add(1)
				if r.Method == http.MethodPost {
					_ = r.ParseForm()
					if r.FormValue("username") == os.Getenv("INDAGO_AUTH_USER") && r.FormValue("password") == os.Getenv("INDAGO_AUTH_PASS") {
						credentialPosts.Add(1)
					}
				}
				w.Header().Set("Content-Type", "text/html")
				if r.URL.Path == "/login" {
					fmt.Fprint(w, `<form method="post" action="/done"><input name="username"><input name="password" type="password"><button type="submit">Login</button></form>`)
				} else {
					fmt.Fprint(w, "done")
				}
			}))
			defer outside.Close()
			outsideURL := strings.Replace(outside.URL, "127.0.0.1", "localhost", 1)
			inside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					_ = r.ParseForm()
					if r.FormValue("username") == os.Getenv("INDAGO_AUTH_USER") && r.FormValue("password") == os.Getenv("INDAGO_AUTH_PASS") {
						insidePosts.Add(1)
					}
				}
				if r.URL.Path == "/done" {
					fmt.Fprint(w, "done")
					return
				}
				if scenario == "redirect" || scenario == "explicit-sso" {
					http.Redirect(w, r, outsideURL+"/login", http.StatusFound)
					return
				}
				action := "/done"
				if scenario == "form" {
					action = outsideURL + "/done"
				}
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprintf(w, `<form method="post" action="%s"><input name="username"><input name="password" type="password"><button type="submit">Login</button></form>`, action)
				if scenario == "subresource-popup" {
					fmt.Fprintf(w, `<img src="%s/pixel"><script>window.open(%q);fetch(%q).catch(()=>{});</script>`, outsideURL, outsideURL+"/popup", outsideURL+"/fetch")
				}
			}))
			defer inside.Close()
			scope := domain.Scope{IncludeHosts: []string{"127.0.0.1"}}
			if scenario == "explicit-sso" {
				scope.IncludeHosts = append(scope.IncludeHosts, "localhost")
			}
			cfg := browser.DefaultConfig()
			cfg.NavigationTimeout = 3 * time.Second
			m := newManagerOrSkip(t, cfg)
			defer m.Close()
			login := inside.URL + "/login"
			if scenario == "initial" {
				login = outsideURL + "/login"
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_, err := m.AutoLogin(ctx, browser.AutoLoginOptions{AllowRequest: func(raw string) bool { return scope.Permits(raw).Allowed }, LoginURL: login, Username: os.Getenv("INDAGO_AUTH_USER"), Password: os.Getenv("INDAGO_AUTH_PASS"), SuccessURLGlob: "**/done", StorageStatePath: filepath.Join(t.TempDir(), "state.json"), Timeout: time.Second})
			denied := scenario == "initial" || scenario == "redirect" || scenario == "form"
			if denied && err == nil {
				t.Error("denied login unexpectedly succeeded")
			}
			if !denied && err != nil {
				t.Errorf("permitted login failed: %v", err)
			}
			if scenario == "explicit-sso" {
				if outsideHits.Load() == 0 || credentialPosts.Load() != 1 {
					t.Errorf("explicitly scoped SSO not exercised: hits=%d posts=%d", outsideHits.Load(), credentialPosts.Load())
				}
			} else if outsideHits.Load() != 0 || credentialPosts.Load() != 0 {
				t.Errorf("scope leak: outside_hits=%d credential_posts=%d", outsideHits.Load(), credentialPosts.Load())
			}
			if scenario == "scoped-control" || scenario == "subresource-popup" {
				if insidePosts.Load() != 1 {
					t.Errorf("scoped credential submission not exercised: posts=%d", insidePosts.Load())
				}
			}
			t.Logf("outside_hits=%d outside_credential_posts=%d inside_posts=%d", outsideHits.Load(), credentialPosts.Load(), insidePosts.Load())
		})
	}
}
