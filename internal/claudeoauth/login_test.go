package claudeoauth

import (
	"context"
	"net/url"
	"os"
	"strings"
	"testing"
)

func TestStartBuildsPKCEAuthorizationURL(t *testing.T) {
	l := NewLogin(NewStore(t.TempDir()))
	raw, state, err := l.Start()
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if u.Host != "claude.ai" || u.Path != "/oauth/authorize" || q.Get("client_id") != ClientID {
		t.Fatalf("url = %s", raw)
	}
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		t.Fatalf("missing PKCE challenge: %s", raw)
	}
	if q.Get("state") != state || q.Get("redirect_uri") != RedirectURI {
		t.Fatalf("state/redirect mismatch: %s", raw)
	}
	if q.Get("code") != "true" {
		t.Fatalf("manual code flow marker missing: %s", raw)
	}
	if q.Get("redirect_uri") != "https://platform.claude.com/oauth/code/callback" {
		t.Fatalf("redirect_uri = %q", q.Get("redirect_uri"))
	}
	scope := q.Get("scope")
	for _, want := range []string{"org:create_api_key", "user:profile", "user:inference", "user:sessions:claude_code", "user:mcp_servers", "user:file_upload", "user:plugins"} {
		if !strings.Contains(scope, want) {
			t.Fatalf("scope %q is missing %q", scope, want)
		}
	}
}

func TestFinishRejectsUnknownState(t *testing.T) {
	l := NewLogin(NewStore(t.TempDir()))
	if _, err := l.Finish(context.Background(), "code#state", "not-started"); err == nil {
		t.Fatal("finish accepted a state that was never started")
	}
}

func TestStoreRoundTripAndPermissions(t *testing.T) {
	dir := t.TempDir()
	st := NewStore(dir)
	if st.Configured() {
		t.Fatal("fresh store must be empty")
	}
	c := Credentials{AccessToken: "a", RefreshToken: "r"}
	if err := st.Save(c); err != nil {
		t.Fatal(err)
	}
	back, err := st.Load()
	if err != nil || back.AccessToken != "a" || back.RefreshToken != "r" {
		t.Fatalf("load = %+v err=%v", back, err)
	}
	info, err := os.Stat(dir + "/credentials.json")
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("mode = %o", perm)
	}
}
