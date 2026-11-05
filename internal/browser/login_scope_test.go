package browser

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoginScopeRejectsInitialURLBeforeLaunch(t *testing.T) {
	for _, auto := range []bool{false, true} {
		t.Run(map[bool]string{false: "interactive", true: "auto"}[auto], func(t *testing.T) {
			d := &fakeDriver{}
			m := newFakeManager(t, Config{PoolSize: 1}, d)
			defer m.Close()
			before := d.launched
			deny := func(string) bool { return false }
			path := filepath.Join(t.TempDir(), "state.json")
			var err error
			if auto {
				_, err = m.AutoLogin(context.Background(), AutoLoginOptions{AllowRequest: deny, LoginURL: "https://outside/login", Username: "dummy", Password: "dummy", SuccessURLGlob: "**/done", StorageStatePath: path})
			} else {
				_, err = m.InteractiveLogin(context.Background(), LoginOptions{AllowRequest: deny, LoginURL: "https://outside/login", StorageStatePath: path})
			}
			if err == nil || d.launched != before {
				t.Fatalf("out-of-scope login must fail before launch: err=%v launches=%d", err, d.launched-before)
			}
		})
	}
}

func TestLoginScopePassedToBothContexts(t *testing.T) {
	for _, auto := range []bool{false, true} {
		t.Run(map[bool]string{false: "interactive", true: "auto"}[auto], func(t *testing.T) {
			d := &fakeDriver{}
			m := newFakeManager(t, Config{PoolSize: 1}, d)
			defer m.Close()
			allow := func(raw string) bool { return strings.HasPrefix(raw, "https://app/") }
			path := filepath.Join(t.TempDir(), "state.json")
			var err error
			if auto {
				_, err = m.AutoLogin(context.Background(), AutoLoginOptions{AllowRequest: allow, LoginURL: "https://app/login", Username: "dummy", Password: "dummy", SuccessURLGlob: "**/done", StorageStatePath: path})
			} else {
				_, err = m.InteractiveLogin(context.Background(), LoginOptions{AllowRequest: allow, LoginURL: "https://app/login", StorageStatePath: path})
			}
			if err != nil {
				t.Fatal(err)
			}
			b := d.browsers[len(d.browsers)-1]
			if len(b.contexts) != 1 || !b.contexts[0].gated {
				t.Fatal("login context is not scope gated")
			}
		})
	}
}

func TestLoginRequiresScopeBeforeLaunch(t *testing.T) {
	for _, auto := range []bool{false, true} {
		t.Run(map[bool]string{false: "interactive", true: "auto"}[auto], func(t *testing.T) {
			d := &fakeDriver{}
			m := newFakeManager(t, Config{PoolSize: 1}, d)
			defer m.Close()
			before := d.launched
			path := filepath.Join(t.TempDir(), "state.json")
			var err error
			if auto {
				_, err = m.AutoLogin(context.Background(), AutoLoginOptions{LoginURL: "https://app/login", Username: "dummy", Password: "dummy", SuccessURLGlob: "**/done", StorageStatePath: path})
			} else {
				_, err = m.InteractiveLogin(context.Background(), LoginOptions{LoginURL: "https://app/login", StorageStatePath: path})
			}
			if err == nil || !strings.Contains(err.Error(), "scope") {
				t.Errorf("missing scope must fail closed, got %v", err)
			}
			if d.launched != before {
				t.Errorf("missing scope launched a login browser")
			}
		})
	}
}
