package web_test

import (
	"context"
	"testing"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/web"
)

func TestLoginUsesActualProjectScope(t *testing.T) {
	for _, tc := range []struct {
		name    string
		scope   domain.Scope
		url     string
		allowed bool
	}{
		{"empty", domain.Scope{}, "http://127.0.0.1/login", false},
		{"outside-host", domain.Scope{IncludeHosts: []string{"127.0.0.1"}}, "http://localhost/login", false},
		{"excluded-host", domain.Scope{IncludeHosts: []string{"127.0.0.1"}, ExcludeHosts: []string{"127.0.0.1"}}, "http://127.0.0.1/login", false},
		{"excluded-path", domain.Scope{IncludeHosts: []string{"127.0.0.1"}, ExcludePathPrefixes: []string{"/login"}}, "http://127.0.0.1/login", false},
		{"path-not-included", domain.Scope{IncludeHosts: []string{"127.0.0.1"}, IncludePathPrefixes: []string{"/app"}}, "http://127.0.0.1/login", false},
		{"explicit-sso", domain.Scope{IncludeHosts: []string{"127.0.0.1", "localhost"}}, "http://localhost/login", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			a := newAPIWith(t, nil, func(s *web.Server) {
				s.SetLoginFunc(func(_ context.Context, p web.LoginParams) (string, string, error) {
					called = true
					for _, raw := range []string{tc.url, "http://localhost/login", "http://127.0.0.1/app", "http://127.0.0.1/login", "http://outside.invalid/"} {
						if p.AllowRequest == nil || p.AllowRequest(raw) != tc.scope.Permits(raw).Allowed {
							t.Fatalf("gate differs from project Scope.Permits for %s", raw)
						}
					}
					return "", "", nil
				})
			})
			ctx := context.Background()
			if err := a.st.Projects().Create(ctx, &domain.Project{ID: "p", Name: "login"}); err != nil {
				t.Fatal(err)
			}
			tc.scope.ID = "s"
			tc.scope.ProjectID = "p"
			if err := a.st.Scopes().Create(ctx, &tc.scope); err != nil {
				t.Fatal(err)
			}
			rec := a.do("POST", "/api/auth/login", map[string]string{"project_id": "p", "login_url": tc.url})
			want := 400
			if tc.allowed {
				want = 200
			}
			if rec.Code != want || called != tc.allowed {
				t.Fatalf("status=%d called=%v want status=%d called=%v", rec.Code, called, want, tc.allowed)
			}
		})
	}
}

func TestLoginRequiresProjectScope(t *testing.T) {
	called := false
	a := newAPIWith(t, nil, func(s *web.Server) {
		s.SetLoginFunc(func(context.Context, web.LoginParams) (string, string, error) { called = true; return "", "", nil })
	})
	ctx := context.Background()
	if err := a.st.Projects().Create(ctx, &domain.Project{ID: "login-project", Name: "login"}); err != nil {
		t.Fatal(err)
	}
	for _, pid := range []string{"", "unknown", "login-project"} {
		called = false
		rec := a.do("POST", "/api/auth/login", map[string]string{"project_id": pid, "login_url": "http://127.0.0.1/login"})
		if rec.Code != 400 || called {
			t.Errorf("project %q: status=%d login_called=%v; require 400 before launch", pid, rec.Code, called)
		}
	}
}
