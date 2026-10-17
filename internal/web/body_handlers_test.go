package web_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/scan"
	"github.com/indago/indago/internal/store/memory"
	"github.com/indago/indago/internal/web"
)

func TestEveryJSONHandlerUses413(t *testing.T) {
	st := memory.New()
	ctx := context.Background()
	p := &domain.Project{ID: domain.NewID(), Name: "body test"}
	if err := st.Projects().Create(ctx, p); err != nil {
		t.Fatal(err)
	}
	sc := &domain.Scan{ID: domain.NewID(), ProjectID: p.ID}
	if err := st.Scans().Create(ctx, sc); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctrl := scan.NewController(st, queue.NewMemory(), log, "test", scan.Options{})
	defer ctrl.Shutdown()
	s := web.NewServer(st, ctrl, "test", log, nil, t.TempDir())
	s.SetLoginFunc(func(context.Context, web.LoginParams) (string, string, error) {
		t.Fatal("oversize triggered login")
		return "", "", nil
	})
	h := s.Handler()
	for _, route := range []struct{ method, path string }{
		{"POST", "/api/projects"}, {"POST", "/api/projects/" + string(p.ID) + "/targets"},
		{"PUT", "/api/projects/" + string(p.ID) + "/scope"}, {"POST", "/api/scans"},
		{"POST", "/api/scans/" + string(sc.ID) + "/reports"}, {"POST", "/api/scans/" + string(sc.ID) + "/config"}, {"POST", "/api/auth/login"},
	} {
		t.Run(route.path, func(t *testing.T) {
			req := httptest.NewRequest(route.method, route.path, strings.NewReader(`{} `+strings.Repeat(" ", 1<<20)))
			req.Header.Set(web.ClientHeader, "test")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != 413 {
				t.Fatalf("want 413 got %d: %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestProjectJSONBoundaryAndSafeErrors(t *testing.T) {
	for _, c := range []struct {
		name, body string
		want       int
	}{
		{"normal", `{"name":"ok"}`, 201},
		{"exact limit", `{"name":"ok"}` + strings.Repeat(" ", (1<<20)-len(`{"name":"ok"}`)), 201},
		{"one over", `{"name":"ok"}` + strings.Repeat(" ", (1<<20)-len(`{"name":"ok"}`)+1), 413},
		{"malformed", `{"name":"dummy-secret-body",`, 400},
		{"second over", `{"name":"ok"} {"name":"` + strings.Repeat("x", 1<<20) + `"}`, 413},
		{"second small", `{"name":"ok"} {}`, 400},
		{"trailing garbage", `{"name":"ok"} !dummy-secret-body`, 400},
	} {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/projects", strings.NewReader(c.body))
			req.Header.Set(web.ClientHeader, "test")
			rec := httptest.NewRecorder()
			newServer(t).ServeHTTP(rec, req)
			if rec.Code != c.want {
				t.Fatalf("want %d got %d: %s", c.want, rec.Code, rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), "dummy-secret-body") {
				t.Fatal("body secret leaked")
			}
		})
	}
}
