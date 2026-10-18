package web_test

import (
	"github.com/indago/indago/internal/web"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProjectSecondJSONDocumentIs400(t *testing.T) {
	h := newServer(t)
	req := httptest.NewRequest("POST", "/api/projects", strings.NewReader(`{"name":"first"} {"name":"second"}`))
	req.Header.Set(web.ClientHeader, "test")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rec.Code)
	}
}

func TestProjectJSONPaddingOverLimitIs413(t *testing.T) {
	h := newServer(t)
	req := httptest.NewRequest("POST", "/api/projects", strings.NewReader(`{"name":"padded"}`+strings.Repeat(" ", 1<<20)))
	req.Header.Set(web.ClientHeader, "test")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("want 413, got %d", rec.Code)
	}
}
