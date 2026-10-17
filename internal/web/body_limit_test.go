package web_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/indago/indago/internal/web"
)

func TestProjectOversizedJSONIs413WithoutSideEffect(t *testing.T) {
	h := newServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/projects", strings.NewReader(`{"name":"oversized","notes":"`+strings.Repeat("x", 1<<20)+`"}`))
	req.Header.Set(web.ClientHeader, "test")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("want 413, got %d: %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/projects", nil))
	var rows []any
	if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatal("oversize created a project")
	}
}
