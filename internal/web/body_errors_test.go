package web_test

import (
	"errors"
	"github.com/indago/indago/internal/web"
	"net/http/httptest"
	"strings"
	"testing"
)

type failingJSONBody struct{ read int }

func (b *failingJSONBody) Read(p []byte) (int, error) {
	b.read++
	return 0, errors.New("dummy-read-body-secret")
}
func (*failingJSONBody) Close() error { return nil }

func TestJSONReadErrorsAreSafe(t *testing.T) {
	body := &failingJSONBody{}
	req := httptest.NewRequest("POST", "/api/projects", nil)
	req.Body = body
	req.Header.Set(web.ClientHeader, "test")
	rec := httptest.NewRecorder()
	newServer(t).ServeHTTP(rec, req)
	if rec.Code != 400 || strings.Contains(rec.Body.String(), "dummy-read-body-secret") {
		t.Fatalf("unsafe read error: %d %s", rec.Code, rec.Body.String())
	}
	if body.read != 1 {
		t.Fatal("unexpected read attempts", body.read)
	}
}
