package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthLoginRequiresProject(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.Write([]byte(`{}`)) }))
	defer srv.Close()
	c := newCLI(srv.URL, &bytes.Buffer{})
	if err := c.authLogin([]string{"-login-url", "http://127.0.0.1/login"}); err == nil || calls != 0 {
		t.Fatalf("missing project must fail locally, calls=%d err=%v", calls, err)
	}
}

func TestAuthLoginForwardsProject(t *testing.T) {
	var got map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&got)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	c := newCLI(srv.URL, &bytes.Buffer{})
	if err := c.authLogin([]string{"-project", "project-id", "-login-url", "http://127.0.0.1/login"}); err != nil {
		t.Fatal(err)
	}
	if got["project_id"] != "project-id" {
		t.Fatalf("project context lost: %v", got)
	}
}
