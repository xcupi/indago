package discovery_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/indago/indago/internal/discovery"
	"github.com/indago/indago/internal/domain"
)

func TestHandlerFormExtraction(t *testing.T) {
	tests := []struct {
		name, attrs, controls, action string
		method                        domain.HTTPMethod
		handler                       bool
	}{
		{"onsubmit", `onsubmit='jsonSubmit(this, event, "/my-account/change-email")'`, "", "/my-account/change-email", domain.MethodPOST, true},
		{"declared", `action="/real" onsubmit='go("/ignored")'`, "", "/real", domain.MethodGET, false},
		{"declared post", `action="/real" method="post" onsubmit='go("/ignored")'`, "", "/real", domain.MethodPOST, false},
		{"empty action", `action="  " onsubmit='go("/profile")'`, "", "/profile", domain.MethodPOST, true},
		{"last literal", `onsubmit='go("/first", "/last")'`, "", "/last", domain.MethodPOST, true},
		{"onclick", "", `<button onclick='go("/profile")'>Save</button>`, "/profile", domain.MethodPOST, true},
		{"input onclick", "", `<input type="submit" onclick='go("/profile")'>`, "/profile", domain.MethodPOST, true},
		{"non submit", "", `<button type="button" onclick='go("/ignored")'>Other</button>`, "", domain.MethodGET, false},
		{"onsubmit precedence", `onsubmit='return false'`, `<button onclick='go("/ignored")'>Save</button>`, "", domain.MethodGET, false},
	}
	for _, path := range []string{"https://evil.example/x", "//evil/x", "javascript:alert(1)", "relative/no-slash", "/white space", `/back\slash`, "/" + strings.Repeat("x", 512)} {
		tests = append(tests, struct {
			name, attrs, controls, action string
			method                        domain.HTTPMethod
			handler                       bool
		}{path, fmt.Sprintf(`onsubmit='go("%s")'`, path), "", "", domain.MethodGET, false})
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			forms := discovery.ExtractForms(`<form ` + tt.attrs + `><input type="email" name="email" value="me@example.test">` + tt.controls + `</form>`)
			if len(forms) != 1 {
				t.Fatalf("forms=%v", forms)
			}
			f := forms[0]
			if f.Action != tt.action || f.Method != tt.method {
				t.Fatalf("action=%q method=%s, want %q %s", f.Action, f.Method, tt.action, tt.method)
			}
			if f.ActionFromHandler != tt.handler {
				t.Fatalf("ActionFromHandler missing or wrong: %+v", f)
			}
			if len(f.Inputs) != 1 || f.Inputs[0].Name != "email" || f.Inputs[0].Value != "me@example.test" {
				t.Fatalf("inputs changed: %+v", f.Inputs)
			}
		})
	}
}

func TestHandlerFormRegistration(t *testing.T) {
	for _, handler := range []string{`jsonSubmit(this, event, "/my-account/change-email")`, `go("https://evil.example/x")`, `go("//evil/x")`, `go("javascript:alert(1)")`, `go("relative/no-slash")`} {
		t.Run(handler, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/" {
					http.NotFound(w, r)
					return
				}
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprintf(w, `<form onsubmit='%s'><input name="email" value="me@example.test"></form>`, handler)
			}))
			defer srv.Close()
			cfg := discovery.DefaultConfig()
			cfg.MaxDepth = 0
			m, st, _ := newManagerFor(t, cfg, nil)
			id := domain.NewID()
			if _, err := m.Run(context.Background(), discovery.RunParams{ScanID: id, Scope: scopeFor(srv), SeedURLs: []string{srv.URL}}); err != nil {
				t.Fatal(err)
			}
			eps, err := st.Endpoints().ListByScan(context.Background(), id)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, ep := range eps {
				if ep.Method != domain.MethodPOST {
					continue
				}
				found = true
				if ep.URL != srv.URL+"/my-account/change-email" {
					t.Fatalf("unexpected POST: %+v", ep)
				}
				ps, err := st.Parameters().ListByEndpoint(context.Background(), ep.ID)
				if err != nil {
					t.Fatal(err)
				}
				var bodyParams []*domain.Parameter
				for _, p := range ps {
					if p.Location == domain.LocationForm {
						bodyParams = append(bodyParams, p)
					}
				}
				if len(bodyParams) != 1 || bodyParams[0].Name != "email" || bodyParams[0].Example != "me@example.test" {
					t.Fatalf("body parameters=%+v", ps)
				}
			}
			if found != strings.HasPrefix(handler, "jsonSubmit") {
				t.Fatalf("POST registered=%v, endpoints=%+v", found, eps)
			}
		})
	}
}
