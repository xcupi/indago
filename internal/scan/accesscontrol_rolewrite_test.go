package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/indago/indago/internal/accesscontrol"
	"github.com/indago/indago/internal/domain"
)

func TestRoleWriteJSONFallback(t *testing.T) {
	for _, tt := range []struct {
		name, path, encoding string
		elevate              bool
		budget, writes       int
		verdict              domain.Verdict
	}{
		{"json elevates", "/my-account/change-email", "json", true, 6, 2, domain.VerdictConfirmed},
		{"form elevates without retry", "/my-account/change-email", "form", true, 6, 1, domain.VerdictConfirmed},
		{"successful writes and changed profile do not elevate", "/my-account/change-email", "json", false, 6, 6, domain.VerdictRejected},
		{"budget prevents fallback", "/my-account/change-email", "json", true, 1, 1, domain.VerdictRejected},
		{"non profile skipped", "/orders", "json", true, 6, 0, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			env := newScanEnv(t)
			var mu sync.Mutex
			role := 1
			elevated := false
			var encodings, fields []string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				switch {
				case r.URL.Path == tt.path && r.Method == "POST":
					enc := "form"
					field := ""
					if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
						enc = "json"
						var body map[string]any
						if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
							t.Error(err)
							return
						}
						if body["email"] != "me@example.test" {
							t.Errorf("identity not preserved: %v", body)
						}
						for k := range body {
							if accesscontrol.RoleName(k) {
								field = k
							}
						}
						if field == "role" && body[field] != "admin" {
							t.Errorf("role must be a JSON string: %v", body)
						}
						if field == "is_admin" && body[field] != true {
							t.Errorf("is_admin must be a JSON boolean: %v", body)
						}
						if field == "roleid" && body[field] != float64(2) {
							t.Errorf("roleid must be JSON number 2: %v", body)
						}
					} else {
						if err := r.ParseForm(); err != nil {
							t.Error(err)
						}
						for k := range r.PostForm {
							if accesscontrol.RoleName(k) {
								field = k
							}
						}
					}
					encodings = append(encodings, enc)
					fields = append(fields, field)
					if enc == tt.encoding && field == "roleid" {
						role = 2
						elevated = tt.elevate
					}
					fmt.Fprint(w, `{"ok":true}`)
				case r.URL.Path == "/my-account":
					w.Header().Set("Content-Type", "application/json")
					fmt.Fprintf(w, `{"username":"wiener","email":"me@example.test","roleid":%d}`, role)
				case r.URL.Path == "/admin":
					if elevated {
						fmt.Fprint(w, acAdminPanel)
					} else {
						w.WriteHeader(403)
						fmt.Fprint(w, "forbidden")
					}
				default:
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()
			ep := acEndpoint(t, env, srv.URL+tt.path, domain.SourceForm, domain.MethodPOST)
			p := &domain.Parameter{ID: domain.NewID(), EndpointID: ep.ID, Name: "email", Location: domain.LocationForm, Example: "me@example.test", Source: domain.SourceForm}
			if err := env.st.Parameters().Create(context.Background(), p); err != nil {
				t.Fatal(err)
			}
			acEndpoint(t, env, srv.URL+"/admin", domain.SourceCrawler, domain.MethodGET)
			ex := newAccessControlExecutor(env.st, acSessionEngine(t), env.ev, ExecutorConfig{AllowStateChanging: true}, execLog(), nil, true)
			ex.budget.writeLeft = tt.budget
			job := acJob(env, ep)
			job.Payload = accessControlModePayload(accessModeRoleField)
			if err := ex.Handle(context.Background(), job); err != nil {
				t.Fatal(err)
			}
			d := acDetail(t, acCases(t, env)[0])
			if d.Verdict != tt.verdict {
				t.Errorf("verdict=%s want %s: %s", d.Verdict, tt.verdict, d.Reason)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(encodings) != tt.writes || len(encodings) > accesscontrol.MaxWritesPerScan {
				t.Errorf("writes=%v want %d", encodings, tt.writes)
			}
			if len(encodings) == 2 && (strings.Join(encodings, ",") != "form,json" || fields[0] != fields[1]) {
				t.Errorf("must retry same field once: %v %v", encodings, fields)
			}
			if remaining := ex.budget.writeRemaining(); remaining != tt.budget-len(encodings) {
				t.Errorf("write budget remaining=%d, writes=%d starting=%d", remaining, len(encodings), tt.budget)
			}
			if tt.writes == 6 {
				for i := 0; i < len(encodings); i += 2 {
					if encodings[i] != "form" || encodings[i+1] != "json" || fields[i] != fields[i+1] {
						t.Errorf("unexpected encoding loop: %v %v", encodings, fields)
					}
				}
			}
			if tt.verdict == domain.VerdictConfirmed {
				if d.BeforeStatus != 403 || d.AfterStatus != 200 {
					t.Errorf("missing denied-to-granted evidence: %+v", d)
				}
				findings := acFindings(t, env)
				if len(findings) != 1 {
					t.Fatalf("findings=%d want 1", len(findings))
				}
				var sawForm, sawJSON bool
				for _, id := range findings[0].EvidenceIDs {
					row, blob := env.evidenceBlob(id)
					if row.Kind == domain.EvidenceRequest {
						sawForm = sawForm || strings.Contains(blob, "application/x-www-form-urlencoded")
						sawJSON = sawJSON || strings.Contains(blob, "application/json")
					}
				}
				if !sawForm || (tt.writes == 2 && !sawJSON) {
					t.Errorf("finding lost write evidence: form=%v json=%v", sawForm, sawJSON)
				}
			}
			if tt.budget == 1 && !strings.Contains(d.Reason, "budget") {
				t.Errorf("missing budget explanation: %s", d.Reason)
			}
			if tt.writes == 0 && !d.Skipped {
				t.Error("non-profile endpoint not skipped")
			}
		})
	}
}
