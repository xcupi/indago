package assessment

import (
	"bytes"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
)

func TestAutomatedFindingAssessment(t *testing.T) {
	cases := []struct {
		name   string
		class  domain.VulnClass
		engine string
		detail string
		want   string
	}{
		{"CORS error response", domain.VulnCORS, "cors", `{"http_status":400}`, "cors_response_policy"},
		{"CORS wildcard and credentials", domain.VulnCORS, "cors", `{"signal":"wildcard_with_credentials"}`, "cors_response_policy"},
		{"WebSocket status only", domain.VulnWebSocket, "websocket_security", `{"status":101}`, "websocket_transport_signal"},
		{"WebSocket handshake only", domain.VulnWebSocket, "websocket_security", `{"accept_valid":true}`, "websocket_transport_signal"},
		{"GraphQL introspection", domain.VulnGraphQL, "graphql", `{"name":"introspection"}`, "graphql_feature_observed"},
		{"GraphQL batching", domain.VulnGraphQL, "graphql", `{"name":"batching"}`, "graphql_feature_observed"},
		{"GraphQL validation suggestion", domain.VulnGraphQL, "graphql", `{"name":"verbose_errors"}`, "graphql_feature_observed"},
		{"GraphQL GET query", domain.VulnGraphQL, "graphql", `{"name":"get_queries"}`, "graphql_feature_observed"},
		{"File upload empty success", domain.VulnFileUpload, "file_upload", `{"http_status":200,"body_length":0}`, "upload_http_response"},
		{"File upload generic JSON", domain.VulnFileUpload, "file_upload", `{"http_status":200}`, "upload_http_response"},
		{"SSRF response differential", domain.VulnSSRF, "ssrf", `{"confirm_method":"differential"}`, "ssrf_response_only"},
		{"SSRF missing callback", domain.VulnSSRF, "ssrf", `{"confirm_method":"oast","attempts":[{"callback":false}]}`, "ssrf_response_only"},
		{"SSRF archived callback", domain.VulnSSRF, "ssrf", `{"confirm_method":"oast","attempts":[{"callback":true}]}`, ""},
		{"SQL error only", domain.VulnSQLi, "sqli", `{"confirm_method":"error","error_signals":2}`, "sql_signal_insufficient"},
		{"SQL two boolean controls", domain.VulnSQLi, "sqli", `{"confirm_method":"boolean","boolean_signals":2}`, ""},
		{"SQL differential label only", domain.VulnSQLi, "sqli", `{"confirm_method":"boolean"}`, "sql_signal_insufficient"},
		{"Legacy malformed SQL record", domain.VulnSQLi, "sqli", "{", "sql_signal_insufficient"},
		{"NoSQL error only", domain.VulnNoSQLi, "nosqli", `{"confirm_method":"error","error_signals":2}`, "nosql_signal_insufficient"},
		{"NoSQL mixed evidence", domain.VulnNoSQLi, "nosqli", `{"confirm_method":"error_differential","error_signals":1,"differential_signals":1,"control_judgeable":true}`, ""},
		{"NoSQL unusable control", domain.VulnNoSQLi, "nosqli", `{"confirm_method":"differential","differential_signals":2}`, "nosql_signal_insufficient"},
		{"Header observation", domain.VulnSecurityHeaders, "security_headers", `{}`, ConfigurationObserved},
		{"Cookie observation", domain.VulnCookiePolicy, "security_headers", `{}`, ConfigurationObserved},
		{"HTTP method observation", domain.VulnHTTPMethods, "method_tls_hygiene", `{}`, ConfigurationObserved},
		{"TLS observation", domain.VulnTLSConfig, "method_tls_hygiene", `{}`, ConfigurationObserved},
		{"Manual review", domain.VulnCORS, "manual_review", `{}`, ""},
		{"Unrelated class", domain.VulnJWT, "jwt", `{}`, ""},
	}
	now := time.Now()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := &domain.Finding{VulnClass: tc.class, Verdict: domain.VerdictConfirmed,
				Severity: domain.SeverityHigh, Confidence: domain.ConfidenceHigh, Summary: "engine summary",
				EvidenceIDs: []domain.ID{"stored-evidence"}, Detail: []byte(tc.detail),
				Provenance: domain.Provenance{Engine: tc.engine, VerifiedAt: &now}}
			got, changed := Finding(in)
			if !changed && got == in && tc.want == "" {
				return
			}
			if tc.want == "" || !changed || got.Provenance.Assessment != tc.want ||
				got.Verdict != domain.VerdictInconclusive || got.Severity != domain.SeverityInfo ||
				got.Confidence != domain.ConfidenceLow || got.Provenance.VerifiedAt != nil || got.Summary == in.Summary {
				t.Fatalf("assessment = %+v, want %q", got, tc.want)
			}
			if !bytes.Equal(got.Detail, in.Detail) || len(got.EvidenceIDs) != 1 || got.EvidenceIDs[0] != "stored-evidence" ||
				in.Verdict != domain.VerdictConfirmed || in.Provenance.VerifiedAt == nil {
				t.Fatal("assessment modified evidence or its input")
			}
			got.Severity, got.Summary = domain.SeverityHigh, "updated engine summary"
			if updated, _ := Finding(got); updated.Severity != domain.SeverityInfo || updated.Summary == got.Summary {
				t.Fatal("correlation update overwrote the finding assessment")
			}
		})
	}
}
