// Package assessment qualifies automated findings from their recorded signals.
package assessment

import (
	"encoding/json"

	"github.com/indago/indago/internal/domain"
)

const ConfigurationObserved = "configuration_observed"

// Finding returns a downgraded copy when an automated finding's recorded
// method establishes an observation rather than the reported security impact.
// Manual decisions and evidence are preserved. The original engine detail
// remains available as telemetry.
func Finding(f *domain.Finding) (*domain.Finding, bool) {
	if f.Verdict != domain.VerdictConfirmed && (f.Verdict != domain.VerdictInconclusive || f.Provenance.Assessment == "") {
		return f, false
	}
	code, summary := limitation(f)
	if code == "" {
		return f, false
	}
	reviewed := *f
	reviewed.Verdict = domain.VerdictInconclusive
	reviewed.Severity = domain.SeverityInfo
	reviewed.Confidence = domain.ConfidenceLow
	reviewed.Summary = summary
	reviewed.Provenance.VerifiedAt = nil
	reviewed.Provenance.Assessment = code
	return &reviewed, true
}

func limitation(f *domain.Finding) (code, summary string) {
	engine := f.Provenance.Engine
	switch {
	case f.VulnClass == domain.VulnCORS && engine == "cors":
		return "cors_response_policy", "The HTTP response recorded a CORS policy signal. The stored evidence does not establish browser access to protected content."
	case f.VulnClass == domain.VulnWebSocket && engine == "websocket_security":
		return "websocket_transport_signal", "The engine recorded a WebSocket transport or handshake signal. The stored evidence does not establish access to protected messages or actions."
	case f.VulnClass == domain.VulnGraphQL && engine == "graphql":
		return "graphql_feature_observed", graphQLObservation(f.Detail)
	case f.VulnClass == domain.VulnFileUpload && engine == "file_upload":
		return "upload_http_response", "The endpoint returned an upload response. The stored evidence does not establish how an uploaded object was accepted or handled."
	case f.VulnClass == domain.VulnSSRF && engine == "ssrf":
		record := readConfirmation(f.Detail)
		if record.Method != "oast" || len(f.EvidenceIDs) == 0 || !record.hasCallback() {
			return "ssrf_response_only", "The endpoint response changed. The stored evidence does not independently establish an outbound request from the server."
		}
	case f.VulnClass == domain.VulnSQLi && engine == "sqli":
		if !readConfirmation(f.Detail).sqlDifferential() {
			return "sql_signal_insufficient", "The stored database signals do not establish altered query behavior."
		}
	case f.VulnClass == domain.VulnNoSQLi && engine == "nosqli":
		if !readConfirmation(f.Detail).noSQLDifferential() {
			return "nosql_signal_insufficient", "The stored database signals do not establish altered query behavior."
		}
	case (f.VulnClass == domain.VulnSecurityHeaders || f.VulnClass == domain.VulnCookiePolicy) && engine == "security_headers":
		return ConfigurationObserved, "The HTTP response shows a header or cookie configuration observation. Application impact was not established."
	case (f.VulnClass == domain.VulnHTTPMethods || f.VulnClass == domain.VulnTLSConfig) && engine == "method_tls_hygiene":
		return ConfigurationObserved, "The engine observed HTTP method or TLS configuration. The stored evidence does not establish application-level impact."
	}
	return "", ""
}

type confirmationRecord struct {
	Method              string `json:"confirm_method"`
	ErrorSignals        int    `json:"error_signals"`
	BooleanSignals      int    `json:"boolean_signals"`
	TimingSignals       int    `json:"timing_signals"`
	DifferentialSignals int    `json:"differential_signals"`
	ControlJudgeable    bool   `json:"control_judgeable"`
	Attempts            []struct {
		Callback bool `json:"callback"`
	} `json:"attempts"`
}

func readConfirmation(detail []byte) confirmationRecord {
	var record confirmationRecord
	if json.Unmarshal(detail, &record) != nil {
		return confirmationRecord{}
	}
	return record
}

func (r confirmationRecord) hasCallback() bool {
	for _, a := range r.Attempts {
		if a.Callback {
			return true
		}
	}
	return false
}

func (r confirmationRecord) sqlDifferential() bool {
	switch r.Method {
	case "error_boolean":
		return r.ErrorSignals >= 1 && r.BooleanSignals >= 1
	case "boolean":
		return r.BooleanSignals >= 2
	case "error_timing":
		return r.ErrorSignals >= 1 && r.TimingSignals >= 1
	case "boolean_timing":
		return r.BooleanSignals >= 1 && r.TimingSignals >= 1
	case "timing":
		return r.TimingSignals >= 1
	default:
		return false
	}
}

func (r confirmationRecord) noSQLDifferential() bool {
	if !r.ControlJudgeable {
		return false
	}
	switch r.Method {
	case "error_differential":
		return r.ErrorSignals >= 1 && r.DifferentialSignals >= 1
	case "differential":
		return r.DifferentialSignals >= 2
	default:
		return false
	}
}

func graphQLObservation(detail []byte) string {
	var check struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(detail, &check) != nil {
		return "The engine recorded a GraphQL feature. Security impact needs review."
	}
	switch check.Name {
	case "introspection":
		return "GraphQL schema introspection was available. Unauthorized access to protected data was not established."
	case "batching":
		return "GraphQL accepted multiple operations or fields in one request. A rate-limit bypass was not established."
	case "verbose_errors":
		return "GraphQL returned a detailed validation error. Its security impact needs review."
	case "get_queries":
		return "GraphQL accepted a query through a simple HTTP request. An authenticated cross-site action was not established."
	default:
		return "The engine recorded a GraphQL feature. Security impact needs review."
	}
}
