package domain

// This file holds the *value* enums (classification, not lifecycle). Lifecycle
// state enums and their transition rules live in state.go.

// VulnClass identifies a vulnerability class. The domain is generic across
// classes; Phase 1 implements only ReflectedXSS.
type VulnClass string

const (
	VulnReflectedXSS VulnClass = "reflected_xss"
	VulnStoredXSS    VulnClass = "stored_xss" // designed-for, not implemented
	VulnDOMXSS       VulnClass = "dom_xss"    // designed-for, not implemented
)

// IsValid reports whether the vulnerability class is a known value.
func (v VulnClass) IsValid() bool {
	switch v {
	case VulnReflectedXSS, VulnStoredXSS, VulnDOMXSS:
		return true
	default:
		return false
	}
}

// Severity is the impact rating of a finding.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// IsValid reports whether the severity is a known value.
func (s Severity) IsValid() bool {
	switch s {
	case SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	default:
		return false
	}
}

// Confidence expresses how certain the engine is about a result. It is distinct
// from Verdict: Verdict is the decision, Confidence is the strength behind it.
type Confidence string

const (
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)

// IsValid reports whether the confidence is a known value.
func (c Confidence) IsValid() bool {
	switch c {
	case ConfidenceLow, ConfidenceMedium, ConfidenceHigh:
		return true
	default:
		return false
	}
}

// HTTPMethod is an HTTP request method.
type HTTPMethod string

const (
	MethodGET     HTTPMethod = "GET"
	MethodPOST    HTTPMethod = "POST"
	MethodPUT     HTTPMethod = "PUT"
	MethodPATCH   HTTPMethod = "PATCH"
	MethodDELETE  HTTPMethod = "DELETE"
	MethodHEAD    HTTPMethod = "HEAD"
	MethodOPTIONS HTTPMethod = "OPTIONS"
)

// IsValid reports whether the method is a known value.
func (m HTTPMethod) IsValid() bool {
	switch m {
	case MethodGET, MethodPOST, MethodPUT, MethodPATCH, MethodDELETE, MethodHEAD, MethodOPTIONS:
		return true
	default:
		return false
	}
}

// ParamLocation is where a parameter (injection point) lives in a request.
// Phase 1 requires at minimum query, form, and JSON body parameters.
type ParamLocation string

const (
	LocationQuery  ParamLocation = "query"  // GET / query-string parameter
	LocationForm   ParamLocation = "form"   // application/x-www-form-urlencoded
	LocationJSON   ParamLocation = "json"   // JSON body field
	LocationHeader ParamLocation = "header" // request header
	LocationCookie ParamLocation = "cookie" // cookie value
	LocationPath   ParamLocation = "path"   // path segment
)

// IsValid reports whether the location is a known value.
func (l ParamLocation) IsValid() bool {
	switch l {
	case LocationQuery, LocationForm, LocationJSON, LocationHeader, LocationCookie, LocationPath:
		return true
	default:
		return false
	}
}

// DiscoverySource records how an endpoint or parameter was discovered. Useful
// for provenance and for prioritization.
type DiscoverySource string

const (
	SourceUserProvided     DiscoverySource = "user_provided"
	SourceCrawler          DiscoverySource = "crawler"
	SourceForm             DiscoverySource = "form"
	SourceBrowserNetwork   DiscoverySource = "browser_network"
	SourceSitemap          DiscoverySource = "sitemap"
	SourceRobots           DiscoverySource = "robots"
	SourceContentDiscovery DiscoverySource = "content_discovery"
	SourceParamDiscovery   DiscoverySource = "param_discovery"
)

// IsValid reports whether the source is a known value.
func (d DiscoverySource) IsValid() bool {
	switch d {
	case SourceUserProvided, SourceCrawler, SourceForm, SourceBrowserNetwork,
		SourceSitemap, SourceRobots, SourceContentDiscovery, SourceParamDiscovery:
		return true
	default:
		return false
	}
}

// EvidenceKind classifies a stored evidence artifact.
type EvidenceKind string

const (
	EvidenceRequest    EvidenceKind = "request"
	EvidenceResponse   EvidenceKind = "response"
	EvidenceContext    EvidenceKind = "context"
	EvidencePayload    EvidenceKind = "payload"
	EvidenceScreenshot EvidenceKind = "screenshot"
	EvidenceBrowserLog EvidenceKind = "browser_log"
	EvidenceHAR        EvidenceKind = "har"
	EvidenceOther      EvidenceKind = "other"
)

// IsValid reports whether the evidence kind is a known value.
func (e EvidenceKind) IsValid() bool {
	switch e {
	case EvidenceRequest, EvidenceResponse, EvidenceContext, EvidencePayload,
		EvidenceScreenshot, EvidenceBrowserLog, EvidenceHAR, EvidenceOther:
		return true
	default:
		return false
	}
}

// Verdict is the decision about a candidate finding. "Reflection alone is NOT a
// confirmed XSS" — a reflection yields at most VerdictPending until browser
// verification produces Confirmed / Rejected / Inconclusive.
type Verdict string

const (
	VerdictPending      Verdict = "pending"
	VerdictConfirmed    Verdict = "confirmed"
	VerdictRejected     Verdict = "rejected"
	VerdictInconclusive Verdict = "inconclusive"
)

// IsValid reports whether the verdict is a known value.
func (v Verdict) IsValid() bool {
	switch v {
	case VerdictPending, VerdictConfirmed, VerdictRejected, VerdictInconclusive:
		return true
	default:
		return false
	}
}

// IsTerminal reports whether the verdict is a final decision.
func (v Verdict) IsTerminal() bool {
	return v == VerdictConfirmed || v == VerdictRejected
}
