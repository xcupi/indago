package domain

// This file defines the lifecycle state enums and their legal transitions.
// The transition tables are the single source of truth; store and orchestration
// layers must validate transitions through the CanTransitionTo helpers so that
// illegal states cannot be persisted.
//
// Diagrams for these machines live in docs/state-machines.md.

// ---------------------------------------------------------------------------
// Scan lifecycle
// ---------------------------------------------------------------------------

// ScanState is the lifecycle state of a Scan.
type ScanState string

const (
	ScanCreated      ScanState = "created"
	ScanRunning      ScanState = "running"
	ScanPaused       ScanState = "paused"
	ScanAwaitingAuth ScanState = "awaiting_auth" // session expired; re-auth needed
	ScanCanceling    ScanState = "canceling"
	ScanCanceled     ScanState = "canceled"
	ScanCompleted    ScanState = "completed"
	ScanFailed       ScanState = "failed"
)

// IsValid reports whether the scan state is a known value.
func (s ScanState) IsValid() bool {
	_, ok := scanTransitions[s]
	return ok
}

// IsTerminal reports whether the scan state is final.
func (s ScanState) IsTerminal() bool {
	switch s {
	case ScanCanceled, ScanCompleted, ScanFailed:
		return true
	default:
		return false
	}
}

var scanTransitions = map[ScanState]map[ScanState]bool{
	ScanCreated: {
		ScanRunning:  true,
		ScanCanceled: true,
		ScanFailed:   true,
	},
	ScanRunning: {
		ScanPaused:       true,
		ScanAwaitingAuth: true,
		ScanCanceling:    true,
		ScanCompleted:    true,
		ScanFailed:       true,
	},
	ScanPaused: {
		ScanRunning:   true,
		ScanCanceling: true,
		ScanCanceled:  true,
		ScanFailed:    true,
	},
	ScanAwaitingAuth: {
		ScanRunning:   true, // after successful re-authentication
		ScanPaused:    true,
		ScanCanceling: true,
		ScanCanceled:  true,
		ScanFailed:    true,
	},
	ScanCanceling: {
		ScanCanceled: true,
		ScanFailed:   true,
	},
	// Terminal states have no outgoing transitions.
	ScanCanceled:  {},
	ScanCompleted: {},
	ScanFailed:    {},
}

// CanTransitionTo reports whether moving to next is a legal scan transition.
func (s ScanState) CanTransitionTo(next ScanState) bool {
	return scanTransitions[s][next]
}

// ---------------------------------------------------------------------------
// Discovery state (per scan)
// ---------------------------------------------------------------------------

// DiscoveryState is the persisted state of a scan's discovery run. Discovery
// runs concurrently with testing; a scan cannot complete until discovery has
// finished (see docs/scan-orchestration.md).
type DiscoveryState string

const (
	DiscoveryPending  DiscoveryState = "pending"  // not started yet
	DiscoveryRunning  DiscoveryState = "running"  // sources are active (or were, at last persist)
	DiscoveryComplete DiscoveryState = "complete" // every source finished
	DiscoveryCanceled DiscoveryState = "canceled" // scan canceled mid-discovery
)

// IsValid reports whether the discovery state is a known value.
func (s DiscoveryState) IsValid() bool {
	switch s {
	case DiscoveryPending, DiscoveryRunning, DiscoveryComplete, DiscoveryCanceled:
		return true
	default:
		return false
	}
}

// ---------------------------------------------------------------------------
// Job (TestJob) lifecycle
// ---------------------------------------------------------------------------

// JobState is the lifecycle state of a TestJob in the persistent queue.
type JobState string

const (
	JobQueued    JobState = "queued"
	JobLeased    JobState = "leased" // claimed by a worker, not yet started
	JobRunning   JobState = "running"
	JobSucceeded JobState = "succeeded"
	JobFailed    JobState = "failed" // transient failure, may be retried
	JobCanceled  JobState = "canceled"
	JobDead      JobState = "dead" // exhausted retries / permanently failed
)

// IsValid reports whether the job state is a known value.
func (s JobState) IsValid() bool {
	_, ok := jobTransitions[s]
	return ok
}

// IsTerminal reports whether the job state is final.
func (s JobState) IsTerminal() bool {
	switch s {
	case JobSucceeded, JobCanceled, JobDead:
		return true
	default:
		return false
	}
}

// IsActive reports whether the job is claimed by a worker (leased or running).
// Active jobs are the ones reclaimed by restart/crash recovery.
func (s JobState) IsActive() bool {
	return s == JobLeased || s == JobRunning
}

var jobTransitions = map[JobState]map[JobState]bool{
	JobQueued: {
		JobLeased:   true,
		JobCanceled: true,
	},
	JobLeased: {
		JobRunning:  true,
		JobQueued:   true, // lease expired / worker crash → requeue (recovery)
		JobCanceled: true,
	},
	JobRunning: {
		JobSucceeded: true,
		JobFailed:    true,
		JobQueued:    true, // crash recovery requeues an in-flight job
		JobCanceled:  true,
	},
	JobFailed: {
		JobQueued: true, // retry
		JobDead:   true, // retries exhausted
	},
	// Terminal states have no outgoing transitions.
	JobSucceeded: {},
	JobCanceled:  {},
	JobDead:      {},
}

// CanTransitionTo reports whether moving to next is a legal job transition.
func (s JobState) CanTransitionTo(next JobState) bool {
	return jobTransitions[s][next]
}

// ---------------------------------------------------------------------------
// Auth session lifecycle
// ---------------------------------------------------------------------------

// SessionState is the lifecycle state of an authenticated Session. One session
// is established per scan and reused; on expiry the scan moves to AwaitingAuth
// rather than silently re-authenticating.
type SessionState string

const (
	SessionNone           SessionState = "none"
	SessionAuthenticating SessionState = "authenticating"
	SessionActive         SessionState = "active"
	SessionExpired        SessionState = "expired"
	SessionFailed         SessionState = "failed"
)

// IsValid reports whether the session state is a known value.
func (s SessionState) IsValid() bool {
	_, ok := sessionTransitions[s]
	return ok
}

var sessionTransitions = map[SessionState]map[SessionState]bool{
	SessionNone: {
		SessionAuthenticating: true,
		SessionActive:         true, // existing/imported session material
	},
	SessionAuthenticating: {
		SessionActive: true,
		SessionFailed: true,
	},
	SessionActive: {
		SessionExpired: true,
		SessionFailed:  true,
	},
	SessionExpired: {
		SessionAuthenticating: true, // re-auth
		SessionActive:         true, // refreshed
		SessionFailed:         true,
	},
	SessionFailed: {
		SessionAuthenticating: true, // retry auth
	},
}

// CanTransitionTo reports whether moving to next is a legal session transition.
func (s SessionState) CanTransitionTo(next SessionState) bool {
	return sessionTransitions[s][next]
}

// ---------------------------------------------------------------------------
// Job / test-case classification enums (non-lifecycle)
// ---------------------------------------------------------------------------

// JobType distinguishes the kind of work a TestJob represents. The queue is
// generic; the scan controller routes each type to its handler.
type JobType string

const (
	JobDiscovery JobType = "discovery" // expand the endpoint/parameter registry
	JobTest      JobType = "test"      // exercise an injection point
	JobVerify    JobType = "verify"    // browser-verify a candidate finding
	// JobDOMXSS probes one discovered Endpoint for the DOM-XSS engine's
	// first slice (location.hash -> innerHTML/outerHTML/document.write —
	// see internal/scan/domxss.go and docs/dom-xss.md). Dispatched to the
	// SAME browser worker group as JobVerify: it needs a real browser,
	// never the raw HTTP engine (the whole point of this engine is that
	// location.hash never reaches the server at all).
	JobDOMXSS JobType = "dom_xss"
	// JobIDOR runs the IDOR engine's object-identifier differential for one
	// injection point (see internal/idor and internal/scan/idor.go). It uses
	// the raw HTTP engine (GET/HEAD reads only) and is dispatched to the
	// HTTP worker group.
	JobIDOR JobType = "idor"
	// JobDisclosure runs the information-disclosure classification for one
	// endpoint (cases 38/39): one GET, no mutation.
	JobDisclosure JobType = "disclosure"
	// JobAccessControl probes one discovered admin-like path for missing
	// function-level authorization: it sends an anonymous GET and, when the
	// scan has a session, the same GET as the authenticated non-admin, then
	// decides from the response bodies (see internal/accesscontrol and
	// internal/scan/accesscontrol.go). Raw HTTP, GET only.
	JobAccessControl JobType = "access_control"
	// JobCommandInjection probes one injection point for OS command injection.
	// It sends harmless echo markers through query/form/JSON/path parameters
	// and requires two independent markers before confirming.
	JobCommandInjection JobType = "command_injection"
	// JobSSTI probes one injection point for server-side template injection.
	// It sends only arithmetic template expressions and requires two
	// independent computed results before confirming.
	JobSSTI JobType = "ssti"
	// JobSQLi probes one injection point for SQL injection. It sends only
	// harmless quote-breaking and boolean-differential probes and requires
	// two independent signals (a new database error signature or a stable
	// true/false divergence) before confirming.
	JobSQLi JobType = "sqli"
	// JobXXE probes one XML request body for external-entity processing.
	JobXXE JobType = "xxe"
	// JobSSRF probes one injection point for server-side request forgery using
	// non-destructive OAST/canary URLs.
	JobSSRF JobType = "ssrf"
	// JobCORS probes one endpoint for cross-origin resource sharing misconfigurations.
	JobCORS JobType = "cors"
	// JobOpenRedirect probes one endpoint for server-side open redirect vulnerabilities.
	JobOpenRedirect JobType = "open_redirect"
	// JobGraphQL probes one endpoint for safe GraphQL misconfigurations.
	JobGraphQL JobType = "graphql"
	// JobPathTraversal probes one injection point for path traversal / local
	// file inclusion. It is strictly READ-ONLY: a bounded payload set asks the
	// endpoint to read /etc/passwd or windows\win.ini, and a finding is
	// confirmed only when the response carries the file's own multi-token
	// content, which an untouched baseline and a nonexistent-path control did
	// NOT produce. See internal/scan/pathtraversal.go.
	JobPathTraversal JobType = "path_traversal"
	// JobSecurityHeaders inspects ONE origin's HTTP response security headers
	// and Set-Cookie attributes with a single read-only GET. Findings are
	// deduplicated per origin and header/cookie name, never per URL. See
	// internal/scan/securityheaders.go.
	JobSecurityHeaders JobType = "security_headers"
	// JobHostHeader inspects ONE origin for host header injection with a
	// bounded read-only GET baseline plus control requests carrying a canary
	// Host / X-Forwarded-Host value. Findings are deduplicated per origin,
	// never per URL. See internal/scan/hostheader.go.
	JobHostHeader JobType = "host_header"
	// JobJWT inspects ONE origin's Bearer JWT: the token's own claims/header
	// hygiene (offline) plus a bounded read-only GET differential that checks
	// the server actually rejects a modified signature and an unverified
	// "none" algorithm. Findings are deduplicated per origin/issuer, never per
	// URL. See internal/scan/jwtcheck.go.
	JobJWT JobType = "jwt_validation"
	// JobNoSQLi probes one GET/query injection point for NoSQL query-operator
	// injection. It sends only read-only selection operators ($ne, $gt) and
	// array-shaped values, and confirms only when a new database error
	// signature or an operator-versus-control differential independently
	// agrees. See internal/scan/nosqli.go.
	JobNoSQLi JobType = "nosqli"
	// JobMethodTLS inspects ONE origin for HTTP method exposure and TLS
	// transport hygiene: read-only OPTIONS and TRACE probes (TRACE is only
	// reported when the server echoes the request back; OPTIONS only when it
	// advertises write methods to an anonymous non-API page) plus the TLS
	// state of the scan's own handshake. Findings are deduplicated per
	// origin. See internal/scan/methodtls.go.
	JobMethodTLS JobType = "method_tls_hygiene"
	// JobWebSocket inspects ONE discovered, WebSocket-shaped endpoint for
	// handshake and Origin-validation weaknesses: a bounded, strictly
	// read-only HTTP Upgrade handshake carrying an untrusted Origin (reported
	// only when the server answers 101 Switching Protocols) plus an anonymous
	// handshake that exposes an unauthenticated or plaintext upgrade during an
	// authenticated scan. No WebSocket frame is ever sent. Findings are
	// deduplicated per origin and path. See internal/scan/websocket.go.
	JobWebSocket JobType = "websocket_security"
	// JobCSRF inspects ONE state-changing endpoint for Cross-Site Request
	// Forgery protection (anti-CSRF token, SameSite cookie posture, and
	// cross-origin Origin/Referer validation). See internal/scan/csrf.go.
	JobCSRF JobType = "csrf"
	// JobPrototypePollution inspects ONE GET HTML page in Chromium for
	// client-side Object.prototype pollution via bounded query/hash vectors.
	// See internal/scan/prototype_pollution.go.
	JobPrototypePollution JobType = "prototype_pollution"
	// JobStoredXSS submits a bounded benign marker to ONE state-changing
	// endpoint and verifies whether it executes on visited HTML pages in
	// Chromium. See internal/scan/storedxss.go.
	JobStoredXSS JobType = "stored_xss"
	// JobCachePoisoning probes ONE origin for unkeyed header cache poisoning
	// using a unique cache-buster query parameter. See
	// internal/scan/cache_poisoning.go.
	JobCachePoisoning JobType = "cache_poisoning"
	// JobFileUpload inspects ONE upload-shaped endpoint with bounded benign
	// extension/MIME probes when AllowStateChanging is enabled. See
	// internal/scan/fileupload.go.
	JobFileUpload JobType = "file_upload"
)

// IsValid reports whether the job type is a known value.
func (t JobType) IsValid() bool {
	switch t {
	case JobDiscovery, JobTest, JobVerify, JobDOMXSS, JobIDOR, JobAccessControl, JobDisclosure, JobCommandInjection, JobSSTI, JobSQLi, JobXXE, JobSSRF, JobCORS, JobOpenRedirect, JobGraphQL, JobPathTraversal, JobSecurityHeaders, JobHostHeader, JobJWT, JobNoSQLi, JobMethodTLS, JobWebSocket, JobCSRF, JobPrototypePollution, JobStoredXSS, JobCachePoisoning, JobFileUpload:
		return true
	default:
		return false
	}
}

// TestCaseStatus is the lifecycle of a single TestCase.
type TestCaseStatus string

const (
	TestCasePending   TestCaseStatus = "pending"
	TestCaseRunning   TestCaseStatus = "running"
	TestCaseCompleted TestCaseStatus = "completed"
	TestCaseFailed    TestCaseStatus = "failed"
	TestCaseSkipped   TestCaseStatus = "skipped"
	TestCaseCancelled TestCaseStatus = "cancelled"
)

// IsValid reports whether the test-case status is a known value.
func (s TestCaseStatus) IsValid() bool {
	switch s {
	case TestCasePending, TestCaseRunning, TestCaseCompleted, TestCaseFailed, TestCaseSkipped, TestCaseCancelled:
		return true
	default:
		return false
	}
}
