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
)

// IsValid reports whether the job type is a known value.
func (t JobType) IsValid() bool {
	switch t {
	case JobDiscovery, JobTest, JobVerify:
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
)

// IsValid reports whether the test-case status is a known value.
func (s TestCaseStatus) IsValid() bool {
	switch s {
	case TestCasePending, TestCaseRunning, TestCaseCompleted, TestCaseFailed, TestCaseSkipped:
		return true
	default:
		return false
	}
}
