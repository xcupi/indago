package domain

import "time"

// JobTarget references what a TestJob acts upon. Fields are optional and
// depend on the job Type (e.g. a discovery job may carry only a URL, a test job
// an InjectionPointID).
type JobTarget struct {
	URL              string `json:"url,omitempty"`
	EndpointID       ID     `json:"endpoint_id,omitempty"`
	InjectionPointID ID     `json:"injection_point_id,omitempty"`
}

// TestJob is a unit of work in the persistent queue. It is generic: Type
// distinguishes discovery, test, and verify work. The queue persists jobs so a
// scan can pause/resume/cancel and recover in-flight work after a restart.
type TestJob struct {
	ID       ID       `json:"id"`
	ScanID   ID       `json:"scan_id"`
	Type     JobType  `json:"type"`
	State    JobState `json:"state"`
	Priority int      `json:"priority"` // higher runs first

	Target JobTarget `json:"target"`

	// Payload is opaque, handler-specific parameters (JSON). The queue never
	// interprets it.
	Payload []byte `json:"payload,omitempty"`

	Attempts    int        `json:"attempts"`
	MaxAttempts int        `json:"max_attempts"`
	LeaseID     string     `json:"lease_id,omitempty"`
	LeasedUntil *time.Time `json:"leased_until,omitempty"`
	LastError   string     `json:"last_error,omitempty"`

	AvailableAt time.Time `json:"available_at"` // for backoff/scheduling
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// TestOutcome is how an executed test ended. It is about the EXECUTION of the
// request, not about any vulnerability verdict.
type TestOutcome string

const (
	// OutcomeSuccess: the request completed and a response was received. Any HTTP
	// status counts (a 404 or 500 is still a successful execution).
	OutcomeSuccess TestOutcome = "success"
	// OutcomeError: the request could not be completed (connection failure,
	// out-of-scope, invalid request, unresolvable job, ...).
	OutcomeError TestOutcome = "error"
	// OutcomeTimeout: the request exceeded its time limit.
	OutcomeTimeout TestOutcome = "timeout"
	// OutcomeCancelled: execution was interrupted by scan cancel or shutdown.
	OutcomeCancelled TestOutcome = "cancelled"
)

// IsValid reports whether the outcome is a known value.
func (o TestOutcome) IsValid() bool {
	switch o {
	case OutcomeSuccess, OutcomeError, OutcomeTimeout, OutcomeCancelled:
		return true
	default:
		return false
	}
}

// TestCase is one concrete execution of a request for a job. It is generic across
// engines (VulnClass is empty for a plain baseline execution; a detection engine
// sets it). One TestCase is recorded per job attempt, so retries keep a history.
// Request and response bodies live in evidence blobs referenced by EvidenceIDs.
type TestCase struct {
	ID               ID             `json:"id"`
	ScanID           ID             `json:"scan_id"`
	JobID            ID             `json:"job_id"`
	Attempt          int            `json:"attempt,omitempty"` // job attempt number
	InjectionPointID ID             `json:"injection_point_id,omitempty"`
	VulnClass        VulnClass      `json:"vuln_class,omitempty"`
	Status           TestCaseStatus `json:"status"`
	Outcome          TestOutcome    `json:"outcome,omitempty"` // set once finished
	Note             string         `json:"note,omitempty"`

	// What was executed.
	Method string `json:"method,omitempty"`
	URL    string `json:"url,omitempty"`

	// Result.
	HTTPStatus  int    `json:"http_status,omitempty"`
	DurationMS  int64  `json:"duration_ms,omitempty"`
	Error       string `json:"error,omitempty"`
	EvidenceIDs []ID   `json:"evidence_ids,omitempty"` // request/response evidence

	// Detail is an engine-specific structured result (JSON), opaque to the
	// domain — e.g. a reflection report. It keeps the domain model generic while
	// letting detectors persist their findings in the shared TestCase.
	Detail []byte `json:"detail,omitempty"`

	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}
