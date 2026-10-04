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

// TestCase is a single concrete test produced while exercising an injection
// point. It is generic across engines; Phase 1 will attach the payload, marker,
// and reflection context. Phase 0 keeps it as a lifecycle shell.
type TestCase struct {
	ID               ID             `json:"id"`
	ScanID           ID             `json:"scan_id"`
	JobID            ID             `json:"job_id"`
	InjectionPointID ID             `json:"injection_point_id"`
	VulnClass        VulnClass      `json:"vuln_class"`
	Status           TestCaseStatus `json:"status"`
	Note             string         `json:"note,omitempty"`
	CreatedAt        time.Time      `json:"created_at"`
	UpdatedAt        time.Time      `json:"updated_at"`
}
