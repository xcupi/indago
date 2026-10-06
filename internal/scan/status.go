package scan

import (
	"context"
	"time"

	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/queue"
)

// Status is the live, operator-facing view of a scan: persisted state plus
// discovery progress, job counts, and findings. It backs the web UI and CLI
// status views, so both always agree.
type Status struct {
	Scan      *domain.Scan    `json:"scan"`
	Running   bool            `json:"running"` // the controller holds a live execution
	Discovery DiscoveryStatus `json:"discovery"`
	Jobs      queue.Stats     `json:"jobs"`
	Findings  FindingCounts   `json:"findings"`
	Tests     TestCounts      `json:"tests"`
	// Session is the scan's authentication session, redacted for display: its
	// mode and lifecycle state, whether saved session material is on file, and
	// expiry — never the material itself (no cookies/tokens/paths).
	Session *SessionStatus `json:"session,omitempty"`
	// Workers is the live per-group worker count (discovery/http/browser) when
	// the controller holds a running execution; nil when the scan is not
	// actively running.
	Workers *WorkerStatus `json:"workers,omitempty"`
}

// SessionStatus is the operator-facing, redacted view of a scan's auth session.
// It deliberately omits StatePath and any session material (AGENTS.md §2.6 /
// the UI must never expose cookies, tokens, or session-state contents).
type SessionStatus struct {
	Mode      domain.AuthMode     `json:"mode"`
	State     domain.SessionState `json:"state"`
	HasState  bool                `json:"has_state"` // saved session material exists on disk
	ExpiresAt *time.Time          `json:"expires_at,omitempty"`
	LastError string              `json:"last_error,omitempty"`
}

// WorkerStatus is the live worker-pool size per group, for the monitoring view.
type WorkerStatus struct {
	Discovery int `json:"discovery"`
	HTTP      int `json:"http"`
	Browser   int `json:"browser"`
}

// TestCounts tallies executed test cases by outcome. Each job attempt is one
// test case, so a retried job counts once per attempt.
type TestCounts struct {
	Success   int `json:"success"`
	Error     int `json:"error"`
	Timeout   int `json:"timeout"`
	Cancelled int `json:"cancelled"`
	Skipped   int `json:"skipped"` // not executed (e.g. state-changing method, opt-in off)
	Running   int `json:"running"`
	// Reflection tallies (successful reflected-XSS reflection tests). Reflected +
	// NotReflected <= Success.
	Reflected    int `json:"reflected"`
	NotReflected int `json:"not_reflected"`
	// HTTP-status tallies observed by the executor, surfaced for monitoring:
	// RateLimited counts 429 responses, ServerError counts 5xx. They are
	// observational only and never change any verdict.
	RateLimited int `json:"rate_limited"`
	ServerError int `json:"server_error"`
}

// DiscoveryStatus summarizes a scan's discovery progress. EndpointsBySource
// exposes provenance: how each endpoint was found.
type DiscoveryStatus struct {
	State             domain.DiscoveryState          `json:"state"`
	Paused            bool                           `json:"paused"`
	Endpoints         int                            `json:"endpoints"`
	Parameters        int                            `json:"parameters"`
	InjectionPoints   int                            `json:"injection_points"`
	EndpointsBySource map[domain.DiscoverySource]int `json:"endpoints_by_source"`
}

// FindingCounts tallies findings by verdict.
type FindingCounts struct {
	Confirmed    int `json:"confirmed"`
	Rejected     int `json:"rejected"`
	Inconclusive int `json:"inconclusive"`
	Pending      int `json:"pending"`
}

// Status returns the live status of a scan. It reads persisted state, so it is
// accurate after a restart even before the scan is resumed.
func (c *Controller) Status(ctx context.Context, scanID domain.ID) (*Status, error) {
	sc, err := c.store.Scans().Get(ctx, scanID)
	if err != nil {
		return nil, err
	}

	st := &Status{
		Scan:    sc,
		Running: c.IsRunning(scanID),
		Discovery: DiscoveryStatus{
			State:             sc.Discovery,
			EndpointsBySource: map[domain.DiscoverySource]int{},
		},
	}
	st.Discovery.Paused = sc.State == domain.ScanPaused

	eps, err := c.store.Endpoints().ListByScan(ctx, scanID)
	if err != nil {
		return nil, err
	}
	st.Discovery.Endpoints = len(eps)
	for _, e := range eps {
		st.Discovery.EndpointsBySource[e.Source]++
	}
	params, err := c.store.Parameters().ListByScan(ctx, scanID)
	if err != nil {
		return nil, err
	}
	st.Discovery.Parameters = len(params)
	ips, err := c.store.InjectionPoints().ListByScan(ctx, scanID)
	if err != nil {
		return nil, err
	}
	st.Discovery.InjectionPoints = len(ips)

	if st.Jobs, err = c.queue.Stats(ctx, scanID); err != nil {
		return nil, err
	}

	cases, err := c.store.TestCases().ListByScan(ctx, scanID)
	if err != nil {
		return nil, err
	}
	for _, tc := range cases {
		switch {
		case tc.Status == domain.TestCaseSkipped:
			st.Tests.Skipped++
		case tc.Status == domain.TestCaseRunning:
			st.Tests.Running++
		case tc.Outcome == domain.OutcomeSuccess:
			st.Tests.Success++
			if rep, err := detection.ParseReflection(tc.Detail); err == nil && rep != nil {
				if rep.Reflected {
					st.Tests.Reflected++
				} else {
					st.Tests.NotReflected++
				}
			}
		case tc.Outcome == domain.OutcomeTimeout:
			st.Tests.Timeout++
		case tc.Outcome == domain.OutcomeCancelled:
			st.Tests.Cancelled++
		case tc.Outcome == domain.OutcomeError:
			st.Tests.Error++
		}
		switch {
		case tc.HTTPStatus == 429:
			st.Tests.RateLimited++
		case tc.HTTPStatus >= 500 && tc.HTTPStatus <= 599:
			st.Tests.ServerError++
		}
	}

	findings, err := c.store.Findings().ListByScan(ctx, scanID)
	if err != nil {
		return nil, err
	}
	for _, f := range findings {
		switch f.Verdict {
		case domain.VerdictConfirmed:
			st.Findings.Confirmed++
		case domain.VerdictRejected:
			st.Findings.Rejected++
		case domain.VerdictInconclusive:
			st.Findings.Inconclusive++
		default:
			st.Findings.Pending++
		}
	}

	st.Session = c.sessionStatus(ctx, sc)
	st.Workers = c.workerStatus(scanID)
	return st, nil
}

// sessionStatus builds the redacted session view. Errors degrade to nil (the
// session is simply not shown) rather than failing the whole status read.
func (c *Controller) sessionStatus(ctx context.Context, sc *domain.Scan) *SessionStatus {
	if sc.SessionID.Empty() {
		return nil
	}
	sess, err := c.store.Sessions().Get(ctx, sc.SessionID)
	if err != nil {
		return nil
	}
	return &SessionStatus{
		Mode:      sess.Mode,
		State:     sess.State,
		HasState:  sess.StatePath != "", // presence only; never the path or its contents
		ExpiresAt: sess.ExpiresAt,
		LastError: sess.LastError,
	}
}

// workerStatus returns the live per-group worker counts when the controller
// holds a running execution for the scan, else nil (not actively running).
func (c *Controller) workerStatus(scanID domain.ID) *WorkerStatus {
	c.mu.Lock()
	ex, ok := c.running[scanID]
	c.mu.Unlock()
	if !ok {
		return nil
	}
	sizes := ex.pool.Sizes()
	return &WorkerStatus{
		Discovery: sizes[GroupDiscovery],
		HTTP:      sizes[GroupHTTP],
		Browser:   sizes[GroupBrowser],
	}
}
