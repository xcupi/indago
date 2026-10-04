package scan

import (
	"context"

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
	return st, nil
}
