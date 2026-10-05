package scan

// This file is the Finding correlation layer: it turns a reflected candidate
// into a Finding (Pending), and a browser-verification result into that
// Finding's Confirmed/Rejected/Inconclusive promotion — without ever
// multiplying near-duplicate Finding rows for the same underlying site, and
// without ever discarding the raw evidence a correlated attempt produced.
//
// Boundaries (see AGENTS.md §2):
//   - Only verification's own Verdict ever reaches the Finding (correlate
//     never invents or overrides it); the ONE rule this file adds is that a
//     Finding's verdict only ever moves UP the pending→inconclusive/
//     rejected→confirmed lattice — a later, weaker result at the same
//     correlated site never downgrades an already-confirmed finding.
//   - Correlation is keyed on meaningful differences only: injection point
//     (= scan+endpoint+parameter) and the reflection's category+context. A
//     different parameter or a different context is a different Finding.

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/store"
	"github.com/indago/indago/internal/verification"
)

// findingDetail is Finding.Detail's engine-specific payload for Reflected XSS:
// the correlation key, every distinct candidate that correlated into this
// finding (raw evidence of what was actually tried, preserved even when
// merged), and the TestCase IDs that back it end to end.
type findingDetail struct {
	Method        domain.HTTPMethod     `json:"method,omitempty"`
	ParameterName string                `json:"parameter_name,omitempty"`
	DedupKey      string                `json:"dedup_key"`
	Occurrences   int                   `json:"occurrences"`
	TestCaseIDs   []domain.ID           `json:"test_case_ids,omitempty"`
	Candidates    []detection.Candidate `json:"candidates,omitempty"`
}

func decodeFindingDetail(b []byte) findingDetail {
	var d findingDetail
	if len(b) > 0 {
		_ = json.Unmarshal(b, &d)
	}
	return d
}

func (d findingDetail) encode() []byte {
	b, _ := json.Marshal(d)
	return b
}

// findingDedupKey is the correlation key for a reflected candidate: the SAME
// injection point (scan+endpoint+parameter) producing the SAME candidate
// category at the SAME reflection context is one underlying site, however many
// distinct candidates or attempts confirm it. A different injection point, or
// the same injection point reflecting into a genuinely different context
// (e.g. one site in html_text, another in js_string), is a different finding.
func findingDedupKey(injectionPointID domain.ID, cand detection.Candidate) string {
	return string(injectionPointID) + "\x00" + string(cand.Category) + "\x00" + string(cand.Context)
}

// severityFor rates a reflected candidate by how directly its category reaches
// code execution. This is a prioritization aid for the PENDING finding, not a
// verdict — only verification decides confirmed/rejected/inconclusive.
func severityFor(cand detection.Candidate) domain.Severity {
	switch cand.Category {
	case detection.CatHTMLText, detection.CatHTMLAttr, detection.CatJS:
		return domain.SeverityHigh
	case detection.CatCSS, detection.CatURL:
		return domain.SeverityMedium
	default:
		return domain.SeverityLow
	}
}

func findingTitle(cand detection.Candidate, focus *domain.Parameter) string {
	return fmt.Sprintf("Reflected XSS candidate (%s) in parameter %q", cand.Category, focus.Name)
}

// upsertPendingFinding returns the Finding a reflected candidate correlates
// into. An existing finding at the same dedup key (see findingDedupKey)
// absorbs this candidate — its own TestCase ID and candidate value are
// recorded, and its occurrence count bumped, but its Verdict is left to
// verification alone. Otherwise a new Finding is created at VerdictPending,
// carrying full provenance: scan, endpoint, parameter, injection point, the
// candidate, and the endpoint's own discovery source.
func upsertPendingFinding(ctx context.Context, st store.Store, scanID domain.ID, ep *domain.Endpoint, injectionPointID domain.ID, focus *domain.Parameter, cand detection.Candidate, candTestCaseID domain.ID) (*domain.Finding, error) {
	key := findingDedupKey(injectionPointID, cand)

	existing, err := st.Findings().ListByScan(ctx, scanID)
	if err != nil {
		return nil, fmt.Errorf("list findings for correlation: %w", err)
	}
	for _, f := range existing {
		if f.VulnClass != domain.VulnReflectedXSS {
			continue
		}
		d := decodeFindingDetail(f.Detail)
		if d.DedupKey != key {
			continue
		}
		d.Occurrences++
		d.TestCaseIDs = appendUniqueID(d.TestCaseIDs, candTestCaseID)
		d.Candidates = appendUniqueCandidate(d.Candidates, cand)
		f.Detail = d.encode()
		f.UpdatedAt = time.Now()
		if err := st.Findings().Update(ctx, f); err != nil {
			return nil, fmt.Errorf("update correlated finding: %w", err)
		}
		return f, nil
	}

	sc, err := st.Scans().Get(ctx, scanID)
	if err != nil {
		return nil, fmt.Errorf("load scan: %w", err)
	}
	now := time.Now()
	d := findingDetail{
		Method: ep.Method, ParameterName: focus.Name, DedupKey: key, Occurrences: 1,
		TestCaseIDs: []domain.ID{candTestCaseID}, Candidates: []detection.Candidate{cand},
	}
	f := &domain.Finding{
		ID: domain.NewID(), ScanID: scanID, ProjectID: sc.ProjectID, VulnClass: domain.VulnReflectedXSS,
		Verdict: domain.VerdictPending, Severity: severityFor(cand), Confidence: domain.ConfidenceLow,
		Title:            findingTitle(cand, focus),
		Summary:          cand.Rationale,
		EndpointID:       ep.ID,
		InjectionPointID: injectionPointID,
		ParameterID:      focus.ID,
		Location:         focus.Location,
		Provenance:       domain.Provenance{Engine: "reflected-xss", DiscoverySource: ep.Source, DetectedAt: now, AIAssisted: false},
		Detail:           d.encode(),
		CreatedAt:        now, UpdatedAt: now,
	}
	if err := st.Findings().Create(ctx, f); err != nil {
		return nil, fmt.Errorf("create finding: %w", err)
	}
	return f, nil
}

// verdictRank orders verdicts for the monotonic-confirmation rule: Pending <
// Inconclusive < Rejected < Confirmed. Rejected outranks Inconclusive because
// it is itself a high-confidence negative (the candidate WAS observed, just
// did not execute), while Inconclusive means the candidate could not even be
// re-observed — strictly less informative.
func verdictRank(v domain.Verdict) int {
	switch v {
	case domain.VerdictConfirmed:
		return 3
	case domain.VerdictRejected:
		return 2
	case domain.VerdictInconclusive:
		return 1
	default: // Pending or unset
		return 0
	}
}

// correlateVerification merges one completed verification attempt into the
// Finding it targets. The verdict only ever moves up verdictRank — a finding
// already Confirmed stays Confirmed regardless of what a later, correlated
// attempt finds — but evidence (this attempt's browser evidence AND the
// original candidate's own request/response evidence) and the contributing
// TestCase IDs are unioned in every time, so correlating never discards raw
// evidence. It is the only place a Finding's Verdict leaves Pending.
func (e *verifyExecutor) correlateVerification(ctx context.Context, findingID domain.ID, candTestCaseID domain.ID, vres *verification.Result, verifyTestCaseID domain.ID, newEvidenceIDs []domain.ID) {
	// Serialized: two verify jobs for the same correlated finding (two
	// candidates at the same site) can complete at the same time on different
	// browser workers, and this is a plain Get-mutate-Update — without the
	// lock, the second Update to commit would silently overwrite the first's
	// evidence/verdict rather than merge with it.
	e.findingsMu.Lock()
	defer e.findingsMu.Unlock()

	f, err := e.store.Findings().Get(ctx, findingID)
	if err != nil {
		e.log.Warn("load finding for verification update", "finding", findingID, "err", err)
		return
	}

	now := time.Now()
	if verdictRank(vres.Verdict) > verdictRank(f.Verdict) {
		f.Verdict = vres.Verdict
		f.Confidence = vres.Confidence
		if vres.Notes != "" {
			f.Summary = vres.Notes
		}
	}

	// Include request, response, browser event, DOM/screenshot evidence where
	// available: newEvidenceIDs is this attempt's browser evidence (screenshot/
	// DOM/browser log); the candidate TestCase's own evidence is its HTTP
	// request/response.
	all := append([]domain.ID(nil), newEvidenceIDs...)
	if !candTestCaseID.Empty() {
		if candTC, err := e.store.TestCases().Get(ctx, candTestCaseID); err == nil {
			all = append(all, candTC.EvidenceIDs...)
		}
	}
	f.EvidenceIDs = appendUniqueIDs(f.EvidenceIDs, all)

	d := decodeFindingDetail(f.Detail)
	d.TestCaseIDs = appendUniqueID(d.TestCaseIDs, verifyTestCaseID)
	d.TestCaseIDs = appendUniqueID(d.TestCaseIDs, candTestCaseID)
	f.Detail = d.encode()

	f.Provenance.VerifiedAt = &now
	f.UpdatedAt = now
	if err := e.store.Findings().Update(ctx, f); err != nil {
		e.log.Warn("persist finding verification result", "finding", findingID, "err", err)
	}
}

func appendUniqueID(ids []domain.ID, id domain.ID) []domain.ID {
	if id.Empty() {
		return ids
	}
	for _, x := range ids {
		if x == id {
			return ids
		}
	}
	return append(ids, id)
}

func appendUniqueIDs(existing, add []domain.ID) []domain.ID {
	for _, id := range add {
		existing = appendUniqueID(existing, id)
	}
	return existing
}

// appendUniqueCandidate records a correlated candidate only once (by its own
// dedup key + value), so repeated confirmations of the SAME candidate do not
// bloat the finding's raw-evidence list — but every genuinely DISTINCT
// candidate that reached this site is kept.
func appendUniqueCandidate(cands []detection.Candidate, c detection.Candidate) []detection.Candidate {
	for _, x := range cands {
		if x.DedupKey == c.DedupKey && x.Value == c.Value {
			return cands
		}
	}
	return append(cands, c)
}
