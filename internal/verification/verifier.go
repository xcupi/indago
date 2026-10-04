// Package verification defines the verification contract: turning a detection
// *candidate* into a Verdict (confirmed / rejected / inconclusive) using real
// browser evidence. "Reflection alone is NOT a confirmed XSS" — verification is
// the authority that promotes a candidate to confirmed, backed by evidence. An
// LLM is never consulted for this decision (AGENTS.md §2.5): the verdict is
// produced by the deterministic signal match in signal.go.
//
// Phase 0 provided the interface and a Stub only. Phase 1 (browser.go) is the
// real, Chromium-backed implementation.
package verification

import (
	"context"
	"errors"

	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
)

// ErrNotImplemented indicates the Phase 0 stub with no behavior.
var ErrNotImplemented = errors.New("verification: not implemented in Phase 0")

// ErrUnsupportedMethod is returned when Input.Method is not browser-navigable
// (browser navigation carries no request body, so only GET/HEAD/OPTIONS
// candidates can be replayed this way). The caller should treat this as "not
// attempted", not as a failed verification.
var ErrUnsupportedMethod = errors.New("verification: only GET-navigable candidates can be browser-verified")

// Input is the context for one verification attempt: the candidate that
// reflected, the exact request that produced the reflection, and the
// scope/session under which to replay it.
type Input struct {
	ScanID         domain.ID
	VulnClass      domain.VulnClass
	InjectionPoint domain.InjectionPoint

	// Candidate is the detection candidate that reflected (its Value is what was
	// sent; its Source distinguishes builtin from a future advisory candidate).
	Candidate detection.Candidate
	// Marker is the bare, unique sentinel substring (the reflection probe's
	// token) embedded inside Candidate.Value. It — not the whole candidate
	// value — is what an uncaught-exception message would name, and what is
	// searched for in the rendered DOM.
	Marker string
	// Method and URL are the exact request that produced the reflection. Browser
	// navigation is GET-only; a non-GET/HEAD/OPTIONS Method yields
	// ErrUnsupportedMethod.
	Method string
	URL    string

	// Scope gates every request the browser makes (navigation, redirects,
	// subresources) — see browser.ContextOptions.AllowRequest. A zero Scope
	// permits nothing (fails closed), matching domain.Scope's own default.
	Scope domain.Scope
	// SessionStatePath, when non-empty, seeds the browser context with the
	// scan's saved (authenticated) session material.
	SessionStatePath string
}

// ResultEvidence carries the raw artifacts a verification attempt produced. The
// caller (the scan executor) persists these and fills Result.EvidenceRefs with
// their IDs — verification itself has no store dependency, mirroring how
// internal/detection stays pure and leaves persistence to internal/scan.
type ResultEvidence struct {
	Screenshot []byte   // PNG, nil if not captured
	DOMHTML    string   // rendered HTML at observation time
	BrowserLog []string // console errors + page errors + dialog messages, in order
}

// Result is the outcome of one verification attempt. The Verdict is
// authoritative (subject to the operator); EvidenceRefs is populated by the
// caller once Evidence has been persisted. Report is the structured detail
// meant for TestCase.Detail (mirroring detection.ReflectionReport).
type Result struct {
	Verdict      domain.Verdict
	Confidence   domain.Confidence
	Notes        string
	EvidenceRefs []domain.ID
	Evidence     ResultEvidence
	Report       *Report
}

// Verifier confirms or rejects a candidate using runtime evidence.
type Verifier interface {
	Verify(ctx context.Context, in Input) (*Result, error)
}

// Stub is the Phase 0 no-op verifier.
type Stub struct{}

// Verify implements Verifier.
func (Stub) Verify(context.Context, Input) (*Result, error) { return nil, ErrNotImplemented }

var _ Verifier = Stub{}
