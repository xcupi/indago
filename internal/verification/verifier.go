// Package verification defines the verification contract: turning a detection
// *candidate* into a Verdict (confirmed / rejected / inconclusive) using real
// browser evidence. "Reflection alone is NOT a confirmed XSS" — verification is
// the authority that promotes a candidate to confirmed, backed by evidence.
//
// Phase 0 provides the interface and a Stub only. Real browser verification
// arrives with Phase 1.
package verification

import (
	"context"
	"errors"

	"github.com/indago/indago/internal/domain"
)

// ErrNotImplemented indicates a Phase 0 stub with no behavior yet.
var ErrNotImplemented = errors.New("verification: not implemented in Phase 0")

// Input is the generic context for verification. Phase 1 extends it with the
// candidate payload, reflection context, and the URL/request to re-exercise.
type Input struct {
	ScanID         domain.ID
	VulnClass      domain.VulnClass
	InjectionPoint domain.InjectionPoint
}

// Result is the outcome of verification. The Verdict is authoritative (subject
// to the operator), and EvidenceRefs point at the artifacts that substantiate it.
type Result struct {
	Verdict      domain.Verdict
	Confidence   domain.Confidence
	Notes        string
	EvidenceRefs []domain.ID
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
