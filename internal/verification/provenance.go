package verification

import (
	"strings"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/domain"
)

// MatchRuntimeExecution is the verdict authority. MatchExecutionSignal is only
// a diagnostic signature matcher for legacy logs, never execution provenance.
func MatchRuntimeExecution(marker string, observations browser.RuntimeObservations) (Signal, string, bool) {
	if marker == "" || !observations.Available || observations.MainFrameID == "" {
		return SignalNone, "", false
	}
	for _, ex := range observations.Exceptions {
		if ex.MarkerIdentifier && ex.Location.FrameID == observations.MainFrameID && ex.Location.ContextID != 0 && ex.Location.ScriptID != "" && ex.Location.SourceSHA256 != "" && ex.ClassName == "ReferenceError" && strings.HasPrefix(ex.Description, "ReferenceError: "+marker+" is not defined") {
			return SignalPageError, ex.Description, true
		}
	}
	return SignalNone, "", false
}

// hasUnattributedMarkerException reports whether the page raised an exception
// whose message names the marker without being a main-frame evaluation of the
// marker identifier. That is how a page forges a "MARKER is not defined" error,
// and also what genuine execution in a child frame looks like, so the caller
// must not treat the candidate as either executed or safe. Exceptions that do not mention the marker are
// unrelated noise and never reach this verdict path.
func hasUnattributedMarkerException(marker string, observations browser.RuntimeObservations) bool {
	if marker == "" {
		return false
	}
	for _, ex := range observations.Exceptions {
		if !strings.Contains(firstLine(ex.Description), marker) {
			continue
		}
		// Names the marker but is not a main-frame evaluation of the marker
		// identifier: either a forged message, or genuine execution in a child
		// frame (or an unknown main frame) that cannot be tied to this page.
		if !ex.MarkerIdentifier || observations.MainFrameID == "" || ex.Location.FrameID != observations.MainFrameID {
			return true
		}
	}
	return false
}

// firstLine returns the error message without the stack CDP appends to it.
// Stack lines carry the page URL, and the payload (hence the marker) lives in
// that URL for every reflected candidate.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// DecideWithProvenance is the single verdict rule for reflected and DOM XSS.
// matched must come from MatchRuntimeExecution: it is true only when the
// engine's paused instruction was the bare marker identifier in the main
// frame. Page-controlled text (console, page-error strings) never feeds it.
//
// Fail-closed cases are Inconclusive, not Rejected: missing provenance means
// the attempt cannot be attributed, and an exception that names the marker
// without originating from the marker identifier is the shape of a forged
// error. Unrelated page errors are ignored on purpose.
func DecideWithProvenance(marker string, matched, markerInDOM bool, observations browser.RuntimeObservations) (domain.Verdict, domain.Confidence, string) {
	verdict, confidence, notes := decide(matched, markerInDOM)
	switch {
	case !observations.Available || observations.MainFrameID == "":
		return domain.VerdictInconclusive, domain.ConfidenceLow, "execution provenance is unavailable (unsupported driver, enable failure or exceeded budget); the verdict cannot be attributed, replay manually"
	case !matched && hasUnattributedMarkerException(marker, observations):
		return domain.VerdictInconclusive, domain.ConfidenceLow, "a page exception names the marker but does not originate from the marker identifier; possible forged error, replay manually"
	}
	return verdict, confidence, notes
}
