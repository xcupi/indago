package scan

// Built-in OAST collaborator wiring.
//
// When the server is started with a built-in OAST listener (`indago serve
// -oast-addr`, see internal/oast), every engine that can only be sure of a
// vulnerability out of band gets a collaborator for free: one callback base URL
// a target can reach, plus the loopback poll API the scanner reads its own hits
// from. Without this, SSRF, XXE and command injection each need an operator to
// register with a third-party webhook service and paste two URLs into a scan.
//
// Rules this file keeps:
//
//   - Operator configuration always wins. An engine is wired to the built-in
//     collaborator only when the operator supplied neither half of its callback
//     pair; a half-configured pair is passed through untouched (never mixed with
//     a poll API that cannot see that service's hits).
//   - SSRF only gets a canary the engine itself will accept. ssrfOASTCanary
//     refuses a loopback/private/instance-metadata host by design — asking a
//     target to fetch the scanner's own loopback address is the canonical
//     internal probe, not a collaborator — so a loopback-only listener leaves
//     SSRF on its existing response-differential path, and publishing the
//     listener (-oast-public-url) is what makes it eligible.
//   - Nothing else changes when no collaborator is configured: with Options.OAST
//     nil the engines receive exactly the values they received before.
//   - A hit is evidence, never a verdict: these are the same URLs the engines
//     already accepted from an operator, so every engine's own deterministic
//     confirmation rules decide what a callback means (AGENTS.md §2.5).

import (
	"log/slog"
	"net/url"
	"strings"

	"github.com/indago/indago/internal/oast"
)

// OASTCollaborator is the surface a scan needs from an OAST collaborator: a
// callback base URL a target can reach, and the loopback read API the scanner
// polls for what arrived. *oast.Manager (local listener mode) implements it;
// Options.OAST carries the server's single shared instance.
type OASTCollaborator interface {
	// BaseURL is the base URL callbacks are built from.
	BaseURL() string
	// PollURL starts (on first call) and returns the loopback read API that
	// lists recorded interactions.
	PollURL() (string, error)
	// ListenAddr is the local listener's bound address, "" when there is none.
	ListenAddr() string
}

// Compile-time proof the concrete manager the CLI starts satisfies the seam.
var _ OASTCollaborator = (*oast.Manager)(nil)

// oastWiring is the collaborator configuration derived from Options.OAST, once
// per controller, and shared by every scan it runs.
type oastWiring struct {
	// CallbackURL is the base URL a target can reach, without a trailing
	// slash. Engines append their own correlation marker to it (XXE adds a
	// path segment, command injection a query parameter).
	CallbackURL string
	// PollURL is the loopback read API listing every recorded interaction.
	PollURL string
	// ListenAddr is the callback listener's bound address, for diagnostics.
	ListenAddr string
	// SSRFCanaryURL is CallbackURL when the SSRF engine may use it as a
	// canary, else "". See SSRFNote for why it may be empty.
	SSRFCanaryURL string
	// SSRFNote explains an empty SSRFCanaryURL.
	SSRFNote string
}

// oastCollaborator returns this controller's wiring, deriving it on first use.
// A nil result means "no built-in collaborator", which is the default.
func (c *Controller) oastCollaborator() *oastWiring {
	c.oastOnce.Do(func() {
		c.oastCollab = deriveOASTWiring(c.opts.OAST, c.log)
	})
	return c.oastCollab
}

func deriveOASTWiring(mgr OASTCollaborator, log *slog.Logger) *oastWiring {
	if mgr == nil {
		return nil
	}
	if log == nil {
		log = slog.Default()
	}
	base := strings.TrimRight(strings.TrimSpace(mgr.BaseURL()), "/")
	if base == "" {
		log.Warn("oast: collaborator has no base URL; out-of-band engines keep their operator configuration")
		return nil
	}
	poll, err := mgr.PollURL()
	if err != nil || strings.TrimSpace(poll) == "" {
		// Without the read API an engine could send a callback and never see
		// the hit, which is worse than no collaborator at all: it would spend
		// target requests on a probe it cannot confirm.
		log.Warn("oast: poll API unavailable; out-of-band engines keep their operator configuration", "err", err)
		return nil
	}
	w := &oastWiring{
		CallbackURL: base,
		PollURL:     strings.TrimSpace(poll),
		ListenAddr:  mgr.ListenAddr(),
	}
	if u, perr := url.Parse(base); perr != nil || u.Hostname() == "" {
		w.SSRFNote = "the collaborator base URL has no parsable host"
	} else if reason, forbidden := ssrfForbiddenCanaryHost(u.Hostname()); forbidden {
		w.SSRFNote = "the collaborator host is " + reason +
			"; SSRF needs a target-reachable collaborator (set -oast-public-url)"
	} else {
		w.SSRFCanaryURL = base
	}
	log.Info("oast collaborator wired",
		"callback", w.CallbackURL, "poll", w.PollURL, "listen", w.ListenAddr,
		"ssrf", w.SSRFCanaryURL != "")
	if w.SSRFCanaryURL == "" {
		log.Info("oast: SSRF collaborator not wired; the engine keeps its response-differential confirmation", "reason", w.SSRFNote)
	}
	return w
}

// callbackPair returns the callback/poll pair an engine should use. An operator
// pair (either half set) is returned untouched — it belongs to a service the
// built-in poll API knows nothing about. Otherwise the built-in collaborator is
// used; a nil wiring yields an empty pair, which is exactly the "no
// collaborator configured" behaviour every engine already had.
func (w *oastWiring) callbackPair(operatorCallback, operatorPoll string) (string, string) {
	cb, poll := strings.TrimSpace(operatorCallback), strings.TrimSpace(operatorPoll)
	if cb != "" || poll != "" {
		return cb, poll
	}
	if w == nil {
		return "", ""
	}
	return w.CallbackURL, w.PollURL
}

// ssrfCallbackPair is callbackPair for SSRF, which additionally needs a canary
// host its own safety rules accept (see oastWiring.SSRFCanaryURL).
func (w *oastWiring) ssrfCallbackPair(operatorCallback, operatorPoll string) (string, string) {
	cb, poll := strings.TrimSpace(operatorCallback), strings.TrimSpace(operatorPoll)
	if cb != "" || poll != "" {
		return cb, poll
	}
	if w == nil || w.SSRFCanaryURL == "" {
		return "", ""
	}
	return w.SSRFCanaryURL, w.PollURL
}
