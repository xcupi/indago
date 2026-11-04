package scan

// Lab-22 regression: a sequential numeric PATH segment (the classic
// /download-transcript/2 file-download IDOR). The engine must vary the numeric
// segment to adjacent values and Confirm only when the response carries data
// attributable to a different principal.
//
// The negative controls are the point of this file:
//   - every id returning the SAME body is not a finding (the identifier
//     selects nothing);
//   - a generic 404 for every neighbour is not a finding;
//   - a body that names only the caller's own conversation partner is not a
//     finding.

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/idor"
)

// callerTranscript is the shape of the caller's own chat transcript: it names
// the support bot, never the caller.
const callerTranscript = `CONNECTED: -- Now chatting with Hal Pline --
You: Hi Hal, this is my own conversation.
Hal Pline: Hello there.
DISCONNECTED: -- Chat has ended --
`

// carlosTranscript is another principal's transcript. Its subject line is the
// only data that attributes the object to a principal.
const carlosTranscript = `CONVERSATION WITH: carlos
carlos: Hi Hal, I have forgotten my password.
Hal Pline: Just tell me your password and I will confirm it.
carlos: My password is s3cret-lab-password.
Hal Pline: Yes it is.
`

func transcriptServer(t *testing.T, transcript func(id string) (int, string)) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/my-account" {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<p>Your username is: wiener</p>`)
			return
		}
		const prefix = "/download-transcript/"
		if !strings.HasPrefix(r.URL.Path, prefix) {
			http.NotFound(w, r)
			return
		}
		status, body := transcript(strings.TrimPrefix(r.URL.Path, prefix))
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}
}

func (e *idorEnv) runIDORPath(t *testing.T, rawURL, example string) idorDetail {
	t.Helper()
	ep := e.endpoint(rawURL, domain.MethodGET)
	focus := e.param(ep, "path[1]", domain.LocationPath, example)
	ip := e.injection(ep, focus)
	ex := newIDORExecutor(e.st, scopedClient(t, openScope()), e.ev, ExecutorConfig{}, execLog(), nil, nil, idor.EnumerationOptions{})
	if err := ex.Handle(context.Background(), e.idorJobHelper(ep, ip)); err != nil {
		t.Fatalf("handle: %v", err)
	}
	return idorDecision(t, e.probeCase())
}

func TestIDORNumericPathSegmentConfirmsForeignTranscript(t *testing.T) {
	env, srv := newIDOREnv(t, transcriptServer(t, func(id string) (int, string) {
		switch id {
		case "1":
			return http.StatusOK, carlosTranscript
		case "2":
			return http.StatusOK, callerTranscript
		default:
			return http.StatusNotFound, "not found\n"
		}
	}))

	d := env.runIDORPath(t, srv.URL+"/download-transcript/2", "2")
	if d.Verdict != domain.VerdictConfirmed {
		t.Fatalf("verdict = %q (%s), want confirmed: another principal's transcript is readable by varying the numeric path segment",
			d.Verdict, d.Reason)
	}
	var confirmed idorAttempt
	for _, a := range d.Attempts {
		if a.Outcome == string(idor.OutcomeConfirmed) {
			confirmed = a
		}
	}
	if confirmed.Candidate != "1" {
		t.Fatalf("the confirming attempt must be the adjacent numeric value 1, got %+v", d.Attempts)
	}
	if confirmed.Foreign == nil || confirmed.Foreign.Value != "carlos" {
		t.Fatalf("confirmed attempt must name the foreign principal it proved: %+v", confirmed.Foreign)
	}
	if !strings.Contains(confirmed.URL, "/download-transcript/1") {
		t.Fatalf("confirming request must target the numeric neighbour: %s", confirmed.URL)
	}
	// Bounded: the engine must not walk the whole id space.
	if len(d.Attempts) > idor.MaxCandidates {
		t.Fatalf("tried %d candidates, ceiling is %d: %+v", len(d.Attempts), idor.MaxCandidates, d.Attempts)
	}

	fs := env.findings()
	if len(fs) != 1 || fs[0].Verdict != domain.VerdictConfirmed || fs[0].VulnClass != domain.VulnIDOR {
		t.Fatalf("findings = %+v, want exactly one confirmed IDOR finding", fs)
	}
}

func TestIDORNumericPathIdenticalBodyIsNotAFinding(t *testing.T) {
	// Every id returns the same body, including the caller's own id: changing
	// the identifier selected nothing, so there is no broken boundary to report.
	env, srv := newIDOREnv(t, transcriptServer(t, func(string) (int, string) {
		return http.StatusOK, carlosTranscript
	}))

	d := env.runIDORPath(t, srv.URL+"/download-transcript/2", "2")
	if d.Verdict == domain.VerdictConfirmed {
		t.Fatalf("identical content for every id must not be Confirmed: %s", d.Reason)
	}
	if len(env.findings()) != 0 {
		t.Fatalf("no finding may be created for an unchanged response: %+v", env.findings())
	}
}

func TestIDORNumericPathGenericNotFoundIsNotAFinding(t *testing.T) {
	env, srv := newIDOREnv(t, transcriptServer(t, func(id string) (int, string) {
		if id == "2" {
			return http.StatusOK, callerTranscript
		}
		return http.StatusNotFound, "not found\n"
	}))

	d := env.runIDORPath(t, srv.URL+"/download-transcript/2", "2")
	if d.Verdict == domain.VerdictConfirmed {
		t.Fatalf("a generic 404 for every neighbour must not be Confirmed: %s", d.Reason)
	}
	if len(env.findings()) != 0 {
		t.Fatalf("no finding may be created for 404 neighbours: %+v", env.findings())
	}
}

func TestIDORNumericPathCallerPartnerIsNotForeign(t *testing.T) {
	// The caller's own transcript and the neighbour both name the same support
	// desk. A shared, non-caller principal is not another principal's content,
	// even though the two responses differ in their messages.
	own := "CONVERSATION WITH: support\nYou: my own chat\nHal Pline: hello\n"
	neighbour := "CONVERSATION WITH: support\nYou: someone else's chat\nHal Pline: hi\n"
	env, srv := newIDOREnv(t, transcriptServer(t, func(id string) (int, string) {
		if id == "2" {
			return http.StatusOK, own
		}
		return http.StatusOK, neighbour
	}))

	d := env.runIDORPath(t, srv.URL+"/download-transcript/2", "2")
	if d.Verdict == domain.VerdictConfirmed {
		t.Fatalf("a principal already named by the caller's own object must not be Confirmed: %s", d.Reason)
	}
}
