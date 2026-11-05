package scan

// Bounded-enumeration and harvest-precision integration tests. They use the
// fake httpengine from idor_harvest_test.go so the exact request list is an
// assertion, not an inference: enumeration has to be provably bounded, and a
// scan with nothing to try has to provably send nothing.

import (
	"context"
	"strings"
	"testing"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/idor"
)

// idorProbeCases returns every IDOR probe (non-identity-baseline) test case of
// the scan, in creation order.
func idorProbeCases(t *testing.T, env *idorHarvestEnv) []*domain.TestCase {
	t.Helper()
	var out []*domain.TestCase
	for _, tc := range env.cases() {
		if tc.VulnClass == domain.VulnIDOR && !strings.HasPrefix(tc.Note, "idor identity") {
			out = append(out, tc)
		}
	}
	return out
}

func candidateSequence(d idorDetail) []string {
	var out []string
	for _, a := range d.Attempts {
		out = append(out, a.Candidate)
	}
	return out
}

// TestIDOREnumerationNumericSetIsExact: baseline 7 with N=3 tries exactly
// 6, 8, 1, 2, 3 — the arithmetic the operator can predict before running.
func TestIDOREnumerationNumericSetIsExact(t *testing.T) {
	env := newIDORHarvestEnv(t)
	const base = "http://app.test"
	ep := env.endpoint(base+"/my-account?id=7", domain.MethodGET)
	focus := env.param(ep, "id", domain.LocationQuery, "7")
	ip := env.injection(ep, focus)

	eng := &idorFakeEngine{respond: func(string) (int, string) {
		return 200, `<p>Your username is <strong>wiener</strong></p>`
	}}
	ex := newIDORExecutor(env.st, eng, env.ev, ExecutorConfig{}, execLog(), nil, nil,
		idor.EnumerationOptions{Enabled: true, Neighbours: 3})
	if err := ex.Handle(context.Background(), env.idorJobHelper(ep, ip)); err != nil {
		t.Fatalf("handle: %v", err)
	}

	d := idorDecision(t, env.probeCase())
	want := []string{"6", "8", "1", "2", "3"}
	if got := strings.Join(candidateSequence(d), ","); got != strings.Join(want, ",") {
		t.Fatalf("enumeration candidates = %s, want %s", got, strings.Join(want, ","))
	}
	if !d.Enumeration || !strings.Contains(d.EnumerationNote, "N=3") {
		t.Fatalf("detail must record the enumeration decision and N: %+v", d)
	}
	// Every response identifies the caller: a same-principal enumeration hit is
	// Rejected, never Confirmed.
	if d.Verdict != domain.VerdictRejected {
		t.Fatalf("verdict = %q (%s), want rejected for same-principal enumeration", d.Verdict, d.Reason)
	}
	if len(env.findings()) != 0 {
		t.Fatalf("same-principal enumeration created a finding: %+v", env.findings())
	}
	// identity + own baseline + five enumerated candidates.
	if len(eng.seen()) != 7 {
		t.Fatalf("requests = %v, want identity + baseline + 5 candidates", eng.seen())
	}
	if d.ProbesLeft != maxIDORProbesPerScan-5 {
		t.Fatalf("ProbesLeft = %d, want %d", d.ProbesLeft, maxIDORProbesPerScan-5)
	}
}

// TestIDOREnumerationConfirmsAForeignNumericObject: the whole point of the
// pass — id=1/2/3 style enumeration finds another principal's object.
func TestIDOREnumerationConfirmsAForeignNumericObject(t *testing.T) {
	env := newIDORHarvestEnv(t)
	const base = "http://app.test"
	ep := env.endpoint(base+"/my-account?id=7", domain.MethodGET)
	focus := env.param(ep, "id", domain.LocationQuery, "7")
	ip := env.injection(ep, focus)

	eng := &idorFakeEngine{respond: func(raw string) (int, string) {
		if strings.Contains(raw, "id=3") {
			return 200, `<p>Your username is <strong>carlos</strong></p>`
		}
		return 200, `<p>Your username is <strong>wiener</strong></p>`
	}}
	ex := newIDORExecutor(env.st, eng, env.ev, ExecutorConfig{}, execLog(), nil, nil,
		idor.EnumerationOptions{Enabled: true, Neighbours: 3})
	if err := ex.Handle(context.Background(), env.idorJobHelper(ep, ip)); err != nil {
		t.Fatalf("handle: %v", err)
	}

	d := idorDecision(t, env.probeCase())
	if d.Verdict != domain.VerdictConfirmed {
		t.Fatalf("verdict = %q (%s), want confirmed on enumerated id=3", d.Verdict, d.Reason)
	}
	last := d.Attempts[len(d.Attempts)-1]
	if last.Candidate != "3" || last.Source != "enumerate" || last.Foreign == nil || last.Foreign.Value != "carlos" {
		t.Fatalf("confirming attempt = %+v, want enumerated 3 naming carlos", last)
	}
	// One positive mismatch stops the pass: 6, 8, 1, 2 then 3 — never 1..N
	// after a confirmation.
	if got := strings.Join(candidateSequence(d), ","); got != "6,8,1,2,3" {
		t.Fatalf("candidate sequence = %s, want 6,8,1,2,3", got)
	}
	if len(env.findings()) != 1 || env.findings()[0].Verdict != domain.VerdictConfirmed {
		t.Fatalf("findings = %+v, want one confirmed", env.findings())
	}
}

// TestIDOREnumerationRespectsSharedBudget: one scan-wide budget, spent by
// derived and enumerated candidates alike, caps the probes even when the
// candidate list is longer.
func TestIDOREnumerationRespectsSharedBudget(t *testing.T) {
	env := newIDORHarvestEnv(t)
	const base = "http://app.test"
	ep := env.endpoint(base+"/my-account?id=7", domain.MethodGET)
	focus := env.param(ep, "id", domain.LocationQuery, "7")
	ip := env.injection(ep, focus)

	eng := &idorFakeEngine{respond: func(string) (int, string) {
		return 200, `<p>Your username is <strong>wiener</strong></p>`
	}}
	ex := newIDORExecutor(env.st, eng, env.ev, ExecutorConfig{}, execLog(), nil, nil,
		idor.EnumerationOptions{Enabled: true, Neighbours: 5}) // would be 7 candidates
	ex.probes = newIDORProbeBudget(3)

	if err := ex.Handle(context.Background(), env.idorJobHelper(ep, ip)); err != nil {
		t.Fatalf("handle: %v", err)
	}

	d := idorDecision(t, env.probeCase())
	if len(d.Attempts) != 3 {
		t.Fatalf("attempts = %v, want exactly the 3 the budget allowed", candidateSequence(d))
	}
	if !d.BudgetExhausted || d.ProbesLeft != 0 {
		t.Fatalf("budget state = exhausted:%v left:%d, want exhausted with none left", d.BudgetExhausted, d.ProbesLeft)
	}
	// identity + baseline + exactly 3 candidate requests, never 7.
	if len(eng.seen()) != 5 {
		t.Fatalf("requests = %v, want identity + baseline + 3 budgeted candidates", eng.seen())
	}
}

// TestIDORLoginPageIsReportedOncePerScan: a login page means the session never
// reached the object. It is stated once, stops the site immediately, and is not
// repeated per candidate or per later site.
func TestIDORLoginPageIsReportedOncePerScan(t *testing.T) {
	env := newIDORHarvestEnv(t)
	const base = "http://app.test"

	eng := &idorFakeEngine{respond: func(raw string) (int, string) {
		if strings.Contains(raw, "id=") && !strings.Contains(raw, "id=7") {
			return 200, `<html><body><form><input type="password" name="password"></form></body></html>`
		}
		return 200, `<p>Your username is <strong>wiener</strong></p>`
	}}
	ex := newIDORExecutor(env.st, eng, env.ev, ExecutorConfig{}, execLog(), nil, nil,
		idor.EnumerationOptions{Enabled: true, Neighbours: 5})

	ep1 := env.endpoint(base+"/my-account?id=7", domain.MethodGET)
	focus1 := env.param(ep1, "id", domain.LocationQuery, "7")
	ip1 := env.injection(ep1, focus1)
	if err := ex.Handle(context.Background(), env.idorJobHelper(ep1, ip1)); err != nil {
		t.Fatalf("handle site 1: %v", err)
	}

	ep2 := env.endpoint(base+"/account?id=7", domain.MethodGET)
	focus2 := env.param(ep2, "id", domain.LocationQuery, "7")
	ip2 := env.injection(ep2, focus2)
	if err := ex.Handle(context.Background(), env.idorJobHelper(ep2, ip2)); err != nil {
		t.Fatalf("handle site 2: %v", err)
	}

	cases := idorProbeCases(t, env)
	if len(cases) != 2 {
		t.Fatalf("probe test cases = %d, want 2", len(cases))
	}
	// The store's listing order is not creation order: identify each site by
	// the endpoint its baseline request used.
	var site1, site2 *domain.TestCase
	for _, tc := range cases {
		if strings.Contains(tc.URL, "/account?") {
			site2 = tc
		} else {
			site1 = tc
		}
	}
	if site1 == nil || site2 == nil {
		t.Fatalf("could not identify both sites: %+v", cases)
	}
	first, second := idorDecision(t, site1), idorDecision(t, site2)

	for i, d := range []idorDetail{first, second} {
		if !d.SessionBlocked {
			t.Fatalf("site %d did not record the blocked session: %+v", i+1, d)
		}
		if len(d.Attempts) != 1 {
			t.Fatalf("site %d sent %d candidates; a login page must stop the site at the first one", i+1, len(d.Attempts))
		}
	}
	if n := strings.Count(first.Reason, "did not reach"); n != 1 {
		t.Fatalf("site 1 states the login-page conclusion %d times, want once: %q", n, first.Reason)
	}
	if n := strings.Count(second.Reason, "did not reach"); n != 0 {
		t.Fatalf("site 2 repeated the scan's login-page conclusion: %q", second.Reason)
	}
	if !strings.Contains(second.Reason, "already reported") {
		t.Fatalf("site 2 must reference the scan's single report: %q", second.Reason)
	}
	// identity + baseline + ONE candidate for site 1, then identity is cached
	// so site 2 costs baseline + ONE candidate.
	if len(eng.seen()) != 5 {
		t.Fatalf("requests = %v, want site1(identity+baseline+1) + site2(baseline+1)", eng.seen())
	}
}

// TestIDOREnumerationOffAddsNothing: with the switch off, the candidate set is
// exactly the pre-enumeration derivation — no 1..N probes appear.
func TestIDOREnumerationOffAddsNothing(t *testing.T) {
	env := newIDORHarvestEnv(t)
	const base = "http://app.test"
	ep := env.endpoint(base+"/my-account?id=7", domain.MethodGET)
	focus := env.param(ep, "id", domain.LocationQuery, "7")
	ip := env.injection(ep, focus)

	eng := &idorFakeEngine{respond: func(string) (int, string) {
		return 200, `<p>Your username is <strong>wiener</strong></p>`
	}}
	// Zero-value options: the default, unchanged engine.
	ex := newIDORExecutor(env.st, eng, env.ev, ExecutorConfig{}, execLog(), nil, nil, idor.EnumerationOptions{})
	if err := ex.Handle(context.Background(), env.idorJobHelper(ep, ip)); err != nil {
		t.Fatalf("handle: %v", err)
	}

	d := idorDecision(t, env.probeCase())
	want := []string{"8", "6", "9", "5", "10"} // legacy numeric neighbours of 7
	if got := strings.Join(candidateSequence(d), ","); got != strings.Join(want, ",") {
		t.Fatalf("candidates with enumeration off = %s, want legacy %s", got, strings.Join(want, ","))
	}
	if d.Enumeration || d.EnumerationNote != "" {
		t.Fatalf("enumeration-off detail claims enumeration: %+v", d)
	}
	for _, v := range candidateSequence(d) {
		if v == "1" || v == "2" || v == "3" || v == "4" {
			t.Fatalf("enumeration probe %q leaked into the default pass", v)
		}
	}
}

// TestIDOROrdinaryProductLinkIsNeverProbed is the live defect's end-to-end
// regression: a stored page whose only "identifier-looking" value is the last
// segment of an ordinary link must produce no candidate and no request at all.
func TestIDOROrdinaryProductLinkIsNeverProbed(t *testing.T) {
	env := newIDORHarvestEnv(t)
	const base = "http://app.test"
	ep := env.endpoint(base+"/my-account?id=wiener", domain.MethodGET)
	focus := env.param(ep, "id", domain.LocationQuery, "wiener")
	ip := env.injection(ep, focus)

	// The caller's home page: navigation links only, no foreign identity.
	seedResponseEvidence(t, env, base+"/", `<html><body>
	  <a href="/product">Product</a>
	  <a href="/catalog">Catalog</a>
	  <p>Your username is <strong>wiener</strong></p>
	  <a href="/my-account?id=wiener">My account</a>
	</body></html>`)

	eng := &idorFakeEngine{respond: func(string) (int, string) {
		return 200, `<p>Your username is <strong>wiener</strong></p>`
	}}
	ex := newIDORExecutor(env.st, eng, env.ev, ExecutorConfig{}, execLog(), nil, nil, idor.EnumerationOptions{})
	if err := ex.Handle(context.Background(), env.idorJobHelper(ep, ip)); err != nil {
		t.Fatalf("handle: %v", err)
	}

	tc := env.probeCase()
	if tc.Status != domain.TestCaseSkipped {
		t.Fatalf("status = %s, want skipped (no candidate)", tc.Status)
	}
	d := idorDecision(t, tc)
	if d.Verdict != "" {
		t.Fatalf("verdict = %q, want none: nothing was probed", d.Verdict)
	}
	if !strings.Contains(d.SkipReason, "no foreign object identifier available") {
		t.Fatalf("skip reason must be the clean no-candidate conclusion: %q", d.SkipReason)
	}
	if d.HarvestedCount != 0 {
		t.Fatalf("harvested %d identifiers from navigation links", d.HarvestedCount)
	}
	if len(eng.seen()) != 0 {
		t.Fatalf("engine probed despite having no candidate: %v", eng.seen())
	}
}

// TestIDORZeroPaddedBaselineKeepsPadding at the engine level: the requests a
// padded id produces are padded too.
func TestIDORZeroPaddedBaselineKeepsPadding(t *testing.T) {
	env := newIDORHarvestEnv(t)
	const base = "http://app.test"
	ep := env.endpoint(base+"/my-account?id=007", domain.MethodGET)
	focus := env.param(ep, "id", domain.LocationQuery, "007")
	ip := env.injection(ep, focus)

	eng := &idorFakeEngine{respond: func(string) (int, string) {
		return 200, `<p>Your username is <strong>wiener</strong></p>`
	}}
	ex := newIDORExecutor(env.st, eng, env.ev, ExecutorConfig{}, execLog(), nil, nil,
		idor.EnumerationOptions{Enabled: true, Neighbours: 3})
	if err := ex.Handle(context.Background(), env.idorJobHelper(ep, ip)); err != nil {
		t.Fatalf("handle: %v", err)
	}

	d := idorDecision(t, env.probeCase())
	if got := strings.Join(candidateSequence(d), ","); got != "006,008,001,002,003" {
		t.Fatalf("padded candidates = %s, want 006,008,001,002,003", got)
	}
	for _, call := range eng.seen() {
		if strings.Contains(call, "id=") && !strings.Contains(call, "id=00") {
			t.Fatalf("unpadded request sent from a padded baseline: %s", call)
		}
	}
}

// TestValidateIDOREnumeration pins the scan-creation gate: enumeration cannot
// be enabled without the engine, N cannot be set without the switch, and N is
// hard-capped.
func TestValidateIDOREnumeration(t *testing.T) {
	for _, tc := range []struct {
		name      string
		idor      bool
		enumerate bool
		n         int
		wantErr   bool
	}{
		{"off by default", false, false, 0, false},
		{"engine on, enumeration off", true, false, 0, false},
		{"enumeration without the engine", false, true, 0, true},
		{"N without the switch", true, false, 3, true},
		{"valid N", true, true, 3, false},
		{"negative N", true, true, -1, true},
		{"N above the ceiling", true, true, idor.MaxEnumerationNeighbours + 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateIDOREnumeration(tc.idor, tc.enumerate, tc.n)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validateIDOREnumeration(%v, %v, %d) = %v, want error %v",
					tc.idor, tc.enumerate, tc.n, err, tc.wantErr)
			}
		})
	}
}
