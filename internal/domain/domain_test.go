package domain

import "testing"

func TestNewIDUniqueAndFormatted(t *testing.T) {
	seen := make(map[ID]bool)
	for i := 0; i < 1000; i++ {
		id := NewID()
		if id.Empty() {
			t.Fatal("NewID returned empty ID")
		}
		if len(id) != 36 {
			t.Fatalf("expected 36-char UUID, got %d: %q", len(id), id)
		}
		if id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' {
			t.Fatalf("UUID dashes misplaced: %q", id)
		}
		if id[14] != '4' { // version nibble
			t.Fatalf("expected UUIDv4 version nibble, got %q in %q", id[14], id)
		}
		if seen[id] {
			t.Fatalf("duplicate ID generated: %q", id)
		}
		seen[id] = true
	}
}

func TestScanStateTransitions(t *testing.T) {
	legal := []struct{ from, to ScanState }{
		{ScanCreated, ScanRunning},
		{ScanRunning, ScanPaused},
		{ScanPaused, ScanRunning},
		{ScanRunning, ScanAwaitingAuth},
		{ScanAwaitingAuth, ScanRunning},
		{ScanRunning, ScanCanceling},
		{ScanCanceling, ScanCanceled},
		{ScanRunning, ScanCompleted},
	}
	for _, c := range legal {
		if !c.from.CanTransitionTo(c.to) {
			t.Errorf("expected legal transition %s -> %s", c.from, c.to)
		}
	}

	illegal := []struct{ from, to ScanState }{
		{ScanCreated, ScanCompleted}, // must run first
		{ScanCompleted, ScanRunning}, // terminal
		{ScanCanceled, ScanRunning},  // terminal
		{ScanPaused, ScanCompleted},  // must resume to complete
	}
	for _, c := range illegal {
		if c.from.CanTransitionTo(c.to) {
			t.Errorf("expected illegal transition %s -> %s", c.from, c.to)
		}
	}
}

func TestScanTerminalStates(t *testing.T) {
	for _, s := range []ScanState{ScanCanceled, ScanCompleted, ScanFailed} {
		if !s.IsTerminal() {
			t.Errorf("%s should be terminal", s)
		}
	}
	for _, s := range []ScanState{ScanCreated, ScanRunning, ScanPaused, ScanAwaitingAuth, ScanCanceling} {
		if s.IsTerminal() {
			t.Errorf("%s should not be terminal", s)
		}
	}
}

func TestJobStateRecoveryTransitions(t *testing.T) {
	// Crash/restart recovery requeues active jobs.
	if !JobLeased.CanTransitionTo(JobQueued) {
		t.Error("leased job must be requeueable for recovery")
	}
	if !JobRunning.CanTransitionTo(JobQueued) {
		t.Error("running job must be requeueable for recovery")
	}
	if !JobFailed.CanTransitionTo(JobQueued) {
		t.Error("failed job must be retryable")
	}
	if !JobFailed.CanTransitionTo(JobDead) {
		t.Error("failed job must be able to die after retries")
	}
	if JobSucceeded.CanTransitionTo(JobQueued) {
		t.Error("succeeded is terminal")
	}

	if !JobLeased.IsActive() || !JobRunning.IsActive() {
		t.Error("leased/running must be active")
	}
	if JobQueued.IsActive() {
		t.Error("queued is not active")
	}
}

func TestSessionStateTransitions(t *testing.T) {
	if !SessionActive.CanTransitionTo(SessionExpired) {
		t.Error("active -> expired expected")
	}
	if !SessionExpired.CanTransitionTo(SessionAuthenticating) {
		t.Error("expired -> authenticating (re-auth) expected")
	}
	if SessionActive.CanTransitionTo(SessionAuthenticating) {
		t.Error("active should not jump straight to authenticating")
	}
}

func TestScopePermitsFailsClosed(t *testing.T) {
	empty := Scope{}
	if d := empty.Permits("https://example.com/"); d.Allowed {
		t.Errorf("empty scope must deny, got allow: %s", d.Reason)
	}

	s := Scope{
		IncludeHosts:        []string{"example.com"},
		ExcludeHosts:        []string{"admin.example.com"},
		IncludePathPrefixes: []string{"/app"},
		ExcludePathPrefixes: []string{"/app/logout"},
		AllowSubdomains:     true,
	}

	cases := []struct {
		url  string
		want bool
	}{
		{"https://example.com/app/page", true},
		{"https://api.example.com/app/x", true},    // subdomain allowed
		{"https://admin.example.com/app/x", false}, // excluded host wins
		{"https://example.com/other", false},       // path not included
		{"https://example.com/app/logout", false},  // excluded path wins
		{"https://evil.com/app", false},            // host not in scope
		{"not a url", false},                       // unparseable → deny
		{"https:///app", false},                    // hostless → deny
	}
	for _, c := range cases {
		d := s.Permits(c.url)
		if d.Allowed != c.want {
			t.Errorf("Permits(%q) = %v (%s), want %v", c.url, d.Allowed, d.Reason, c.want)
		}
	}
}

func TestScopeSubdomainDisallowedByDefault(t *testing.T) {
	s := Scope{IncludeHosts: []string{"example.com"}, AllowSubdomains: false}
	if d := s.Permits("https://api.example.com/"); d.Allowed {
		t.Error("subdomain should be denied when AllowSubdomains is false")
	}
	if d := s.Permits("https://example.com/"); !d.Allowed {
		t.Errorf("apex host should be allowed: %s", d.Reason)
	}
	// Leading-dot pattern always matches subdomains.
	s2 := Scope{IncludeHosts: []string{".example.com"}}
	if d := s2.Permits("https://api.example.com/"); !d.Allowed {
		t.Errorf("leading-dot pattern should allow subdomain: %s", d.Reason)
	}
}

func TestValueEnumsValidate(t *testing.T) {
	valid := []interface{ IsValid() bool }{
		VulnReflectedXSS, SeverityHigh, ConfidenceMedium, MethodPOST,
		LocationJSON, SourceCrawler, EvidenceScreenshot, VerdictConfirmed,
		ProfileBalanced, StopFirstConfirmed, AuthMFA, ReportJSON,
		JobTest, TestCasePending, AIPrioritize, AIPending,
	}
	for _, v := range valid {
		if !v.IsValid() {
			t.Errorf("%v should be valid", v)
		}
	}

	invalid := []interface{ IsValid() bool }{
		VulnClass("nope"), Severity("nope"), Confidence("nope"), HTTPMethod("nope"),
		ParamLocation("nope"), Verdict("nope"), ProfileName("nope"), AuthMode("nope"),
	}
	for _, v := range invalid {
		if v.IsValid() {
			t.Errorf("%v should be invalid", v)
		}
	}
}

func TestVerdictTerminal(t *testing.T) {
	if !VerdictConfirmed.IsTerminal() || !VerdictRejected.IsTerminal() {
		t.Error("confirmed/rejected are terminal verdicts")
	}
	if VerdictPending.IsTerminal() || VerdictInconclusive.IsTerminal() {
		t.Error("pending/inconclusive are not terminal")
	}
}
