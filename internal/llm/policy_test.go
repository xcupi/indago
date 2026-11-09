package llm

import "testing"

// The advisory policy (master switch + per-parameter budget) must survive the
// disk round-trip: a switch that silently reads back as enabled is worse than
// no switch at all.
func TestPolicyRoundTripsThroughDisk(t *testing.T) {
	st := NewStore(t.TempDir())
	off := false
	if _, err := st.Set(SetRequest{Provider: "openai", Model: "m", APIKey: "k", MaxAttempts: 2, Enabled: &off}); err != nil {
		t.Fatal(err)
	}
	back, err := st.Load()
	if err != nil {
		t.Fatal(err)
	}
	if back.AttemptBudget() != 2 {
		t.Fatalf("attempts = %d", back.AttemptBudget())
	}
	if back.AIEnabled() {
		t.Fatal("enabled came back true after saving false")
	}

	// A second save that omits the switch keeps it (nil = unchanged).
	on := true
	if _, err := st.Set(SetRequest{Provider: "openai", Model: "m", Enabled: &on}); err != nil {
		t.Fatal(err)
	}
	back, err = st.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !back.AIEnabled() || back.AttemptBudget() != 2 {
		t.Fatalf("after re-enable: enabled=%v attempts=%d", back.AIEnabled(), back.AttemptBudget())
	}
}

// A config written before the switch existed has no "enabled" field and must
// be treated as enabled, so upgrading never turns advisory off by surprise.
func TestLegacyConfigWithoutSwitchStaysEnabled(t *testing.T) {
	var c Config
	if !c.AIEnabled() {
		t.Fatal("zero-value config must default to enabled")
	}
	if c.AttemptBudget() != DefaultMaxAttempts {
		t.Fatalf("budget = %d", c.AttemptBudget())
	}
}
