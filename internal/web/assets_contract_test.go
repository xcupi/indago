package web_test

import (
	"os"
	"strings"
	"testing"
)

// The scan status card explains when the automatic evasion fallback can run.
// Its skip list has to include the backpressure rule: the server suppresses the
// pass for a 429/503 point, and a card that omits that reason tells the operator
// the fallback is still pending there.
func TestScanStatusCardListsEveryFallbackSkipReason(t *testing.T) {
	b, err := os.ReadFile("assets/scans.js")
	if err != nil {
		t.Fatal(err)
	}
	js := string(b)
	for _, want := range []string{
		"CAPTCHA",
		"incomplete evidence",
		"no replayable verifier",
		"already-recorded bypass attempt",
		"429/503 backpressure",
	} {
		if !strings.Contains(js, want) {
			t.Fatalf("scan status card does not name skip reason %q", want)
		}
	}
}
