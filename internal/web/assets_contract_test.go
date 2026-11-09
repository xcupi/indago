package web_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The scan coverage panel explains when the automatic evasion fallback can run.
// Its skip list has to include the backpressure rule: the server suppresses the
// pass for a 429/503 point, and a card that omits that reason tells the operator
// the fallback is still pending there.
//
// The UI is a bundled SPA (web/ -> internal/web/assets), so the strings are
// asserted against every emitted script rather than one hand-written file.
func TestScanStatusCardListsEveryFallbackSkipReason(t *testing.T) {
	var js strings.Builder
	err := filepath.Walk("assets", func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".js") {
			return err
		}
		b, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		js.Write(b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if js.Len() == 0 {
		t.Fatal("no JavaScript assets found; run the UI build (npm --prefix web run build)")
	}
	for _, want := range []string{
		"CAPTCHA",
		"incomplete evidence",
		"no replayable verifier",
		"already-recorded bypass attempt",
		"429/503 backpressure",
	} {
		if !strings.Contains(js.String(), want) {
			t.Fatalf("scan coverage panel does not name skip reason %q", want)
		}
	}
}
