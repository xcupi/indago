package scan

// Unit-level contract for the DOM sink-report parser after the marker-window
// fix. The bounded excerpt itself is produced by the browser harness and is
// covered by the tagged browser tests; this pins the Go-side rule that the
// parser still requires the REAL marker in the value it was given. The old
// truncation shape (a prefix-only report) must stay a negative, so the fix
// cannot have been achieved by weakening marker validation.

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/detection"
)

func TestParseDOMXSSReachabilityRequiresMarkerInReportedExcerpt(t *testing.T) {
	marker := "indMarkerWindowUnit"
	prefix := strings.Repeat("A", 600)
	cases := []struct {
		name  string
		value string
		want  bool
	}{
		{"prefix-only excerpt (old truncation shape)", prefix, false},
		{"marker-centered excerpt", prefix + marker + strings.Repeat("B", 300), true},
		{"short whole value", "hello " + marker + " world", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			value, err := json.Marshal(tc.value)
			if err != nil {
				t.Fatal(err)
			}
			messages := []browser.ConsoleMessage{
				consoleLog(domXSSConsolePrefix + `{"sink":"innerHTML","value":` + string(value) + `}`),
			}
			got := parseDOMXSSReachability(messages, marker)
			if (len(got) == 1) != tc.want {
				t.Fatalf("parseDOMXSSReachability = %v, want marker present=%v", got, tc.want)
			}
			if tc.want && got[0] != detection.DOMSinkInnerHTML {
				t.Fatalf("sink = %s, want innerHTML", got[0])
			}
		})
	}
}
