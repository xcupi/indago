package main

import (
	"testing"

	"github.com/indago/indago/internal/discovery"
)

// The bare form -raw-query-injection arrives at flag.Value.Set as "true";
// it must select the conservative "auto" mode, while =always stays explicit
// and anything else is rejected at parse time.
func TestRawQueryModeFlag(t *testing.T) {
	cases := map[string]discovery.RawQueryMode{
		"true":   discovery.RawQueryAuto,
		"auto":   discovery.RawQueryAuto,
		"always": discovery.RawQueryAlways,
		"off":    discovery.RawQueryOff,
		"false":  discovery.RawQueryOff,
	}
	for in, want := range cases {
		var f rawQueryModeFlag
		if err := f.Set(in); err != nil {
			t.Fatalf("Set(%q): %v", in, err)
		}
		if string(f) != string(want) {
			t.Fatalf("Set(%q) = %q, want %q", in, f, want)
		}
	}

	var f rawQueryModeFlag
	if err := f.Set("sometimes"); err == nil {
		t.Fatal("an invalid mode must be rejected")
	}
	if !f.IsBoolFlag() {
		t.Fatal("the flag must be boolean-style so the bare -raw-query-injection form is legal")
	}
}
