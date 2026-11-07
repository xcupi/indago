package main

import (
	"bytes"
	"strings"
	"testing"
)

// A -h/--help on any client subcommand must print that subcommand's flags and
// succeed. Before this, newFlags discarded the FlagSet's output (so a parse
// error cannot dump usage), which also swallowed the help text: the operator
// saw only "flag: help requested" and got exit status 1 for asking.
func TestSubcommandHelpPrintsFlagsInsteadOfAnError(t *testing.T) {
	out := &bytes.Buffer{}
	c := newCLI("http://127.0.0.1:8750", out)

	if err := c.runClient("scan", []string{"create", "-h"}); err != nil {
		t.Fatalf("asking for help must not be an error, got %v", err)
	}
	got := out.String()
	for _, want := range []string{"-project", "-target", "-max-candidates", "-enable-evasion"} {
		if !strings.Contains(got, want) {
			t.Fatalf("help output is missing %q:\n%s", want, got)
		}
	}
	if !strings.Contains(got, "Usage of scan create") {
		t.Fatalf("help output does not name the command:\n%s", got)
	}
}

// The same choke point must NOT swallow real parse errors.
func TestSubcommandUnknownFlagStillFails(t *testing.T) {
	out := &bytes.Buffer{}
	c := newCLI("http://127.0.0.1:8750", out)

	err := c.runClient("scan", []string{"create", "-not-a-flag"})
	if err == nil {
		t.Fatal("an unknown flag must still be an error")
	}
	if !strings.Contains(err.Error(), "not-a-flag") {
		t.Fatalf("error should name the bad flag, got %v", err)
	}
}
