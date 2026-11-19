package main

import (
	"bytes"
	"flag"
	"io"
	"strings"
	"testing"
)

// The -api-token flag and $INDAGO_API_TOKEN resolve with the flag winning, and
// the empty/unset cases keep today's open behaviour exactly.

const flagTestToken = "indago-test-token-5c1e8a93b7d24f60a1c8e5d2b9f3a740" // dummy
const flagTestOther = "indago-test-token-0f4d7b2a9c6e1538d0a4f7b1e8c2d965" // dummy

// parseTokenFlag runs the same binding cmdServe and every client subcommand use.
func parseTokenFlag(t *testing.T, args ...string) (apiTokenFlagState, error) {
	t.Helper()
	var st apiTokenFlagState
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	st.register(fs, "test usage")
	return st, fs.Parse(args)
}

func TestResolveAPITokenPrecedence(t *testing.T) {
	fromFlag := func(v string) apiTokenFlagState {
		st, err := parseTokenFlag(t, "-api-token", v)
		if err != nil {
			t.Fatalf("parse -api-token: %v", err)
		}
		return st
	}
	cases := []struct {
		name       string
		flag       apiTokenFlagState
		env        string
		wantToken  string
		wantSource string
		wantErr    bool
	}{
		{"neither: open mode unchanged", apiTokenFlagState{}, "", "", "", false},
		{"env only", apiTokenFlagState{}, flagTestToken, flagTestToken, "INDAGO_API_TOKEN", false},
		{"flag only", fromFlag(flagTestToken), "", flagTestToken, "-api-token", false},
		{"both: flag wins", fromFlag(flagTestToken), flagTestOther, flagTestToken, "-api-token", false},
		{"short env token refused", apiTokenFlagState{}, "short", "", "", true},
		{"short flag token refused", fromFlag("short"), flagTestToken, "", "", true},
	}
	for _, c := range cases {
		tok, src, err := resolveAPIToken(c.flag, c.env)
		if (err != nil) != c.wantErr {
			t.Errorf("%s: err = %v, wantErr %v", c.name, err, c.wantErr)
			continue
		}
		if c.wantErr {
			// The error names where the bad value came from, never the value.
			if strings.Contains(err.Error(), "short") {
				t.Errorf("%s: error text contains the token: %v", c.name, err)
			}
			continue
		}
		if tok != c.wantToken || src != c.wantSource {
			t.Errorf("%s: got (%q, %q), want (%q, %q)", c.name, tok, src, c.wantToken, c.wantSource)
		}
	}
}

func TestAPITokenFlagRefusesEmptyValue(t *testing.T) {
	for _, args := range [][]string{
		{"-api-token", ""},
		{"-api-token="},
		{"-api-token", "   "},
	} {
		st, err := parseTokenFlag(t, args...)
		if err == nil {
			t.Fatalf("%v: empty -api-token accepted", args)
		}
		if !strings.Contains(err.Error(), "-api-token") {
			t.Errorf("%v: error should name -api-token, got %v", args, err)
		}
		if st.set {
			t.Errorf("%v: a rejected value must not be recorded as set", args)
		}
	}
}

func TestAPITokenFlagEqualsFormAndUnsetDefault(t *testing.T) {
	st, err := parseTokenFlag(t, "-api-token="+flagTestToken)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !st.set || st.value != flagTestToken {
		t.Fatalf("got set=%v value=%q", st.set, st.value)
	}

	st, err = parseTokenFlag(t)
	if err != nil {
		t.Fatalf("parse with no args: %v", err)
	}
	if st.set || st.value != "" {
		t.Fatalf("unset flag: got set=%v value=%q, want both empty", st.set, st.value)
	}
	// An unset flag must fall back to the environment, not disable it.
	if tok, src, err := resolveAPIToken(st, flagTestToken); err != nil || tok != flagTestToken || src != "INDAGO_API_TOKEN" {
		t.Fatalf("unset flag did not fall back to the environment: %q %q %v", tok, src, err)
	}
}

// `indago serve -h` and `indago scan create -h` must list the flag without ever
// printing the token — the flag's default can be the environment value for
// clients, so a naive String() would leak it into help output.
func TestAPITokenFlagUsageNeverPrintsTheToken(t *testing.T) {
	var st apiTokenFlagState
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	st.register(fs, "control API token")
	var buf bytes.Buffer
	fs.SetOutput(&buf)
	fs.PrintDefaults()
	if !strings.Contains(buf.String(), "-api-token") {
		t.Fatalf("help does not list -api-token:\n%s", buf.String())
	}
	if strings.Contains(buf.String(), flagTestToken) {
		t.Fatalf("help printed a token:\n%s", buf.String())
	}
	// Also after a value was set: PrintDefaults must still stay silent.
	if err := fs.Parse([]string{"-api-token", flagTestToken}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	buf.Reset()
	fs.PrintDefaults()
	if strings.Contains(buf.String(), flagTestToken) {
		t.Fatalf("help printed the configured token:\n%s", buf.String())
	}
}

// flag.UnquoteUsage treats the first backquoted word in a usage string as the
// flag's value NAME. Serve's description once contained "`ps`", which printed
// the line as "-api-token ps". Guard the real description used by cmdServe.
func TestServeAPITokenUsageHasAProperValueName(t *testing.T) {
	var st apiTokenFlagState
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	st.register(fs, apiTokenServeUsage())
	var buf bytes.Buffer
	fs.SetOutput(&buf)
	fs.PrintDefaults()
	got := buf.String()
	if !strings.Contains(got, "-api-token value") {
		t.Fatalf("help line is mangled (backticks in the usage string?):\n%s", got)
	}
	if strings.Contains(got, "`") {
		t.Fatalf("help output contains a raw backtick:\n%s", got)
	}
	if !strings.Contains(got, "INDAGO_API_TOKEN") || !strings.Contains(got, "32") {
		t.Fatalf("help does not name the env var and minimum length:\n%s", got)
	}
}
