package main

// Client side of -api-token: every subcommand accepts it, it overrides
// $INDAGO_API_TOKEN for that invocation, it is sent as Authorization: Bearer,
// and asking for help never prints the token.

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestCLIAPITokenFlagOverridesEnvironment(t *testing.T) {
	rec := &authRecorder{requireT: cliTestToken}
	srv := httptest.NewServer(rec)
	defer srv.Close()

	// A wrong environment token would 401 on its own; the flag must win.
	t.Setenv("INDAGO_API_TOKEN", flagTestOther)
	c := newCLI(srv.URL, io.Discard)
	if err := c.runClient("project", []string{"list", "-api-token", cliTestToken}); err != nil {
		t.Fatalf("project list with -api-token: %v", err)
	}

	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.seen) != 1 || rec.seen[0] != "GET Bearer "+cliTestToken {
		t.Fatalf("server saw %v, want [GET Bearer <flag token>]", rec.seen)
	}
}

func TestCLIAPITokenFlagAlsoBeatsAWorkingEnvironmentToken(t *testing.T) {
	rec := &authRecorder{requireT: flagTestToken}
	srv := httptest.NewServer(rec)
	defer srv.Close()

	t.Setenv("INDAGO_API_TOKEN", flagTestOther) // valid format, wrong for this server
	c := newCLI(srv.URL, io.Discard)
	if err := c.runClient("scan", []string{"list", "-api-token", flagTestToken}); err != nil {
		t.Fatalf("scan list with -api-token: %v", err)
	}
}

func TestCLIAPITokenFlagRefusesEmptyValue(t *testing.T) {
	c := newCLI("http://127.0.0.1:8750", io.Discard)
	for _, args := range [][]string{
		{"list", "-api-token", ""},
		{"list", "-api-token="},
	} {
		err := c.runClient("project", args)
		if err == nil || !strings.Contains(err.Error(), "-api-token") {
			t.Fatalf("%v: want an error naming -api-token, got %v", args, err)
		}
	}
}

// apiToken() is the single place precedence is decided; getRaw (report/evidence
// bytes) and call() must agree with it.
func TestCLITokenPrecedenceAppliesToEveryRequestPath(t *testing.T) {
	rec := &authRecorder{requireT: cliTestToken}
	srv := httptest.NewServer(rec)
	defer srv.Close()

	t.Setenv("INDAGO_API_TOKEN", "")
	os.Unsetenv("INDAGO_API_TOKEN")
	c := newCLI(srv.URL, io.Discard)
	if err := c.token.Set(cliTestToken); err != nil {
		t.Fatal(err)
	}
	if _, err := c.getRaw("/api/version"); err != nil {
		t.Fatalf("getRaw with -api-token: %v", err)
	}
	var list []any
	if err := c.call(http.MethodGet, "/api/projects", nil, &list); err != nil {
		t.Fatalf("call with -api-token: %v", err)
	}
	if c.apiToken() != cliTestToken {
		t.Fatalf("apiToken() = %q, want the flag value", c.apiToken())
	}
}

func TestClientHelpListsAPITokenAndNeverPrintsIt(t *testing.T) {
	t.Setenv("INDAGO_API_TOKEN", cliTestToken)
	out := &bytes.Buffer{}
	c := newCLI("http://127.0.0.1:8750", out)
	if err := c.runClient("project", []string{"create", "-h"}); err != nil {
		t.Fatalf("project create -h: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "-api-token") {
		t.Fatalf("help output does not list -api-token:\n%s", got)
	}
	if strings.Contains(got, cliTestToken) {
		t.Fatalf("help output leaks the environment token:\n%s", got)
	}
}

// The flag is bound in the shared FlagSet, so it must be present on every
// client subcommand — not only scan.
func TestEveryClientSubcommandAcceptsAPIToken(t *testing.T) {
	c := newCLI("http://127.0.0.1:8750", io.Discard)
	cmds := []struct {
		group string
		args  []string
	}{
		{"project", []string{"create", "-h"}},
		{"target", []string{"add", "-h"}},
		{"scope", []string{"set", "-h"}},
		{"scan", []string{"create", "-h"}},
		{"scan", []string{"status", "-h"}},
		{"finding", []string{"list", "-h"}},
		{"endpoint", []string{"list", "-h"}},
		{"auth", []string{"login", "-h"}},
		{"report", []string{"create", "-h"}},
	}
	for _, cmd := range cmds {
		out := &bytes.Buffer{}
		c.out = out
		if err := c.runClient(cmd.group, cmd.args); err != nil {
			t.Fatalf("%s %v: %v", cmd.group, cmd.args, err)
		}
		if !strings.Contains(out.String(), "-api-token") {
			t.Errorf("%s %v: help does not list -api-token:\n%s", cmd.group, cmd.args, out.String())
		}
	}
}
