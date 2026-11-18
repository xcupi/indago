package main

// CLI coverage for the scheme/port half of a project's scope.
//
// `scope set` is a replace, so it must state the scheme/port policy explicitly:
// -origins names the exact origins, -allow-any-scheme-port records the legacy
// any-scheme/any-port choice, and a command with neither is refused before any
// request is sent. Nothing is derived from the host list, so a scope can never
// gain a scheme or port the operator did not write.

import (
	"bytes"
	"strings"
	"testing"

	"github.com/indago/indago/internal/domain"
)

func TestCLIScopeSetOriginRules(t *testing.T) {
	c, out := newTestServer(t)
	must := func(args ...string) {
		t.Helper()
		if err := c.runClient("scope", args); err != nil {
			t.Fatalf("indago scope %v: %v", args, err)
		}
	}
	if err := c.runClient("project", []string{"create", "Origins"}); err != nil {
		t.Fatalf("project create: %v", err)
	}
	project := idFrom(t, out)
	out.Reset()

	// No policy flags: refused locally, with the two ways to state one.
	err := c.runClient("scope", []string{"set", "-project", project, "-include", "app.example.com"})
	if err == nil {
		t.Fatal("expected `scope set` without a scheme/port policy to be refused")
	}
	if !strings.Contains(err.Error(), "state the scheme/port policy") {
		t.Fatalf("error = %v, want the policy message", err)
	}
	if !strings.Contains(err.Error(), "-origins") || !strings.Contains(err.Error(), "-allow-any-scheme-port") {
		t.Fatalf("error = %v, want both flags named", err)
	}
	out.Reset()

	// An explicit origin is stored exactly, with no second scheme or port.
	must("set", "-project", project, "-include", "app.example.com", "-origins", "https://app.example.com:8443")
	if got := out.String(); !strings.Contains(got, "allowed origins:      https://app.example.com:8443") {
		t.Fatalf("scope output = %q, want the explicit origin", got)
	}
	if strings.Contains(out.String(), "http://app.example.com") {
		t.Fatalf("plain http was authorized by an https-only statement: %q", out.String())
	}
	out.Reset()

	// `show` reports the persisted rule too.
	must("show", "-project", project)
	if got := out.String(); !strings.Contains(got, "allowed origins:      https://app.example.com:8443") {
		t.Fatalf("scope show = %q, want the explicit origin", got)
	}
	out.Reset()

	// The explicit legacy opt-out is visible instead of looking like an empty
	// unconfigured field.
	must("set", "-project", project, "-include", "app.example.com", "-allow-any-scheme-port")
	if got := out.String(); !strings.Contains(got, "any scheme and port — explicitly chosen") {
		t.Fatalf("scope output = %q, want the explicit legacy opt-out", got)
	}
	out.Reset()

	// Declaring both is contradictory and refused before any request.
	err = c.runClient("scope", []string{"set", "-project", project, "-include", "app.example.com", "-origins", "https://app.example.com", "-allow-any-scheme-port"})
	if err == nil {
		t.Fatal("expected -origins with -allow-any-scheme-port to be refused")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("error = %v, want a mutual-exclusion message", err)
	}
}

// printScope is the only place an operator sees what a stored scope means, so a
// scope with no origin list must say it is legacy instead of printing an empty
// line (or, worse, implying a standard-port rule exists).
func TestPrintScopeLabelsLegacyClearly(t *testing.T) {
	var buf bytes.Buffer
	printScope(&buf, &domain.Scope{IncludeHosts: []string{"app.example.com"}})
	if got := buf.String(); !strings.Contains(got, "legacy: no scheme/port rule recorded") {
		t.Fatalf("legacy scope output = %q, want the legacy label", got)
	}
	buf.Reset()
	printScope(&buf, &domain.Scope{IncludeHosts: []string{"app.example.com"}, AllowAnySchemePorts: true})
	if got := buf.String(); !strings.Contains(got, "any scheme and port — explicitly chosen") {
		t.Fatalf("explicit opt-out output = %q, want the explicit label", got)
	}
}
