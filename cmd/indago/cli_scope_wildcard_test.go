package main

// CLI coverage for the wildcard half of a project's scope (subdomain_only_hosts).
//
// `scope set` is a replace: it must be able to write a wildcard-only scope, and
// it must clear a wildcard list the operator no longer wants instead of relying
// on the server's "absent field means keep" rule (that rule exists so a UI save
// cannot silently delete an imported program's wildcard authorization).

import (
	"strings"
	"testing"
)

func TestCLIScopeSetWildcardOnly(t *testing.T) {
	c, out := newTestServer(t)
	must := func(args ...string) {
		t.Helper()
		if err := c.runClient("scope", args); err != nil {
			t.Fatalf("indago scope %v: %v", args, err)
		}
	}

	if err := c.runClient("project", []string{"create", "Wild"}); err != nil {
		t.Fatalf("project create: %v", err)
	}
	project := idFrom(t, out)
	out.Reset()

	// A wildcard-only scope: no include hosts, one subdomains-only host. The
	// scheme/port statement is mandatory and explicit.
	must("set", "-project", project, "-subdomains-only", "example.com", "-origins", "https://*.example.com")
	if !strings.Contains(out.String(), "subdomains only:      example.com") {
		t.Fatalf("scope output = %q, want the wildcard list", out.String())
	}
	if strings.Contains(out.String(), "include hosts:        example.com") {
		t.Fatalf("wildcard host was reported as an include host: %q", out.String())
	}
	out.Reset()

	// `show` must report it too (the field is not silently dropped on read).
	must("show", "-project", project)
	if !strings.Contains(out.String(), "subdomains only:      example.com") {
		t.Fatalf("scope show = %q, want the wildcard list", out.String())
	}
	out.Reset()

	// A plain replace without the flag clears the wildcard list.
	must("set", "-project", project, "-include", "app.example.com", "-origins", "https://app.example.com")
	if strings.Contains(out.String(), "subdomains only:      example.com") {
		t.Fatalf("plain scope set kept the wildcard list: %q", out.String())
	}
	if !strings.Contains(out.String(), "include hosts:        app.example.com") {
		t.Fatalf("scope output = %q, want the new include host", out.String())
	}
}
