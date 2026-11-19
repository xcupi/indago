package main

// -allow-insecure-tls on `scan create` must reach the persisted
// domain.ScanConfig through the real API (CLI -> createScanReq ->
// Controller.CreateScan), and omitting it must leave strict verification on.

import (
	"context"
	"testing"

	"github.com/indago/indago/internal/domain"
)

func TestCLIScanCreateAllowInsecureTLSFlag(t *testing.T) {
	c, out, st, _ := newTestServerAndStore(t)
	site := targetSite(t)
	run := func(group string, args ...string) error { t.Helper(); return c.runClient(group, args) }

	if err := run("project", "create", "p"); err != nil {
		t.Fatal(err)
	}
	project := idFrom(t, out)
	if err := run("scope", "set", "-project", project, "-include", "127.0.0.1", "-origins", site.URL); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := run("target", "add", "-project", project, "-name", "s", "-url", site.URL); err != nil {
		t.Fatal(err)
	}
	target := idFrom(t, out)

	if err := run("scan", "create", "-project", project, "-target", target, "-allow-insecure-tls"); err != nil {
		t.Fatalf("scan create -allow-insecure-tls: %v", err)
	}
	on, err := st.Scans().Get(context.Background(), domain.ID(idFrom(t, out)))
	if err != nil {
		t.Fatal(err)
	}
	if !on.Config.AllowInsecureTLS {
		t.Fatalf("-allow-insecure-tls did not reach the stored ScanConfig: %+v", on.Config)
	}

	// Omitted: the default scan keeps strict certificate verification.
	out.Reset()
	if err := run("scan", "create", "-project", project, "-target", target); err != nil {
		t.Fatalf("scan create (default): %v", err)
	}
	off, err := st.Scans().Get(context.Background(), domain.ID(idFrom(t, out)))
	if err != nil {
		t.Fatal(err)
	}
	if off.Config.AllowInsecureTLS {
		t.Fatalf("an omitted -allow-insecure-tls must stay off (strict verification), got %+v", off.Config)
	}
}
