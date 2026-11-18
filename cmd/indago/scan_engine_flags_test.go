package main

// The Wave-1 engine switches on `scan create`: every flag must reach the
// persisted domain.ScanConfig through the real API (CLI → web createScanReq →
// controller.CreateScan), and an OAST pair that cannot confirm anything is
// refused locally instead of creating a scan that silently probes nothing.

import (
	"context"
	"strings"
	"testing"

	"github.com/indago/indago/internal/domain"
)

func TestCLIScanCreateWiresWave1EngineFlags(t *testing.T) {
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

	err := run("scan", "create", "-project", project, "-target", target,
		"-enable-command-injection", "-enable-ssti", "-enable-sqli",
		"-enable-xxe", "-xxe-callback", "https://oast.example.test/hook", "-xxe-poll", "https://oast.example.test/poll",
		"-skip-ssrf", "-skip-cors", "-skip-open-redirect", "-skip-graphql",
		"-ssrf-callback", "https://oast.example.test/ssrf", "-ssrf-poll", "https://oast.example.test/ssrf-poll",
	)
	if err != nil {
		t.Fatalf("scan create: %v", err)
	}
	scanID := idFrom(t, out)

	sc, err := st.Scans().Get(context.Background(), domain.ID(scanID))
	if err != nil {
		t.Fatal(err)
	}
	cfg := sc.Config
	for _, tc := range []struct {
		name string
		got  bool
	}{
		{"enable_command_injection", cfg.EnableCommandInjection},
		{"enable_ssti", cfg.EnableSSTI},
		{"enable_sqli", cfg.EnableSQLi},
		{"enable_xxe", cfg.EnableXXE},
		{"skip_ssrf", cfg.SkipSSRF},
		{"skip_cors", cfg.SkipCORS},
		{"skip_open_redirect", cfg.SkipOpenRedirect},
		{"skip_graphql", cfg.SkipGraphQL},
	} {
		if !tc.got {
			t.Errorf("%s did not reach the stored ScanConfig", tc.name)
		}
	}
	for _, tc := range []struct{ name, got, want string }{
		{"xxe_callback_url", cfg.XXECallbackURL, "https://oast.example.test/hook"},
		{"xxe_callback_poll_url", cfg.XXECallbackPollURL, "https://oast.example.test/poll"},
		{"ssrf_callback_url", cfg.SSRFCallbackURL, "https://oast.example.test/ssrf"},
		{"ssrf_callback_poll_url", cfg.SSRFCallbackPollURL, "https://oast.example.test/ssrf-poll"},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %q, want %q", tc.name, tc.got, tc.want)
		}
	}
}

// Omitting every flag must leave the server's defaults alone: the Wave-1 skip
// switches stay false and the opt-in engines stay off.
func TestCLIScanCreateDefaultsLeaveWave1EnginesAlone(t *testing.T) {
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
	if err := run("scan", "create", "-project", project, "-target", target); err != nil {
		t.Fatal(err)
	}
	scanID := idFrom(t, out)

	sc, err := st.Scans().Get(context.Background(), domain.ID(scanID))
	if err != nil {
		t.Fatal(err)
	}
	cfg := sc.Config
	if cfg.SkipSSRF || cfg.SkipCORS || cfg.SkipOpenRedirect || cfg.SkipGraphQL {
		t.Errorf("an omitted -skip-* flag must not disable a default engine: %+v", cfg)
	}
	if cfg.EnableCommandInjection || cfg.EnableSSTI || cfg.EnableSQLi || cfg.EnableXXE {
		t.Errorf("an omitted -enable-* flag must not opt an engine in: %+v", cfg)
	}
	if cfg.SSRFCallbackURL != "" || cfg.SSRFCallbackPollURL != "" || cfg.XXECallbackURL != "" || cfg.XXECallbackPollURL != "" {
		t.Errorf("no callback URL may be invented: %+v", cfg)
	}
}

// One half of an OAST pair can never confirm anything, so it is rejected by
// the client before any request is made.
func TestCLIScanCreateRefusesHalfAnOASTPair(t *testing.T) {
	out := &strings.Builder{}
	// Nothing listens here: a request would fail with the "cannot reach the
	// indago server" error, which must NOT be what comes back.
	c := newCLI("http://127.0.0.1:1", out)
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"-ssrf-callback", "https://oast.example.test/hook"}, "-ssrf-poll"},
		{[]string{"-ssrf-poll", "https://oast.example.test/poll"}, "-ssrf-callback"},
		{[]string{"-xxe-callback", "https://oast.example.test/hook"}, "-xxe-poll"},
		{[]string{"-xxe-poll", "https://oast.example.test/poll"}, "-xxe-callback"},
	} {
		args := append([]string{"create", "-project", "p", "-target", "t"}, tc.args...)
		err := c.runClient("scan", args)
		if err == nil {
			t.Fatalf("%v: expected a usage error", tc.args)
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%v: error should name %s, got %v", tc.args, tc.want, err)
		}
		if strings.Contains(err.Error(), "cannot reach") {
			t.Fatalf("%v: the pair must be refused before any request is sent, got %v", tc.args, err)
		}
	}
}
