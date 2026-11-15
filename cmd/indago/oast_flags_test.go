package main

// Tests for the serve command's built-in OAST collaborator flags. The point of
// these flags is that the whole wiring is a no-op unless -oast-addr is given,
// so both halves matter: "nothing requested" must stay exactly as it was, and
// "requested" must produce a manager the scan layer can actually use.

import (
	"context"
	"net"
	"net/url"
	"strings"
	"testing"

	"github.com/indago/indago/internal/oast"
)

func TestOASTWiringServeFlagsDisabledByDefault(t *testing.T) {
	cfg, requested, err := oastConfigFromFlags("", "", false)
	if err != nil {
		t.Fatalf("no flags: %v", err)
	}
	if requested {
		t.Fatal("requested = true with no -oast-addr, want nothing started")
	}
	if cfg.ListenAddr != "" || cfg.PublicBaseURL != "" || cfg.Mode != "" {
		t.Fatalf("config = %+v, want the zero value when nothing was requested", cfg)
	}
}

func TestOASTWiringServeFlagsValidation(t *testing.T) {
	cases := []struct {
		name      string
		addr      string
		publicURL string
		allow     bool
		wantErr   string
	}{
		{"public URL without a listener", "", "https://abc.example-tunnel.net", false, "-oast-addr"},
		{"missing port", "127.0.0.1", "", false, "host:port"},
		{"bad public URL", "127.0.0.1:0", "not-a-url", false, ""}, // rejected by oast.New, not here
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg, requested, err := oastConfigFromFlags(c.addr, c.publicURL, c.allow)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("err = %v, want it to mention %q", err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !requested {
				t.Fatal("requested = false, want true")
			}
			if cfg.Mode != oast.ModeLocal {
				t.Fatalf("mode = %q, want the built-in local listener", cfg.Mode)
			}
			// The public URL itself is validated where every other manager
			// setting is: oast.New.
			if _, nerr := oast.New(context.Background(), cfg); nerr == nil {
				t.Fatalf("oast.New accepted the invalid public URL %q", c.publicURL)
			}
		})
	}
}

// TestOASTWiringServeFlagsStartsUsableManager is the real assertion: a serve
// invocation with -oast-addr only yields something an operator can rely on if
// the manager answers, publishes a callback URL and exposes a loopback poll
// API the scan engines can read.
func TestOASTWiringServeFlagsStartsUsableManager(t *testing.T) {
	cfg, requested, err := oastConfigFromFlags("127.0.0.1:0", "https://abc.example-tunnel.net", false)
	if err != nil {
		t.Fatalf("oastConfigFromFlags: %v", err)
	}
	if !requested {
		t.Fatal("requested = false with -oast-addr set")
	}
	cfg.Logger = nil
	mgr, err := oast.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("oast.New: %v", err)
	}
	defer mgr.Close()

	// The callback URL is what a target is given: the published one, not the
	// loopback listener behind it.
	if mgr.BaseURL() != "https://abc.example-tunnel.net" {
		t.Fatalf("base URL = %q, want -oast-public-url", mgr.BaseURL())
	}
	if host, _, _ := net.SplitHostPort(mgr.ListenAddr()); host != "127.0.0.1" {
		t.Fatalf("listener = %q, want it bound to loopback", mgr.ListenAddr())
	}
	poll, err := mgr.PollURL()
	if err != nil {
		t.Fatalf("PollURL: %v", err)
	}
	u, err := url.Parse(poll)
	if err != nil {
		t.Fatalf("parse poll URL: %v", err)
	}
	if u.Hostname() != "127.0.0.1" {
		t.Fatalf("poll host = %q, want loopback even when the listener is published", u.Host)
	}
	if strings.Contains(poll, "abc.example-tunnel.net") {
		t.Fatalf("poll URL %q leaks the published name", poll)
	}
}

func TestOASTWiringServeFlagsRefusesExternalBindWithoutOptIn(t *testing.T) {
	cfg, requested, err := oastConfigFromFlags("0.0.0.0:0", "", false)
	if err != nil {
		t.Fatalf("oastConfigFromFlags: %v", err)
	}
	if !requested || cfg.AllowExternalBind {
		t.Fatalf("config = %+v, want the bind left unacknowledged", cfg)
	}
	if _, err := oast.New(context.Background(), cfg); err == nil {
		t.Fatal("oast.New accepted a wildcard bind without -oast-allow-external-bind")
	}

	cfg, _, err = oastConfigFromFlags("0.0.0.0:0", "", true)
	if err != nil {
		t.Fatalf("oastConfigFromFlags (acknowledged): %v", err)
	}
	if !cfg.AllowExternalBind {
		t.Fatal("AllowExternalBind = false after the explicit opt-in")
	}
}
