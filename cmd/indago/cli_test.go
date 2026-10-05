package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/evidence"
	"github.com/indago/indago/internal/httpengine"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/scan"
	"github.com/indago/indago/internal/store"
	"github.com/indago/indago/internal/store/memory"
	"github.com/indago/indago/internal/web"
)

// newTestServer runs the real web handler + controller and returns a CLI aimed
// at it, plus the captured output.
func newTestServer(t *testing.T) (*cli, *bytes.Buffer) {
	t.Helper()
	c, out, _, _ := newTestServerAndStore(t)
	return c, out
}

// newTestServerAndStore is newTestServer plus direct access to the store and
// evidence backing it, for tests that seed findings/evidence directly instead
// of driving a full scan (detection/verification are out of scope here; this
// phase only exposes already-correlated data over HTTP).
func newTestServerAndStore(t *testing.T) (*cli, *bytes.Buffer, store.Store, evidence.Store) {
	t.Helper()
	cfg := httpengine.DefaultConfig()
	cfg.FollowRedirects = false
	eng, err := httpengine.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(eng.Close)

	st, q := memory.New(), queue.NewMemory()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctrl := scan.NewController(st, q, log, "test", scan.Options{
		HTTP: eng, IdlePoll: 10 * time.Millisecond, PollInterval: 20 * time.Millisecond,
	})
	t.Cleanup(ctrl.Shutdown)
	evStore, err := evidence.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(web.NewServer(st, ctrl, "test", log, evStore, t.TempDir()).Handler())
	t.Cleanup(srv.Close)

	out := &bytes.Buffer{}
	return newCLI(srv.URL, out), out, st, evStore
}

var uuidRe = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

// idFrom extracts the first UUID from the CLI's last output.
func idFrom(t *testing.T, out *bytes.Buffer) string {
	t.Helper()
	id := uuidRe.FindString(out.String())
	if id == "" {
		t.Fatalf("no ID in output: %q", out.String())
	}
	out.Reset()
	return id
}

func targetSite(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, `<a href="/x?id=1">x</a><form action="/f" method="post"><input name="q"></form>`)
	})
	mux.HandleFunc("/x", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") })
	mux.HandleFunc("/f", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestCLIWorkflowAndStatus(t *testing.T) {
	c, out := newTestServer(t)
	site := targetSite(t)

	must := func(group string, args ...string) {
		t.Helper()
		if err := c.runClient(group, args); err != nil {
			t.Fatalf("indago %s %v: %v", group, args, err)
		}
	}

	must("project", "create", "Acme")
	project := idFrom(t, out)
	must("scope", "set", "-project", project, "-include", "127.0.0.1")
	if !strings.Contains(out.String(), "127.0.0.1") {
		t.Fatalf("scope output: %q", out.String())
	}
	out.Reset()
	must("target", "add", "-project", project, "-name", "site", "-url", site.URL)
	target := idFrom(t, out)
	must("scan", "create", "-project", project, "-target", target, "-name", "cli scan", "-profile", "fast")
	scanID := idFrom(t, out)

	// Flags may follow the positional ID.
	must("scan", "start", scanID[:8], "-server", c.server)
	if !strings.Contains(out.String(), "scan "+scanID) {
		t.Fatalf("start output: %q", out.String())
	}
	out.Reset()

	// Poll status until the scan completes; the output must show discovery.
	deadline := time.Now().Add(10 * time.Second)
	for {
		out.Reset()
		must("scan", "status", scanID)
		if strings.Contains(out.String(), "State      completed") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("scan never completed:\n%s", out.String())
		}
		time.Sleep(30 * time.Millisecond)
	}
	status := out.String()
	if strings.Contains(status, "no live execution") {
		t.Errorf("a completed scan should not be flagged as needing a resume:\n%s", status)
	}
	for _, want := range []string{"Discovery  complete", "endpoints", "by source:", "crawler=", "form=", "user_provided=", "Jobs ", "Tests      success", "Findings"} {
		if !strings.Contains(status, want) {
			t.Errorf("status output missing %q:\n%s", want, status)
		}
	}

	// JSON status round-trips.
	out.Reset()
	must("scan", "status", scanID, "-json")
	var st scan.Status
	if err := json.Unmarshal(out.Bytes(), &st); err != nil {
		t.Fatalf("status -json is not JSON: %v\n%s", err, out.String())
	}
	if string(st.Scan.ID) != scanID || st.Discovery.Endpoints < 3 {
		t.Fatalf("json status: %+v", st.Discovery)
	}

	out.Reset()
	must("scan", "list")
	if !strings.Contains(out.String(), scanID) || !strings.Contains(out.String(), "completed") {
		t.Fatalf("scan list: %q", out.String())
	}
}

func TestCLIPauseResumeCancel(t *testing.T) {
	c, out := newTestServer(t)
	// A target that never answers keeps discovery in flight.
	block := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-block:
		case <-r.Context().Done():
		}
	}))
	defer slow.Close()
	defer close(block)

	run := func(group string, args ...string) {
		t.Helper()
		if err := c.runClient(group, args); err != nil {
			t.Fatalf("%s %v: %v", group, args, err)
		}
	}
	run("project", "create", "p")
	project := idFrom(t, out)
	run("scope", "set", "-project", project, "-include", "127.0.0.1")
	out.Reset()
	run("target", "add", "-project", project, "-name", "t", "-url", slow.URL)
	target := idFrom(t, out)
	run("scan", "create", "-project", project, "-target", target)
	scanID := idFrom(t, out)
	run("scan", "start", scanID)

	// Ordered: each step depends on the previous one's resulting state.
	for _, step := range []struct{ action, want string }{
		{"pause", "paused"}, {"resume", "running"}, {"cancel", "canceled"},
	} {
		out.Reset()
		run("scan", step.action, scanID)
		if !strings.Contains(out.String(), "now "+step.want) {
			t.Fatalf("%s: %q", step.action, out.String())
		}
	}
}

func TestCLIErrorsAreActionable(t *testing.T) {
	c, out := newTestServer(t)

	// Unknown scan → the server's message, with the HTTP status.
	err := c.runClient("scan", []string{"status", "does-not-exist"})
	if err == nil || !strings.Contains(err.Error(), "no scan matches") {
		t.Fatalf("expected 'no scan matches', got %v", err)
	}

	// Server-side validation error is surfaced verbatim.
	c.runClient("project", []string{"create", "p"})
	project := idFrom(t, out)
	err = c.runClient("scope", []string{"set", "-project", project, "-include", " , "})
	if err == nil {
		t.Fatal("expected an error for an empty include list")
	}
	var ae *apiError
	if !asAPIError(err, &ae) || ae.Status != 400 {
		t.Fatalf("expected a 400 apiError, got %v", err)
	}

	// Missing flags give usage, not a confusing server error.
	if err := c.runClient("target", []string{"add", "-project", project}); err == nil || !strings.Contains(err.Error(), "usage") {
		t.Fatalf("expected usage error, got %v", err)
	}
	if err := c.runClient("scan", []string{"bogus"}); err == nil {
		t.Fatal("expected an error for an unknown subcommand")
	}
	if err := c.runClient("scan", nil); err == nil {
		t.Fatal("expected a usage error with no subcommand")
	}
}

func asAPIError(err error, target **apiError) bool {
	for err != nil {
		if ae, ok := err.(*apiError); ok {
			*target = ae
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

func TestCLIAmbiguousPrefix(t *testing.T) {
	c, out := newTestServer(t)
	site := targetSite(t)
	c.runClient("project", []string{"create", "p"})
	project := idFrom(t, out)
	c.runClient("scope", []string{"set", "-project", project, "-include", "127.0.0.1"})
	out.Reset()
	c.runClient("target", []string{"add", "-project", project, "-name", "t", "-url", site.URL})
	target := idFrom(t, out)
	// Create scans until two share a first character (guaranteed within 17).
	var ids []string
	for i := 0; i < 17; i++ {
		if err := c.runClient("scan", []string{"create", "-project", project, "-target", target}); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, idFrom(t, out))
	}
	seen := map[byte]bool{}
	var shared string
	for _, id := range ids {
		if seen[id[0]] {
			shared = id[:1]
			break
		}
		seen[id[0]] = true
	}
	if shared == "" {
		t.Skip("no shared prefix produced (astronomically unlikely)")
	}
	err := c.runClient("scan", []string{"status", shared})
	if err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("expected ambiguity error, got %v", err)
	}
}

func TestCLIServerUnreachable(t *testing.T) {
	out := &bytes.Buffer{}
	c := newCLI("http://127.0.0.1:1", out) // nothing listens on port 1
	err := c.runClient("scan", []string{"list"})
	if err == nil || !strings.Contains(err.Error(), "indago serve") {
		t.Fatalf("expected a hint to run `indago serve`, got %v", err)
	}
}

func TestIsLoopbackAddr(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1:8750": true, "localhost:8750": true, "[::1]:8750": true,
		"0.0.0.0:8750": false, ":8750": false, "10.0.0.5:8750": false, "garbage": false,
	} {
		if got := isLoopbackAddr(addr); got != want {
			t.Errorf("isLoopbackAddr(%q) = %v, want %v", addr, got, want)
		}
	}
}

func TestCheckRemoteBindAllowed(t *testing.T) {
	cases := []struct {
		addr        string
		allowRemote bool
		wantErr     bool
	}{
		{"127.0.0.1:8750", false, false},
		{"localhost:8750", false, false},
		{"0.0.0.0:8750", false, true},  // non-loopback, not opted in: refused
		{"10.0.0.5:8750", false, true}, // non-loopback, not opted in: refused
		{"0.0.0.0:8750", true, false},  // non-loopback, explicit opt-in: allowed
		{"10.0.0.5:8750", true, false}, // non-loopback, explicit opt-in: allowed
	}
	for _, c := range cases {
		err := checkRemoteBindAllowed(c.addr, c.allowRemote)
		if (err != nil) != c.wantErr {
			t.Errorf("checkRemoteBindAllowed(%q, %v) = %v, wantErr %v", c.addr, c.allowRemote, err, c.wantErr)
		}
		if err != nil && !strings.Contains(err.Error(), "-allow-remote") {
			t.Errorf("error should mention -allow-remote: %v", err)
		}
	}
}

func TestCLIScanCreateExistingSession(t *testing.T) {
	c, out, st, _ := newTestServerAndStore(t)
	site := targetSite(t)
	run := func(group string, args ...string) error { t.Helper(); return c.runClient(group, args) }

	if err := run("project", "create", "p"); err != nil {
		t.Fatal(err)
	}
	project := idFrom(t, out)
	if err := run("scope", "set", "-project", project, "-include", "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := run("target", "add", "-project", project, "-name", "s", "-url", site.URL); err != nil {
		t.Fatal(err)
	}
	target := idFrom(t, out)

	// A relative -auth-state is resolved against the CLI's working directory,
	// not the server's; -auth defaults to "existing" when a state is given.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte(`{"cookies":[],"origins":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	if err := run("scan", "create", "-project", project, "-target", target, "-auth-state", "state.json"); err != nil {
		t.Fatalf("create with existing session: %v", err)
	}
	scanID := idFrom(t, out)
	sess, err := st.Sessions().GetByScan(context.Background(), domain.ID(scanID))
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(dir, "state.json"); sess.Mode != domain.AuthExisting || sess.StatePath != want {
		t.Fatalf("session = mode %s path %q, want existing %q", sess.Mode, sess.StatePath, want)
	}

	// Unusable configurations come back as the server's clear 400.
	for _, args := range [][]string{
		{"-auth", "existing"},
		{"-auth-state", "missing.json"},
		{"-auth", "password"},
		{"-auth", "anonymous", "-auth-state", "state.json"},
	} {
		err := run("scan", append([]string{"create", "-project", project, "-target", target}, args...)...)
		var ae *apiError
		if !asAPIError(err, &ae) || ae.Status != 400 || !strings.Contains(err.Error(), "authentication") {
			t.Errorf("%v: want a 400 authentication error, got %v", args, err)
		}
	}
}
