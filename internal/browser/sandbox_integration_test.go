//go:build linux

package browser_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"github.com/indago/indago/internal/browser"
)

// chromiumProc is one Chromium process observed under the test binary.
type chromiumProc struct {
	pid     int
	kind    string // value of --type=, or "browser"
	noFlag  bool   // launched with --no-sandbox
	seccomp string // /proc/PID/status Seccomp field (2 = a BPF filter is active)
	cmdline string
	// isolatedNS lists which of the pid and net namespaces differ from this
	// test process. Both the user-namespace and the setuid Chromium sandbox
	// create these, and unlike Seccomp they are not inherited from an ambient
	// filter (Docker, systemd, a seccomp-wrapped CI runner).
	isolatedNS map[string]bool
}

// namespaceIsolation reports, per namespace, whether pid differs from this
// test process. An unreadable link counts as not isolated, so a probe failure
// can never pass as isolation.
func namespaceIsolation(pid int) map[string]bool {
	out := map[string]bool{}
	for _, ns := range []string{"pid", "net"} {
		self, err1 := os.Readlink("/proc/self/ns/" + ns)
		other, err2 := os.Readlink(fmt.Sprintf("/proc/%d/ns/%s", pid, ns))
		out[ns] = err1 == nil && err2 == nil && self != other
	}
	return out
}

// descendantChromium lists the Chromium processes beneath this test process.
// Chromium rewrites the argv of its child processes into one space-separated
// string, so the command line is split on whitespace, not only on NUL.
func descendantChromium(t *testing.T) []chromiumProc {
	t.Helper()
	out, err := exec.Command("ps", "-eo", "pid,ppid").Output()
	if err != nil {
		t.Fatalf("ps: %v", err)
	}
	kids := map[int][]int{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n")[1:] {
		f := strings.Fields(line)
		if len(f) != 2 {
			continue
		}
		p, _ := strconv.Atoi(f[0])
		pp, _ := strconv.Atoi(f[1])
		kids[pp] = append(kids[pp], p)
	}
	var procs []chromiumProc
	stack := append([]int(nil), kids[os.Getpid()]...)
	for len(stack) > 0 {
		pid := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		stack = append(stack, kids[pid]...)
		raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		if err != nil {
			continue // exited meanwhile
		}
		cmd := strings.ReplaceAll(string(raw), "\x00", " ")
		fields := strings.Fields(cmd)
		if len(fields) == 0 || !strings.Contains(fields[0], "chrom") {
			continue
		}
		p := chromiumProc{pid: pid, kind: "browser", cmdline: cmd, isolatedNS: namespaceIsolation(pid)}
		for _, a := range fields {
			if strings.HasPrefix(a, "--type=") {
				p.kind = strings.TrimPrefix(a, "--type=")
			}
			if a == "--no-sandbox" {
				p.noFlag = true
			}
		}
		status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
		if err != nil {
			continue
		}
		for _, l := range strings.Split(string(status), "\n") {
			if strings.HasPrefix(l, "Seccomp:") {
				p.seccomp = strings.TrimSpace(strings.TrimPrefix(l, "Seccomp:"))
			}
		}
		procs = append(procs, p)
	}
	return procs
}

// renderersWithOpenPage keeps one page open and returns the live renderers.
// Unlike newManagerOrSkip, a launch failure is a FAILURE here: a sandboxed
// launch that cannot start must never be reported as a skipped test.
func renderersWithOpenPage(t *testing.T, cfg browser.Config) []chromiumProc {
	t.Helper()
	exe := findChromium()
	if exe == "" {
		t.Skip("no Chromium found (set INDAGO_CHROMIUM_PATH)")
	}
	cfg.ExecutablePath = exe
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!doctype html><body>sandbox probe</body>`)
	}))
	defer srv.Close()

	m, err := browser.NewManager(cfg, nil)
	if err != nil {
		t.Fatalf("browser failed to start (sandboxDisabled=%v): %v", cfg.DisableSandbox, err)
	}
	defer m.Close()
	ctx := context.Background()
	c, err := m.NewContext(ctx, browser.ContextOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	p, err := c.NewPage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Navigate(ctx, srv.URL, browser.NavOptions{WaitUntil: browser.WaitLoad}); err != nil {
		t.Fatalf("navigate: %v", err)
	}
	var renderers []chromiumProc
	for _, pr := range descendantChromium(t) {
		if pr.kind == "renderer" {
			renderers = append(renderers, pr)
		}
	}
	if len(renderers) == 0 {
		t.Fatal("no renderer process observed beneath the test process; the probe cannot discriminate")
	}
	return renderers
}

// ownSeccomp is this test process's own Seccomp mode. A non-zero value means an
// ambient filter (Docker, systemd, a CI wrapper) is inherited by every child, so
// the Seccomp field alone cannot distinguish sandboxed from unsandboxed.
func ownSeccomp(t *testing.T) string {
	t.Helper()
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(l, "Seccomp:") {
			return strings.TrimSpace(strings.TrimPrefix(l, "Seccomp:"))
		}
	}
	t.Fatal("no Seccomp field in /proc/self/status")
	return ""
}

// The default configuration must run page content inside Chromium's process
// sandbox: no --no-sandbox, a seccomp-BPF filter (Seccomp: 2) and separate pid
// and net namespaces on every renderer, measured from the kernel rather than
// inferred from arguments.
func TestIntegrationDefaultConfigRendererIsSandboxed(t *testing.T) {
	for _, r := range renderersWithOpenPage(t, browser.DefaultConfig()) {
		if r.noFlag {
			t.Errorf("renderer %d was launched with --no-sandbox: %.200s", r.pid, r.cmdline)
		}
		if r.seccomp != "2" {
			t.Errorf("renderer %d has no seccomp filter (Seccomp: %q); the sandbox is not effective", r.pid, r.seccomp)
		}
		for _, ns := range []string{"pid", "net"} {
			if !r.isolatedNS[ns] {
				t.Errorf("renderer %d shares the scanner's %s namespace; the sandbox is not effective", r.pid, ns)
			}
		}
	}
}

// The explicit opt-out must really turn the sandbox off. This also proves the
// probe above discriminates: the same measurement reads differently here.
func TestIntegrationDisableSandboxIsExplicitOptOut(t *testing.T) {
	cfg := browser.DefaultConfig()
	cfg.DisableSandbox = true
	ambient := ownSeccomp(t)
	for _, r := range renderersWithOpenPage(t, cfg) {
		if !r.noFlag {
			t.Errorf("renderer %d should carry --no-sandbox when explicitly disabled: %.200s", r.pid, r.cmdline)
		}
		// Without the sandbox a renderer adds no filter of its own: it has only
		// whatever this process already inherited.
		if r.seccomp != ambient {
			t.Errorf("renderer %d has Seccomp %q, expected only the ambient %q with the sandbox disabled", r.pid, r.seccomp, ambient)
		}
		for _, ns := range []string{"pid", "net"} {
			if r.isolatedNS[ns] {
				t.Errorf("renderer %d has a separate %s namespace even though the sandbox is disabled", r.pid, ns)
			}
		}
	}
}
