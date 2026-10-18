package deploy_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The Docker sandbox job must be a real, required CI gate and its verdict logic
// must not be vacuous. These tests pin both.

func TestCIDockerSandboxJobContract(t *testing.T) {
	wf := requireText(t, ".github/workflows/ci.yml",
		"docker-sandbox:",
		"docker build",
		"python3 scripts/ci-docker-sandbox-check.py",
		"timeout-minutes:",
	)
	// A gate that can fail without failing the run is not a gate.
	if strings.Contains(wf, "continue-on-error") {
		t.Error("CI must not use continue-on-error: the Docker sandbox job is a required gate")
	}
	requireText(t, "scripts/ci-docker-sandbox-check.py",
		// Supply chain: the upstream profile is pinned to a commit AND a hash.
		"6fe7deb1b9fb7c0397a4593480d7d22b9ee8caef",
		"6416b47770785a41ac59073cdc77d9fe98517df2799dc83ef207e622de3053f6",
		// The documented recipe: exactly these three syscalls are added.
		"clone", "unshare", "chroot",
		// Scenarios: fail-closed control, sandboxed run, discriminating control.
		"No usable sandbox", "--judge", "unsandboxed", "sandboxed",
	)
}

const (
	rootLine = "ROOT net=net:[1] pid=pid:[1] user=user:[1]\n"
	// Properly isolated renderer.
	goodRenderer = "P 101 renderer nosandbox=0 seccomp=2 nnp=1 net=net:[2] pidns=pid:[2] user=user:[2]\n"
	// Non-renderer rows are never evidence either way.
	browserRow = "P 50 browser nosandbox=0 seccomp=2 nnp=1 net=net:[1] pidns=pid:[1] user=user:[1]\n"
	// What an --no-sandbox renderer looks like inside Docker (seccomp inherited).
	openRenderer = "P 102 renderer nosandbox=1 seccomp=2 nnp=1 net=net:[1] pidns=pid:[1] user=user:[1]\n"
)

func TestCIDockerSandboxJudge(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, mode, input string
		wantPass          bool
		reason            string // required substring of the failure output
	}{
		{"sandboxed-ok", "sandboxed", rootLine + browserRow + goodRenderer + strings.Replace(goodRenderer, "101", "103", 1), true, ""},
		{"sandboxed-ok-ignores-unreadable-row", "sandboxed", rootLine + goodRenderer +
			"P 104 renderer nosandbox=0 seccomp=2 nnp=1 net=ERR pidns=ERR user=ERR\n", true, ""},
		{"sandboxed-no-renderer", "sandboxed", rootLine + browserRow, false, "no definite renderer"},
		{"sandboxed-only-unreadable", "sandboxed", rootLine +
			"P 104 renderer nosandbox=0 seccomp=2 nnp=1 net=ERR pidns=ERR user=ERR\n", false, "no definite renderer"},
		{"sandboxed-empty", "sandboxed", "", false, "scanner process"},
		{"sandboxed-no-root", "sandboxed", "NOROOT\n" + goodRenderer, false, "scanner process"},
		{"sandboxed-root-unreadable", "sandboxed", "ROOT net=ERR pid=ERR user=ERR\n" + goodRenderer, false, "unreadable"},
		{"sandboxed-flag", "sandboxed", rootLine + goodRenderer + openRenderer, false, "--no-sandbox"},
		// The flag is read from the command line, so an unreadable namespace
		// cannot hide an unsandboxed renderer.
		{"sandboxed-flag-despite-unreadable-ns", "sandboxed", rootLine + goodRenderer +
			"P 105 renderer nosandbox=1 seccomp=2 nnp=1 net=ERR pidns=ERR user=ERR\n", false, "--no-sandbox"},
		{"sandboxed-shares-net", "sandboxed", rootLine +
			"P 101 renderer nosandbox=0 seccomp=2 nnp=1 net=net:[1] pidns=pid:[2] user=user:[2]\n", false, "net namespace"},
		{"sandboxed-shares-pid", "sandboxed", rootLine +
			"P 101 renderer nosandbox=0 seccomp=2 nnp=1 net=net:[2] pidns=pid:[1] user=user:[2]\n", false, "pid namespace"},
		{"sandboxed-shares-user", "sandboxed", rootLine +
			"P 101 renderer nosandbox=0 seccomp=2 nnp=1 net=net:[2] pidns=pid:[2] user=user:[1]\n", false, "user namespace"},
		// Repeated polls: the latest definite row for a pid wins.
		{"sandboxed-repeated-polls", "sandboxed", rootLine + goodRenderer + rootLine + goodRenderer, true, ""},
		// Control: the probe must be able to read the opposite answer.
		{"unsandboxed-ok", "unsandboxed", rootLine + openRenderer, true, ""},
		{"unsandboxed-control-reads-sandboxed", "unsandboxed", rootLine + goodRenderer, false, "control did not read as unsandboxed"},
		{"unsandboxed-mixed", "unsandboxed", rootLine + openRenderer + goodRenderer, false, "control did not read as unsandboxed"},
		{"unsandboxed-no-renderer", "unsandboxed", rootLine + browserRow, false, "no definite renderer"},
		// An unreadable later sample must neither erase earlier evidence nor
		// hide an earlier bad row.
		{"sandboxed-later-unreadable-keeps-evidence", "sandboxed", rootLine + goodRenderer +
			"P 101 renderer nosandbox=0 seccomp=2 nnp=1 net=ERR pidns=ERR user=ERR\n", true, ""},
		{"sandboxed-later-unreadable-does-not-hide-bad-row", "sandboxed", rootLine +
			"P 101 renderer nosandbox=0 seccomp=2 nnp=1 net=net:[1] pidns=pid:[2] user=user:[2]\n" +
			"P 101 renderer nosandbox=0 seccomp=2 nnp=1 net=ERR pidns=ERR user=ERR\n", false, "net namespace"},
		{"unsandboxed-all-unreadable", "unsandboxed", rootLine +
			"P 102 renderer nosandbox=1 seccomp=2 nnp=1 net=ERR pidns=ERR user=ERR\n", false, "no definite renderer"},
		// Startup-log checks. Only the sandbox warning counts: an unrelated
		// "DISABLED" message (e.g. the API rate limit) must not decide anything.
		{"log-sandboxed-ok", "log-sandboxed", `level=INFO msg="browser manager started" pool=1 headless=true sandbox=true` + "\n", true, ""},
		{"log-sandboxed-ignores-unrelated-disabled", "log-sandboxed",
			`level=WARN msg="api rate limit DISABLED"` + "\n" +
				`level=INFO msg="browser manager started" pool=1 headless=true sandbox=true` + "\n", true, ""},
		{"log-sandboxed-missing", "log-sandboxed", `level=INFO msg="web server listening"` + "\n", false, "sandbox=true"},
		{"log-sandboxed-has-warning", "log-sandboxed",
			`level=WARN msg="Chromium process sandbox is DISABLED (--no-sandbox): hostile page"` + "\n" +
				`level=INFO msg="browser manager started" sandbox=true` + "\n", false, "sandbox-disabled warning"},
		{"log-optout-ok", "log-optout",
			`level=WARN msg="Chromium process sandbox is DISABLED (--no-sandbox): hostile page"` + "\n" +
				`level=INFO msg="browser manager started" sandbox=false` + "\n", true, ""},
		{"log-optout-missing-warning", "log-optout", `level=INFO msg="browser manager started" sandbox=false` + "\n", false, "warning"},
		{"log-optout-claims-sandbox", "log-optout",
			`level=WARN msg="Chromium process sandbox is DISABLED"` + "\n" + `level=INFO msg="browser manager started" sandbox=true` + "\n", false, "sandbox=false"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := filepath.Join(t.TempDir(), "measure.txt")
			if err := os.WriteFile(f, []byte(tc.input), 0600); err != nil {
				t.Fatal(err)
			}
			out, err := exec.Command(python, "../scripts/ci-docker-sandbox-check.py", "--judge", tc.mode, f).CombinedOutput()
			if (err == nil) != tc.wantPass {
				t.Fatalf("pass=%v want %v; err=%v\n%s", err == nil, tc.wantPass, err, out)
			}
			if !tc.wantPass && !strings.Contains(strings.ToLower(string(out)), strings.ToLower(tc.reason)) {
				t.Fatalf("failed for the wrong reason: want substring %q in:\n%s", tc.reason, out)
			}
		})
	}
}
