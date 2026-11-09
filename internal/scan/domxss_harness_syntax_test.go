package scan

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// The init-script harness is injected into every page a DOM scan opens. A
// syntax error there would silently disable the whole pass, so the generated
// script is parsed by a real JavaScript engine when one is available.
func TestDOMXSSHarnessIsValidJavaScript(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "harness.js")
	if err := os.WriteFile(path, []byte(domXSSHarnessScript("indM123")), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(node, "--check", path).CombinedOutput()
	if err != nil {
		t.Fatalf("harness does not parse: %v\n%s", err, out)
	}
}
