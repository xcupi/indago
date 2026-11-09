package disclosure_test

import (
	"bytes"
	"compress/zlib"
	"encoding/hex"
	"testing"

	"github.com/indago/indago/internal/disclosure"
)

func gitObject(t *testing.T, kind, payload string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write([]byte(kind + " " + itoa(len(payload)) + "\x00" + payload)); err != nil {
		t.Fatalf("write object: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close object: %v", err)
	}
	return buf.Bytes()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func treePayload(entries ...disclosure.GitTreeEntry) string {
	var b bytes.Buffer
	for _, e := range entries {
		raw, _ := hex.DecodeString(e.SHA)
		b.WriteString(e.Mode + " " + e.Name + "\x00")
		b.Write(raw)
	}
	return b.String()
}

func TestGitHeadRef(t *testing.T) {
	ref, sha, ok := disclosure.GitHeadRef([]byte("ref: refs/heads/master\n"))
	if !ok || ref != "refs/heads/master" || sha != "" {
		t.Fatalf("ref HEAD = %q/%q/%v", ref, sha, ok)
	}
	detached := "0123456789abcdef0123456789abcdef01234567"
	_, sha, ok = disclosure.GitHeadRef([]byte(detached + "\n"))
	if !ok || sha != detached {
		t.Fatalf("detached HEAD = %q/%v", sha, ok)
	}
	if _, _, ok := disclosure.GitHeadRef([]byte("<html>not found</html>")); ok {
		t.Fatal("an HTML page must not parse as a HEAD")
	}
}

func TestGitConfigIsRepository(t *testing.T) {
	cfg := []byte("[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n")
	if !disclosure.GitConfigIsRepository(cfg) {
		t.Fatal("a real config must be accepted")
	}
	if disclosure.GitConfigIsRepository([]byte("<html>A page about git config</html>")) {
		t.Fatal("an HTML page must be refused")
	}
}

func TestGitLogSHAsNewestFirst(t *testing.T) {
	old := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	newer := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	logs := old + " " + old + " User <u@example> 1 +0000\tinit\n" +
		old + " " + newer + " User <u@example> 2 +0000\tsecond\n"
	got := disclosure.GitLogSHAs([]byte(logs), 3)
	if len(got) != 2 || got[0] != newer || got[1] != old {
		t.Fatalf("log SHAs = %v, want newest first", got)
	}
}

func TestInflateCommitTreeAndSubject(t *testing.T) {
	tree := "cccccccccccccccccccccccccccccccccccccccc"
	raw := gitObject(t, "commit", "tree "+tree+"\nauthor A <a@example> 1 +0000\ncommitter A <a@example> 1 +0000\n\nAdd config\n")
	kind, payload, ok := disclosure.InflateLooseObject(raw)
	if !ok || kind != "commit" {
		t.Fatalf("inflate = %q/%v", kind, ok)
	}
	gotTree, ok := disclosure.GitCommitTree(payload)
	if !ok || gotTree != tree {
		t.Fatalf("commit tree = %q/%v", gotTree, ok)
	}
	if subject := disclosure.GitCommitSubject(payload); subject != "Add config" {
		t.Fatalf("subject = %q", subject)
	}
}

func TestParseGitTreeAndSecretHint(t *testing.T) {
	blobSHA := "dddddddddddddddddddddddddddddddddddddddd"
	srcSHA := "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	payload := treePayload(
		disclosure.GitTreeEntry{Mode: "100644", Name: ".env", SHA: blobSHA},
		disclosure.GitTreeEntry{Mode: "100755", Name: "run.sh", SHA: srcSHA},
	)
	raw := gitObject(t, "tree", payload)
	kind, body, ok := disclosure.InflateLooseObject(raw)
	if !ok || kind != "tree" {
		t.Fatalf("inflate tree = %q/%v", kind, ok)
	}
	entries := disclosure.ParseGitTree(body)
	if len(entries) != 2 || entries[0].Name != ".env" || entries[0].SHA != blobSHA {
		t.Fatalf("tree entries = %+v", entries)
	}
	if !disclosure.GitBlobNameInteresting(".env") || disclosure.GitBlobNameInteresting("logo.png") {
		t.Fatal("blob interest ranking is wrong")
	}
	key, found := disclosure.GitSecretHint([]byte("DB_PASSWORD=hunter2\n"))
	if !found || key != "db_password" {
		t.Fatalf("secret hint = %q/%v", key, found)
	}
	if _, found := disclosure.GitSecretHint([]byte("just text\n")); found {
		t.Fatal("plain text must not be reported as a credential")
	}
}

func TestInflateRejectsNonGitBytes(t *testing.T) {
	if _, _, ok := disclosure.InflateLooseObject([]byte("<html>404</html>")); ok {
		t.Fatal("HTML must not inflate as an object")
	}
}
