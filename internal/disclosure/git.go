package disclosure

// Version-control history disclosure (the exposed-.git class).
//
// The leak is not one response: the origin serves its own repository metadata,
// so the caller can reconstruct history that was never meant to be public. The
// rules here are pure parsers over the bytes the scan fetched, plus one small
// git object decoder:
//
//   - HEAD names a ref (or a raw commit id);
//   - .git/config is a real repository file, not a page that mentions git;
//   - .git/logs/HEAD lists commit ids the caller can fetch;
//   - a loose object decompresses to "commit <size>\0…" and names its tree;
//   - a tree lists blobs, and a blob may carry a credential literal.
//
// Nothing is written and nothing is executed: the pass is GET-only, and the
// finding quotes what the repository itself published (credential values are
// reported by NAME, never echoed).

import (
	"bytes"
	"compress/zlib"
	"encoding/hex"
	"io"
	"regexp"
	"strconv"
	"strings"
)

// GitHeadPath, GitConfigPath and GitLogPath are the fixed metadata paths the
// probe reads on one origin. They are the three files a served .git directory
// exposes without needing a pack decoder.
const (
	GitHeadPath   = "/.git/HEAD"
	GitConfigPath = "/.git/config"
	GitLogPath    = "/.git/logs/HEAD"
)

// MaxGitLogCommits bounds how many commit ids one logs/HEAD file contributes.
const MaxGitLogCommits = 3

var (
	gitRefRE    = regexp.MustCompile(`^ref:\s+(refs/[A-Za-z0-9._/-]+)\s*$`)
	gitSHA1RE   = regexp.MustCompile(`^[0-9a-f]{40}$`)
	gitSHA256RE = regexp.MustCompile(`^[0-9a-f]{64}$`)
	gitLogRE    = regexp.MustCompile(`(?m)^[0-9a-f]{40,64} ([0-9a-f]{40,64}) `)
)

// GitHeadRef parses .git/HEAD. It returns the ref it names (empty for a
// detached HEAD) and the commit id when HEAD carries one directly.
func GitHeadRef(body []byte) (ref, sha string, ok bool) {
	line := strings.TrimSpace(string(body))
	if line == "" || strings.Contains(line, "\x00") {
		return "", "", false
	}
	if m := gitRefRE.FindStringSubmatch(line); m != nil {
		return m[1], "", true
	}
	if gitSHA1RE.MatchString(line) || gitSHA256RE.MatchString(line) {
		return "", line, true
	}
	return "", "", false
}

// GitConfigIsRepository reports whether the body is a git repository config:
// the [core] section with repositoryformatversion, which a page that merely
// mentions git does not carry.
func GitConfigIsRepository(body []byte) bool {
	lower := strings.ToLower(string(body))
	return strings.Contains(lower, "[core]") &&
		strings.Contains(lower, "repositoryformatversion") &&
		!strings.Contains(lower, "<html")
}

// GitLogSHAs returns the commit ids .git/logs/HEAD records, newest last in the
// file and therefore reported newest FIRST, de-duplicated and capped.
func GitLogSHAs(body []byte, max int) []string {
	if max <= 0 {
		max = MaxGitLogCommits
	}
	matches := gitLogRE.FindAllStringSubmatch(string(body), -1)
	out := make([]string, 0, max)
	seen := map[string]struct{}{}
	for i := len(matches) - 1; i >= 0; i-- {
		sha := matches[i][1]
		if _, dup := seen[sha]; dup {
			continue
		}
		seen[sha] = struct{}{}
		out = append(out, sha)
		if len(out) >= max {
			break
		}
	}
	return out
}

// GitObjectURL is the loose-object URL for one commit/blob id.
func GitObjectURL(origin, sha string) string {
	if len(sha) < 4 || origin == "" {
		return ""
	}
	return origin + "/.git/objects/" + sha[:2] + "/" + sha[2:]
}

// InflateLooseObject decodes one loose git object: a zlib stream whose first
// bytes are "<type> <size>\x00" followed by the payload. Anything that does not
// inflate, or whose header is not one of the four object types, is not a git
// object (an HTML error page served under the path is the common case).
func InflateLooseObject(raw []byte) (kind string, payload []byte, ok bool) {
	if len(raw) == 0 {
		return "", nil, false
	}
	zr, err := zlib.NewReader(bytes.NewReader(raw))
	if err != nil {
		return "", nil, false
	}
	defer zr.Close()
	inflated, err := io.ReadAll(io.LimitReader(zr, 8<<20))
	if err != nil || len(inflated) == 0 {
		return "", nil, false
	}
	nul := bytes.IndexByte(inflated, 0)
	if nul <= 0 {
		return "", nil, false
	}
	header := string(inflated[:nul])
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 {
		return "", nil, false
	}
	switch parts[0] {
	case "commit", "tree", "blob", "tag":
	default:
		return "", nil, false
	}
	size, err := strconv.Atoi(parts[1])
	if err != nil || size < 0 {
		return "", nil, false
	}
	body := inflated[nul+1:]
	if size > len(body) {
		return "", nil, false
	}
	return parts[0], body[:size], true
}

// GitCommitTree returns the tree id a commit object names.
func GitCommitTree(payload []byte) (string, bool) {
	const prefix = "tree "
	if !bytes.HasPrefix(payload, []byte(prefix)) {
		return "", false
	}
	rest := payload[len(prefix):]
	end := bytes.IndexByte(rest, '\n')
	if end < 0 {
		return "", false
	}
	sha := string(rest[:end])
	if !gitSHA1RE.MatchString(sha) && !gitSHA256RE.MatchString(sha) {
		return "", false
	}
	return sha, true
}

// GitCommitSubject returns the first line of a commit message (empty when the
// message is absent).
func GitCommitSubject(payload []byte) string {
	i := bytes.Index(payload, []byte("\n\n"))
	if i < 0 || i+2 >= len(payload) {
		return ""
	}
	msg := string(payload[i+2:])
	if j := strings.IndexByte(msg, '\n'); j >= 0 {
		msg = msg[:j]
	}
	return strings.TrimSpace(msg)
}

// GitTreeEntry is one entry of a tree object.
type GitTreeEntry struct {
	Mode string
	Name string
	SHA  string
}

// ParseGitTree decodes a tree object's entries: "<mode> <name>\x00<raw sha>".
func ParseGitTree(payload []byte) []GitTreeEntry {
	var out []GitTreeEntry
	for len(payload) > 0 {
		sp := bytes.IndexByte(payload, ' ')
		if sp <= 0 {
			break
		}
		mode := string(payload[:sp])
		payload = payload[sp+1:]
		nul := bytes.IndexByte(payload, 0)
		if nul <= 0 {
			break
		}
		name := string(payload[:nul])
		payload = payload[nul+1:]
		if len(payload) < 20 {
			break
		}
		sha := hex.EncodeToString(payload[:20])
		payload = payload[20:]
		out = append(out, GitTreeEntry{Mode: mode, Name: name, SHA: sha})
	}
	return out
}

// GitBlobNameInteresting ranks a blob for credential reading: configuration and
// documentation files first, binaries never.
func GitBlobNameInteresting(name string) bool {
	lower := strings.ToLower(name)
	for _, suffix := range []string{".env", ".txt", ".md", ".yml", ".yaml", ".json", ".ini", ".cfg", ".conf", ".properties", ".xml", ".sql"} {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	switch lower {
	case "config", "settings", "dockerfile", "readme", "makefile":
		return true
	}
	return false
}

// gitSecretRE finds a credential assignment in a blob. The KEY is captured in
// full (so DB_PASSWORD reports as db_password); the value is captured only to
// bound the match and is never reported.
var gitSecretRE = regexp.MustCompile(`(?i)\b([a-z0-9_]*(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|token))\b\s*[:=]\s*["']?([A-Za-z0-9_./+!@#$%^&*-]{4,})`)

// GitSecretHint reports the credential KEY a blob carries, without its value.
func GitSecretHint(payload []byte) (string, bool) {
	if len(payload) == 0 || bytes.IndexByte(payload, 0) >= 0 {
		return "", false // binary blob
	}
	m := gitSecretRE.FindStringSubmatch(string(payload))
	if m == nil {
		return "", false
	}
	return strings.ToLower(m[1]), true
}
