package disclosure

// Information disclosure rules (cases 38 and 39).
//
// Both cases are PASSIVE: the scan classifies bytes it already discovered. No
// parameter is mutated, nothing is submitted, and the finding says exactly what
// the response body showed.
//
//   - debug page (38): a reachable page dumps the runtime's own configuration
//     (phpinfo(), a Django debug page, a Spring actuator env document). The
//     markers below are the shapes those pages emit, not words a normal page
//     happens to contain.
//   - backup source (39): a URL that names a backup artefact (`.bak`, `.old`,
//     `~`, `.swp`, …) answers with SOURCE CODE instead of a rendered page. The
//     pair (backup suffix + source markers + a body that is not HTML) is what
//     makes it a disclosure rather than a download of a data file.

import (
	"bytes"
	"net/url"
	"path"
	"regexp"
	"strings"
)

// Kind names the disclosure a response proved.
type Kind string

const (
	KindNone         Kind = ""
	KindDebugPage    Kind = "debug_page"
	KindBackupSource Kind = "backup_source"
	KindGitHistory   Kind = "git_history"
)

// Verdict is one classification result.
type Verdict struct {
	Kind   Kind
	Reason string
	// Detail names what the page disclosed that matters (a secret-bearing key),
	// so the finding can say more than "a page exists".
	Detail string
}

type markerGroup struct {
	label   string
	all     []string // every marker must appear
	anyHTML bool     // when true the body must NOT look like a rendered page
}

var debugPageGroups = []markerGroup{
	// A real phpinfo() dump always names the loaded php.ini as well as its own
	// title and credits; prose that merely mentions PHP does not.
	{label: "phpinfo()", all: []string{"php version", "php credits", "php.ini"}},
	{label: "phpinfo()", all: []string{"php version", "configuration file (php.ini)"}},
	{label: "Django debug page", all: []string{"you're seeing this error because you have", "debug = true"}},
	{label: "Spring Boot actuator", all: []string{"\"activeprofiles\"", "\"propertysources\""}},
	{label: "Spring Boot actuator", all: []string{"\"activeprofiles\"", "\"systemproperties\""}},
}

// backupSuffixes are the artefact names a source file leaves behind. The list is
// short on purpose: each entry is a convention, not a guess list of filenames.
var backupSuffixes = []string{".bak", ".old", ".orig", ".save", ".backup", ".swp", ".swo", ".tmp", "~"}

var sourceMarkers = []string{
	"<?php",
	"package ",
	"import ",
	"public class ",
	"private static ",
	"#include",
	"def __init__",
	"func main(",
	"from django",
	"require_once",
}

// sensitiveKeys are the configuration names that turn a debug dump from
// interesting into dangerous.
var sensitiveKeys = []string{
	"secret_key", "secretkey", "db_password", "database_password", "db_pass",
	"aws_access_key", "aws_secret", "api_key", "apikey", "smtp_password",
	"jdbc:", "mysql_password", "redis_password",
}

// Classify returns the disclosure a response proves, if any. status/contentType
// describe the response, rawURL the request that produced it.
func Classify(rawURL string, status int, contentType string, body []byte) (Verdict, bool) {
	if status != 200 || len(bytes.TrimSpace(body)) == 0 {
		return Verdict{}, false
	}
	lower := bytes.ToLower(body)

	if v, ok := debugPage(lower, body); ok {
		return v, true
	}
	if v, ok := backupSource(rawURL, contentType, lower, body); ok {
		return v, true
	}
	return Verdict{}, false
}

func debugPage(lower, body []byte) (Verdict, bool) {
	text := string(lower)
	for _, g := range debugPageGroups {
		matched := true
		for _, m := range g.all {
			if !strings.Contains(text, m) {
				matched = false
				break
			}
		}
		if !matched {
			continue
		}
		detail := sensitiveDetail(text)
		reason := "a reachable page dumps the runtime's own configuration (" + g.label + ")"
		if detail != "" {
			reason += " including " + detail
		}
		return Verdict{Kind: KindDebugPage, Reason: reason, Detail: detail}, true
	}
	return Verdict{}, false
}

// sourceCredentialKeys are the weaker signals that only count inside SOURCE
// CODE: a source file that names a password almost always carries one, while a
// rendered page that says "password" is just a login form.
var sourceCredentialKeys = []string{"password", "passwd", "jdbc:", "secret"}

// sensitiveDetail names the first dangerous configuration key the dump contains.
func sensitiveDetail(lowerText string) string {
	for _, k := range sensitiveKeys {
		if strings.Contains(lowerText, k) {
			return k
		}
	}
	return ""
}

// dbLiteralRE matches a quoted, credential-shaped literal (>= 12 chars of
// letters/digits). It only ever runs on source that already proved to be a
// backup artefact AND that names a database driver.
var dbLiteralRE = regexp.MustCompile(`["']([A-Za-z0-9]{12,})["']`)

var dbContext = []string{"postgres", "mysql", "mariadb", "jdbc", "driver", "connectionbuilder", "datasource"}

// databaseCredentialDetail reports a connection-credential literal in source.
func databaseCredentialDetail(lowerText string) string {
	ctx := ""
	for _, c := range dbContext {
		if strings.Contains(lowerText, c) {
			ctx = c
			break
		}
	}
	if ctx == "" {
		return ""
	}
	if dbLiteralRE.MatchString(lowerText) {
		return "database credential literal (" + ctx + " connection)"
	}
	return ""
}

// firstCredentialInSource is sensitiveDetail widened for source code.
func firstCredentialInSource(lowerText string) string {
	if d := sensitiveDetail(lowerText); d != "" {
		return d
	}
	for _, k := range sourceCredentialKeys {
		if strings.Contains(lowerText, k) {
			return k
		}
	}
	return ""
}

func backupSource(rawURL, contentType string, lower, body []byte) (Verdict, bool) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return Verdict{}, false
	}
	base := strings.ToLower(path.Base(u.Path))
	if base == "" || base == "/" {
		return Verdict{}, false
	}
	suffix := ""
	for _, s := range backupSuffixes {
		if strings.HasSuffix(base, s) {
			suffix = s
			break
		}
	}
	if suffix == "" {
		return Verdict{}, false
	}
	// A backup artefact must answer with code, not with a rendered page: an HTML
	// error page served under /x.bak is not a disclosure.
	if strings.Contains(strings.ToLower(contentType), "html") {
		return Verdict{}, false
	}
	text := string(lower)
	if strings.Contains(text, "<html") || strings.Contains(text, "<!doctype") {
		return Verdict{}, false
	}
	found := ""
	for _, m := range sourceMarkers {
		if strings.Contains(text, m) {
			found = m
			break
		}
	}
	if found == "" {
		return Verdict{}, false
	}
	detail := firstCredentialInSource(text)
	if detail == "" {
		detail = databaseCredentialDetail(text)
	}
	reason := "a backup artefact (" + base + ") serves source code (" + strings.TrimSpace(found) + ") instead of a rendered page"
	if detail != "" {
		reason += " and contains " + detail
	}
	return Verdict{Kind: KindBackupSource, Reason: reason, Detail: detail}, true
}

// interestingPathTokens are the URL fragments that make an endpoint worth
// fetching first for this slice. They are discovery PRIORITY, not confirmation:
// a response named /debug that discloses nothing is never a finding.
var interestingPathTokens = []string{
	"phpinfo", "debug", "actuator", "telescope", "server-status", "server-info",
	"env", "config", "info.php", "test.php", "console", "trace",
}

// LooksInteresting reports whether a URL's own path suggests a debug surface or
// a backup artefact.
func LooksInteresting(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	p := strings.ToLower(u.Path)
	for _, tok := range interestingPathTokens {
		if strings.Contains(p, tok) {
			return true
		}
	}
	base := strings.ToLower(path.Base(p))
	for _, s := range backupSuffixes {
		if strings.HasSuffix(base, s) {
			return true
		}
	}
	return false
}

var (
	// commentRE matches HTML comments, including commented-out markup: a page
	// that "hides" a debug link behind <!-- --> has still published it.
	commentRE = regexp.MustCompile(`(?s)<!--(.*?)-->`)
	hrefRE    = regexp.MustCompile(`(?i)href\s*=\s*["']?([^"'\s>]+)["']?`)
	// listingRE recognizes an open directory listing.
	listingRE = regexp.MustCompile(`(?i)<title>\s*index of\s+/`)
)

// CandidateLinks returns the links a crawler usually ignores but a disclosure
// pass must follow: hrefs inside HTML comments, and the files an open directory
// listing names. The result is bounded and de-duplicated; it is a fetch list,
// never a finding.
func CandidateLinks(body []byte) []string {
	var out []string
	seen := map[string]bool{}
	add := func(href string) {
		href = strings.TrimSpace(strings.TrimSuffix(href, "/"))
		if href == "" || strings.HasPrefix(href, "#") || strings.HasPrefix(href, "mailto:") || seen[href] {
			return
		}
		seen[href] = true
		out = append(out, href)
	}

	for _, c := range commentRE.FindAllSubmatch(body, 8) {
		for _, m := range hrefRE.FindAllSubmatch(c[1], 8) {
			add(string(m[1]))
		}
	}
	if listingRE.Match(body) {
		for _, m := range hrefRE.FindAllSubmatch(body, 32) {
			add(string(m[1]))
		}
	}
	if len(out) > 6 {
		out = out[:6]
	}
	return out
}

// KindErrorDisclosure is the verbose-error case (37): a wrong-typed value makes
// the application answer with its own stack trace, which names internals and
// often the framework version.
const KindErrorDisclosure Kind = "error_message"

var (
	// stackTraceMarkers are the shapes a server-side crash prints, each with the
	// label the finding uses. Every entry is a fragment of a real runtime's
	// trace, not a word a page uses in prose.
	stackTraceMarkers = []struct{ label, marker string }{
		{"Java", "at java."},
		{"Java", "java.lang."},
		{"Java", "exception in thread"},
		{"Python", "traceback (most recent call last)"},
		{".NET", "system.nullreferenceexception"},
		{"PHP", "php fatal error"},
		{"stack trace", "stack trace:"},
		{"Spring/Java", "org.springframework"},
		{".NET", "at system."},
		{"SQL error", "sqlstate["},
	}
	// frameworkVersionRE names a framework and the version beside it.
	frameworkVersionRE = regexp.MustCompile(`(?i)\b(apache\s+struts|struts|spring(?:\s+boot)?|hibernate|django|flask|rails|laravel|tomcat|jetty|express|asp\.net)\b[^\n<]{0,24}?\b\d+\.\d+(?:\.\d+)?\b`)
	// poweredByRE reports a version in the Server/X-Powered-By headers.
	poweredByRE = regexp.MustCompile(`(?i)\b([a-z][a-z0-9_.-]{2,})\s*/?\s*(\d+\.\d+(?:\.\d+)?)\b`)
)

// ClassifyError decides whether an error response discloses the server's
// internals. The response must be an error (4xx/5xx) AND carry a real stack
// trace; a framework version alone is reported as detail, never as the reason.
func ClassifyError(status int, contentType string, body []byte, headers map[string][]string) (Verdict, bool) {
	if status < 400 || len(bytes.TrimSpace(body)) == 0 {
		return Verdict{}, false
	}
	// An HTML error page that only says "something went wrong" is not this case.
	if strings.Contains(strings.ToLower(contentType), "html") {
		lower := bytes.ToLower(body)
		if !bytes.Contains(lower, []byte("at java.")) && !bytes.Contains(lower, []byte("traceback")) &&
			!bytes.Contains(lower, []byte("stack trace")) && !bytes.Contains(lower, []byte("php fatal error")) {
			return Verdict{}, false
		}
	}
	text := strings.ToLower(string(body))
	label := ""
	for _, m := range stackTraceMarkers {
		if strings.Contains(text, m.marker) {
			label = m.label
			break
		}
	}
	if label == "" {
		return Verdict{}, false
	}
	detail := ""
	if m := frameworkVersionRE.FindString(text); m != "" {
		detail = strings.TrimSpace(m)
	} else {
		for _, h := range []string{"Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"} {
			for _, v := range headers[h] {
				if mm := poweredByRE.FindString(strings.TrimSpace(v)); mm != "" {
					detail = strings.TrimSpace(mm)
					break
				}
			}
			if detail != "" {
				break
			}
		}
	}
	reason := "an error response prints the server's own " + label + " stack trace"
	if detail != "" {
		reason += " and names " + detail
	}
	return Verdict{Kind: KindErrorDisclosure, Reason: reason, Detail: detail}, true
}
