package idor

// Object families: the object a request CREATES tells us where its siblings
// live (case 34).
//
// Some endpoints do not take an identifier at all — they mint one. A chat
// transcript is posted to /download-transcript and the response redirects to
// /download-transcript/2.txt, the caller's own object. The identifiers of the
// caller's neighbours are then the arithmetic around that number, which is why
// this needs no wordlist and no guessing: the application itself named the
// family.
//
// Confirmation here is NOT the identity-field differential in Decide: a plain
// text transcript names nobody. It is the narrower object-family rule:
//
//   - the caller's own object exists and carries the marker the scan submitted
//     (proof the scan created it),
//   - a sibling object answers 200 with a DIFFERENT document,
//   - that sibling does not contain the marker (it is not ours), and
//   - it discloses a credential.
//
// A sibling that equals the caller's document, or that carries no credential,
// is never confirmed.

import (
	"bytes"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
)

// ObjectFamily is one redirect-named object: base path, numeric id, extension.
type ObjectFamily struct {
	Base string // e.g. /download-transcript
	Ext  string // e.g. .txt (may be empty)
	ID   int    // the caller's own object id
}

// ParseObjectFamily reads a redirect target of the form <base>/<n>[.<ext>].
// Anything else (no number, a query string, a different host shape) is not an
// object family and the caller keeps the plain response.
func ParseObjectFamily(location string) (ObjectFamily, bool) {
	u, err := url.Parse(strings.TrimSpace(location))
	if err != nil || u.Host == "" {
		return ObjectFamily{}, false
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return ObjectFamily{}, false
	}
	dir, file := path.Split(u.Path)
	dir = strings.TrimSuffix(dir, "/")
	if dir == "" {
		return ObjectFamily{}, false
	}
	ext := path.Ext(file)
	stem := strings.TrimSuffix(file, ext)
	id, err := strconv.Atoi(stem)
	if err != nil || id <= 0 || stem != strconv.Itoa(id) {
		return ObjectFamily{}, false
	}
	return ObjectFamily{Base: dir, Ext: ext, ID: id}, true
}

// URLAt builds the absolute URL of id n in this family.
func (f ObjectFamily) URLAt(origin string, n int) string {
	return strings.TrimSuffix(origin, "/") + f.Base + "/" + strconv.Itoa(n) + f.Ext
}

// Siblings is the bounded probe set: the direct neighbours of the caller's own
// object, plus the family's FIRST object when that is not already one of them.
// A family's id 1 is normally the seed object rather than the caller's own, and
// it is the one an application most often forgets to authorize. Never more than
// three ids, and never zero or negative.
func (f ObjectFamily) Siblings() []int {
	var out []int
	if f.ID > 1 {
		out = append(out, f.ID-1)
	}
	out = append(out, f.ID+1)
	if f.ID > 2 {
		out = append(out, 1)
	}
	return out
}

var credentialPatterns = []struct {
	label string
	re    *regexp.Regexp
}{
	{"password", regexp.MustCompile(`(?i)\bpass(?:word|wd|phrase)\b\s*(?:is|:|=|was)\s*[^\s<]{4,}`)},
	{"api key", regexp.MustCompile(`(?i)\bapi[ _-]?key\b\s*(?:is|:|=)\s*[A-Za-z0-9_\-]{8,}`)},
	{"secret", regexp.MustCompile(`(?i)\bsecret\b\s*(?:is|:|=)\s*[A-Za-z0-9_\-]{8,}`)},
	{"access token", regexp.MustCompile(`(?i)\b(?:access[ _-]?)?token\b\s*(?:is|:|=)\s*[A-Za-z0-9_\-.]{12,}`)},
}

// CredentialHint names the credential kind the document discloses, or "" when it
// discloses none.
func CredentialHint(body []byte) string {
	for _, p := range credentialPatterns {
		if p.re.Match(body) {
			return p.label
		}
	}
	return ""
}

// ObjectFamilyDecision classifies one sibling response.
//
// ownBody/ownURL describe the object the scan created. marker is the literal it
// submitted, so "ours" is decided by content, not by the id.
func ObjectFamilyDecision(ownBody []byte, ownURL string, siblingID int, siblingURL string, siblingStatus int, siblingBody []byte, marker string) Decision {
	if siblingStatus == 401 || siblingStatus == 403 {
		return Decision{Outcome: OutcomeRejected,
			Reason: fmt.Sprintf("the sibling object %d was refused (HTTP %d): the boundary holds", siblingID, siblingStatus)}
	}
	if siblingStatus != 200 {
		return Decision{Outcome: OutcomeInconclusive,
			Reason: fmt.Sprintf("the sibling object %d answered HTTP %d: no document to compare", siblingID, siblingStatus)}
	}
	if len(bytes.TrimSpace(siblingBody)) == 0 {
		return Decision{Outcome: OutcomeInconclusive, Reason: "the sibling object is empty"}
	}
	if bytes.Equal(bytes.TrimSpace(siblingBody), bytes.TrimSpace(ownBody)) {
		return Decision{Outcome: OutcomeRejected,
			Reason: fmt.Sprintf("the sibling object %d is the caller's own document: the identifier does not select another object", siblingID)}
	}
	if marker != "" && bytes.Contains(siblingBody, []byte(marker)) {
		return Decision{Outcome: OutcomeRejected,
			Reason: "the sibling object carries this scan's own marker: it is not another principal's document"}
	}
	hint := CredentialHint(siblingBody)
	if hint == "" {
		return Decision{Outcome: OutcomeInconclusive,
			Reason: fmt.Sprintf("the sibling object %d is a different document but discloses no credential", siblingID)}
	}
	where := "neighbouring object"
	if siblingID == 1 {
		where = "family's first object"
	}
	return Decision{Outcome: OutcomeConfirmed,
		Reason: fmt.Sprintf("the scan's own object %s answered with its submitted marker, while the %s %s returned a different document disclosing a %s",
			ownURL, where, siblingURL, hint)}
}
