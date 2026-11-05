package idor

// Object attribution: whose object is this?
//
// ExtractIdentity understands ACCOUNT pages: a page that says
// "Your username is: wiener". Object downloads (a chat transcript, an export,
// an attachment, an invoice) usually carry no account widget at all — they
// carry a SUBJECT line instead: "CONVERSATION WITH: carlos", "Owner: carlos",
// "Transcript for: carlos".
//
// Without reading that line the engine can only ever return Inconclusive for
// exactly the sequential-id file-download IDOR class, even when the response
// plainly states whose object it is. This file adds that signal as a separate,
// deliberately conservative attribution — never as an identity field:
//
//   - identity fields answer "who does this PAGE belong to?", and are compared
//     field-by-field with the caller;
//   - an attribution answers "who does this OBJECT belong to?", and is only
//     ever evidence of a foreign object when the caller's OWN object response
//     does not name the same principal (see DecideWithBaseline).
//
// Keeping the two apart matters: a chat transcript legitimately names its
// conversation partner ("CONVERSATION WITH: Hal Pline") without belonging to
// that partner, so an attribution can never be treated as the response's own
// identity.
//
// Precision rules (a false negative costs one unconfirmed site; a false
// positive fabricates a finding):
//
//   - only a small, closed vocabulary of OWNERSHIP/SUBJECT labels;
//   - a separator is required between the label and its value (":", "=" or
//     "is"), so prose such as "the owner is responsible for ..." yields
//     nothing;
//   - the value must be the rest of the line/element;
//   - the value must pass the same strict username-shape filter as every
//     other identity value (a display name with spaces is refused, not
//     guessed at);
//   - content metadata that says nothing about ownership ("Author:",
//     "Created by:") and chat-partner phrasing ("chatting with") are NOT
//     labels: they describe the content or the other party, not the object's
//     principal.

import (
	"bytes"
	"fmt"
	"html"
	"regexp"
	"strings"
)

// FieldOwner is the identity kind of an explicitly labelled object owner. It
// is not comparable with the caller's username/email/user-id fields: it says
// which principal the object belongs to, not who the page is.
const FieldOwner FieldKind = "owner"

var (
	brTagRE       = regexp.MustCompile(`(?is)<br\s*/?>`)
	blockEndTagRE = regexp.MustCompile(`(?is)</(?:p|div|li|tr|td|th|h[1-6]|section|article|header|footer|pre|blockquote)\s*>`)
	attributionRE = regexp.MustCompile(`(?i)^[\s\-*>#|]*` +
		`(?:object owner|file owner|document owner|transcript owner|account owner|resource owner|` +
		`owned by|belongs to|` +
		`conversation with|chat transcript of|chat transcript for|chat transcript|` +
		`transcript of|transcript for|` +
		`account holder|issued to|prepared for|` +
		`owner|user)` +
		`\s*(?::|=|\bis\b)\s*(.+?)\s*$`)
	// A multi-word document label may omit the punctuation when the value is
	// the only remaining token ("CONVERSATION WITH carlos", "Transcript for
	// carlos"). The single-token requirement is what keeps "transcript for
	// internal use" from naming "internal".
	attributionBareRE = regexp.MustCompile(`(?i)^[\s\-*>#|]*` +
		`(?:conversation with|chat transcript of|chat transcript for|chat transcript|transcript of|transcript for)` +
		`\s+([a-z0-9._-]{2,32})\s*$`)
	// Possessive ownership header: "carlos's transcript", "carlos' chat
	// transcript". The noun after the possessive must itself denote an object,
	// so ordinary prose ("carlos's opinion") is not attribution.
	attributionPossessiveRE = regexp.MustCompile(`(?i)^[\s\-*>#|]*(?:the\s+)?([a-z0-9._-]{2,32})['\x{2019}]s?\s+` +
		`(?:chat\s+)?(?:transcript|conversation|account|profile|file|document|invoice|order|report|attachment|download)\b`)
	attributionLineMax = 240
)

// nonPrincipalWords are common nouns that can sit before a possessive without
// naming a principal ("the user's transcript").
var nonPrincipalWords = map[string]bool{
	"user": true, "users": true, "customer": true, "member": true, "account": true,
	"profile": true, "owner": true, "client": true, "employee": true, "holder": true,
}

// attributionText renders a body as text with structural line breaks: every
// block/line boundary becomes a newline, other markup collapses to a space,
// and non-rendered regions are dropped. Attribution is line-scoped, so a
// sentinel-everywhere substitution (visibleText) would not work here.
func attributionText(body []byte) string {
	s := string(body)
	s = commentRE.ReplaceAllString(s, "\n")
	for _, re := range []*regexp.Regexp{headRE, scriptRE, styleRE, titleRE, templateRE, noscriptRE} {
		s = re.ReplaceAllString(s, "\n")
	}
	s = brTagRE.ReplaceAllString(s, "\n")
	s = blockEndTagRE.ReplaceAllString(s, "\n")
	s = tagRE.ReplaceAllString(s, " ")
	return html.UnescapeString(s)
}

// ExtractAttribution returns the principals a response explicitly attributes
// its object to, in the order they appear. It returns nil when the response
// carries no ownership/subject label — the caller then has no attribution
// evidence and must not confirm on this signal.
func ExtractAttribution(body []byte) []Field {
	if len(bytes.TrimSpace(body)) == 0 {
		return nil
	}
	var out []Field
	seen := map[string]bool{}
	for _, line := range strings.Split(attributionText(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || len(line) > attributionLineMax {
			continue
		}
		v, ok := attributionValue(line)
		if !ok {
			continue
		}
		key := strings.ToLower(v)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, Field{Kind: FieldOwner, Value: v})
	}
	return out
}

// attributionValue reads one principal from one line, or reports false.
func attributionValue(line string) (string, bool) {
	for _, re := range []*regexp.Regexp{attributionRE, attributionBareRE} {
		if m := re.FindStringSubmatch(line); m != nil {
			return validAttribution(m[1])
		}
	}
	m := attributionPossessiveRE.FindStringSubmatch(line)
	if m == nil {
		return "", false
	}
	if nonPrincipalWords[strings.ToLower(m[1])] {
		return "", false
	}
	return validAttribution(m[1])
}

// validAttribution applies the same strict value rules as identity
// extraction, plus the rule that an attribution must name someone.
func validAttribution(raw string) (string, bool) {
	v, ok := acceptableValue(FieldUsername, strings.TrimSpace(raw))
	if !ok || !hasLetter(v) {
		return "", false
	}
	return v, true
}

// hasLetter keeps a bare number ("Owner: 42") from being read as a principal
// name; an attribution has to name someone.
func hasLetter(v string) bool {
	for _, r := range v {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			return true
		}
	}
	return false
}

// callerLabel is the human-readable caller for a reason string: the first
// identity value the baseline carries, whatever its kind.
func callerLabel(i Identity) string {
	for _, f := range i.Fields {
		if v := strings.TrimSpace(f.Value); v != "" {
			return v
		}
	}
	return ""
}

// DecideWithBaseline is Decide plus the caller's OWN object response (request
// A). The extra body supplies the two rules a single-response differential
// cannot express:
//
//   - a response identical to the caller's own means the identifier selected
//     nothing, so a name in it is not evidence of another object;
//   - an explicitly attributed owner (ExtractAttribution) is only foreign when
//     the caller's own object does not already name the same principal, so a
//     shared conversation partner or a page footer cannot fabricate a finding.
//
// The identity-field rules are unchanged; attribution is a fallback for
// responses (object downloads, transcripts, exports) that carry no account
// page identity at all. It never overrides a comparable identity field.
func DecideWithBaseline(caller Identity, candidateID string, status int, body, ownBody []byte) Decision {
	// Errors, empty bodies and protected objects keep the exact Decide
	// classification: their reason must not be rewritten by this wrapper.
	if status >= 400 || len(bytes.TrimSpace(body)) == 0 {
		return Decide(caller, candidateID, status, body)
	}
	if len(bytes.TrimSpace(ownBody)) > 0 && bytes.Equal(bytes.TrimSpace(body), bytes.TrimSpace(ownBody)) {
		return Decision{Outcome: OutcomeRejected,
			Reason: "the response did not change when the identifier changed: the tested identifier does not select a distinct object"}
	}
	// Attribution is only consulted when the response carries no identity
	// field: an account-page identity is strictly stronger evidence.
	if ExtractIdentity(body).Empty() && !looksLikeLoginPage(body) {
		if d, ok := attributionDecision(caller, body, ownBody); ok {
			return d
		}
	}
	return Decide(caller, candidateID, status, body)
}

// attributionDecision applies the object-attribution rules. ok is false when
// the response carries no attribution at all, so the caller keeps the
// documented Inconclusive outcome.
func attributionDecision(caller Identity, body, ownBody []byte) (Decision, bool) {
	attrs := ExtractAttribution(body)
	if len(attrs) == 0 {
		return Decision{}, false
	}
	for _, a := range attrs {
		for _, cf := range caller.Fields {
			if strings.EqualFold(strings.TrimSpace(cf.Value), strings.TrimSpace(a.Value)) {
				return Decision{Outcome: OutcomeRejected,
					Reason: "candidate object attributes its content to the caller (same principal): no broken object authorization observed"}, true
			}
		}
	}
	own := map[string]bool{}
	for _, f := range ExtractAttribution(ownBody) {
		own[strings.ToLower(strings.TrimSpace(f.Value))] = true
	}
	for _, a := range attrs {
		if own[strings.ToLower(strings.TrimSpace(a.Value))] {
			continue
		}
		f := a
		return Decision{Outcome: OutcomeConfirmed, Foreign: &f,
			Reason: fmt.Sprintf("candidate object is attributable to a different principal (%q) while the caller is %q and the caller's own object does not name that principal",
				a.Value, callerLabel(caller))}, true
	}
	return Decision{Outcome: OutcomeRejected,
		Reason: "every principal the candidate object names is already named by the caller's own object: changing the identifier did not select another principal's content"}, true
}
