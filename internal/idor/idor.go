package idor

// The IDOR engine's pure core: identity extraction, candidate derivation and
// the differential decision. It performs no I/O and imports nothing outside
// the standard library, so the verdict rules can be tested exhaustively
// against fixed response bodies.
//
// Current slice: object-level (family A) broken object authorization on
// GET/HEAD reads. Function/role-level (family B) checks are out of scope.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// FieldKind classifies one identity attribute extracted from a response.
type FieldKind string

const (
	FieldUsername FieldKind = "username"
	FieldEmail    FieldKind = "email"
	FieldUserID   FieldKind = "user_id"
)

// Field is one extracted identity attribute.
type Field struct {
	Kind  FieldKind `json:"kind"`
	Value string    `json:"value"`
}

// Identity is the set of identity attributes a response exposes about the
// principal it belongs to.
type Identity struct {
	Fields []Field `json:"fields,omitempty"`
}

// Empty reports whether the identity carries no attributes.
func (i Identity) Empty() bool { return len(i.Fields) == 0 }

// Values returns the normalized values this identity has for kind.
func (i Identity) Values(kind FieldKind) []string {
	var out []string
	for _, f := range i.Fields {
		if f.Kind == kind {
			out = append(out, f.Value)
		}
	}
	return out
}

// MaxValueLen bounds any stored identity value.
const MaxValueLen = 120

// ExtractIdentity pulls identity attributes out of a response body. JSON is
// parsed structurally; otherwise HTML input values and labelled fields are
// read. Values that are placeholders rather than real identities are dropped,
// as are identities inside arrays (a page listing other users does not tell
// us who the page itself belongs to).
func ExtractIdentity(body []byte) Identity {
	if len(bytes.TrimSpace(body)) == 0 {
		return Identity{}
	}
	if fields := extractJSONIdentity(body); len(fields) > 0 {
		return Identity{Fields: dedupeFields(fields)}
	}
	return Identity{Fields: dedupeFields(extractHTMLIdentity(body))}
}

// unmarshalAny accepts only a TRUTHY JSON document: a bare number/string or a
// top-level array is not an identity-bearing object we can reason about.
func unmarshalAny(body []byte) (map[string]any, bool) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, false
	}
	m, ok := v.(map[string]any)
	return m, ok
}

func extractJSONIdentity(body []byte) []Field {
	root, ok := unmarshalAny(body)
	if !ok {
		return nil
	}
	var out []Field
	walkIdentity(root, "", 0, &out)
	return out
}

// walkIdentity visits maps only, to a bounded depth, and never descends into
// arrays: an array of users is a listing, not the response's own principal.
func walkIdentity(m map[string]any, parent string, depth int, out *[]Field) {
	if depth > 3 {
		return
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := m[k]
		switch val := v.(type) {
		case string:
			if kind, ok := identityKey(k, parent); ok {
				if s, ok := acceptableValue(kind, val); ok {
					*out = append(*out, Field{Kind: kind, Value: s})
				}
			}
		case json.Number:
			if kind, ok := identityKey(k, parent); ok {
				if s, ok := acceptableValue(kind, val.String()); ok {
					*out = append(*out, Field{Kind: kind, Value: s})
				}
			}
		case float64:
			if kind, ok := identityKey(k, parent); ok {
				if s, ok := acceptableValue(kind, strconv.FormatFloat(val, 'f', -1, 64)); ok {
					*out = append(*out, Field{Kind: kind, Value: s})
				}
			}
		case map[string]any:
			walkIdentity(val, strings.ToLower(k), depth+1, out)
		}
	}
}

// identityKey maps a JSON key to an identity kind. A bare "id" is accepted
// only inside a user/account/profile-ish object; otherwise it is an object
// identifier, not proof of WHO the response belongs to.
func identityKey(key, parent string) (FieldKind, bool) {
	switch strings.ToLower(key) {
	case "username", "user_name", "login":
		return FieldUsername, true
	case "email", "email_address", "mail":
		return FieldEmail, true
	case "user_id", "userid", "uid", "account_id", "accountid", "profile_id", "profileid",
		"customer_id", "customerid", "member_id", "memberid":
		return FieldUserID, true
	case "id":
		p := strings.ToLower(parent)
		for _, hint := range []string{"user", "account", "profile", "member", "customer", "me"} {
			if strings.Contains(p, hint) {
				return FieldUserID, true
			}
		}
	}
	return "", false
}

// labelSeparator is the punctuation or verb that MUST appear between an
// identity label and its value. Requiring at least one is what keeps prose
// from being mined as an identity: "<title>User ID controlled by request
// parameter</title>" has no separator after the label, so "controlled" is not
// a value, while "Your username is: wiener" carries two ("is" and ":").
// Without this, the live lab's page title and the word after "is" were both
// extracted as identity fields, making every response look the same.
const labelSeparator = `[\s\x00]*(?:is|:|=)`

var (
	inputTagRE  = regexp.MustCompile(`(?is)<input\b[^>]*>`)
	inputAttrRE = regexp.MustCompile(`(?is)\b(name|value)\s*=\s*(?:"([^"]*)"|'([^']*)')`)
	tagRE       = regexp.MustCompile(`(?s)<[^>]*>`)
	spacesRE    = regexp.MustCompile(`\s+`)

	// Invisible regions: their text is not rendered page copy, so it must not
	// be mined for identity. A page <title> such as "User ID controlled by
	// request parameter" is exactly the kind of prose that produced a bogus
	// identity (user_id="controlled") on the live lab.
	commentRE  = regexp.MustCompile(`(?s)<!--.*?-->`)
	scriptRE   = regexp.MustCompile(`(?is)<script\b[^>]*>.*?</script\s*>`)
	styleRE    = regexp.MustCompile(`(?is)<style\b[^>]*>.*?</style\s*>`)
	headRE     = regexp.MustCompile(`(?is)<head\b[^>]*>.*?</head\s*>`)
	titleRE    = regexp.MustCompile(`(?is)<title\b[^>]*>.*?</title\s*>`)
	templateRE = regexp.MustCompile(`(?is)<template\b[^>]*>.*?</template\s*>`)
	noscriptRE = regexp.MustCompile(`(?is)<noscript\b[^>]*>.*?</noscript\s*>`)

	usernameText = regexp.MustCompile(`(?i)\busername\b(?:` + labelSeparator + `)+[\s\x00]*([A-Za-z0-9][A-Za-z0-9._@+-]{0,63})`)
	emailText    = regexp.MustCompile(`(?i)\b(?:email|e-mail)(?:\s+address)?\b(?:` + labelSeparator + `)+[\s\x00]*([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})`)
	userIDText   = regexp.MustCompile(`(?i)\b(?:user\s*id|userid|account\s*id|accountid|profile\s*id|profileid)\b(?:` + labelSeparator + `)+[\s\x00]*([A-Za-z0-9._-]{1,64})`)
)

type positionedField struct {
	pos int
	Field
}

// visibleText returns the page's rendered text: comments and non-rendered
// elements (head, script, style, title, template, noscript) are dropped, every
// remaining tag becomes an element boundary sentinel (\x00), and runs of
// whitespace collapse. The sentinel lets a labelled value be recognised as the
// END of an element's text ("…wiener</p>") rather than the first word of a
// longer sentence.
func visibleText(body []byte) string {
	s := string(body)
	s = commentRE.ReplaceAllString(s, " ")
	for _, re := range []*regexp.Regexp{headRE, scriptRE, styleRE, titleRE, templateRE, noscriptRE} {
		s = re.ReplaceAllString(s, " ")
	}
	s = tagRE.ReplaceAllString(s, "\x00")
	return spacesRE.ReplaceAllString(s, " ")
}

// valueContinues reports whether text after a captured labelled value is more
// of the same sentence (the next word starts with a letter/digit) rather than
// the end of the element. "user ID is controlled by the request parameter"
// must not yield "controlled": the value is followed by another word. A tag
// boundary always terminates the value, so ordinary markup line breaks are
// unaffected.
func valueContinues(text string, end int) bool {
	rest := text[end:]
	for i := 0; i < len(rest); i++ {
		switch rest[i] {
		case ' ', '	', '\r', '\n':
			continue
		case 0:
			return false // element boundary: the value ended here
		}
		r, _ := utf8.DecodeRuneInString(rest[i:])
		return unicode.IsLetter(r) || unicode.IsDigit(r)
	}
	return false
}

func extractHTMLIdentity(body []byte) []Field {
	var found []positionedField

	for _, loc := range inputTagRE.FindAllIndex(body, -1) {
		tag := body[loc[0]:loc[1]]
		attrs := map[string]string{}
		for _, m := range inputAttrRE.FindAllSubmatch(tag, -1) {
			name := strings.ToLower(string(m[1]))
			val := string(m[2])
			if val == "" {
				val = string(m[3])
			}
			attrs[name] = val
		}
		kind, ok := htmlInputKind(attrs["name"])
		if !ok {
			continue
		}
		if s, ok := acceptableValue(kind, attrs["value"]); ok {
			found = append(found, positionedField{loc[0], Field{Kind: kind, Value: s}})
		}
	}

	// Labelled text ("Your username is: <strong>wiener</strong>"): read only
	// rendered text, require a real separator between label and value, and
	// reject a capture that is just the next word of a sentence.
	text := visibleText(body)
	for _, spec := range []struct {
		re    *regexp.Regexp
		kind  FieldKind
		guard bool
	}{
		{usernameText, FieldUsername, true},
		{emailText, FieldEmail, false},
		{userIDText, FieldUserID, true},
	} {
		for _, m := range spec.re.FindAllStringSubmatchIndex(text, -1) {
			val := text[m[2]:m[3]]
			if spec.guard && valueContinues(text, m[3]) {
				continue
			}
			if s, ok := acceptableValue(spec.kind, val); ok {
				found = append(found, positionedField{m[2], Field{Kind: spec.kind, Value: s}})
			}
		}
	}

	sort.SliceStable(found, func(i, j int) bool {
		if found[i].pos != found[j].pos {
			return found[i].pos < found[j].pos
		}
		return found[i].Kind < found[j].Kind
	})
	out := make([]Field, 0, len(found))
	for _, f := range found {
		out = append(out, f.Field)
	}
	return out
}

func htmlInputKind(name string) (FieldKind, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "username", "user_name", "login":
		return FieldUsername, true
	case "email", "email_address":
		return FieldEmail, true
	case "user_id", "userid", "uid", "account_id", "accountid", "profile_id", "profileid":
		return FieldUserID, true
	}
	return "", false
}

// placeholderValues are form defaults, not identities.
var placeholderValues = map[string]bool{
	"username": true, "user_name": true, "user name": true, "your username": true,
	"email": true, "e-mail": true, "email address": true, "your email": true,
	"user id": true, "userid": true, "value": true, "placeholder": true,
	"none": true, "null": true, "undefined": true, "n/a": true, "na": true,
	"unknown": true, "enter username": true, "enter email": true,
}

// grammarValues are sentence words that can end up after an identity label by
// accident ("Your username is not set"). They are never identifiers, so they
// are rejected even if a label pattern captured them.
var grammarValues = map[string]bool{
	"is": true, "are": true, "was": true, "were": true, "be": true, "been": true,
	"not": true, "and": true, "or": true, "the": true, "a": true, "an": true,
	"your": true, "my": true, "this": true, "that": true, "here": true, "below": true,
}

func acceptableValue(kind FieldKind, raw string) (string, bool) {
	v := strings.TrimSpace(raw)
	if v == "" || len(v) > MaxValueLen {
		return "", false
	}
	if strings.ContainsAny(v, "<>{}\"'\\\r\n\t") || strings.Contains(v, "{{") || strings.Contains(v, "%s") {
		return "", false
	}
	if placeholderValues[strings.ToLower(v)] || grammarValues[strings.ToLower(v)] {
		return "", false
	}
	switch kind {
	case FieldEmail:
		at := strings.IndexByte(v, '@')
		if at <= 0 || at == len(v)-1 || !strings.Contains(v[at+1:], ".") {
			return "", false
		}
	case FieldUserID:
		for _, r := range v {
			if !(r == '.' || r == '_' || r == '-' || (r >= '0' && r <= '9') ||
				(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
				return "", false
			}
		}
	case FieldUsername:
		for _, r := range v {
			if !(r == '.' || r == '_' || r == '-' || r == '@' || r == '+' ||
				(r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
				return "", false
			}
		}
	}
	return v, true
}

func dedupeFields(fields []Field) []Field {
	seen := map[string]bool{}
	out := fields[:0]
	for _, f := range fields {
		key := string(f.Kind) + "\x00" + strings.ToLower(f.Value)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	// Canonical order (username, email, user_id) makes both the evidence record
	// and "which field proved the mismatch" independent of response layout.
	sort.SliceStable(out, func(i, j int) bool {
		if fieldRank(out[i].Kind) != fieldRank(out[j].Kind) {
			return fieldRank(out[i].Kind) < fieldRank(out[j].Kind)
		}
		return out[i].Value < out[j].Value
	})
	return out
}

func fieldRank(k FieldKind) int {
	switch k {
	case FieldUsername:
		return 0
	case FieldEmail:
		return 1
	default:
		return 2
	}
}

// Outcome is the engine's per-response classification.
type Outcome string

const (
	OutcomeConfirmed    Outcome = "confirmed"
	OutcomeRejected     Outcome = "rejected"
	OutcomeInconclusive Outcome = "inconclusive"
	OutcomeSkipped      Outcome = "skipped"
)

// Decision is the differential verdict for one foreign-object request.
type Decision struct {
	Outcome Outcome `json:"outcome"`
	Reason  string  `json:"reason"`
	// Foreign is the identity field that proved the response belongs to a
	// different principal. Set only for OutcomeConfirmed.
	Foreign *Field `json:"foreign,omitempty"`
}

// Decide compares one foreign-object response against the established caller
// identity. Confirmed requires a POSITIVE identity mismatch: a response that
// names a different principal in a field the caller's own identity also
// carries. Status codes, lengths, redirects and bare identifier echoes are
// never enough.
func Decide(caller Identity, candidateID string, status int, body []byte) Decision {
	switch {
	case status == 401 || status == 403:
		return Decision{Outcome: OutcomeRejected,
			Reason: fmt.Sprintf("the target denied access to the candidate object (HTTP %d): the object is protected", status)}
	case status >= 400:
		return Decision{Outcome: OutcomeInconclusive,
			Reason: fmt.Sprintf("error response HTTP %d: no identity data could be observed", status)}
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return Decision{Outcome: OutcomeInconclusive, Reason: "empty response body: no identity data could be observed"}
	}

	foreign := ExtractIdentity(body)
	if foreign.Empty() {
		if looksLikeLoginPage(body) {
			return Decision{Outcome: OutcomeInconclusive,
				Reason: "a login page was returned: the session did not reach the candidate object"}
		}
		return Decision{Outcome: OutcomeInconclusive,
			Reason: fmt.Sprintf("candidate response for %q carries no identity fields", candidateID)}
	}

	var differing *Field
	comparable := 0
	matched := false
	for _, cf := range caller.Fields {
		for _, ff := range foreign.Fields {
			if ff.Kind != cf.Kind {
				continue
			}
			comparable++
			if strings.EqualFold(strings.TrimSpace(cf.Value), strings.TrimSpace(ff.Value)) {
				matched = true
				continue
			}
			if differing == nil {
				f := ff
				differing = &f
			}
		}
	}
	// A response that identifies the caller ANYWHERE is not proof of a broken
	// object boundary, even when it also lists other principals (a comment
	// author, a directory row): the object may still be the caller's own page.
	if matched {
		return Decision{Outcome: OutcomeRejected,
			Reason: "candidate response identifies the caller (same principal): no broken object authorization observed"}
	}
	if differing != nil {
		return Decision{Outcome: OutcomeConfirmed, Foreign: differing,
			Reason: fmt.Sprintf("candidate object returned a different principal's %s (%q) while the caller is %q",
				differing.Kind, differing.Value, firstValue(caller, differing.Kind))}
	}
	if comparable == 0 {
		return Decision{Outcome: OutcomeInconclusive,
			Reason: "candidate response has identity fields but none comparable with the caller's established identity"}
	}
	return Decision{Outcome: OutcomeRejected,
		Reason: "candidate response identifies the caller (same principal): no broken object authorization observed"}
}

func firstValue(i Identity, kind FieldKind) string {
	if vs := i.Values(kind); len(vs) > 0 {
		return vs[0]
	}
	return ""
}

var passwordInputRE = regexp.MustCompile(`(?i)<input\b[^>]*type\s*=\s*["']?password`)

func looksLikeLoginPage(body []byte) bool {
	return passwordInputRE.Match(body)
}

// Candidate is one foreign object identifier to try.
type Candidate struct {
	Value  string `json:"value"`
	Source string `json:"source"` // "supplied" | "numeric" | "observed" | "harvested"
	// Shape is the identifier family (see Shape). Empty on the legacy
	// DeriveCandidates path, which does not shape-match.
	Shape Shape `json:"shape,omitempty"`
	// Origin is where a harvested candidate came from. Set only for
	// candidates that were harvested from the scan's own data, so a finding
	// can attribute the identifier it tested.
	Origin *Origin `json:"origin,omitempty"`
}

// MaxCandidates bounds how many foreign identifiers one injection point may
// try. Guessing is never unbounded: at most five extra object reads per
// parameter, and none at all for opaque identifiers.
const MaxCandidates = 5

// DeriveCandidates returns the bounded, deterministic set of foreign object
// identifiers to try for one parameter:
//
//  1. operator-supplied identifiers (in the order given) — the only way to
//     test an opaque identifier, never guessed by the tool;
//  2. small numeric neighbours of the caller's own numeric id;
//  3. identifier-shaped values already observed elsewhere in this scan.
//
// It is the pre-harvest entry point: observed values are NOT shape-filtered.
// New callers use DeriveCandidatesFromHarvest, which adds provenance and shape
// matching.
//
// A non-empty reason means no candidate could be derived safely.
func DeriveCandidates(own string, supplied, observed []string, limit int) ([]Candidate, string) {
	hs := make([]Harvest, 0, len(observed))
	for _, v := range observed {
		hs = append(hs, Harvest{Value: v, Shape: ShapeOf(v)})
	}
	out, reason := deriveCandidates(own, supplied, hs, limit, false)
	for i := range out {
		if out[i].Source == "harvested" {
			out[i].Source = "observed"
		}
	}
	return out, reason
}

// DeriveCandidatesFromHarvest is DeriveCandidates with provenance and shape
// matching, for candidates harvested from data the scan already holds:
//
//  1. operator-supplied identifiers, in the order given, always first and
//     never shape-filtered — they are the operator's explicit intent;
//  2. small numeric neighbours of the caller's own numeric id;
//  3. harvested identifiers whose shape matches the endpoint's own identifier
//     (a UUID endpoint never receives a numeric id, and vice versa), ranked
//     deterministically by HarvestCandidates.
//
// The cap stays MaxCandidates per injection point, so harvesting never turns
// the pass into enumeration.
func DeriveCandidatesFromHarvest(own string, supplied []string, harvested []Harvest, limit int) ([]Candidate, string) {
	return deriveCandidates(own, supplied, harvested, limit, true)
}

func deriveCandidates(own string, supplied []string, harvested []Harvest, limit int, matchShape bool) ([]Candidate, string) {
	if limit <= 0 || limit > MaxCandidates {
		limit = MaxCandidates
	}
	own = strings.TrimSpace(own)
	ownShape := ShapeOf(own)

	seen := map[string]bool{}
	if own != "" {
		seen[strings.ToLower(own)] = true
	}
	var out []Candidate
	add := func(raw, source string, shape Shape, origin *Origin, force bool) bool {
		v := strings.TrimSpace(raw)
		if v == "" || len(v) > MaxValueLen || seen[strings.ToLower(v)] {
			return false
		}
		if !candidateShaped(v) {
			return false
		}
		if matchShape && !force && !shapeCompatible(ownShape, shape) {
			return false
		}
		seen[strings.ToLower(v)] = true
		out = append(out, Candidate{Value: v, Source: source, Shape: shape, Origin: origin})
		return len(out) >= limit
	}

	for _, v := range supplied {
		// Operator-supplied values are explicit intent: they are tried even
		// when their shape differs from the endpoint's own identifier.
		if add(v, "supplied", ShapeOf(v), nil, true) {
			return out, ""
		}
	}
	if n, ok := numericID(own); ok {
		for _, delta := range []int{1, -1, 2, -2, 3, -3} {
			next := n + delta
			if next <= 0 {
				continue
			}
			if add(strconv.Itoa(next), "numeric", ShapeNumeric, nil, false) {
				return out, ""
			}
		}
	}
	for _, h := range harvested {
		origin := h.Origin
		if add(h.Value, "harvested", h.Shape, &origin, false) {
			return out, ""
		}
	}
	if len(out) == 0 {
		return nil, noCandidateReason(own, ownShape, len(harvested), matchShape)
	}
	return out, ""
}

// noCandidateReason explains a skip without ever sounding like a guess was
// made. It names the shape constraint so an operator can see why a harvested
// value was not used.
func noCandidateReason(own string, ownShape Shape, harvestedCount int, matchShape bool) string {
	if !matchShape {
		return fmt.Sprintf("no bounded candidate identifiers available for own value %q: "+
			"the identifier looks unpredictable, so guessing is not attempted", own)
	}
	if harvestedCount == 0 {
		return fmt.Sprintf("no candidate identifiers were harvested from this scan's own data for own value %q "+
			"(shape %s): the identifier itself looks unpredictable, so guessing is not attempted", own, ownShape)
	}
	return fmt.Sprintf("no harvested identifier matches the endpoint's identifier shape (%s) for own value %q: "+
		"the identifier looks unpredictable, so cross-shape guessing is not attempted", ownShape, own)
}

func numericID(v string) (int, bool) {
	if v == "" || len(v) > 12 {
		return 0, false
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

func candidateShaped(v string) bool {
	for _, r := range v {
		switch {
		case r == ' ' || r == '\t' || r == '\r' || r == '\n' || r < 0x20 || r == 0x7f:
			return false
		case r == '<' || r == '>' || r == '"' || r == '\'' || r == '\\' || r == '{' || r == '}':
			return false
		}
	}
	return true
}

// objectIDParams is the conservative set of parameter names that select an
// object by identifier. Anything not listed is left alone: a wrong guess would
// read an unrelated object rather than test authorization.
var objectIDParams = map[string]bool{
	"id": true, "uid": true, "user": true, "username": true, "userid": true, "user_id": true,
	"account": true, "accountid": true, "account_id": true,
	"profile": true, "profileid": true, "profile_id": true,
	"file": true, "filename": true, "file_name": true, "fileid": true, "file_id": true,
	"doc": true, "document": true, "documentid": true, "document_id": true, "docid": true,
	"object": true, "objectid": true, "object_id": true,
	"order": true, "orderid": true, "order_id": true,
	"invoice": true, "invoiceid": true, "invoice_id": true,
	"post": true, "postid": true, "post_id": true,
	"message": true, "messageid": true, "message_id": true, "msg": true, "msgid": true, "msg_id": true,
	"report": true, "reportid": true, "report_id": true,
	"record": true, "recordid": true, "record_id": true,
	"item": true, "itemid": true, "item_id": true,
	"product": true, "productid": true, "product_id": true,
	"tenant": true, "tenantid": true, "tenant_id": true,
	"customer": true, "customerid": true, "customer_id": true,
	"employee": true, "employeeid": true, "employee_id": true,
	"group": true, "groupid": true, "group_id": true,
	"org": true, "orgid": true, "org_id": true,
	"company": true, "companyid": true, "company_id": true,
	"patient": true, "patientid": true, "patient_id": true,
	"booking": true, "bookingid": true, "booking_id": true,
	"ticket": true, "ticketid": true, "ticket_id": true,
	"comment": true, "commentid": true, "comment_id": true,
	"attachment": true, "attachmentid": true, "attachment_id": true,
	"download": true, "downloadid": true, "download_id": true,
	"number": true, "num": true,
}

// nonObjectHints always win: these select sessions, credentials, navigation or
// filters, never another principal's object.
var nonObjectHints = []string{"csrf", "token", "sess", "auth", "pass", "secret", "nonce", "signature", "redirect", "next", "return", "callback"}

// ObjectIDParameter reports whether a parameter name plausibly selects an
// object by identifier.
func ObjectIDParameter(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return false
	}
	for _, hint := range nonObjectHints {
		if strings.Contains(n, hint) {
			return false
		}
	}
	return objectIDParams[n]
}
