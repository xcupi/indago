package idor

// Candidate harvesting: where do the identifiers to test come from?
//
// On a real target the operator does not know the foreign object identifiers
// an authorized brief would name, so the engine has to find them in data the
// scan ALREADY holds — endpoint URLs, discovered parameters, and response
// bodies stored as evidence. This file is the pure part of that: classify,
// filter, attribute and rank. It performs no I/O and no requests, and imports
// only the standard library (like the rest of this package), so the rules can
// be tested exhaustively against fixed fixtures.
//
// Harvesting never widens what the engine may do: a harvested value is only
// ever tried as a read-only GET/HEAD object lookup, through the same
// scope-enforcing engine, inside the same per-injection-point candidate cap,
// and the decision rule (idor.Decide) is unchanged — a response must identify
// a DIFFERENT principal before anything is Confirmed.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Shape is the syntactic family of an object identifier. The engine only ever
// sends a harvested identifier to an endpoint whose OWN observed value has the
// same shape: a numeric endpoint never receives a UUID, a UUID endpoint never
// receives a numeric id. Guessing across shapes reads unrelated objects.
type Shape string

const (
	ShapeUsername Shape = "username"
	ShapeNumeric  Shape = "numeric"
	ShapeUUID     Shape = "uuid"
	ShapeEmail    Shape = "email"
	// ShapeOpaque is anything the harvester cannot classify. It is never
	// proposed, and an endpoint whose own identifier is opaque accepts no
	// harvested candidate at all (no shape to match).
	ShapeOpaque Shape = "opaque"
)

const (
	// MaxHarvested bounds the scan-wide harvested candidate set. Twenty is
	// deliberately small: the per-injection-point cap (MaxCandidates) is
	// still five, so the harvest can never turn the IDOR pass into
	// enumeration. Ranking is deterministic, so the same scan data always
	// yields the same twenty.
	MaxHarvested = 20
	// MaxHarvestBodyBytes bounds how much of one stored response body is
	// mined. Reading is bounded even though it is local: a scan's evidence
	// store can hold multi-megabyte responses.
	MaxHarvestBodyBytes = 256 << 10
	// MaxHarvestValueLen bounds a single harvested identifier, in characters.
	MaxHarvestValueLen = 64
	// maxHarvestDepth bounds JSON descent.
	maxHarvestDepth = 6
	// maxHarvestArrayItems bounds how many elements of one JSON array are
	// mined, so a huge listing cannot dominate the work.
	maxHarvestArrayItems = 200
)

// Via says what kind of already-collected scan data an identifier came from.
const (
	ViaJSON      = "json"
	ViaHTML      = "html"
	ViaLink      = "link"
	ViaQuery     = "query"
	ViaParameter = "parameter"
	ViaPath      = "path"
)

// Origin attributes a harvested identifier to the scan data that carried it,
// so a finding can say "tested carlos harvested from /admin/users". It is
// stored verbatim on the candidate and on every attempt that uses it.
type Origin struct {
	// Endpoint is the page or endpoint whose data carried the value (the
	// TestCase URL for a stored body, the endpoint URL for a parameter).
	Endpoint string `json:"endpoint,omitempty"`
	// Field is the JSON field path (users.username), parameter name, or link
	// path that carried the value.
	Field string `json:"field,omitempty"`
	// Via is one of the Via* constants.
	Via string `json:"via,omitempty"`
}

// Describe renders the provenance for a human-readable finding/reason string.
func (o Origin) Describe() string {
	where := o.Endpoint
	if where == "" {
		where = "the scan's stored data"
	}
	switch o.Via {
	case ViaJSON:
		if o.Field != "" {
			return fmt.Sprintf("harvested from %s (JSON field %s)", where, o.Field)
		}
	case ViaLink:
		if o.Field != "" {
			return fmt.Sprintf("harvested from %s (link %s)", where, o.Field)
		}
	case ViaQuery, ViaParameter:
		if o.Field != "" {
			return fmt.Sprintf("harvested from %s (parameter %s)", where, o.Field)
		}
	case ViaPath:
		return fmt.Sprintf("harvested from %s (path segment)", where)
	case ViaHTML:
		if o.Field != "" {
			return fmt.Sprintf("harvested from %s (HTML field %s)", where, o.Field)
		}
	}
	return fmt.Sprintf("harvested from %s", where)
}

// Harvest is one identifier mined from data the scan already holds.
type Harvest struct {
	Value  string `json:"value"`
	Shape  Shape  `json:"shape"`
	Origin Origin `json:"origin"`
	// Count is how many times the value was observed in the scan's data. It
	// only orders candidates; it is never sent anywhere.
	Count int `json:"count,omitempty"`
}

// Observation is one unit of already-collected scan data handed to the
// harvester. Values are explicit identifiers (path segment, query value,
// parameter example); Body is a stored response body (HTML or JSON) mined for
// identity fields and same-origin links. The harvester never fetches anything:
// an Observation is always data the scan already has.
type Observation struct {
	// Endpoint is the page/endpoint this data came from (provenance).
	Endpoint string
	// Field names the parameter or path context of Values.
	Field string
	// Via classifies Values (ViaPath, ViaQuery, ViaParameter).
	Via string
	// Values are explicit identifiers observed in already-collected data.
	Values []string
	// Body is a stored response body, already bounded by the caller to
	// MaxHarvestBodyBytes.
	Body []byte
	// BodyURL is the absolute URL the body was fetched from. It resolves
	// relative links and keeps only same-origin ones.
	BodyURL string
}

// HarvestCandidates mines observations for foreign object identifiers and
// returns a deterministic, priority-ordered, de-duplicated set, capped at
// limit (MaxHarvested when limit is <= 0 or too large).
//
// Priority is the documented extraction order — usernames/handles, numeric
// ids, UUIDs, emails — with more-observed values first inside a shape and the
// value itself as the final tie-break, so the set never depends on map
// iteration or response layout.
//
// exclude names values that must NEVER be proposed: the caller's own identity,
// the scan's session cookies/tokens. Matching is case-insensitive.
func HarvestCandidates(observations []Observation, exclude []string, limit int) []Harvest {
	if limit <= 0 || limit > MaxHarvested {
		limit = MaxHarvested
	}
	excluded := make(map[string]bool, len(exclude))
	for _, v := range exclude {
		if v = strings.TrimSpace(v); v != "" {
			excluded[strings.ToLower(v)] = true
		}
	}

	type agg struct {
		value  string
		shape  Shape
		origin Origin
		count  int
	}
	byValue := map[string]*agg{}
	add := func(raw string, origin Origin) {
		v := strings.TrimSpace(raw)
		shape, ok := classifyHarvested(v)
		if !ok {
			return
		}
		key := strings.ToLower(v)
		if excluded[key] {
			return
		}
		if a, seen := byValue[key]; seen {
			a.count++
			// Prefer the most precise provenance, but keep it deterministic:
			// better via rank wins, an equal rank keeps the first origin.
			if viaRank(origin.Via) < viaRank(a.origin.Via) {
				a.origin = origin
			}
			return
		}
		byValue[key] = &agg{value: v, shape: shape, origin: origin, count: 1}
	}

	for _, ob := range observations {
		if ob.Field == "" && len(ob.Values) > 0 {
			ob.Field = "value"
		}
		for _, v := range ob.Values {
			add(v, Origin{Endpoint: ob.Endpoint, Field: ob.Field, Via: ob.Via})
		}
		if len(ob.Body) > 0 {
			body := ob.Body
			if len(body) > MaxHarvestBodyBytes {
				body = body[:MaxHarvestBodyBytes]
			}
			mineBody(body, ob, add)
		}
	}

	out := make([]Harvest, 0, len(byValue))
	for _, a := range byValue {
		out = append(out, Harvest{Value: a.value, Shape: a.shape, Origin: a.origin, Count: a.count})
	}
	sort.Slice(out, func(i, j int) bool {
		if shapeRank(out[i].Shape) != shapeRank(out[j].Shape) {
			return shapeRank(out[i].Shape) < shapeRank(out[j].Shape)
		}
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Value < out[j].Value
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func shapeRank(s Shape) int {
	switch s {
	case ShapeUsername:
		return 0
	case ShapeNumeric:
		return 1
	case ShapeUUID:
		return 2
	case ShapeEmail:
		return 3
	default:
		return 4
	}
}

func viaRank(v string) int {
	switch v {
	case ViaJSON:
		return 0
	case ViaHTML:
		return 1
	case ViaParameter:
		return 2
	case ViaQuery:
		return 3
	case ViaLink:
		return 4
	case ViaPath:
		return 5
	default:
		return 6
	}
}

// ---------------------------------------------------------------------------
// classification and filtering
// ---------------------------------------------------------------------------

var (
	uuidValueRE  = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	emailValueRE = regexp.MustCompile(`^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$`)
	numericRE    = regexp.MustCompile(`^[0-9]+$`)
	usernameRE   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._\-]{1,31}$`)
	versionRE    = regexp.MustCompile(`^[vV]?[0-9]+(?:\.[0-9]+){1,3}(?:[-+][0-9A-Za-z.\-]+)?$`)
	hexRE        = regexp.MustCompile(`^[0-9a-fA-F]+$`)
	epochRE      = regexp.MustCompile(`^(?:1[0-9]{9}|1[0-9]{12})$`)
	ymdRE        = regexp.MustCompile(`^(?:19|20)[0-9]{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12][0-9]|3[01])$`)
	ymRE         = regexp.MustCompile(`^(?:19|20)[0-9]{2}(?:0[1-9]|1[0-2])$`)
	assetExtRE   = regexp.MustCompile(`(?i)\.(?:png|jpe?g|gif|svg|webp|ico|css|js|mjs|map|woff2?|ttf|eot|otf|html?|php|aspx?|jsp|xml|txt|csv)$`)
)

// nonIdentifierWords are values that match the username shape but are route
// keywords, HTTP verbs, form vocabulary or placeholders rather than a real
// principal. They can appear as link segments (/users/edit) or as button
// values, and proposing one would read an unrelated page. Conservative: a
// false negative just means one identifier is not tested.
var nonIdentifierWords = map[string]bool{
	"api": true, "v1": true, "v2": true, "v3": true, "v4": true,
	"login": true, "logout": true, "signin": true, "signup": true, "signout": true,
	"register": true, "user": true, "users": true,
	"account": true, "accounts": true, "profile": true, "profiles": true,
	"settings": true, "dashboard": true, "home": true, "index": true,
	"static": true, "assets": true, "public": true, "auth": true, "oauth": true,
	"oauth2": true, "callback": true, "webhook": true, "docs": true, "help": true,
	"about": true, "contact": true, "search": true, "edit": true, "new": true,
	"create": true, "update": true, "delete": true, "view": true, "show": true,
	"list": true, "detail": true, "details": true, "items": true, "item": true,
	"products": true, "product": true, "orders": true, "order": true,
	"invoices": true, "invoice": true, "documents": true, "document": true,
	"doc": true, "articles": true, "article": true,
	"categories": true, "category": true,
	"cart": true, "checkout": true, "download": true, "upload": true,
	"files": true, "images": true, "css": true, "js": true, "favicon": true,
	"robots": true, "sitemap": true, "health": true, "healthz": true, "status": true,
	"submit": true, "cancel": true, "save": true, "close": true, "next": true,
	"prev": true, "previous": true, "page": true, "true": true, "false": true,
	"null": true, "none": true, "undefined": true, "default": true,
}

// classifyHarvested reports the shape of a candidate identifier and whether the
// harvester may propose it at all.
//
// Rules (see docs/idor.md "Harvesting"):
//
//	username  carlos, john.smith   2..32 chars, starts with a letter
//	numeric   1001                 2..12 digits, not a timestamp/year
//	uuid      8f14e45f-…           canonical 8-4-4-4-12
//	email     a@example.com        local@domain.tld
//	opaque    anything else        never proposed
//
// Rejected regardless of shape: values shorter than 2 or longer than
// MaxHarvestValueLen, whitespace/control/markup, URLs and encoded fragments,
// version strings (v1.2.3), hash-like hex (asset fingerprints), asset file
// names, and route/placeholder words.
func classifyHarvested(raw string) (Shape, bool) {
	v := strings.TrimSpace(raw)
	if len(v) < 2 || len(v) > MaxHarvestValueLen {
		return "", false
	}
	if !candidateShaped(v) { // no whitespace, control chars, markup
		return "", false
	}
	if strings.ContainsAny(v, `/\?#&=:;%*()[]|"`) {
		return "", false
	}
	if emailValueRE.MatchString(v) {
		return ShapeEmail, true
	}
	if uuidValueRE.MatchString(v) {
		return ShapeUUID, true
	}
	if numericRE.MatchString(v) {
		if !acceptableNumber(v) {
			return "", false
		}
		return ShapeNumeric, true
	}
	if versionRE.MatchString(v) {
		return "", false
	}
	if assetExtRE.MatchString(v) {
		return "", false
	}
	// Hex strings are asset/build fingerprints far more often than object ids.
	// UUIDs are handled above; any other long hex run is refused.
	if len(v) >= 16 && hexRE.MatchString(v) {
		return "", false
	}
	if usernameRE.MatchString(v) {
		lower := strings.ToLower(v)
		if placeholderValues[lower] || grammarValues[lower] || nonIdentifierWords[lower] {
			return "", false
		}
		return ShapeUsername, true
	}
	return ShapeOpaque, false
}

// acceptableNumber rejects numbers that are timestamps rather than identifiers.
// Four-digit numbers in the calendar range are treated as years: a real
// four-digit object id is still reachable as a numeric neighbour of the
// caller's own id, so the loss is bounded and the false-positive risk (reading
// "2025" as an object) is removed.
func acceptableNumber(v string) bool {
	if len(v) < 2 || len(v) > 12 {
		return false
	}
	if epochRE.MatchString(v) || ymdRE.MatchString(v) || ymRE.MatchString(v) {
		return false
	}
	if len(v) == 4 {
		if n, err := strconv.Atoi(v); err == nil && n >= 1990 && n <= 2100 {
			return false
		}
	}
	return true
}

// ShapeOf classifies a value without proposing it. An unrecognised value is
// ShapeOpaque.
func ShapeOf(v string) Shape {
	if s, ok := classifyHarvested(v); ok {
		return s
	}
	if s, ok := classifyLenient(v); ok {
		return s
	}
	return ShapeOpaque
}

// classifyLenient classifies a value the harvester would reject but whose shape
// still matters for matching: the caller's own identifier may legitimately be
// an opaque slug or a hash. It only answers "what family is this?".
func classifyLenient(raw string) (Shape, bool) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return ShapeOpaque, false
	}
	switch {
	case emailValueRE.MatchString(v):
		return ShapeEmail, true
	case uuidValueRE.MatchString(v):
		return ShapeUUID, true
	case numericRE.MatchString(v):
		return ShapeNumeric, true
	case usernameRE.MatchString(v):
		return ShapeUsername, true
	}
	return ShapeOpaque, false
}

// shapeCompatible reports whether a harvested shape may be tried against an
// endpoint whose own identifier has ownShape. Only an exact family match is
// allowed; ShapeOpaque matches nothing.
func shapeCompatible(ownShape, cand Shape) bool {
	if ownShape == "" || ownShape == ShapeOpaque {
		return false
	}
	return ownShape == cand
}

// ---------------------------------------------------------------------------
// body mining: JSON and HTML
// ---------------------------------------------------------------------------

func mineBody(body []byte, ob Observation, add func(string, Origin)) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return
	}
	if trimmed[0] == '{' || trimmed[0] == '[' {
		if mineJSON(trimmed, ob, add) {
			return
		}
	}
	mineHTML(body, ob, add)
}

func mineJSON(body []byte, ob Observation, add func(string, Origin)) bool {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var root any
	if err := dec.Decode(&root); err != nil {
		return false
	}
	walkHarvest(root, "", 0, func(value, path string) {
		add(value, Origin{Endpoint: ob.Endpoint, Field: path, Via: ViaJSON})
	})
	return true
}

// walkHarvest descends maps AND arrays (a user listing is exactly where foreign
// identifiers live) to a bounded depth, and only offers values whose key names
// an identity/object attribute — the page title or a product name is never
// mined.
func walkHarvest(v any, path string, depth int, add func(value, path string)) {
	if depth > maxHarvestDepth {
		return
	}
	switch node := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(node))
		for k := range node {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			child := k
			if path != "" {
				child = path + "." + k
			}
			switch val := node[k].(type) {
			case string:
				if harvestKey(k) {
					add(val, child)
				}
			case json.Number:
				if harvestKey(k) {
					add(val.String(), child)
				}
			case map[string]any:
				walkHarvest(val, child, depth+1, add)
			case []any:
				walkHarvest(val, child, depth+1, add)
			}
		}
	case []any:
		for i, item := range node {
			if i >= maxHarvestArrayItems {
				return
			}
			walkHarvest(item, path, depth+1, add)
		}
	}
}

// harvestKey reports whether a JSON key names an object identifier (the
// documented vocabulary) or an identity attribute of the record it belongs
// to. A bare "id" is accepted here (unlike identity extraction, where it must
// sit inside a user-ish object): harvesting is explicitly looking for object
// identifiers anywhere in a listing — but only where the FIELD NAME says it
// is one, never because some value merely looks identifier-shaped.
func harvestKey(key string) bool {
	if IdentifierName(key) {
		return true
	}
	switch normalizeIdentifierName(key) {
	case "username", "user_name", "login", "handle", "screen_name", "nickname", "nick",
		"email", "mail", "email_address", "contact_email",
		"uuid", "guid", "owner", "author", "created_by":
		return true
	}
	return false
}

var (
	hrefRE = regexp.MustCompile(`(?is)\b(?:href|action)\s*=\s*(?:"([^"<>]*)"|'([^'<>]*)')`)
)

func mineHTML(body []byte, ob Observation, add func(string, Origin)) {
	// Ordinary route words this page links to in a NON-object position: a
	// bare /product or /login link makes "product"/"login" a route, never an
	// identifier, even if the same word also appears as an input value or in
	// labelled text. Precision first: one identifier not tested is safe; a
	// route probed as an object is a wasted request and a misleading verdict.
	routeWords := linkRouteWords(body, ob)
	addHTML := func(raw string, origin Origin) {
		if isRouteWordValue(raw, routeWords) {
			return
		}
		add(raw, origin)
	}

	// Form fields: <input name="username" value="carlos">.
	for _, tag := range inputTagRE.FindAll(body, -1) {
		attrs := map[string]string{}
		for _, m := range inputAttrRE.FindAllSubmatch(tag, -1) {
			name := strings.ToLower(string(m[1]))
			val := string(m[2])
			if val == "" {
				val = string(m[3])
			}
			attrs[name] = val
		}
		name := attrs["name"]
		if !harvestInputName(name) {
			continue
		}
		addHTML(attrs["value"], Origin{Endpoint: ob.Endpoint, Field: name, Via: ViaHTML})
	}

	// Same-origin links: the crawler's own link graph, recovered from a stored
	// body. Only relative/absolute links on the body's own origin are mined.
	for _, m := range hrefRE.FindAllStringSubmatch(string(body), -1) {
		raw := string(m[1])
		if raw == "" {
			raw = string(m[2])
		}
		mineLink(raw, ob, addHTML)
	}

	// Labelled text ("Username: carlos", "Your username is carlos"). Reuse the
	// identity extractor's strict separator rule so prose is never mined.
	text := visibleText(body)
	for _, spec := range []struct {
		re   *regexp.Regexp
		kind FieldKind
	}{
		{usernameText, FieldUsername},
		{emailText, FieldEmail},
		{userIDText, FieldUserID},
	} {
		for _, m := range spec.re.FindAllStringSubmatchIndex(text, -1) {
			if valueContinues(text, m[3]) {
				continue
			}
			val := text[m[2]:m[3]]
			if s, ok := acceptableValue(spec.kind, val); ok {
				addHTML(s, Origin{Endpoint: ob.Endpoint, Field: "labelled text", Via: ViaHTML})
			}
		}
	}
}

// harvestInputName extends the identity input-name rule with the bare id names
// a listing form may carry.
func harvestInputName(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	switch n {
	case "id", "uuid", "guid", "author", "owner", "username", "user_name", "login", "email", "mail":
		return true
	}
	_, ok := htmlInputKind(n)
	return ok
}

// resolveSameOriginLink resolves one href/action against the body URL and
// reports whether it is usable and same-origin, returning its path. Cross-
// origin links, fragments and non-navigational schemes are refused, so a
// stored body can only attribute data to its own origin.
func resolveSameOriginLink(raw string, ob Observation) (*url.URL, string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(raw, "#") {
		return nil, "", false
	}
	lower := strings.ToLower(raw)
	for _, prefix := range []string{"javascript:", "mailto:", "tel:", "data:"} {
		if strings.HasPrefix(lower, prefix) {
			return nil, "", false
		}
	}
	ref, err := url.Parse(raw)
	if err != nil {
		return nil, "", false
	}
	base, baseErr := url.Parse(ob.BodyURL)
	if baseErr != nil || base.Scheme == "" || base.Host == "" {
		base = nil
	}
	if ref.IsAbs() {
		if base == nil || !strings.EqualFold(ref.Scheme, base.Scheme) || !strings.EqualFold(ref.Host, base.Host) {
			return nil, "", false
		}
	} else if base != nil {
		ref = base.ResolveReference(ref)
	}
	return ref, ref.Path, true
}

// linkRouteWords collects the ordinary route segments this body links to:
// every path segment that is NOT positionally an object. A page linking
// /product marks "product" as a route; a page linking /users/dave does not
// mark "dave", because that segment is in object position.
func linkRouteWords(body []byte, ob Observation) map[string]bool {
	out := map[string]bool{}
	for _, m := range hrefRE.FindAllStringSubmatch(string(body), -1) {
		raw := string(m[1])
		if raw == "" {
			raw = string(m[2])
		}
		_, linkPath, ok := resolveSameOriginLink(raw, ob)
		if !ok {
			continue
		}
		segs := splitPathSegments(linkPath)
		for i, seg := range segs {
			if objectPosition(segs, i) {
				continue
			}
			out[strings.ToLower(seg)] = true
		}
	}
	return out
}

// isRouteWordValue reports whether a pure alphabetic value is also an
// ordinary route on this page ("product" because /product is linked). Such a
// word is a route, not a foreign identifier: probing it reads an unrelated
// page and produces a misleading "session did not reach the object" verdict.
func isRouteWordValue(raw string, routeWords map[string]bool) bool {
	v := strings.ToLower(strings.TrimSpace(raw))
	if v == "" || !routeWords[v] {
		return false
	}
	for _, r := range v {
		if r < 'a' || r > 'z' {
			return false
		}
	}
	return true
}

// mineLink extracts identifier-shaped path segments and object-id query values
// from one same-origin link.
//
// A path segment is mined ONLY when it is positionally an object: the segment
// after a collection noun (/users/dave, /orders/99). A bare top-level route
// (/product) contributes nothing — that was the live defect this rule fixes.
// Route keywords are still refused inside an object position, so
// /users/edit contributes nothing.
func mineLink(raw string, ob Observation, add func(string, Origin)) {
	ref, linkPath, ok := resolveSameOriginLink(raw, ob)
	if !ok {
		return
	}
	segs := splitPathSegments(linkPath)
	for i, seg := range segs {
		if !objectPosition(segs, i) {
			continue
		}
		if _, ok := classifyHarvested(seg); !ok {
			continue
		}
		add(seg, Origin{Endpoint: ob.Endpoint, Field: linkPath, Via: ViaLink})
	}
	query := ref.Query()
	names := make([]string, 0, len(query))
	for name := range query {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if !ObjectIDParameter(name) {
			continue
		}
		for _, v := range query[name] {
			add(v, Origin{Endpoint: ob.Endpoint, Field: linkPath + "?" + name, Via: ViaLink})
		}
	}
}
