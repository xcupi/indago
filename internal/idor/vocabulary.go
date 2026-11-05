package idor

// The identifier vocabulary: which NAMES plausibly select an object.
//
// Precision first. A value is only ever treated as an object identifier when
// it comes from a position that is itself identifier-shaped:
//
//   - a query parameter whose name is in this vocabulary (id, user_id, …),
//   - a JSON field whose name is in this vocabulary,
//   - a path segment that is POSITIONALLY an object — the segment after a
//     collection noun (/users/42, /orders/99) — never a bare top-level route
//     such as /product.
//
// The distinction matters on a real target: a crawler's ordinary link graph
// is full of route words (/product, /login, /account). Treating the last path
// segment of any link as an identifier made the engine probe `/product` and
// then report a misleading "login page" inconclusive. Nothing here sends a
// request; it only decides which values may be proposed at all.

import "strings"

// identifierNouns is the documented object-identifier vocabulary. It holds
// the bare nouns, their compact/camelCase forms (userid, userId → userid) and
// the underscore forms (user_id). Any other name is accepted only through the
// generic `_id` suffix rule below.
var identifierNouns = map[string]bool{
	// Generic object selectors.
	"id": true, "uid": true, "guid": true, "uuid": true, "object": true,
	"objectid": true, "object_id": true, "record": true, "recordid": true, "record_id": true,

	// Principals.
	"user": true, "userid": true, "user_id": true, "username": true, "login": true,
	"handle": true, "screen_name": true, "nickname": true, "nick": true,
	"account": true, "accountid": true, "account_id": true,
	"profile": true, "profileid": true, "profile_id": true,
	"member": true, "memberid": true, "member_id": true,
	"customer": true, "customerid": true, "customer_id": true,
	"employee": true, "employeeid": true, "employee_id": true,
	"patient": true, "patientid": true, "patient_id": true,

	// Commerce/object nouns.
	"order": true, "orderid": true, "order_id": true,
	"invoice": true, "invoiceid": true, "invoice_id": true,
	"item": true, "itemid": true, "item_id": true,
	"product": true, "productid": true, "product_id": true,
	"booking": true, "bookingid": true, "booking_id": true,
	"ticket": true, "ticketid": true, "ticket_id": true,

	// Documents and files.
	"doc": true, "docid": true, "doc_id": true,
	"document": true, "documentid": true, "document_id": true,
	"file": true, "fileid": true, "file_id": true, "filename": true, "file_name": true,
	"attachment": true, "attachmentid": true, "attachment_id": true,
	"download": true, "downloadid": true, "download_id": true,

	// References and numbers.
	"ref": true, "refid": true, "ref_id": true,
	"reference": true, "referenceid": true, "reference_id": true,
	"no": true, "num": true, "number": true,

	// Content and tenancy.
	"post": true, "postid": true, "post_id": true,
	"message": true, "messageid": true, "message_id": true, "msg": true, "msgid": true, "msg_id": true,
	"comment": true, "commentid": true, "comment_id": true,
	"report": true, "reportid": true, "report_id": true,
	"tenant": true, "tenantid": true, "tenant_id": true,
	"org": true, "orgid": true, "org_id": true,
	"group": true, "groupid": true, "group_id": true,
	"company": true, "companyid": true, "company_id": true,
}

// collectionNouns are path segments that introduce a collection of objects.
// A segment is positionally an object only when the segment BEFORE it is one
// of these: /users/42 and /orders/99 qualify, /product does not. Both plural
// and singular API spellings are listed because real targets use both.
var collectionNouns = map[string]bool{
	"users": true, "user": true,
	"accounts": true, "account": true,
	"profiles": true, "profile": true,
	"members": true, "member": true,
	"customers": true, "customer": true,
	"employees": true, "employee": true,
	"patients": true, "patient": true,
	"orders": true, "order": true,
	"invoices": true, "invoice": true,
	"items": true, "item": true,
	"products": true, "product": true,
	"bookings": true, "booking": true,
	"tickets": true, "ticket": true,
	"docs": true, "doc": true,
	"documents": true, "document": true,
	"files": true, "file": true,
	"attachments": true, "attachment": true,
	"downloads": true, "download": true,
	"posts": true, "post": true,
	"messages": true, "message": true,
	"comments": true, "comment": true,
	"reports": true, "report": true,
	"records": true, "record": true,
	"objects": true, "object": true,
	"tenants": true, "tenant": true,
	"orgs": true, "org": true,
	"groups": true, "group": true,
	"companies": true, "company": true,
}

// normalizeIdentifierName reduces a parameter/JSON-field name to its bare
// term: `filters[user_id]`, `data.accountId` and `accountId` all normalize to
// a lookup key. Only the LAST component of a dotted/bracketed path is used —
// a wrapper object name is not the name of the identifier.
func normalizeIdentifierName(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	if i := strings.LastIndexAny(n, ".["); i >= 0 {
		n = n[i+1:]
	}
	n = strings.Trim(n, "[]")
	return n
}

// IdentifierName reports whether a parameter or JSON-field name is part of
// the documented object-identifier vocabulary. The generic `_id` suffix is
// accepted too (victim_id, legacy_account_id): it is unambiguously an
// identifier even when its noun is domain-specific.
func IdentifierName(name string) bool {
	n := normalizeIdentifierName(name)
	if n == "" {
		return false
	}
	if identifierNouns[n] {
		return true
	}
	return strings.HasSuffix(n, "_id") && len(n) > 3
}

// CollectionSegment reports whether a path segment introduces a collection
// (/users, /orders). It is used to decide whether the NEXT segment is
// positionally an object identifier.
func CollectionSegment(seg string) bool {
	return collectionNouns[strings.ToLower(strings.TrimSpace(seg))]
}

// objectPosition reports whether segs[i] is positionally an object: it must
// not be the first segment, and the segment before it must be a collection
// noun. This is what rejects a bare top-level route like /product while
// keeping /users/42.
func objectPosition(segs []string, i int) bool {
	if i <= 0 || i >= len(segs) {
		return false
	}
	return CollectionSegment(segs[i-1])
}

// splitPathSegments splits a URL path into non-empty segments. It mirrors
// discovery.PathSegments for the shapes the harvester sees (leading, trailing
// and doubled slashes contribute no empty element).
func splitPathSegments(path string) []string {
	var out []string
	for _, seg := range strings.Split(strings.Trim(path, "/"), "/") {
		if seg != "" {
			out = append(out, seg)
		}
	}
	return out
}

// ObjectPathSegments returns the path segments of path that are BOTH
// identifier-shaped and positionally objects: /users/42/edit → ["42"],
// /product → nil, /products/99 → ["99"]. The scan layer uses it instead of
// "any qualifying segment" so a crawl's ordinary routes are never mined.
func ObjectPathSegments(path string) []string {
	segs := splitPathSegments(path)
	var out []string
	for i, seg := range segs {
		if !objectPosition(segs, i) {
			continue
		}
		if _, ok := classifyHarvested(seg); !ok {
			continue
		}
		out = append(out, seg)
	}
	return out
}
