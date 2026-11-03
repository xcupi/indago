package idor

// Harvesting tests: fixed fixtures only. Nothing here performs a request or
// touches the network — these are the pure extraction, filtering, ranking and
// merge rules the engine relies on.

import (
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

func harvestValues(hs []Harvest) []string {
	out := make([]string, 0, len(hs))
	for _, h := range hs {
		out = append(out, h.Value)
	}
	return out
}

func TestHarvestFindsForeignUsernameAndUUID(t *testing.T) {
	// A user listing: the caller's own record (wiener) plus one foreign
	// record. The caller's own name and id must never be proposed.
	const callerUUID = "11111111-1111-4111-8111-111111111111"
	const foreignUUID = "5f0c0f4e-1d2a-4c3b-9a11-8f6c2b7d4e10"
	body := []byte(`{
	  "profile": {"username": "wiener", "uuid": "` + callerUUID + `"},
	  "shared": [{"username": "carlos", "uuid": "` + foreignUUID + `"}]
	}`)

	got := HarvestCandidates([]Observation{{
		Endpoint: "https://app.test/admin/users",
		BodyURL:  "https://app.test/admin/users",
		Body:     body,
	}}, []string{"wiener", callerUUID}, 0)

	if len(got) != 2 {
		t.Fatalf("harvested %v, want exactly [carlos %s]", harvestValues(got), foreignUUID)
	}
	seen := map[string]Harvest{}
	for _, h := range got {
		seen[h.Value] = h
	}
	user, ok := seen["carlos"]
	if !ok {
		t.Fatalf("foreign username carlos missing: %v", harvestValues(got))
	}
	if user.Shape != ShapeUsername {
		t.Fatalf("carlos shape = %q, want username", user.Shape)
	}
	if user.Origin.Endpoint != "https://app.test/admin/users" || user.Origin.Via != ViaJSON ||
		user.Origin.Field != "shared.username" {
		t.Fatalf("carlos provenance = %+v, want shared.username on the listing endpoint", user.Origin)
	}
	uuid, ok := seen[foreignUUID]
	if !ok {
		t.Fatalf("foreign uuid missing: %v", harvestValues(got))
	}
	if uuid.Shape != ShapeUUID || uuid.Origin.Field != "shared.uuid" {
		t.Fatalf("uuid = %+v, want shape uuid from shared.uuid", uuid)
	}
	for _, v := range harvestValues(got) {
		if v == "wiener" || v == callerUUID {
			t.Fatalf("harvest proposed the caller's own identifier %q", v)
		}
	}
}

func TestHarvestRejectsTimestampsVersionsAndFingerprints(t *testing.T) {
	t.Run("explicit values", func(t *testing.T) {
		values := []string{
			"1",                    // too short: matches everything
			"1725600000",           // epoch seconds
			"1725600000000",        // epoch milliseconds
			"20240101",             // yyyymmdd
			"2026",                 // year
			"v1.2.3",               // version
			"1.2.3",                // version
			"a3f9c1e0b7d2e4f5",     // 16-hex asset fingerprint
			"deadbeefdeadbeefdead", // longer hex fingerprint
			"style.css",            // asset file
			"https://app.test/x",   // URL
			"user name",            // whitespace
			"<b>carlos</b>",        // markup
			strings.Repeat("a", MaxHarvestValueLen+1), // too long
		}
		got := HarvestCandidates([]Observation{{Endpoint: "https://app.test/", Values: values, Via: ViaParameter}}, nil, 0)
		if len(got) != 0 {
			t.Fatalf("non-identifiers were proposed: %v", harvestValues(got))
		}
	})

	t.Run("json fields", func(t *testing.T) {
		body := []byte(`{"id":"1725600000","user_id":"20240101","uuid":"v1.2.3","username":"a3f9c1e0b7d2e4f5"}`)
		got := HarvestCandidates([]Observation{{Endpoint: "https://app.test/report", Body: body}}, nil, 0)
		if len(got) != 0 {
			t.Fatalf("non-identifiers were proposed from JSON: %v", harvestValues(got))
		}
	})

	t.Run("html label only yields real values", func(t *testing.T) {
		body := []byte(`<p>Username: <strong>carlos</strong></p><p>Build: v1.2.3</p>`)
		got := HarvestCandidates([]Observation{{Endpoint: "https://app.test/", Body: body}}, nil, 0)
		if len(got) != 1 || got[0].Value != "carlos" {
			t.Fatalf("html harvest = %v, want only carlos", harvestValues(got))
		}
	})
}

func TestHarvestFromHTMLAndSameOriginLinks(t *testing.T) {
	body := []byte(`<html><body>
	  <form><input name="username" value="carlos"><input name="q" value="searchterm"></form>
	  <a href="/users/dave">Dave</a>
	  <a href="/users/edit">Edit</a>
	  <a href="/admin/users?account_id=17">account 17</a>
	  <a href="https://evil.test/users/mallory">off-site</a>
	</body></html>`)

	got := HarvestCandidates([]Observation{{
		Endpoint: "https://app.test/admin/users",
		BodyURL:  "https://app.test/admin/users",
		Body:     body,
	}}, nil, 0)

	have := map[string]Harvest{}
	for _, h := range got {
		have[h.Value] = h
	}
	for _, want := range []string{"carlos", "dave", "17"} {
		if _, ok := have[want]; !ok {
			t.Fatalf("%q missing from harvest: %v", want, harvestValues(got))
		}
	}
	for _, banned := range []string{"edit", "searchterm", "mallory"} {
		if _, ok := have[banned]; ok {
			t.Fatalf("%q must not be harvested (route word/non-identifying/external): %v", banned, harvestValues(got))
		}
	}
	if have["dave"].Origin.Via != ViaLink || have["dave"].Origin.Field != "/users/dave" {
		t.Fatalf("dave provenance = %+v, want link /users/dave", have["dave"].Origin)
	}
	if have["carlos"].Origin.Via != ViaHTML || have["carlos"].Origin.Field != "username" {
		t.Fatalf("carlos provenance = %+v, want HTML input username", have["carlos"].Origin)
	}
}

func TestHarvestExcludesCallerAndSessionSecrets(t *testing.T) {
	body := []byte(`{"users":[{"username":"carlos"},{"username":"wiener"}],"token":"s3cr3t-value"}`)
	got := HarvestCandidates([]Observation{{Endpoint: "https://app.test/", Body: body}},
		[]string{"WIENER", "s3cr3t-value"}, 0)
	if len(got) != 1 || got[0].Value != "carlos" {
		t.Fatalf("harvest = %v, want only carlos (caller identity and session value excluded)", harvestValues(got))
	}
}

func TestHarvestIsDeterministicAndCapped(t *testing.T) {
	var values []string
	for i := 0; i < MaxHarvested+10; i++ {
		values = append(values, "user"+string(rune('a'+i%26))+string(rune('a'+i/26)))
	}
	obs := []Observation{{Endpoint: "https://app.test/", Values: values, Via: ViaParameter}}
	first := HarvestCandidates(obs, nil, 0)
	second := HarvestCandidates(obs, nil, 0)
	if len(first) != MaxHarvested {
		t.Fatalf("harvested %d, cap is %d", len(first), MaxHarvested)
	}
	if strings.Join(harvestValues(first), ",") != strings.Join(harvestValues(second), ",") {
		t.Fatalf("harvest is not deterministic:\n%v\n%v", harvestValues(first), harvestValues(second))
	}
}

func TestDeriveFromHarvestMatchesShape(t *testing.T) {
	const u = "5f0c0f4e-1d2a-4c3b-9a11-8f6c2b7d4e10"
	harvested := []Harvest{
		{Value: "carlos", Shape: ShapeUsername},
		{Value: "17", Shape: ShapeNumeric},
		{Value: u, Shape: ShapeUUID},
	}

	t.Run("numeric endpoint only receives numeric ids", func(t *testing.T) {
		got, _ := DeriveCandidatesFromHarvest("3", nil, harvested, 0)
		for _, c := range got {
			if c.Value == u || c.Value == "carlos" {
				t.Fatalf("numeric endpoint received a cross-shape candidate: %+v", got)
			}
		}
		// 4/2/5/1/6 are the numeric neighbours; "17" only if room remains.
		for _, c := range got {
			if c.Shape != ShapeNumeric {
				t.Fatalf("candidate %+v is not numeric", c)
			}
		}
	})

	t.Run("uuid endpoint only receives uuids", func(t *testing.T) {
		const callerUUID = "11111111-1111-4111-8111-111111111111"
		got, _ := DeriveCandidatesFromHarvest(callerUUID, nil, harvested, 0)
		if len(got) != 1 || got[0].Value != u || got[0].Source != "harvested" {
			t.Fatalf("uuid endpoint candidates = %+v, want only the harvested uuid", got)
		}
		if got[0].Origin == nil {
			t.Fatal("harvested candidate must carry its provenance")
		}
	})

	t.Run("username endpoint only receives usernames", func(t *testing.T) {
		got, _ := DeriveCandidatesFromHarvest("wiener", nil, harvested, 0)
		if len(got) != 1 || got[0].Value != "carlos" || got[0].Shape != ShapeUsername {
			t.Fatalf("username endpoint candidates = %+v, want only carlos", got)
		}
	})

	t.Run("opaque endpoint receives nothing and says why", func(t *testing.T) {
		got, reason := DeriveCandidatesFromHarvest("1.txt", nil, harvested, 0)
		if len(got) != 0 {
			t.Fatalf("opaque endpoint received candidates: %+v", got)
		}
		if !strings.Contains(strings.ToLower(reason), "unpredictable") {
			t.Fatalf("skip reason must explain the refusal: %q", reason)
		}
	})

	t.Run("explicit candidate is never shape-filtered", func(t *testing.T) {
		got, _ := DeriveCandidatesFromHarvest("3", []string{"carlos"}, harvested, 0)
		if len(got) == 0 || got[0].Value != "carlos" || got[0].Source != "supplied" {
			t.Fatalf("explicit candidate was dropped by shape matching: %+v", got)
		}
	})
}

func TestDeriveFromHarvestMergesExplicitFirstAndDedupes(t *testing.T) {
	harvested := []Harvest{
		{Value: "carlos", Shape: ShapeUsername, Origin: Origin{Endpoint: "/admin/users", Field: "users.username", Via: ViaJSON}},
		{Value: "dave", Shape: ShapeUsername, Origin: Origin{Endpoint: "/admin/users", Field: "users.username", Via: ViaJSON}},
	}
	got, reason := DeriveCandidatesFromHarvest("wiener", []string{"carlos", "carlos", "wiener"}, harvested, 0)
	if reason != "" {
		t.Fatalf("reason = %q, want none", reason)
	}
	if len(got) != 2 {
		t.Fatalf("merged candidates = %+v, want [carlos dave]", got)
	}
	if got[0].Value != "carlos" || got[0].Source != "supplied" {
		t.Fatalf("explicit candidate must win the dedupe: %+v", got[0])
	}
	if got[0].Origin != nil {
		t.Fatalf("an operator-supplied candidate must not borrow harvest provenance: %+v", got[0])
	}
	if got[1].Value != "dave" || got[1].Source != "harvested" || got[1].Origin == nil {
		t.Fatalf("harvested candidate = %+v, want dave with provenance", got[1])
	}
}

// TestHarvestOnlyMinesIdentifierPositions is the live-lab precision defect:
// an ordinary link (/product) must never yield an identifier, while a
// positional object segment (/users/42) and an id-named query parameter
// (?user_id=77) must.
func TestHarvestOnlyMinesIdentifierPositions(t *testing.T) {
	body := []byte(`<html><body>
	  <a href="/product">Product</a>
	  <a href="/users/42">Alice</a>
	  <a href="/orders/99">Order</a>
	  <a href="/search?user_id=77">search 77</a>
	  <a href="/users/edit">Edit</a>
	</body></html>`)

	got := HarvestCandidates([]Observation{{
		Endpoint: "https://app.test/",
		BodyURL:  "https://app.test/",
		Body:     body,
	}}, nil, 0)

	have := map[string]bool{}
	for _, h := range got {
		have[h.Value] = true
	}
	for _, want := range []string{"42", "99", "77"} {
		if !have[want] {
			t.Fatalf("%q missing from harvest: %v", want, harvestValues(got))
		}
	}
	for _, banned := range []string{"product", "products", "users", "orders", "search", "edit"} {
		if have[banned] {
			t.Fatalf("%q must not be harvested from an ordinary route: %v", banned, harvestValues(got))
		}
	}
}

// TestHarvestDropsRouteWordsUsedAsValues: a bare word that the same page links
// to as an ordinary route is a route, even when it also appears as a form
// value or labelled text. This is the second half of the /product defect.
func TestHarvestDropsRouteWordsUsedAsValues(t *testing.T) {
	body := []byte(`<html><body>
	  <a href="/warehouse">Warehouse</a>
	  <form><input name="username" value="warehouse"></form>
	  <p>Username: warehouse</p>
	</body></html>`)

	got := HarvestCandidates([]Observation{{
		Endpoint: "https://app.test/",
		BodyURL:  "https://app.test/",
		Body:     body,
	}}, nil, 0)
	if len(got) != 0 {
		t.Fatalf("a route word was harvested as an identifier: %v", harvestValues(got))
	}
}

// TestObjectPathSegmentsRequiresPosition pins the path rule directly.
func TestObjectPathSegmentsRequiresPosition(t *testing.T) {
	for _, tc := range []struct {
		path string
		want []string
	}{
		{"/users/42", []string{"42"}},
		{"/users/42/edit", []string{"42"}},
		{"/orders/99", []string{"99"}},
		{"/documents/abc123", []string{"abc123"}},
		{"/product", nil},
		{"/products", nil},
		{"/product/42", []string{"42"}},
		{"/users/edit", nil},
		{"/admin/users", nil},
	} {
		got := ObjectPathSegments(tc.path)
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("ObjectPathSegments(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

// TestIdentifierVocabulary pins the documented name table and the `_id`
// suffix rule.
func TestIdentifierVocabulary(t *testing.T) {
	for _, name := range []string{
		"id", "uid", "user", "user_id", "userId", "account", "accountId",
		"order", "order_id", "invoice", "item", "product", "doc", "document_id",
		"file", "ref", "no", "num", "number", "victim_id", "filters[user_id]",
	} {
		if !IdentifierName(name) {
			t.Errorf("IdentifierName(%q) = false, want true", name)
		}
	}
	for _, name := range []string{"q", "search", "page", "lang", "sort", "path[1]", "", "csrf_token"} {
		if IdentifierName(name) {
			t.Errorf("IdentifierName(%q) = true, want false", name)
		}
	}
}

// TestHarvestStaysPure keeps the package's no-I/O claim honest: harvesting
// must never grow a dependency that could send a request or read a file.
func TestHarvestStaysPure(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "harvest.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	for _, imp := range f.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		// A stdlib import path has no dot in its first element; anything else
		// (github.com/..., a local module path) would be a non-pure dependency.
		if strings.Contains(strings.SplitN(path, "/", 2)[0], ".") {
			t.Fatalf("harvest.go imports non-stdlib package %q: harvesting must stay pure", path)
		}
	}
}
