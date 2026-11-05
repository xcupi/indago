package scan

// Unit-level proof for the encoded forms the cookie redactor must recognise.
// The behavioural tests in accesscontrol_reflection_redaction_test.go prove the
// end-to-end paths; these pin the two cases a serialised blob makes easy to
// miss: a detail record is JSON (encoding/json escapes "&", "<" and ">"), and a
// target may HTML-encode what it echoes back.

import (
	"encoding/json"
	"html"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/indago/indago/internal/httpengine"
)

func TestCookieRedactorRewritesEveryEncodedForm(t *testing.T) {
	const value = "a&b<session" // legal cookie-octet bytes that JSON/HTML escape

	red := newCookieRedactor()
	red.observe(&httpengine.Response{
		Headers: http.Header{"Set-Cookie": []string{"sid=" + value + "; Path=/"}},
		Request: &httpengine.CapturedRequest{Headers: http.Header{}},
	})

	detail := struct {
		Target string `json:"target"`
	}{Target: "/admin/delete?debug=" + value}
	blob, err := json.Marshal(detail)
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]string{
		"raw":         value,
		"html":        html.EscapeString(value),
		"url-encoded": url.QueryEscape(value),
		"json":        string(blob),
	}
	for name, input := range cases {
		got := red.redact(input)
		if strings.Contains(got, value) || (name == "html" && strings.Contains(got, html.EscapeString(value))) {
			t.Fatalf("%s form was not redacted: %q", name, got)
		}
		if !strings.Contains(got, redactedCookieValue) {
			t.Fatalf("%s form produced %q, want the redaction marker", name, got)
		}
	}

	// The serialised detail must stay decodable: redaction replaces bytes, it
	// does not corrupt the record.
	var back struct {
		Target string `json:"target"`
	}
	if err := json.Unmarshal(red.redactBytes(blob), &back); err != nil {
		t.Fatalf("redacted detail is not valid JSON: %v (%s)", err, red.redactBytes(blob))
	}
	if !strings.Contains(back.Target, redactedCookieValue) {
		t.Fatalf("decoded target = %q, want the redaction marker", back.Target)
	}
}

// TestCookieRedactorRedactsShortValuesAndLeavesUnknownTextAlone pins the
// removal of the old length floor: a two-character value ("on"), a four-byte
// value ("dark") and a one-byte value ("1") are all credentials when they were
// observed as cookie values, so every occurrence is rewritten. A value the job
// never observed is untouched. Over-redacting ordinary prose is the accepted
// cost of never persisting a short credential.
func TestCookieRedactorRedactsShortValuesAndLeavesUnknownTextAlone(t *testing.T) {
	red := newCookieRedactor()
	red.observe(&httpengine.Response{
		Headers: http.Header{"Set-Cookie": []string{"ui=on; Path=/", "theme=dark; Path=/", "role=1; Path=/"}},
		Request: &httpengine.CapturedRequest{Headers: http.Header{}},
	})
	body := "<p>theme=dark toggle=on role=1 session unknown-value</p>"
	got := red.redact(body)
	for _, secret := range []string{"dark", "on", "role=1"} {
		if strings.Contains(got, secret) {
			t.Fatalf("short cookie value %q survived redaction: %q", secret, got)
		}
	}
	if !strings.Contains(got, "<redacted>") {
		t.Fatalf("redacted body = %q, want the redaction marker", got)
	}
	if !strings.Contains(got, "unknown-value") {
		t.Fatalf("redaction rewrote a value the job never observed: %q", got)
	}
}

// TestCookieRedactorSingleCharacterValueCannotRewriteTheMarker proves the
// sentinel boundary: a one-character value that also occurs inside the marker
// ("e" in "<redacted>") must still produce exactly one intact marker, not a
// corrupted or recursively rewritten one.
func TestCookieRedactorSingleCharacterValueCannotRewriteTheMarker(t *testing.T) {
	red := newCookieRedactor()
	red.observe(&httpengine.Response{
		Headers: http.Header{"Set-Cookie": []string{"flag=e; Path=/"}},
		Request: &httpengine.CapturedRequest{Headers: http.Header{}},
	})
	if got, want := red.redact("flag=e"), "flag=<redacted>"; got != want {
		t.Fatalf("redacted = %q, want %q", got, want)
	}
}

// TestCookieRedactorRedactsLongerValueFirst proves the ordering rule: when one
// stored value is a prefix of another, the longer one is rewritten whole rather
// than leaving its tail behind as "<redacted>0".
func TestCookieRedactorRedactsLongerValueFirst(t *testing.T) {
	red := newCookieRedactor()
	red.observe(&httpengine.Response{
		Headers: http.Header{"Set-Cookie": []string{"a=sessiontoken1; Path=/", "b=sessiontoken10; Path=/"}},
		Request: &httpengine.CapturedRequest{Headers: http.Header{}},
	})
	got := red.redact("debug=sessiontoken1 debug=sessiontoken10")
	if want := "debug=" + redactedCookieValue + " debug=" + redactedCookieValue; got != want {
		t.Fatalf("redacted = %q, want %q (no fragment of either value may survive)", got, want)
	}
}

// TestCookieRedactorJSONDetailKeepsStructuralPrimitives: a one-digit cookie
// value ("1") must be removed from cookie-derived STRING data, but the record
// is evidence — independent numeric/boolean fields and unknown fields must
// survive unchanged and the whole detail must remain valid JSON.
func TestCookieRedactorJSONDetailKeepsStructuralPrimitives(t *testing.T) {
	red := newCookieRedactor()
	red.observe(&httpengine.Response{
		Headers: http.Header{"Set-Cookie": []string{"role=1; Path=/"}},
		Request: &httpengine.CapturedRequest{Headers: http.Header{}},
	})
	raw := []byte(`{"attempt":1,"cookie":"role=1","status":200,"ok":true,"none":null,` +
		`"unknown":{"n":[1,2.50,"x1y"],"big":12345678901234567890},"nested":{"target":"/p?debug=1"}}`)
	got := red.redactJSON(raw)

	var detail map[string]any
	dec := json.NewDecoder(strings.NewReader(string(got)))
	dec.UseNumber()
	if err := dec.Decode(&detail); err != nil {
		t.Fatalf("redacted detail must remain valid JSON: %v; bytes=%s", err, got)
	}
	if detail["attempt"] != json.Number("1") || detail["status"] != json.Number("200") ||
		detail["ok"] != true || detail["none"] != nil {
		t.Fatalf("structural primitives changed: %s", got)
	}
	if detail["cookie"] != "role=<redacted>" {
		t.Fatalf("cookie string = %v, want role=<redacted>", detail["cookie"])
	}
	if tgt := detail["nested"].(map[string]any)["target"]; tgt != "/p?debug=<redacted>" {
		t.Fatalf("nested target = %v", tgt)
	}
	unk := detail["unknown"].(map[string]any)
	if unk["big"] != json.Number("12345678901234567890") {
		t.Fatalf("unknown numeric field changed: %s", got)
	}
	arr := unk["n"].([]any)
	if arr[0] != json.Number("1") || arr[1] != json.Number("2.50") || arr[2] != "x<redacted>y" {
		t.Fatalf("unknown array field changed: %v", arr)
	}

	// Not-JSON input falls back to strict byte redaction.
	if out := string(red.redactJSON([]byte("not json 1"))); strings.Contains(out, "1") {
		t.Fatalf("non-JSON fallback leaked the value: %q", out)
	}
}
