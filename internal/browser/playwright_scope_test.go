package browser

import (
	"strings"
	"testing"
)

func TestCDPRedirectTargetRejectsBackslashLocation(t *testing.T) {
	params := map[string]interface{}{
		"responseStatusCode": float64(302),
		"responseHeaders": []interface{}{
			map[string]interface{}{"name": "Location", "value": `\outside`},
		},
		"request": map[string]interface{}{"url": "http://127.0.0.1:8122/api/start"},
	}
	target, redirect, invalid := cdpRedirectTarget(params)
	if !redirect || !invalid {
		t.Fatalf("backslash redirect parsed as target=%q redirect=%v invalid=%v; ambiguous browser URL forms must fail closed", target, redirect, invalid)
	}
}

func redirectParams(location string) map[string]interface{} {
	return map[string]interface{}{
		"responseStatusCode": float64(302),
		"responseHeaders": []interface{}{
			map[string]interface{}{"name": "Location", "value": location},
		},
		"request": map[string]interface{}{"url": "http://127.0.0.1:8122/api/start"},
	}
}

// Go's net/url reads these as a path on the CURRENT host; Chromium's WHATWG
// parser (special scheme) skips the extra slashes and reads an authority. Every
// shape here must fail closed rather than be compared as the Go reading.
func TestCDPRedirectTargetRejectsForms(t *testing.T) {
	for _, location := range []string{
		"///evil.example/x",
		"////evil.example/x",
		"/////evil.example/x",
		"///evil.example",
		"///",
		"http:///evil.example/x",
		"https:///evil.example/x",
		"http:evil.example/x",
		"mailto:a@evil.example",
		"/\t/evil.example/x",
		"/\n/evil.example/x",
		"/\r/evil.example/x",
		" //evil.example/x",
		"//evil.example/x ",
		"\x00//evil.example/x",
		"\x7f//evil.example/x",
		`\\evil.example/x`,
		`/\evil.example/x`,
	} {
		target, redirect, invalid := cdpRedirectTarget(redirectParams(location))
		if !redirect || !invalid {
			t.Errorf("Location %q parsed as target=%q invalid=%v; ambiguous forms must fail closed", location, target, invalid)
		}
	}
}

// The fix must not reject ordinary redirects, or every login and canonical-URL
// redirect on a real site would be aborted.
func TestCDPRedirectTargetKeepsOrdinaryForms(t *testing.T) {
	for _, tc := range []struct{ location, want string }{
		{"/login", "http://127.0.0.1:8122/login"},
		{"/a/b/c?x=1&y=2#frag", "http://127.0.0.1:8122/a/b/c?x=1&y=2#frag"},
		{"/a//b", "http://127.0.0.1:8122/a//b"},
		{"next", "http://127.0.0.1:8122/api/next"},
		{"../up", "http://127.0.0.1:8122/up"},
		{"?q=1", "http://127.0.0.1:8122/api/start?q=1"},
		{"//other.example/x", "http://other.example/x"},
		{"http://other.example:8080/p", "http://other.example:8080/p"},
		{"https://other.example/p?q=%2F", "https://other.example/p?q=%2F"},
	} {
		target, redirect, invalid := cdpRedirectTarget(redirectParams(tc.location))
		if !redirect || invalid || target != tc.want {
			t.Errorf("Location %q -> target=%q redirect=%v invalid=%v, want %q", tc.location, target, redirect, invalid, tc.want)
		}
	}
}

// --- browser method gate (non-mutating default) ---

func TestIsReadOnlyMethodFailsClosed(t *testing.T) {
	for _, method := range []string{"GET", "get", "HEAD", "OPTIONS", " Get "} {
		if !isReadOnlyMethod(method) {
			t.Errorf("isReadOnlyMethod(%q) = false, want true", method)
		}
	}
	for _, method := range []string{"POST", "PUT", "PATCH", "DELETE", "CONNECT", "TRACE", "PROPFIND", ""} {
		if isReadOnlyMethod(method) {
			t.Errorf("isReadOnlyMethod(%q) = true; an unrecognized/non-read-only method must fail closed", method)
		}
	}
}

// redirectPolicyParams builds one response-stage Fetch.requestPaused event.
func redirectPolicyParams(status int, method, location string) map[string]interface{} {
	params := redirectParams(location)
	params["responseStatusCode"] = float64(status)
	params["request"] = map[string]interface{}{"url": "http://127.0.0.1:8122/api/start", "method": method}
	return params
}

// A 307/308 repeats the original method, so the per-hop gate must refuse to
// carry a state-changing method onward when the context did not opt in. 301/
// 302/303 rewrite the method to GET, so the initial request's check is enough.
func TestRedirectMustFailOnPreservedStateChangingMethod(t *testing.T) {
	allowAll := func(string) bool { return true }
	for _, tc := range []struct {
		name               string
		status             int
		method             string
		allowStateChanging bool
		want               bool
	}{
		{"307-post-default", 307, "POST", false, true},
		{"308-put-default", 308, "PUT", false, true},
		{"307-delete-default", 307, "DELETE", false, true},
		{"307-empty-method-default", 307, "", false, true}, // malformed event fails closed
		{"307-get-default", 307, "GET", false, false},
		{"308-head-default", 308, "HEAD", false, false},
		{"302-post-default", 302, "POST", false, false}, // browser rewrites it to GET
		{"307-post-opted-in", 307, "POST", true, false},
		{"308-put-opted-in", 308, "PUT", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := redirectMustFail(redirectPolicyParams(tc.status, tc.method, "/next"), allowAll, tc.allowStateChanging); got != tc.want {
				t.Fatalf("redirectMustFail(status=%d method=%q allowStateChanging=%v) = %v, want %v", tc.status, tc.method, tc.allowStateChanging, got, tc.want)
			}
		})
	}
}

// The method policy is additive to the scope gate, never a replacement.
func TestRedirectMustFailKeepsScopeCheck(t *testing.T) {
	allowOnlyAPI := func(raw string) bool { return strings.HasPrefix(raw, "http://127.0.0.1:8122/api/") }
	if !redirectMustFail(redirectPolicyParams(307, "GET", "http://outside.example/x"), allowOnlyAPI, true) {
		t.Fatal("an out-of-scope redirect must be refused even when state-changing requests are allowed")
	}
	if redirectMustFail(redirectPolicyParams(307, "GET", "/api/next"), allowOnlyAPI, false) {
		t.Fatal("an in-scope read-only redirect must not be refused")
	}
}
