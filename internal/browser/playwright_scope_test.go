package browser

import "testing"

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
