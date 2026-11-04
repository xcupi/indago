package verification

import "testing"

// The matcher must accept only Chromium's INLINE EVENT HANDLER wording: an
// unrelated blocked <script> block ("Executing inline script violates ...") is
// a different policy refusal and must not be reported as the reason a handler
// did not run.
func TestCSPInlineHandlerBlocked(t *testing.T) {
	const real = "Executing inline event handler violates the following Content Security Policy directive 'script-src 'self''. Either the 'unsafe-inline' keyword, a hash ('sha256-abc'), or a nonce ('nonce-...') is required to enable inline execution. Note that hashes do not apply to event handlers, style attributes and javascript: navigations unless the 'unsafe-hashes' keyword is present. The action has been blocked."

	tests := []struct {
		name    string
		log     []string
		want    bool
		wantTxt string
	}{
		{name: "empty log"},
		{
			name: "chromium inline event handler block",
			log:  []string{"something else", real},
			want: true,
		},
		{
			name: "multiline message yields its first line",
			log:  []string{real + "\n    at foo (https://example/app.js:1:2)"},
			want: true, wantTxt: real,
		},
		{
			name: "inline script block is a different policy refusal",
			log:  []string{"Executing inline script violates the following Content Security Policy directive 'script-src 'self''. Either the 'unsafe-inline' keyword ... is required to enable inline execution. The action has been blocked."},
		},
		{
			name: "generic CSP text without the signature",
			log:  []string{"Refused to load the image 'https://example/x.png' because it violates the Content Security Policy directive 'img-src 'self''."},
		},
		{
			name: "signature without a block outcome is not a block",
			log:  []string{"Executing inline event handler violates the following Content Security Policy directive 'script-src 'self''."},
		},
		{
			name: "unrelated console error",
			log:  []string{"Failed to load resource: the server responded with a status of 404"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := cspInlineHandlerBlocked(tc.log)
			if ok != tc.want {
				t.Fatalf("blocked = %v, want %v (log %q)", ok, tc.want, tc.log)
			}
			if tc.want && got == "" {
				t.Fatalf("blocked but no log line returned")
			}
			if tc.wantTxt != "" && got != tc.wantTxt {
				t.Fatalf("line = %q, want %q", got, tc.wantTxt)
			}
			if !tc.want && got != "" {
				t.Fatalf("no block, but a line was returned: %q", got)
			}
		})
	}
}
