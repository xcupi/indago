package verification_test

import (
	"runtime"
	"strings"
	"testing"

	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/verification"
)

// TestClassifyActivation locks the candidate→activation mapping. It is pure:
// no browser, no network.
func TestClassifyActivation(t *testing.T) {
	m := "indMARKER"
	tests := []struct {
		name   string
		cand   detection.Candidate
		want   verification.ActivationClass
		reason string // substring the reason must contain
	}{
		{
			name:   "javascript: URL in the page markup is clicked",
			cand:   detection.Candidate{Trigger: detection.TriggerJSURL, Value: `'},x=x=>{throw/**/onerror=alert,` + m + `},toString=x,window+'',{x:'`},
			want:   verification.ActivationClick,
			reason: "javascript: URL",
		},
		{
			name: "load trigger is never activated",
			cand: detection.Candidate{Trigger: detection.TriggerLoad, Value: "<svg onload=" + m + ">"},
			want: verification.ActivationNone,
		},
		{
			name: "empty legacy trigger is never activated",
			cand: detection.Candidate{Value: `"><svg onload=` + m + ">"},
			want: verification.ActivationNone,
		},
		{
			name:   "markup probe has nothing to activate",
			cand:   detection.Candidate{Trigger: detection.TriggerNone, Value: "<" + m + "x>"},
			want:   verification.ActivationUnsupported,
			reason: "markup probe",
		},
		{
			name: "body onresize is resize-class",
			cand: detection.Candidate{Trigger: detection.TriggerInteraction, Value: "<body onresize=" + m + ">"},
			want: verification.ActivationResize,
		},
		{
			name: "autofocus onfocus is focus-class",
			cand: detection.Candidate{Trigger: detection.TriggerInteraction, Value: "<x-" + m + " autofocus tabindex=1 onfocus=" + m + "></x-" + m + ">"},
			want: verification.ActivationFocus,
		},
		{
			name: "bare onfocus is focus-class",
			cand: detection.Candidate{Trigger: detection.TriggerInteraction, Value: "<x-" + m + " tabindex=1 onfocus=" + m + "></x-" + m + ">"},
			want: verification.ActivationFocus,
		},
		{
			name: "smil onbegin is animation-class",
			cand: detection.Candidate{Trigger: detection.TriggerInteraction, Value: "<svg><animatetransform onbegin=" + m + " attributeName=transform></svg>"},
			want: verification.ActivationAnimation,
		},
		{
			name: "onclick is click-class",
			cand: detection.Candidate{Trigger: detection.TriggerInteraction, Value: `<a href="#" onclick=` + m + `>x</a>`},
			want: verification.ActivationClick,
		},
		{
			name: "javascript url is click-class",
			cand: detection.Candidate{Trigger: detection.TriggerInteraction, Value: "javascript:" + m},
			want: verification.ActivationClick,
		},
		{
			name: "tab inside the scheme is still a javascript url",
			cand: detection.Candidate{Trigger: detection.TriggerInteraction, Value: "java\tscript:" + m},
			want: verification.ActivationClick,
		},
		{
			name: "mixed-case scheme is still a javascript url",
			cand: detection.Candidate{Trigger: detection.TriggerInteraction, Value: "JaVaScRiPt:" + m},
			want: verification.ActivationClick,
		},
		{
			name:   "onmouseover is not activatable by this verifier",
			cand:   detection.Candidate{Trigger: detection.TriggerInteraction, Value: `" onmouseover=` + m},
			want:   verification.ActivationUnsupported,
			reason: "onmouseover",
		},
		{
			name:   "unknown trigger class is not activatable",
			cand:   detection.Candidate{Trigger: "timing", Value: "<svg onload=" + m + ">"},
			want:   verification.ActivationUnsupported,
			reason: "unknown trigger class",
		},
		{
			name:   "accesskey plus onclick is keyboard-class",
			cand:   detection.Candidate{Trigger: detection.TriggerInteraction, Value: `'accesskey='x' onclick=` + m + ` x='`},
			want:   verification.ActivationKeyboard,
			reason: "accesskey",
		},
		{
			name:   "accesskey with an unquoted key is keyboard-class",
			cand:   detection.Candidate{Trigger: detection.TriggerInteraction, Value: `accesskey=x onclick=` + m},
			want:   verification.ActivationKeyboard,
			reason: "keyboard-class",
		},
		{
			name:   "accesskey with no usable key is not activatable",
			cand:   detection.Candidate{Trigger: detection.TriggerInteraction, Value: `accesskey="" onclick=` + m},
			want:   verification.ActivationUnsupported,
			reason: "no single printable ASCII key",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := verification.ClassifyActivation(tc.cand)
			if got != tc.want {
				t.Fatalf("class = %q, want %q (reason %q)", got, tc.want, reason)
			}
			if reason == "" {
				t.Fatal("classify returned an empty reason; every activation decision must be explainable in evidence")
			}
			if tc.reason != "" && !strings.Contains(reason, tc.reason) {
				t.Fatalf("reason = %q, want it to contain %q", reason, tc.reason)
			}
			// Anything this verifier cannot activate must SAY so: the recorded
			// outcome is what tells an operator the shape was not tested,
			// rather than tested and found safe.
			if tc.want == verification.ActivationUnsupported && !strings.Contains(reason, "not activatable by this verifier") {
				t.Fatalf("reason = %q, want it to state \"not activatable by this verifier\"", reason)
			}
		})
	}
}

// TestDeclaredAccessKey locks the key reader to the three HTML attribute forms
// (and to a single printable ASCII key), because the chord that is pressed is
// derived from it. It is pure.
func TestDeclaredAccessKey(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{"single-quoted", `'accesskey='x' onclick=indM x='`, "x"},
		{"double-quoted", `"accesskey="Q" onclick=indM y="`, "Q"},
		{"unquoted", " accesskey=z onclick=indM", "z"},
		{"spaced equals", "accesskey = 'k' onclick=indM", "k"},
		{"case-insensitive attribute", "ACCESSKEY='a'", "a"},
		{"first of a multi-key list", `accesskey="j k"`, "j"},
		{"no accesskey", `onclick=indM`, ""},
		{"empty value", `accesskey=""`, ""},
		{"multi-character key", `accesskey="xx"`, ""},
		{"non-ASCII key", `accesskey="é"`, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := verification.DeclaredAccessKey(tc.value); got != tc.want {
				t.Fatalf("DeclaredAccessKey(%q) = %q, want %q", tc.value, got, tc.want)
			}
		})
	}
}

// TestAccessKeyChord pins the platform's access-key shortcut: Chromium uses
// Alt+Shift+<k> everywhere except macOS.
func TestAccessKeyChord(t *testing.T) {
	got := verification.AccessKeyChord("x")
	want := "Alt+Shift+x"
	if runtime.GOOS == "darwin" {
		want = "Control+Alt+x"
	}
	if got != want {
		t.Fatalf("AccessKeyChord(\"x\") = %q, want %q", got, want)
	}
}
