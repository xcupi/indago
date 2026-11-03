package verification_test

import (
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
