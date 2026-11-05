package verification

import (
	"strings"
	"testing"

	"github.com/indago/indago/internal/browser"
)

func TestValidJSONPostInputRequiresBoundedNonEmptyObjectAndJSONMediaType(t *testing.T) {
	max := browser.MaxJSONNavigationBodyBytes
	atLimit := []byte(`{"q":"` + strings.Repeat("x", max-8) + `"}`)
	overLimit := []byte(`{"q":"` + strings.Repeat("x", max-7) + `"}`)
	cases := []struct {
		name        string
		body        []byte
		contentType string
		want        bool
	}{
		{"application JSON", []byte(`{"q":"value"}`), "application/json", true},
		{"vendor JSON with parameters", []byte(`{"q":"value"}`), "application/vnd.api+json; charset=utf-8", true},
		{"exact size limit", atLimit, "application/json", true},
		{"size limit plus one", overLimit, "application/json", false},
		{"empty object", []byte(`{}`), "application/json", false},
		{"array root", []byte(`[]`), "application/json", false},
		{"malformed JSON", []byte(`{"q":`), "application/json", false},
		{"empty body", nil, "application/json", false},
		{"non-JSON media type", []byte(`{"q":"value"}`), "text/plain", false},
		{"malformed media type", []byte(`{"q":"value"}`), "application/json; charset=", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := validJSONPost(tc.body, tc.contentType); got != tc.want {
				t.Fatalf("validJSONPost() = %v, want %v", got, tc.want)
			}
		})
	}
}
