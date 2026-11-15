package browser

import "testing"

// Discovery can only hand an XML request body to the XXE engine when the
// browser observation captured it, so the capture predicate must accept every
// XML media type (and JSON), not just application/json.
func TestCapturedRequestBodyContentTypes(t *testing.T) {
	cases := map[string]bool{
		"application/json":                  true,
		"application/problem+json":          true,
		"application/xml":                   true,
		"text/xml":                          true,
		"text/xml; charset=utf-8":           true,
		"application/soap+xml":              true,
		"application/xhtml+xml":             true,
		"application/x-www-form-urlencoded": false,
		"text/plain":                        false,
		"multipart/form-data":               false,
		"":                                  false,
	}
	for raw, want := range cases {
		if got := isCapturedRequestBodyContentType(raw); got != want {
			t.Fatalf("isCapturedRequestBodyContentType(%q) = %v, want %v", raw, got, want)
		}
	}
}
