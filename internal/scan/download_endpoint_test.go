package scan

import (
	"testing"

	"github.com/indago/indago/internal/domain"
)

func TestDownloadLikeEndpointGuard(t *testing.T) {
	cases := []struct {
		url  string
		want bool
	}{
		{"https://app.example/settlements/export", true},
		{"https://app.example/report/download", true},
		{"https://app.example/files/report.xlsx", true},
		{"https://app.example/files/report.pdf", true},
		{"https://app.example/customer?export=1", true},
		{"https://app.example/customer", false},
		{"https://app.example/report_range", false},
		{"https://app.example/profile_user", false},
	}
	for _, tc := range cases {
		if got := isDownloadLikeEndpoint(&domain.Endpoint{URL: tc.url}); got != tc.want {
			t.Fatalf("isDownloadLikeEndpoint(%q) = %v, want %v", tc.url, got, tc.want)
		}
	}
}
