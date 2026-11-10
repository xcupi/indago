package scan

import (
	"testing"

	"github.com/indago/indago/internal/domain"
)

func TestWriteLikeEndpointGuard(t *testing.T) {
	cases := []struct {
		name   string
		ep     domain.Endpoint
		params []*domain.Parameter
		want   bool
	}{
		{"get search", domain.Endpoint{Method: domain.MethodGET, URL: "https://app.example/search?q=x"}, nil, false},
		{"post form", domain.Endpoint{Method: domain.MethodPOST, URL: "https://app.example/contact"}, nil, true},
		{"put json", domain.Endpoint{Method: domain.MethodPUT, URL: "https://app.example/api/item"}, nil, true},
		{"get store route", domain.Endpoint{Method: domain.MethodGET, URL: "https://app.example/store_sp?amount=1"}, nil, true},
		{"get update route", domain.Endpoint{Method: domain.MethodGET, URL: "https://app.example/update_status_sp"}, nil, true},
		{"get delete route", domain.Endpoint{Method: domain.MethodGET, URL: "https://app.example/delete_project?id=1"}, nil, true},
		{"get upload route", domain.Endpoint{Method: domain.MethodGET, URL: "https://app.example/upload?file=x"}, nil, true},
		{"laravel method override", domain.Endpoint{Method: domain.MethodGET, URL: "https://app.example/contact"}, []*domain.Parameter{{Name: "_method"}}, true},
		{"ordinary profile page", domain.Endpoint{Method: domain.MethodGET, URL: "https://app.example/profile_user"}, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isWriteLikeEndpoint(&tc.ep, tc.params); got != tc.want {
				t.Fatalf("isWriteLikeEndpoint = %v, want %v", got, tc.want)
			}
		})
	}
}
