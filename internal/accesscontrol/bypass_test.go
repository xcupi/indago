package accesscontrol_test

import (
	"testing"

	"github.com/indago/indago/internal/accesscontrol"
)

func TestHeaderOverrideReached(t *testing.T) {
	for _, tc := range []struct {
		name              string
		baseline, variant int
		body              string
		want              bool
	}{
		{"denied then admin panel", 403, 200, "<h1>Admin panel</h1><a href='/admin/delete'>Delete user</a>", true},
		{"denied then denial page", 403, 200, "Access denied", false},
		{"not denied at baseline", 200, 200, "Admin panel", false},
		{"variant not found", 403, 404, "Admin panel", false},
		{"variant redirect", 403, 302, "Admin panel", false},
		{"denied then unrelated", 401, 200, "welcome", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := accesscontrol.HeaderOverrideReached(tc.baseline, tc.variant, tc.body); got != tc.want {
				t.Fatalf("HeaderOverrideReached(%d, %d, %q) = %v, want %v", tc.baseline, tc.variant, tc.body, got, tc.want)
			}
		})
	}
}

func TestMethodBypassReached(t *testing.T) {
	for _, tc := range []struct {
		name              string
		baseline, variant int
		body              string
		want              bool
	}{
		{"post denied, get validated", 401, 400, "Missing parameter 'username'", true},
		{"post denied, get required", 403, 400, `{"error":"required parameter action"}`, true},
		{"post denied, generic 400", 401, 400, "Bad request", false},
		{"get also denied", 401, 401, "Missing parameter 'username'", false},
		{"post not denied", 200, 400, "Missing parameter 'username'", false},
		{"get ok", 401, 200, "Missing parameter 'username'", false},
		{"denial body", 401, 400, "Access denied: missing parameter", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := accesscontrol.MethodBypassReached(tc.baseline, tc.variant, tc.body); got != tc.want {
				t.Fatalf("MethodBypassReached(%d, %d, %q) = %v, want %v", tc.baseline, tc.variant, tc.body, got, tc.want)
			}
		})
	}
}

func TestBypassPathsAreBoundedAndAdminOnly(t *testing.T) {
	if len(accesscontrol.BypassPaths) > 4 {
		t.Fatalf("BypassPaths has %d entries; the bypass pass must stay bounded", len(accesscontrol.BypassPaths))
	}
	for _, p := range accesscontrol.BypassPaths {
		if p == "" || p[0] != '/' {
			t.Fatalf("path %q must be root-relative", p)
		}
	}
}

func TestHandlerRan(t *testing.T) {
	for _, tc := range []struct {
		name              string
		baseStatus, varSt int
		baseBody, varBody string
		want              bool
	}{
		{"denied then app message", 401, 400, `"Unauthorized"`, "Could not change user role", true},
		{"denied then 2xx", 401, 302, `"Unauthorized"`, "", false},
		{"denied then bare 400", 401, 400, `"Unauthorized"`, "Bad Request", false},
		{"denied then denial", 401, 403, `"Unauthorized"`, "Forbidden", false},
		{"no denial at baseline", 200, 400, "ok", "Could not change user role", false},
		{"identical bodies", 401, 400, "Unauthorized", "Unauthorized", false},
		{"server error", 401, 500, `"Unauthorized"`, "boom", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := accesscontrol.HandlerRan(tc.baseStatus, tc.varSt, tc.baseBody, tc.varBody); got != tc.want {
				t.Fatalf("HandlerRan(%d,%d,%q,%q) = %v, want %v", tc.baseStatus, tc.varSt, tc.baseBody, tc.varBody, got, tc.want)
			}
		})
	}
}
