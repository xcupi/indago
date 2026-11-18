package discovery

import (
	"testing"

	"github.com/indago/indago/internal/domain"
)

// TestLooksDataMutating pins the vocabulary and, just as importantly, the
// deliberate exclusions. A false positive here costs one undiscovered page; a
// false negative can delete a record during a crawl.
func TestLooksDataMutating(t *testing.T) {
	cases := []struct {
		name string
		url  string
		want bool
	}{
		// Destructive path shapes.
		{"delete with id", "http://example.com/delete?id=1", true},
		{"delete nested", "http://example.com/users/42/delete", true},
		{"delete with extension", "http://example.com/delete.php", true},
		{"delete uppercase", "http://example.com/DELETE", true},
		{"camel case delete", "http://example.com/api/deleteUser", true},
		{"update with id", "http://example.com/update?id=1", true},
		{"update nested", "http://example.com/users/42/update", true},
		{"camel case update", "http://example.com/api/updateProfile", true},
		{"modify", "http://example.com/items/9/modify", true},
		{"destroy", "http://example.com/posts/9/destroy", true},
		{"remove", "http://example.com/cart/remove?item=3", true},
		{"revoke key", "http://example.com/api/keys/9/revoke", true},
		{"unsubscribe", "http://example.com/unsubscribe?token=abc", true},

		// The action can live in the query string.
		{"action delete", "http://example.com/item?id=1&action=delete", true},
		{"action camel delete", "http://example.com/item?id=1&action=DeleteItem", true},
		{"op update", "http://example.com/item?op=update&id=1", true},
		{"do store laravel", "http://example.com/item?do=store", true},
		{"delete parameter name", "http://example.com/cart?delete=1", true},
		{"delete id parameter name", "http://example.com/cart?delete_id=1", true},

		// SPA route fragments are rendered even though they are not URLs of
		// their own.
		{"spa delete route", "http://example.com/#/items/delete?id=1", true},
		{"spa action route", "http://example.com/#/items?action=remove", true},

		// Data that merely mentions a verb, and ordinary read routes, must
		// keep being discovered.
		{"logout is session guard's job", "http://example.com/logout", false},
		{"logout query is session guard's job", "http://example.com/account?action=logout", false},
		{"logout spa route is session guard's job", "http://example.com/#/logout", false},
		{"login", "http://example.com/login", false},
		{"updates feed", "http://example.com/updates", false},
		{"updated records", "http://example.com/orders?updated=1", false},
		{"editor", "http://example.com/editor", false},
		{"creative", "http://example.com/creative", false},
		{"store shop page", "http://example.com/store", false},
		{"register form page", "http://example.com/register", false},
		{"edit form page", "http://example.com/users/42/edit", false},
		{"address", "http://example.com/address", false},
		{"search for the word", "http://example.com/search?q=delete", false},
		{"redirect target holds the word", "http://example.com/login?next=%2Fdelete", false},
		{"status filter", "http://example.com/orders?status=deleted", false},
		{"sort column", "http://example.com/orders?sort=updated_at", false},
		{"non-action parameter", "http://example.com/orders?actionable=no", false},
		{"view action", "http://example.com/orders?action=view&id=1", false},
		{"spa read route", "http://example.com/#/items/42", false},
		{"spa hash anchor", "http://example.com/#section", false},
		{"toggle-enforce-ssl action param", "http://example.com/index.php?page=dns-lookup.php&do=toggle-enforce-ssl", true},
		{"enable action param", "http://example.com/admin?action=enable-debug", true},
		{"disable action param", "http://example.com/admin?op=disable-waf", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := looksDataMutating(tc.url); got != tc.want {
				t.Errorf("looksDataMutating(%q) = %v, want %v", tc.url, got, tc.want)
			}
		})
	}
}

func TestDataMutationReason(t *testing.T) {
	cases := []struct {
		url  string
		want string
	}{
		{"http://example.com/delete?id=1", "path"},
		{"http://example.com/orders?action=delete", "query"},
		{"http://example.com/#/items/delete", "route"},
		{"http://example.com/account", ""},
		{"http://example.com/logout", ""}, // handled by the session guard
	}
	for _, tc := range cases {
		if got := dataMutationReason(tc.url); got != tc.want {
			t.Errorf("dataMutationReason(%q) = %q, want %q", tc.url, got, tc.want)
		}
	}
}

func TestIsReadMethod(t *testing.T) {
	reads := []domain.HTTPMethod{domain.MethodGET, domain.MethodHEAD, domain.MethodOPTIONS, ""}
	writes := []domain.HTTPMethod{domain.MethodPOST, domain.MethodPUT, domain.MethodPATCH, domain.MethodDELETE}
	for _, m := range reads {
		if !isReadMethod(m) {
			t.Errorf("isReadMethod(%q) = false, want true", m)
		}
	}
	for _, m := range writes {
		if isReadMethod(m) {
			t.Errorf("isReadMethod(%q) = true, want false", m)
		}
	}
}
