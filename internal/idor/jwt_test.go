package idor

// Behavioral tests for the offline JWT identity extractor and the multi-source
// identity merge. A malformed token must never panic or invent an identity, and
// a "sub" claim must be classified (email vs username) exactly like a response
// body would be.

import (
	"encoding/base64"
	"reflect"
	"strings"
	"testing"
)

// jwtWithPayload wraps claims in a compact-JWS shape: only the payload segment
// matters to ExtractJWTIdentity, so the header and signature are placeholders.
func jwtWithPayload(claims string) string {
	return "header." + base64.RawURLEncoding.EncodeToString([]byte(claims)) + ".signature"
}

func TestExtractJWTIdentity(t *testing.T) {
	cases := []struct {
		name  string
		token string
		want  []Field
	}{
		{
			name:  "standard claims under a bearer prefix",
			token: "Bearer " + jwtWithPayload(`{"email":"wiener@example.com","user_id":"42"}`),
			want:  []Field{{FieldEmail, "wiener@example.com"}, {FieldUserID, "42"}},
		},
		{
			name:  "case-insensitive bearer prefix",
			token: "bearer " + jwtWithPayload(`{"username":"wiener"}`),
			want:  []Field{{FieldUsername, "wiener"}},
		},
		{
			name:  "sub that looks like an email is an email",
			token: jwtWithPayload(`{"sub":"wiener@example.com"}`),
			want:  []Field{{FieldEmail, "wiener@example.com"}},
		},
		{
			name:  "sub that is not an email is a username",
			token: jwtWithPayload(`{"sub":"wiener"}`),
			want:  []Field{{FieldUsername, "wiener"}},
		},
		{
			name:  "nested sub is mapped too",
			token: jwtWithPayload(`{"data":{"sub":"carlos"}}`),
			want:  []Field{{FieldUsername, "carlos"}},
		},
		{
			name:  "root id becomes a user id when no other id claim exists",
			token: jwtWithPayload(`{"id":7,"sub":"wiener"}`),
			want:  []Field{{FieldUsername, "wiener"}, {FieldUserID, "7"}},
		},
		{
			name:  "an explicit user_id wins over the root id",
			token: jwtWithPayload(`{"id":7,"user_id":"88"}`),
			want:  []Field{{FieldUserID, "88"}},
		},
		{
			name:  "nested user object is read like a JSON identity response",
			token: jwtWithPayload(`{"data":{"user":{"id":99,"username":"wiener"}}}`),
			want:  []Field{{FieldUsername, "wiener"}, {FieldUserID, "99"}},
		},
		{
			name:  "duplicate claims collapse",
			token: jwtWithPayload(`{"email":"wiener@example.com","sub":"wiener@example.com"}`),
			want:  []Field{{FieldEmail, "wiener@example.com"}},
		},
		{
			name:  "placeholder sub is dropped",
			token: jwtWithPayload(`{"sub":"unknown"}`),
			want:  nil,
		},
		{
			name:  "token metadata alone is not an identity",
			token: jwtWithPayload(`{"iss":"indago","aud":"api","iat":1700000000,"exp":1700003600,"jti":"abc"}`),
			want:  nil,
		},
		{
			name:  "empty token",
			token: "",
			want:  nil,
		},
		{
			name:  "bearer prefix without a token",
			token: "Bearer ",
			want:  nil,
		},
		{
			name:  "not a jwt",
			token: "not-a-jwt",
			want:  nil,
		},
		{
			name:  "two segments is still not a usable payload",
			token: "header.only",
			want:  nil,
		},
		{
			name:  "payload is not json",
			token: jwtWithPayload("hello"),
			want:  nil,
		},
		{
			name:  "payload is a json array",
			token: jwtWithPayload(`[{"email":"wiener@example.com"}]`),
			want:  nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ExtractJWTIdentity(tc.token)
			if !reflect.DeepEqual(got.Fields, tc.want) {
				t.Fatalf("fields = %+v, want %+v", got.Fields, tc.want)
			}
		})
	}
}

func TestExtractJWTIdentityAcceptsPaddedBase64URL(t *testing.T) {
	claims := `{"username":"wienerx"}` // 22 bytes: base64url pads it
	segment := base64.URLEncoding.EncodeToString([]byte(claims))
	if !strings.HasSuffix(segment, "=") {
		t.Fatalf("fixture must exercise the padded form, got %q", segment)
	}
	got := ExtractJWTIdentity("header." + segment + ".signature")
	if len(got.Fields) != 1 || got.Fields[0] != (Field{FieldUsername, "wienerx"}) {
		t.Fatalf("fields = %+v, want the padded payload decoded", got.Fields)
	}
}

func TestExtractJWTIdentityNeverPanics(t *testing.T) {
	for _, token := range []string{
		"....",
		"Bearer ....",
		"a.b.c",
		"a." + strings.Repeat("A", 70000) + ".c", // over the size bound
		"header." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"`)) + ".signature",
	} {
		if got := ExtractJWTIdentity(token); len(got.Fields) != 0 {
			t.Fatalf("%q produced %+v, want no identity", token, got.Fields)
		}
	}
}

func TestMergeIdentities(t *testing.T) {
	page := Identity{Fields: []Field{{FieldEmail, "wiener@example.com"}}}
	token := Identity{Fields: []Field{{FieldUserID, "42"}, {FieldEmail, "wiener@example.com"}}}
	got := MergeIdentities(page, token)
	want := []Field{{FieldEmail, "wiener@example.com"}, {FieldUserID, "42"}}
	if !reflect.DeepEqual(got.Fields, want) {
		t.Fatalf("merged fields = %+v, want %+v", got.Fields, want)
	}
	if empty := MergeIdentities(Identity{}, Identity{}); !empty.Empty() {
		t.Fatalf("merging empty identities produced %+v", empty.Fields)
	}
}
