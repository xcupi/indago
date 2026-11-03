package idor

// Behavioral tests for the pure IDOR core: identity extraction, candidate
// derivation and the differential decision. Each fixture is a response shape
// a real account/object page can produce. The negative controls are the point:
// same-principal data, no identity fields, login pages and error responses
// must never be Confirmed.

import "testing"

func TestExtractIdentity(t *testing.T) {
	cases := []struct {
		name string
		body string
		want []Field
	}{
		{
			name: "labelled html account page",
			body: `<html><body><h1>My Account</h1><p>Your username is <strong>wiener</strong></p>` +
				`<p>Email: wiener@example.com</p></body></html>`,
			want: []Field{{FieldUsername, "wiener"}, {FieldEmail, "wiener@example.com"}},
		},
		{
			name: "html form field values",
			body: `<form><input type="text" name="username" value="wiener">` +
				`<input type="email" value="wiener@example.com" name="email"></form>`,
			want: []Field{{FieldUsername, "wiener"}, {FieldEmail, "wiener@example.com"}},
		},
		{
			name: "json account object",
			body: `{"username":"wiener","email":"wiener@example.com","user_id":3}`,
			want: []Field{{FieldUsername, "wiener"}, {FieldEmail, "wiener@example.com"}, {FieldUserID, "3"}},
		},
		{
			name: "nested user object",
			body: `{"data":{"user":{"username":"wiener","id":"7"}}}`,
			want: []Field{{FieldUsername, "wiener"}, {FieldUserID, "7"}},
		},
		{
			name: "labelled user id",
			body: `<p>User ID: 42</p><p>Username: carlos</p>`,
			want: []Field{{FieldUsername, "carlos"}, {FieldUserID, "42"}},
		},
		{
			name: "login page has no identity",
			body: `<form method="post"><input type="text" name="username">` +
				`<input type="password" name="password"><button>Log in</button></form>`,
			want: nil,
		},
		{
			name: "object page without identity fields",
			body: `<h1>Product</h1><p>Price: 10</p><p>Chat transcript content</p>`,
			want: nil,
		},
		{
			name: "identity inside an array is not the page principal",
			body: `{"users":[{"username":"carlos"},{"username":"wiener"}]}`,
			want: nil,
		},
		{
			name: "placeholder values are not identity",
			body: `<input name="username" value="username"><input name="email" value="">`,
			want: nil,
		},
		{
			name: "generated form token with id in its name is not a user id",
			body: `<input name="csrf_id" value="9f8e7d"><p>Hello</p>`,
			want: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ExtractIdentity([]byte(tc.body))
			if len(got.Fields) != len(tc.want) {
				t.Fatalf("fields = %+v, want %+v", got.Fields, tc.want)
			}
			for i := range tc.want {
				if got.Fields[i].Kind != tc.want[i].Kind || got.Fields[i].Value != tc.want[i].Value {
					t.Fatalf("field %d = %+v, want %+v", i, got.Fields[i], tc.want[i])
				}
			}
		})
	}
}

func callerIdentity() Identity {
	return Identity{Fields: []Field{{FieldUsername, "wiener"}, {FieldEmail, "wiener@example.com"}}}
}

func TestDecide(t *testing.T) {
	cases := []struct {
		name        string
		status      int
		body        string
		want        Outcome
		wantForeign string
	}{
		{
			name:        "foreign principal is confirmed",
			status:      200,
			body:        `<p>Your username is <strong>carlos</strong></p><p>Email: carlos@example.com</p>`,
			want:        OutcomeConfirmed,
			wantForeign: "carlos",
		},
		{
			name:   "same principal is not confirmed",
			status: 200,
			body:   `<p>Your username is <strong>wiener</strong></p>`,
			want:   OutcomeRejected,
		},
		{
			name:   "email case only difference is the same principal",
			status: 200,
			body:   `<p>Email: Wiener@Example.com</p>`,
			want:   OutcomeRejected,
		},
		{
			name:   "no identity fields is inconclusive",
			status: 200,
			body:   `<h1>Chat transcript</h1><p>1.txt content</p>`,
			want:   OutcomeInconclusive,
		},
		{
			name:   "login page is inconclusive",
			status: 200,
			body:   `<form><input name="username"><input type="password" name="password"></form>`,
			want:   OutcomeInconclusive,
		},
		{
			name:   "empty body is inconclusive",
			status: 200,
			body:   "   \n\t ",
			want:   OutcomeInconclusive,
		},
		{
			name:   "access denied is rejected",
			status: 403,
			body:   `<h1>Forbidden</h1>`,
			want:   OutcomeRejected,
		},
		{
			name:   "server error is inconclusive",
			status: 500,
			body:   `<h1>Internal Server Error</h1>`,
			want:   OutcomeInconclusive,
		},
		{
			name:   "id echo without identity fields is inconclusive",
			status: 200,
			body:   `<a href="/my-account?id=carlos">My Account</a><p>Nothing here</p>`,
			want:   OutcomeInconclusive,
		},
		{
			name:   "non-comparable identity field is inconclusive",
			status: 200,
			body:   `{"user_id":"9"}`,
			want:   OutcomeInconclusive,
		},
		{
			name:        "numeric user id mismatch is confirmed",
			status:      200,
			body:        `{"user_id":"9","username":"carlos"}`,
			want:        OutcomeConfirmed,
			wantForeign: "carlos",
		},
		{
			name:   "page listing both the caller and another principal is not confirmed",
			status: 200,
			body:   `<p>Username: wiener</p><p>Username: carlos</p><p>Email: wiener@example.com</p>`,
			want:   OutcomeRejected,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Decide(callerIdentity(), "carlos", tc.status, []byte(tc.body))
			if got.Outcome != tc.want {
				t.Fatalf("outcome = %q (%s), want %q", got.Outcome, got.Reason, tc.want)
			}
			if got.Reason == "" {
				t.Fatal("every decision must state its reason")
			}
			if tc.wantForeign != "" {
				if got.Foreign == nil || got.Foreign.Value != tc.wantForeign {
					t.Fatalf("foreign = %+v, want value %q", got.Foreign, tc.wantForeign)
				}
			} else if got.Outcome != OutcomeConfirmed && got.Foreign != nil {
				t.Fatalf("non-confirmed decision must not carry a foreign field: %+v", got.Foreign)
			}
		})
	}
}

func TestDecideNumericCaller(t *testing.T) {
	caller := Identity{Fields: []Field{{FieldUserID, "3"}}}
	got := Decide(caller, "4", 200, []byte(`{"user_id":4}`))
	if got.Outcome != OutcomeConfirmed {
		t.Fatalf("numeric mismatch outcome = %q (%s), want confirmed", got.Outcome, got.Reason)
	}
	same := Decide(caller, "3", 200, []byte(`{"user_id":3}`))
	if same.Outcome != OutcomeRejected {
		t.Fatalf("numeric same-principal outcome = %q (%s), want rejected", same.Outcome, same.Reason)
	}
}

func TestDeriveCandidates(t *testing.T) {
	t.Run("numeric neighbours are bounded and deterministic", func(t *testing.T) {
		got, reason := DeriveCandidates("3", nil, nil, 0)
		if reason != "" {
			t.Fatalf("reason = %q, want none", reason)
		}
		want := []string{"4", "2", "5", "1", "6"}
		if len(got) != len(want) {
			t.Fatalf("candidates = %+v, want %v", got, want)
		}
		for i := range want {
			if got[i].Value != want[i] {
				t.Fatalf("candidate %d = %q, want %q (all: %+v)", i, got[i].Value, want[i], got)
			}
		}
	})

	t.Run("limit caps the set", func(t *testing.T) {
		got, _ := DeriveCandidates("10", nil, nil, 2)
		if len(got) != 2 {
			t.Fatalf("got %d candidates, want 2: %+v", len(got), got)
		}
	})

	t.Run("operator-supplied identifiers come first", func(t *testing.T) {
		got, _ := DeriveCandidates("wiener", []string{"carlos", "wiener", "carlos"}, nil, 0)
		if len(got) == 0 || got[0].Value != "carlos" || got[0].Source != "supplied" {
			t.Fatalf("first candidate = %+v, want supplied carlos", got)
		}
		if len(got) != 1 {
			t.Fatalf("duplicate/own supplied values must collapse: %+v", got)
		}
	})

	t.Run("opaque identifier is never guessed", func(t *testing.T) {
		got, reason := DeriveCandidates("8f14e45f-ceea-467f-a8d5-1b3c4d5e6f70", nil, nil, 0)
		if len(got) != 0 {
			t.Fatalf("opaque id produced guesses: %+v", got)
		}
		if reason == "" {
			t.Fatal("skipping must state a reason")
		}
	})

	t.Run("opaque identifier accepts an explicit supplied value", func(t *testing.T) {
		got, _ := DeriveCandidates("8f14e45f-ceea-467f-a8d5-1b3c4d5e6f70", []string{"1b2c3d4e-0000-0000-0000-000000000000"}, nil, 0)
		if len(got) != 1 || got[0].Source != "supplied" {
			t.Fatalf("got %+v, want the supplied opaque value", got)
		}
	})

	t.Run("observed identifiers are included after numeric ones", func(t *testing.T) {
		got, _ := DeriveCandidates("1", nil, []string{"2", "carlos", ""}, 0)
		if len(got) < 2 {
			t.Fatalf("got %+v, want observed identifiers included", got)
		}
	})

	t.Run("MaxCandidates bounds every path", func(t *testing.T) {
		got, _ := DeriveCandidates("1", []string{"a", "b", "c", "d", "e", "f"}, []string{"g"}, 100)
		if len(got) > MaxCandidates {
			t.Fatalf("derived %d candidates, ceiling is %d", len(got), MaxCandidates)
		}
	})
}

func TestObjectIDParameter(t *testing.T) {
	for _, name := range []string{"id", "user_id", "userId", "uid", "account", "account_id", "filename", "file", "document_id", "orderId", "invoice_id", "postId", "username", "tenant"} {
		if !ObjectIDParameter(name) {
			t.Errorf("%q should be treated as an object identifier parameter", name)
		}
	}
	for _, name := range []string{"q", "search", "page", "lang", "csrf", "csrf_token", "token", "session", "redirect", "next", "sort"} {
		if ObjectIDParameter(name) {
			t.Errorf("%q must not be treated as an object identifier parameter", name)
		}
	}
}
