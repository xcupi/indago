package idor_test

import (
	"testing"

	"github.com/indago/indago/internal/idor"
)

func TestParseObjectFamily(t *testing.T) {
	for _, tc := range []struct {
		loc  string
		ok   bool
		id   int
		base string
		ext  string
	}{
		{"https://h/download-transcript/2.txt", true, 2, "/download-transcript", ".txt"},
		{"https://h/files/7", true, 7, "/files", ""},
		{"https://h/download-transcript/2.txt?x=1", false, 0, "", ""},
		{"https://h/download-transcript/abc.txt", false, 0, "", ""},
		{"https://h/2.txt", false, 0, "", ""},
		{"https://h/download-transcript/02.txt", false, 0, "", ""},
	} {
		f, ok := idor.ParseObjectFamily(tc.loc)
		if ok != tc.ok {
			t.Fatalf("ParseObjectFamily(%q) ok=%v, want %v", tc.loc, ok, tc.ok)
		}
		if !ok {
			continue
		}
		if f.ID != tc.id || f.Base != tc.base || f.Ext != tc.ext {
			t.Fatalf("ParseObjectFamily(%q) = %+v, want id=%d base=%q ext=%q", tc.loc, f, tc.id, tc.base, tc.ext)
		}
	}
}

func TestObjectFamilySiblings(t *testing.T) {
	for _, tc := range []struct {
		id   int
		want []int
	}{
		{1, []int{2}},
		{2, []int{1, 3}},
		{9, []int{8, 10, 1}},
	} {
		f := idor.ObjectFamily{Base: "/x", ID: tc.id}
		got := f.Siblings()
		if len(got) != len(tc.want) {
			t.Fatalf("Siblings(%d) = %v, want %v", tc.id, got, tc.want)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Fatalf("Siblings(%d) = %v, want %v", tc.id, got, tc.want)
			}
		}
	}
}

func TestObjectFamilyDecision(t *testing.T) {
	const marker = "indago-object-marker-7f3a"
	own := []byte("CONNECTED: -- Now chatting with Hal Pline --\nYou: " + marker + "\n")
	foreign := []byte("CONNECTED: -- Now chatting with Hal Pline --\nYou: Ok so my password is 8au5aj8yoahk0x1ewp9y. Is that right?\n")

	if d := idor.ObjectFamilyDecision(own, "https://h/t/2.txt", 1, "https://h/t/1.txt", 200, foreign, marker); d.Outcome != idor.OutcomeConfirmed {
		t.Fatalf("foreign credential document = %q (%s), want confirmed", d.Outcome, d.Reason)
	}
	if d := idor.ObjectFamilyDecision(own, "https://h/t/2.txt", 1, "https://h/t/1.txt", 200, own, marker); d.Outcome == idor.OutcomeConfirmed {
		t.Fatalf("the caller's own document must never be confirmed: %s", d.Reason)
	}
	if d := idor.ObjectFamilyDecision(own, "https://h/t/2.txt", 3, "https://h/t/3.txt", 200, []byte("CONNECTED: ...\nYou: hello"), marker); d.Outcome == idor.OutcomeConfirmed {
		t.Fatalf("a document with no credential must not be confirmed: %s", d.Reason)
	}
	if d := idor.ObjectFamilyDecision(own, "https://h/t/2.txt", 1, "https://h/t/1.txt", 403, foreign, marker); d.Outcome != idor.OutcomeRejected {
		t.Fatalf("a refused sibling = %q, want rejected", d.Outcome)
	}
	if d := idor.ObjectFamilyDecision(own, "https://h/t/2.txt", 1, "https://h/t/1.txt", 200, []byte("password is "+marker), marker); d.Outcome == idor.OutcomeConfirmed {
		t.Fatalf("a document carrying the scan's marker is not foreign: %s", d.Reason)
	}
}

func TestCredentialHint(t *testing.T) {
	for _, tc := range []struct {
		body string
		want string
	}{
		{"You: Ok so my password is 8au5aj8yoahk0x1ewp9y.", "password"},
		{"Your API Key: cuae9jDVz8RUiTrAwJxsSwlFJgU4BALI", "api key"},
		{"token = abcdef1234567890", "access token"},
		{"nothing sensitive here", ""},
	} {
		if got := idor.CredentialHint([]byte(tc.body)); got != tc.want {
			t.Fatalf("CredentialHint(%q) = %q, want %q", tc.body, got, tc.want)
		}
	}
}
