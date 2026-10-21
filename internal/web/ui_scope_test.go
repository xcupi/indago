package web_test

// Real-browser test for the Scope form: a host entry that could never match is
// refused with a message that says how to write it, and the form says up front
// what a host entry is.

import (
	"strings"
	"testing"

	"github.com/indago/indago/internal/web"
)

func TestUIScopeFormRefusesEntriesThatCanNeverMatch(t *testing.T) {
	u := newUIHarnessWith(t, "", web.Capabilities{})
	uiFindingsScan(t, u) // seeds a project with scope 127.0.0.1
	u.eval(`(async () => { await loadProjects(); setProject(ctx.projects[0].id); })(); true`)
	u.waitUI("project selected", `currentProject()`)
	u.eval(`navigate('#/scope'); true`)
	u.waitUI("scope form", `document.getElementById('s_inchosts')`)

	// The form states the rule before the operator makes the mistake.
	if hint := u.evalStr(`document.querySelector('.scope-host-hint') ? document.querySelector('.scope-host-hint').textContent : ''`); !strings.Contains(hint, "bare hostname") {
		t.Fatalf("the scope form must explain that hosts are bare hostnames, got %q", hint)
	}

	u.setVal("s_inchosts", "127.0.0.1\nhttps://app.example.com")
	u.mustClickText("button", "Save scope")
	u.waitUI("error shown", `Array.from(document.querySelectorAll('.err')).some(n => /bare hostname/.test(n.textContent))`)
	msg := u.evalStr(`Array.from(document.querySelectorAll('.err')).map(n => n.textContent).join(' | ')`)
	for _, want := range []string{"include_hosts", "https://app.example.com", `"app.example.com"`} {
		if !strings.Contains(msg, want) {
			t.Errorf("the error should contain %q, got %q", want, msg)
		}
	}
	// What is stored did not change.
	if got := u.evalStr(`document.querySelector('.detail dd') ? document.querySelector('.detail dd').textContent : ''`); strings.Contains(got, "example.com") {
		t.Fatalf("a refused scope must not appear as the current scope: %q", got)
	}

	// Writing it the suggested way saves.
	u.setVal("s_inchosts", "127.0.0.1\napp.example.com")
	u.mustClickText("button", "Save scope")
	u.waitUI("saved", `Array.from(document.querySelectorAll('.ok-msg')).some(n => /Scope saved/.test(n.textContent))`)
	if !u.evalBool(`document.querySelector('.detail').textContent.indexOf('app.example.com') >= 0`) {
		t.Fatal("the corrected scope should be shown as current")
	}
}
