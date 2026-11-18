package web_test

// Real-browser test for the scheme/port fields on the Scope form. The operator
// must be able to see that a stored scope is legacy (any scheme/port), declare a
// non-standard origin, and explicitly opt into the legacy behaviour — and the
// save must reach the store with exactly that choice.

import (
	"strings"
	"testing"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/web"
)

func TestUIScopeOriginRules(t *testing.T) {
	u := newUIHarnessWith(t, "", web.Capabilities{})
	uiFindingsScan(t, u) // seeds a project whose scope is stored directly (legacy)
	u.selectFirstProject()
	u.eval(`navigate('#/scope'); true`)
	u.waitUI("scope form", `document.getElementById('s_origins') && document.getElementById('s_any')`)

	// The form explains the rule before the operator saves: the scheme/port
	// statement is explicit and is never derived from the host list.
	hint := u.evalStr(`document.querySelector('.scope-host-hint').textContent`)
	if !strings.Contains(hint, "separate statement") || !strings.Contains(hint, "never authorizes http or https by itself") {
		t.Fatalf("the scope hint should describe the explicit scheme/port statement, got %q", hint)
	}
	// A scope with no origin list and no explicit opt-out is the legacy shape,
	// and the page says so instead of pretending every port was declared.
	if detail := u.evalStr(`document.querySelector('.detail').textContent`); !strings.Contains(detail, "legacy: no scheme/port rule recorded") {
		t.Fatalf("the current scope should be labelled legacy, got %q", detail)
	}

	// Saving with neither an origin nor the opt-out is refused by the server:
	// the form must surface the policy message instead of treating the empty
	// list as an implicit (legacy) choice.
	u.setVal("s_origins", "")
	u.mustClickText("button", "Save scope")
	u.waitUI("empty origin error", `Array.from(document.querySelectorAll('.err')).some(n => /allowed_origins is empty/.test(n.textContent))`)

	// An origin without a scheme is refused, naming the expected shape.
	u.setVal("s_origins", "127.0.0.1:8443")
	u.mustClickText("button", "Save scope")
	u.waitUI("origin error", `Array.from(document.querySelectorAll('.err')).some(n => /scheme:\/\/host/.test(n.textContent))`)

	// A valid explicit origin saves and is shown as the current rule.
	u.setVal("s_origins", "https://127.0.0.1:8443")
	u.mustClickText("button", "Save scope")
	u.waitUI("saved", `Array.from(document.querySelectorAll('.ok-msg')).some(n => /Scope saved/.test(n.textContent))`)
	if detail := u.evalStr(`document.querySelector('.detail').textContent`); !strings.Contains(detail, "https://127.0.0.1:8443") {
		t.Fatalf("the saved origin is not shown as current: %q", detail)
	}
	pid := domain.ID(u.evalStr(`currentProject().id`))
	sc, err := u.st.Scopes().GetByProject(u.ctx, pid)
	if err != nil {
		t.Fatal(err)
	}
	if len(sc.AllowedOrigins) != 1 || sc.AllowedOrigins[0] != "https://127.0.0.1:8443" {
		t.Fatalf("stored allowed_origins = %v, want the declared origin", sc.AllowedOrigins)
	}
	if sc.AllowAnySchemePorts {
		t.Fatal("the explicit opt-out was ticked without the operator ticking it")
	}

	// The explicit opt-out is sent as such and clears the origin list.
	u.click("s_any")
	u.mustClickText("button", "Save scope")
	u.waitUI("saved legacy", `Array.from(document.querySelectorAll('.detail dd')).some(n => /any scheme and port \(explicitly chosen\)/.test(n.textContent))`)
	sc, err = u.st.Scopes().GetByProject(u.ctx, pid)
	if err != nil {
		t.Fatal(err)
	}
	if !sc.AllowAnySchemePorts {
		t.Fatal("the explicit any-scheme-port opt-out was not stored")
	}
	if len(sc.AllowedOrigins) != 0 {
		t.Fatalf("the opt-out left an origin list behind: %v", sc.AllowedOrigins)
	}
	if d := sc.Permits("http://127.0.0.1:8080/"); !d.Allowed {
		t.Fatalf("the explicit legacy scope denied its host: %+v", d)
	}
}
