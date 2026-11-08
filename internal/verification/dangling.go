package verification

// Dangling-markup confirmation.
//
// A page whose policy forbids inline script can still be broken with markup
// alone: a value reflected into a quoted attribute value can close the
// attribute, close the element and close the page's OWN form, then open one
// whose action is ours. Everything the page renders after that point — the
// hidden CSRF input in particular — is then parsed as a CHILD of our form.
//
// That is observable in the DOM, deterministically and without any network
// effect: we never submit the form, and its action uses the reserved .invalid
// TLD. The proof is the structure itself — an input whose value the request
// never contained sitting inside a form nobody but a broken parse could have
// produced. Reflection alone cannot create it: a page echoing the payload
// leaves the input in the page's own form, not ours.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/detection"
)

// danglingFormMinValueLen is the shortest captured value we accept. A CSRF
// token (or any credential-shaped hidden field) is far longer; a stray empty or
// single-character value would only add noise.
const danglingFormMinValueLen = 6

type danglingFormObservation struct {
	Found bool `json:"found"`
	// Stolen lists the inputs inside OUR form whose value is non-empty, does not
	// contain the scan's marker, and is credential-shaped. Those values are
	// page-rendered data the request never carried.
	Stolen []danglingFormInput `json:"stolen"`
	// Inputs counts every control inside our form, for the evidence trail.
	Inputs int `json:"inputs"`
}

type danglingFormInput struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// danglingFormCaptured reports whether the page rendered our injected form
// around the page's own hidden input(s), and names them for the evidence.
func danglingFormCaptured(ctx context.Context, page *browser.Page, marker string) (string, bool) {
	action := detection.DanglingFormAction(marker)
	script := fmt.Sprintf(`() => {
  const action = %q, marker = %q, min = %d;
  const forms = Array.from(document.querySelectorAll('form')).filter(f => (f.getAttribute('action') || '') === action);
  if (!forms.length) return JSON.stringify({found: false, stolen: [], inputs: 0});
  const f = forms[0];
  const all = Array.from(f.querySelectorAll('input,textarea,select'));
  const stolen = all
    .map(i => ({name: i.getAttribute('name') || '', value: typeof i.value === 'string' ? i.value : ''}))
    .filter(i => i.value.length >= min && i.value.indexOf(marker) === -1);
  return JSON.stringify({found: true, stolen, inputs: all.length});
}`, action, marker, danglingFormMinValueLen)
	raw, err := page.Evaluate(ctx, script)
	if err != nil {
		return "", false
	}
	s, _ := raw.(string)
	if s == "" {
		return "", false
	}
	var obs danglingFormObservation
	if err := json.Unmarshal([]byte(s), &obs); err != nil {
		return "", false
	}
	if !obs.Found || len(obs.Stolen) == 0 {
		return "", false
	}
	names := make([]string, 0, len(obs.Stolen))
	for _, in := range obs.Stolen {
		name := in.Name
		if name == "" {
			name = "(unnamed)"
		}
		names = append(names, name)
	}
	return strings.Join(names, ", "), true
}
