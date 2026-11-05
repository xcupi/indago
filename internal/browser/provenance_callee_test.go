package browser

import (
	"strings"
	"testing"
)

// V8 reports the creation position of an eval'd script at the argument
// expression's own operator for a computed argument (`eval('a' + b)` points at
// the `+`), not at the `eval(` token. enclosingCompilationCallee must recover
// the real callee from such a position without ever guessing.
func TestEnclosingCompilationCallee(t *testing.T) {
	cases := []struct {
		name, code, at, want string
	}{
		{"concatenated string", `x(); eval('var o = ' + body);`, `+ body`, "eval"},
		{"concatenation after a quote holding parens", `eval("f(" + body + ")");`, `+ body + `, "eval"},
		{"escaped quote in a string", `eval("a\"(" + body);`, `+ body`, "eval"},
		{"nested call argument", `eval(JSON.stringify(a) + body);`, `+ body`, "eval"},
		{"new Function", `var f = new Function('a', 'return ' + body);`, `+ body`, "Function"},
		{"array literal argument", `eval([a, b].join('') + body);`, `+ body`, "eval"},
		{"not a compilation callee", `render('<b>' + body);`, `+ body`, ""},
		{"lookalike name", `myeval('a' + body);`, `+ body`, ""},
		{"another statement first", `eval('1'); other('a' + body);`, `+ body`, ""},
		{"not inside any call", `var s = 'a' + body;`, `+ body`, ""},
		{"inside an object literal", `eval({k: 'a' + body});`, `+ body`, ""},
		// Syntax-awareness controls: text that merely LOOKS like a call must
		// never be read as one.
		{"callee text only in a block comment", `setTimeout(/* eval( */ "constant" + body);`, `+ body`, ""},
		{"callee text only in a line comment", "setTimeout( // eval(\n \"constant\" + body);", `+ body`, ""},
		{"callee text only in a string", `setTimeout("eval(" + body);`, `+ body`, ""},
		{"callee text only in a template", "setTimeout(`eval(` + body);", `+ body`, ""},
		{"callee text only in a regex literal", `setTimeout(/eval(/.source + body);`, `+ body`, ""},
		{"paren in a regex class", `eval(/[(]/.source + body);`, `+ body`, "eval"},
		{"genuine eval after a comment", `eval(/* note */ "a" + body);`, `+ body`, "eval"},
		{"comment between eval and paren is still a call", `eval /* c */ ("a" + body);`, `+ body`, "eval"},
		{"template expression argument", "eval(`a${x}` + body);", `+ body`, "eval"},
		{"call inside a template expression", "var s = `x${eval('a' + body)}`;", `+ body`, "eval"},
		{"non-call inside a template expression", "var s = `eval(${f('a' + body)}`;", `+ body`, ""},
		{"division is not a regex", `eval(a / b + body);`, `+ body`, "eval"},
		{"earlier unbalanced text in a comment", "/* ) ) */ eval('a' + body);", `+ body`, "eval"},
		{"position inside a comment", `eval("a" /* x + body */);`, `+ body`, ""},
		{"position inside a string", `eval("a + body");`, `+ body`, ""},
	}
	for _, tc := range cases {
		at := strings.Index(tc.code, tc.at)
		if at < 0 {
			t.Fatalf("%s: fixture lacks %q", tc.name, tc.at)
		}
		if got := enclosingCompilationCallee(tc.code, at); got != tc.want {
			t.Errorf("%s: callee=%q, want %q", tc.name, got, tc.want)
		}
	}
	long := "eval(" + strings.Repeat("a", 3*compilationCalleeScanLimit) + " + b"
	if got := enclosingCompilationCallee(long, strings.Index(long, "+ b")); got != "" {
		t.Errorf("the backward scan must stay bounded, got %q", got)
	}
}
