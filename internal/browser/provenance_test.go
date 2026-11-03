package browser

import "testing"

func TestMarkerAtPosition(t *testing.T) {
	const m = "ind0123456789abcdef"
	cases := []struct {
		name         string
		src          string
		line, column int
		want         bool
	}{
		{"bare handler body", m, 0, 0, true},
		{"statement after semicolon", "var a=1;" + m, 0, 8, true},
		{"statement with trailing semicolon", m + ";", 0, 0, true},
		{"second line statement", "a();\n" + m + "\n", 1, 0, true},
		{"inside string literal", "x('" + m + "')", 0, 3, false},
		{"inside line comment", "// " + m, 0, 3, false},
		{"inside block comment", "/* " + m + " */", 0, 3, false},
		{"throw expression is not an evaluation", "throw " + m, 0, 6, false},
		{"property read is not a bare identifier", "a." + m, 0, 2, false},
		{"longer identifier", m + "x", 0, 0, false},
		{"member access suffix", m + ".y", 0, 0, false},
		// A ${...} substitution is ordinary code: a marker there is a bare
		// identifier the engine evaluates (and throws on) exactly like a
		// statement position, so it is accepted. Template TEXT is a string and
		// an escaped \$ opens no substitution; both stay refused.
		{"template substitution expression", "`" + "${" + m + "}`", 0, 3, true},
		{"template substitution after literal text", "var x = `a" + "${" + m + "}`", 0, 12, true},
		{"nested template substitution", "`a" + "${" + "`b" + "${" + m, 0, 8, true},
		// V8 reports the template's own start when its first substitution is
		// the throwing one; the marker must still be that whole substitution.
		{"first-substitution reported at the template start", "var x = `" + "${" + m + "}`", 0, 8, true},
		{"template start without an interpolation is text", "var x = `" + m + "`", 0, 8, false},
		{"template start whose first substitution is another identifier", "`" + "${x}" + m + "`", 0, 0, false},
		{"marker in template text", "var x = `" + m + "`", 0, 9, false},
		{"marker after a closed substitution is template text", "`" + "${x}" + m + "`", 0, 5, false},
		{"escaped interpolation stays text", "var x = `" + "\\${" + m + "}`", 0, 12, false},
		{"unterminated template text refused", "var x = `" + m, 0, 9, false},
		{"backtick inside a string does not open a template", "x('`');" + m, 0, 7, true},
		{"non-ascii prefix refused", "var é=1;" + m, 0, 8, false},
		{"division before the marker is refused", "var a=b/c;" + m, 0, 10, false},
		{"position beyond line", m, 3, 0, false},
		{"position beyond column", m, 0, 99, false},
		{"empty marker", "", 0, 0, false},
		{"position not at marker", "a();" + m, 0, 0, false},
		// V8 ends a line at \r, \r\n, U+2028 and U+2029, not only \n. Splitting
		// on \n alone maps V8's (1, 6) onto the marker below, although the engine
		// actually threw inside the forged `throw new ReferenceError(...)`.
		{"bare CR: engine throw position is not the marker", "x=1;\rthrow new ReferenceError('" + m + " is not defined');\n      " + m + ";", 1, 6, false},
		{"bare CR: marker really is on the second line", "x=1;\r" + m + ";", 1, 0, true},
		{"CRLF counts once", "a;\r\n" + m + ";", 1, 0, true},
		{"CRLF is not two lines", "a;\r\n" + m + ";", 2, 0, false},
		{"U+2028 line separator in the prefix is refused", "x\u2028" + m + ";", 1, 0, false},
		{"column inside a line, past a CR", "a;\rb();" + m + ";", 1, 4, true},
		{"column past the end of the line", "a;\r" + m, 1, 99, false},
		{"assignment is not a bare evaluation statement", "x = " + m, 0, 4, false},
		{"conditional operand", "a ? " + m + " : b", 0, 4, false},
		{"void operand", "void " + m, 0, 5, false},
		{"comma operand", m + ", y", 0, 0, false},
		{"parenthesised", "(" + m + ")", 0, 1, false},
		{"CR ends a line comment", "// note\r" + m + ";", 1, 0, true},
		{"after a closing brace", "if(a){b()}" + m + ";", 0, 10, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			marker := m
			if tc.name == "empty marker" {
				marker = ""
			}
			got, excerpt := markerAtPosition(tc.src, marker, tc.line, tc.column)
			if got != tc.want {
				t.Fatalf("got %v want %v (excerpt %q)", got, tc.want, excerpt)
			}
			if got && excerpt == "" {
				t.Fatal("accepted position without a source excerpt")
			}
		})
	}
}

func TestIsInstalledInitScript(t *testing.T) {
	const script = "(() => {\n  const MARKER = \"ind1\";\n})();"
	wrapped := playwrightInitScriptPrefix + script + playwrightInitScriptSuffix
	cases := []struct {
		name string
		code string
		init string
		want bool
	}{
		{"bare script", script, script, true},
		{"playwright wrapped script", wrapped, script, true},
		{"empty install never matches", "", "", false},
		{"page script embedding the harness in a comment", "/* " + script + " */ console.log('forged')", script, false},
		{"page script with harness as a prefix", script + "\nconsole.log('forged')", script, false},
		{"page script with harness as a suffix", "console.log('forged')\n" + script, script, false},
		{"wrapper with extra page code inside", playwrightInitScriptPrefix + script + "\nforged()" + playwrightInitScriptSuffix, script, false},
		{"different marker", wrapped, "(() => {\n  const MARKER = \"ind2\";\n})();", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isInstalledInitScript(tc.code, tc.init); got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}
