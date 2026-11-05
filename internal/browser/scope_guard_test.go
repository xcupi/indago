package browser

// Structural guard for the browser scope boundary.
//
// A browser context created without a scope gate (AllowRequest == nil) installs
// no request route, does not block service workers and does not close
// WebSockets: it can reach any host. That is how login traffic once escaped
// scope. Today every production caller supplies a gate, but nothing stopped a
// new caller from forgetting it, and the failure is silent. This test makes the
// omission a build failure instead.
//
// It parses the production sources (no test files) and rejects any composite
// literal of the option types below that does not set AllowRequest, sets it to
// nil, or is positional (so the field cannot be checked). Matching is by the
// import path of the browser package, not by type name alone, because
// detection.ContextOptions is an unrelated type with the same name.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const browserImportPath = "github.com/indago/indago/internal/browser"

// gatedOptionTypes are the option structs whose AllowRequest decides whether a
// browser context is scope-gated.
var gatedOptionTypes = map[string]bool{
	"ContextOptions":   true,
	"RenderOptions":    true,
	"LoginOptions":     true,
	"AutoLoginOptions": true,
}

// scopeGateViolations returns one message per option literal in src that lacks a
// non-nil AllowRequest. pkg is the package name of the file; inBrowserPkg is
// true for files that belong to package browser itself (bare type names).
func scopeGateViolations(filename string, src []byte) ([]string, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filename, src, 0)
	if err != nil {
		return nil, err
	}
	inBrowserPkg := f.Name.Name == "browser"

	// Local names the browser package is imported under in this file.
	aliases := map[string]bool{}
	for _, imp := range f.Imports {
		path, _ := strconv.Unquote(imp.Path.Value)
		if path != browserImportPath {
			continue
		}
		name := "browser"
		if imp.Name != nil {
			name = imp.Name.Name
		}
		aliases[name] = true
	}

	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok || lit.Type == nil {
			return true
		}
		var typeName string
		switch t := lit.Type.(type) {
		case *ast.SelectorExpr: // browser.ContextOptions
			if x, ok := t.X.(*ast.Ident); ok && aliases[x.Name] {
				typeName = t.Sel.Name
			}
		case *ast.Ident: // ContextOptions inside package browser
			if inBrowserPkg {
				typeName = t.Name
			}
		}
		if !gatedOptionTypes[typeName] {
			return true
		}
		pos := fset.Position(lit.Pos())
		where := filepath.ToSlash(pos.Filename) + ":" + strconv.Itoa(pos.Line)
		var found, positional, isNil bool
		for _, el := range lit.Elts {
			kv, ok := el.(*ast.KeyValueExpr)
			if !ok {
				positional = true
				continue
			}
			if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "AllowRequest" {
				found = true
				if v, ok := kv.Value.(*ast.Ident); ok && v.Name == "nil" {
					isNil = true
				}
			}
		}
		switch {
		case positional:
			out = append(out, where+": positional "+typeName+" literal; use field names so AllowRequest can be checked")
		case !found:
			out = append(out, where+": "+typeName+" literal does not set AllowRequest (an ungated browser context can reach any host)")
		case isNil:
			out = append(out, where+": "+typeName+" sets AllowRequest to nil (an ungated browser context can reach any host)")
		}
		return true
	})

	// pwBrowser/driver-level calls: x.NewContext(storage, proxy, headers, nil)
	// hands the driver an ungated context regardless of any options struct.
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "NewContext" || len(call.Args) != 4 {
			return true // the Manager.NewContext(ctx, opts) form is covered by its options literal
		}
		if v, ok := call.Args[3].(*ast.Ident); ok && v.Name == "nil" {
			pos := fset.Position(call.Pos())
			out = append(out, filepath.ToSlash(pos.Filename)+":"+strconv.Itoa(pos.Line)+": driver NewContext called with a nil scope gate")
		}
		return true
	})
	return out, nil
}

// productionGoFiles lists non-test Go files under root/internal and root/cmd.
func productionGoFiles(t *testing.T, root string) []string {
	t.Helper()
	var files []string
	for _, dir := range []string{"internal", "cmd"} {
		base := filepath.Join(root, dir)
		if _, err := os.Stat(base); err != nil {
			t.Fatalf("scope guard cannot find %s: %v (the guard must not pass by scanning nothing)", base, err)
		}
		err := filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			if strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
				files = append(files, path)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return files
}

func TestScopeGateEveryProductionBrowserContextIsGated(t *testing.T) {
	files := productionGoFiles(t, filepath.Join("..", ".."))
	checked := 0
	var bad []string
	for _, path := range files {
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		v, err := scopeGateViolations(path, src)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		bad = append(bad, v...)
		if strings.Contains(string(src), "AllowRequest") {
			checked++
		}
	}
	// Anti-vacuity: the files known to build gated contexts must have been read.
	if len(files) < 50 || checked < 5 {
		t.Fatalf("scope guard looked at %d files (%d mention AllowRequest); the walk is not covering the tree", len(files), checked)
	}
	for _, m := range bad {
		t.Errorf("%s", m)
	}
}

// The guard must be able to fail. These are the shapes it exists to catch, plus
// the look-alike it must NOT flag.
func TestScopeGateGuardDetectsUngatedShapes(t *testing.T) {
	const hdr = "package p\nimport (\n\t\"github.com/indago/indago/internal/browser\"\n\tdet \"github.com/indago/indago/internal/detection\"\n)\n"
	cases := []struct {
		name string
		body string
		want int
	}{
		{"missing", "var _ = browser.ContextOptions{StorageStatePath: \"x\"}", 1},
		{"nil", "var _ = browser.ContextOptions{AllowRequest: nil}", 1},
		{"render-missing", "var _ = browser.RenderOptions{WaitUntil: 1}", 1},
		{"login-missing", "var _ = browser.LoginOptions{LoginURL: \"u\"}", 1},
		{"autologin-missing", "var _ = browser.AutoLoginOptions{LoginURL: \"u\"}", 1},
		{"positional", "var _ = browser.LoginOptions{nil, \"u\", \"g\", \"p\"}", 1},
		{"driver-nil", "func f(b interface{ NewContext(a, b string, c map[string]string, d func(string) bool) }) { b.NewContext(\"\", \"\", nil, nil) }", 1},
		{"gated", "var _ = browser.ContextOptions{AllowRequest: func(string) bool { return true }}", 0},
		{"gated-forwarded", "func f(o browser.RenderOptions) { _ = browser.ContextOptions{AllowRequest: o.AllowRequest} }", 0},
		{"unrelated-same-name", "var _ = det.ContextOptions{ContentType: \"text/html\"}", 0},
		{"driver-gated", "func f(b interface{ NewContext(a, b string, c map[string]string, d func(string) bool) }, g func(string) bool) { b.NewContext(\"\", \"\", nil, g) }", 0},
	}
	for _, tc := range cases {
		got, err := scopeGateViolations("synthetic.go", []byte(hdr+tc.body))
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if len(got) != tc.want {
			t.Errorf("%s: got %d violations %v, want %d", tc.name, len(got), got, tc.want)
		}
	}
	// Bare type names count inside package browser itself.
	got, err := scopeGateViolations("manager.go", []byte("package browser\nvar _ = ContextOptions{StorageStatePath: \"x\"}\n"))
	if err != nil || len(got) != 1 {
		t.Errorf("bare ContextOptions in package browser: %v %v", got, err)
	}
	// ...but the same text in another package is not this type.
	got, err = scopeGateViolations("other.go", []byte("package detection\nvar _ = ContextOptions{ContentType: \"x\"}\n"))
	if err != nil || len(got) != 0 {
		t.Errorf("bare ContextOptions outside package browser must not be flagged: %v %v", got, err)
	}
}

// Take the REAL production callers and remove their gate: the guard must object.
// This ties the synthetic cases above to the actual code shapes in the tree.
func TestScopeGateGuardCatchesTheRealCallersWhenTheGateIsRemoved(t *testing.T) {
	root := filepath.Join("..", "..")
	cases := []struct{ file, gate string }{
		{"internal/verification/browser.go", "AllowRequest:     allow,"},
		{"internal/scan/domxss.go", "AllowRequest: allow, "},
		{"internal/discovery/sources.go", "AllowRequest:      func(u string) bool { return in.Scope.Permits(u).Allowed },"},
		{"internal/scan/controller.go", "AllowRequest: allow, LoginURL"},
		{"cmd/indago/main.go", "AllowRequest:     p.AllowRequest,"},
	}
	for _, c := range cases {
		src, err := os.ReadFile(filepath.Join(root, c.file))
		if err != nil {
			t.Fatal(err)
		}
		before, err := scopeGateViolations(c.file, src)
		if err != nil || len(before) != 0 {
			t.Fatalf("%s must be clean before mutation: %v %v", c.file, before, err)
		}
		if strings.Count(string(src), c.gate) < 1 {
			t.Fatalf("%s: expected gate text %q not found; update this test to the current code", c.file, c.gate)
		}
		mutated := strings.Replace(string(src), c.gate, strings.Replace(c.gate, "AllowRequest", "ZZRemovedGate", 1), 1)
		after, err := scopeGateViolations(c.file, []byte(mutated))
		if err != nil {
			t.Fatalf("%s mutated does not parse: %v", c.file, err)
		}
		if len(after) == 0 {
			t.Errorf("%s: removing the gate went unnoticed", c.file)
		}
	}
}
