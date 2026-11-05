package browser

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Budgets bound memory and CDP round trips, not correctness. Script metadata is
// ~100 bytes, so the script ceiling is generous: script-heavy sites (tag
// managers, ad frames, one harness copy per navigation and frame) exceed a few
// hundred. Hitting a budget never flips the whole page to "unavailable"; an
// attempt whose script or exception was dropped simply cannot be attributed and
// ends Inconclusive.
const (
	provenanceEventLimit  = 64
	provenanceScriptLimit = 8192
	provenanceSourceLimit = 1 << 20
	// provenanceDrainWait bounds how long a read waits for an in-flight handler.
	provenanceDrainWait = 300 * time.Millisecond
)

type cdpLocation struct {
	ScriptID string `json:"scriptId"`
	Line     int    `json:"lineNumber"`
	Column   int    `json:"columnNumber"`
}
type cdpFrame struct {
	Location cdpLocation `json:"location"`
	URL      string      `json:"url"`
	This     struct {
		ObjectID string `json:"objectId"`
	} `json:"this"`
}
type cdpStackFrame struct {
	ScriptID string `json:"scriptId"`
	URL      string `json:"url"`
	Line     int    `json:"lineNumber"`
	Column   int    `json:"columnNumber"`
}
type cdpStack struct {
	Frames []cdpStackFrame `json:"callFrames"`
}
type cdpScript struct {
	ID          string   `json:"scriptId"`
	URL         string   `json:"url"`
	Context     int      `json:"executionContextId"`
	StartLine   int      `json:"startLine"`
	StartColumn int      `json:"startColumn"`
	Length      int      `json:"length"`
	Stack       cdpStack `json:"stackTrace"`
}

var compilationCallee = regexp.MustCompile(`\b(eval|Function)\s*\(\s*$`)

// automationTag marks a script evaluated by Page.Evaluate. Playwright runs that
// expression through the page's own eval, so without a marker the engine would
// attribute the scanner's automation (a window.name setter, a postMessage
// sender, an activation script - all of which carry the candidate value) to the
// target as an eval sink. Runtime provenance ignores a compilation whose code
// starts with it. The tag is random per process; a page that learned it could
// only hide its own eval use from the reachability report.
var automationTag = func() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("browser: no entropy for the automation tag: " + err.Error())
	}
	return "/*indago-automation-" + hex.EncodeToString(b[:]) + "*/"
}()

// compilationCalleeScanLimit bounds how much source enclosingCompilationCallee
// lexes (the caller script up to V8's reported position).
const compilationCalleeScanLimit = 1 << 20

// enclosingCompilationCallee returns "eval" or "Function" when offset lies
// directly inside the argument list of such a call, "" otherwise. V8 reports
// the creation position of an eval'd script at the argument expression's own
// operator for a computed argument (`eval('var o = ' + body)` points at the
// `+`), so the callee is recovered by lexing the caller script FORWARD from its
// start to offset and reading the innermost open bracket. Forward lexing is
// what makes it syntax-aware: comments, string, template (including ${...}
// nesting) and regular-expression literals are skipped, so text such as
// `/* eval( */` or "eval(" in a string can never be mistaken for a call.
// It declines (returns "") whenever it cannot be sure: offset inside a
// comment/string/template/regex, an unterminated literal, an unbalanced
// bracket, or a script larger than compilationCalleeScanLimit. A decline only
// means no reachability report, never a fabricated one.
func enclosingCompilationCallee(code string, offset int) string {
	if offset < 0 || offset > len(code) || offset > compilationCalleeScanLimit {
		return ""
	}
	type frame struct {
		open   byte // '(' '[' '{' or '$' for a template ${ expression
		callee string
	}
	var stack []frame
	prev := byte('p') // previous significant token: 'i' identifier, 'n' operand-ending, 'p' punctuation/keyword
	lastIdent := ""
	isIdentStart := func(c byte) bool {
		return c == '_' || c == '$' || c >= 0x80 || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
	}
	isIdentPart := func(c byte) bool { return isIdentStart(c) || (c >= '0' && c <= '9') }
	// quoted skips a '...' or "..." literal starting at i, returning the index
	// just past it, or -1 if it is unterminated before offset.
	quoted := func(i int) int {
		q := code[i]
		for j := i + 1; j < offset; j++ {
			switch code[j] {
			case '\\':
				j++
			case '\n':
				return -1
			case q:
				return j + 1
			}
		}
		return -1
	}
	// templateText skips template text starting at i (just after the opening
	// backtick or the closing brace of a ${ expression). It returns the index
	// after the closing backtick, or after "${" with true when an expression
	// opens, or -1 if offset falls inside the text.
	templateText := func(i int) (int, bool) {
		for j := i; j < offset; j++ {
			switch code[j] {
			case '\\':
				j++
			case '`':
				return j + 1, false
			case '$':
				if j+1 < offset && code[j+1] == '{' {
					return j + 2, true
				}
			}
		}
		return -1, false
	}
	keywords := map[string]bool{"return": true, "typeof": true, "case": true, "in": true, "of": true, "delete": true,
		"void": true, "throw": true, "new": true, "else": true, "do": true, "instanceof": true, "yield": true, "await": true}
	for i := 0; i < offset; {
		c := code[i]
		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' || c == '\v':
			i++
		case c == '/' && i+1 < len(code) && code[i+1] == '/':
			nl := strings.IndexByte(code[i:offset], '\n')
			if nl < 0 {
				return ""
			}
			i += nl
		case c == '/' && i+1 < len(code) && code[i+1] == '*':
			end := strings.Index(code[i+2:], "*/")
			if end < 0 || i+2+end+2 > offset {
				return ""
			}
			i += 2 + end + 2
		case c == '\'' || c == '"':
			if i = quoted(i); i < 0 {
				return ""
			}
			prev = 'n'
		case c == '`':
			j, expr := templateText(i + 1)
			if j < 0 {
				return ""
			}
			i = j
			if expr {
				stack = append(stack, frame{open: '$'})
				prev = 'p'
			} else {
				prev = 'n'
			}
		case c == '/':
			if prev != 'p' {
				i++ // division
				prev = 'p'
				break
			}
			// A regular-expression literal: skip to its closing slash,
			// honouring escapes and character classes.
			j, inClass := i+1, false
			for ; j < offset; j++ {
				if code[j] == '\\' {
					j++
					continue
				}
				if code[j] == '\n' {
					return ""
				}
				if code[j] == '[' {
					inClass = true
				} else if code[j] == ']' {
					inClass = false
				} else if code[j] == '/' && !inClass {
					break
				}
			}
			if j >= offset {
				return ""
			}
			i = j + 1
			for i < offset && isIdentPart(code[i]) {
				i++ // flags
			}
			prev = 'n'
		case isIdentStart(c):
			j := i
			for j < len(code) && isIdentPart(code[j]) {
				j++
			}
			if j > offset {
				return "" // offset inside an identifier: not a position we understand
			}
			lastIdent = code[i:j]
			if keywords[lastIdent] {
				prev = 'p'
			} else {
				prev = 'i'
			}
			i = j
		case c >= '0' && c <= '9':
			for i < offset && (isIdentPart(code[i]) || code[i] == '.') {
				i++
			}
			prev = 'n'
		case c == '(':
			f := frame{open: '('}
			if prev == 'i' && (lastIdent == "eval" || lastIdent == "Function") {
				f.callee = lastIdent
			}
			stack = append(stack, f)
			prev = 'p'
			i++
		case c == '[' || c == '{':
			stack = append(stack, frame{open: c})
			prev = 'p'
			i++
		case c == ')' || c == ']' || c == '}':
			if len(stack) == 0 {
				return ""
			}
			top := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			i++
			if c == '}' && top.open == '$' {
				j, expr := templateText(i)
				if j < 0 {
					return ""
				}
				i = j
				if expr {
					stack = append(stack, frame{open: '$'})
					prev = 'p'
				} else {
					prev = 'n'
				}
				break
			}
			prev = 'n'
		default:
			prev = 'p'
			i++
		}
	}
	if len(stack) == 0 || stack[len(stack)-1].open != '(' {
		return ""
	}
	return stack[len(stack)-1].callee
}

func decodeCDP(v any, out any) { b, _ := json.Marshal(v); _ = json.Unmarshal(b, out) }

func (p *pwPage) RuntimeObservations() RuntimeObservations {
	for deadline := time.Now().Add(provenanceDrainWait); p.provInflight.Load() > 0 && time.Now().Before(deadline); {
		time.Sleep(5 * time.Millisecond)
	}
	p.provenanceMu.Lock()
	defer p.provenanceMu.Unlock()
	r := p.provenance
	r.Compilations = append([]RuntimeCompilation(nil), r.Compilations...)
	r.Exceptions = append([]RuntimeException(nil), r.Exceptions...)
	r.Reports = append([]InstrumentationReport(nil), r.Reports...)
	return r
}

// The debugger supplies the actual paused instruction and scriptId. Page error
// messages, Error.stack, sourceURL and console text are not execution authority.
// CDP reads source/DOM metadata only; no Runtime.evaluate/callFunctionOn is used.
func (p *pwPage) EnableRuntimeProvenance(marker, initScript string) error {
	session, err := p.ctx.c.NewCDPSession(p.p)
	if err != nil {
		return err
	}
	scripts := map[string]cdpScript{}
	contexts := map[int]string{}
	var stateMu sync.RWMutex
	location := func(id string, line, column int) RuntimeLocation {
		stateMu.RLock()
		defer stateMu.RUnlock()
		s := scripts[id]
		return RuntimeLocation{ScriptID: id, URL: s.URL, ContextID: s.Context, FrameID: contexts[s.Context], Line: line, Column: column}
	}
	stackLocations := func(stack cdpStack) []RuntimeLocation {
		var out []RuntimeLocation
		for _, f := range stack.Frames {
			if len(out) == 16 {
				break
			}
			out = append(out, location(f.ScriptID, f.Line, f.Column))
		}
		return out
	}
	source := func(id string) (string, bool) {
		stateMu.RLock()
		s, ok := scripts[id]
		stateMu.RUnlock()
		if !ok || s.Length > provenanceSourceLimit {
			return "", false
		}
		raw, e := session.Send("Debugger.getScriptSource", map[string]any{"scriptId": id})
		if e != nil {
			return "", false
		}
		var result struct {
			Source string `json:"scriptSource"`
		}
		decodeCDP(raw, &result)
		return result.Source, len(result.Source) <= provenanceSourceLimit
	}
	nodeID := func(objectID string) int {
		if objectID == "" {
			return 0
		}
		raw, e := session.Send("DOM.describeNode", map[string]any{"objectId": objectID, "depth": 0})
		if e != nil {
			return 0
		}
		var result struct {
			Node struct {
				ID int `json:"backendNodeId"`
			} `json:"node"`
		}
		decodeCDP(raw, &result)
		return result.Node.ID
	}
	fail := func(note string) {
		p.provenanceMu.Lock()
		p.provenance.Available = false
		p.provenance.Note = note
		p.provenanceMu.Unlock()
	}
	session.On("Runtime.executionContextCreated", func(v map[string]any) {
		var event struct {
			Context struct {
				ID  int `json:"id"`
				Aux struct {
					Frame   string `json:"frameId"`
					Default bool   `json:"isDefault"`
				} `json:"auxData"`
			} `json:"context"`
		}
		decodeCDP(v, &event)
		stateMu.Lock()
		if event.Context.Aux.Default {
			contexts[event.Context.ID] = event.Context.Aux.Frame
		}
		stateMu.Unlock()
	})
	session.On("Page.frameNavigated", func(v map[string]any) {
		var event struct {
			Frame struct {
				ID     string `json:"id"`
				Parent string `json:"parentId"`
			} `json:"frame"`
		}
		decodeCDP(v, &event)
		if event.Frame.Parent == "" {
			p.provenanceMu.Lock()
			p.provenance.MainFrameID = event.Frame.ID
			p.provenanceMu.Unlock()
		}
	})
	session.On("Debugger.scriptParsed", func(v map[string]any) {
		var s cdpScript
		decodeCDP(v, &s)
		stateMu.Lock()
		if len(scripts) >= provenanceScriptLimit {
			stateMu.Unlock()
			p.noteProvenance("script metadata budget exceeded; later scripts cannot be attributed")
			return
		}
		scripts[s.ID] = s
		stateMu.Unlock()
		// Observe native compilation rather than replacing eval: a wrapper
		// turns direct eval into indirect eval and destroys lexical semantics.
		if initScript == "" || len(s.Stack.Frames) == 0 {
			return
		}
		p.provInflight.Add(1)
		defer p.provInflight.Add(-1)
		caller := s.Stack.Frames[0]
		callerCode, ok := source(caller.ScriptID)
		if !ok || isInstalledInitScript(callerCode, initScript) {
			return
		}
		stateMu.RLock()
		parent := scripts[caller.ScriptID]
		stateMu.RUnlock()
		line, column := caller.Line-parent.StartLine, caller.Column
		if line == 0 {
			column -= parent.StartColumn
		}
		offset, ok := v8Offset(callerCode, line, column)
		if !ok {
			return
		}
		kind := ""
		call := strings.TrimSpace(callerCode[offset:])
		if strings.HasPrefix(call, "eval(") || strings.HasPrefix(call, "eval (") {
			kind = "eval"
		}
		if strings.HasPrefix(call, "new Function(") || strings.HasPrefix(call, "Function(") {
			kind = "Function"
		}
		if kind == "" {
			// V8 may put the creation position at the first argument,
			// rather than the callee token.
			if m := compilationCallee.FindStringSubmatch(callerCode[:offset]); len(m) > 1 {
				kind = m[1]
			}
		}
		if kind == "" {
			// ... or at the operator of a computed argument.
			kind = enclosingCompilationCallee(callerCode, offset)
		}
		if kind == "" {
			return
		}
		code, ok := source(s.ID)
		if ok && strings.HasPrefix(code, automationTag) {
			return
		}
		at := strings.Index(code, marker)
		if !ok || marker == "" || at < 0 {
			return
		}
		lo, hi := at-160, at+len(marker)+160
		if lo < 0 {
			lo = 0
		}
		if hi > len(code) {
			hi = len(code)
		}
		loc := location(s.ID, s.StartLine, s.StartColumn)
		loc.SourceSHA256 = sourceDigest(code)
		rep := RuntimeCompilation{Kind: kind, Location: loc,
			Caller: location(caller.ScriptID, caller.Line, caller.Column), SourceExcerpt: code[lo:hi]}
		p.provenanceMu.Lock()
		if len(p.provenance.Compilations) < provenanceEventLimit {
			p.provenance.Compilations = append(p.provenance.Compilations, rep)
		}
		p.provenanceMu.Unlock()
	})
	session.On("Debugger.paused", func(v map[string]any) {
		p.provInflight.Add(1)
		defer p.provInflight.Add(-1)
		defer session.Send("Debugger.resume", nil)
		var event struct {
			Reason string     `json:"reason"`
			Frames []cdpFrame `json:"callFrames"`
			Data   struct {
				Class       string `json:"className"`
				Description string `json:"description"`
			} `json:"data"`
		}
		decodeCDP(v, &event)
		if event.Reason != "exception" || len(event.Frames) == 0 {
			return
		}
		// Only an exception whose message names this attempt's marker can be
		// execution evidence or a forgery of it. Anything else is page noise: it
		// costs a pause and a resume but no source fetch and no budget, so a
		// page that throws constantly cannot starve the real signal.
		if marker == "" || !strings.Contains(firstLine(event.Data.Description), marker) {
			return
		}
		f := event.Frames[0]
		stateMu.RLock()
		s := scripts[f.Location.ScriptID]
		stateMu.RUnlock()
		loc := location(f.Location.ScriptID, f.Location.Line, f.Location.Column)
		ex := RuntimeException{Location: loc, Description: event.Data.Description, ClassName: event.Data.Class, NodeID: nodeID(f.This.ObjectID), CreationStack: stackLocations(s.Stack)}
		for _, frame := range event.Frames {
			if len(ex.Stack) == 16 {
				break
			}
			ex.Stack = append(ex.Stack, location(frame.Location.ScriptID, frame.Location.Line, frame.Location.Column))
		}
		if text, ok := source(f.Location.ScriptID); ok {
			ex.Location.SourceSHA256 = sourceDigest(text)
			line, column := f.Location.Line-s.StartLine, f.Location.Column
			if line == 0 {
				column -= s.StartColumn
			}
			ex.MarkerIdentifier, ex.SourceExcerpt = markerAtPosition(text, marker, line, column)
		}
		p.provenanceMu.Lock()
		if len(p.provenance.Exceptions) < provenanceEventLimit {
			p.provenance.Exceptions = append(p.provenance.Exceptions, ex)
		} else if p.provenance.Note == "" {
			// Dropped records only matter when every kept one is forged, and then
			// the verdict is already Inconclusive; a real hit is kept first.
			p.provenance.Note = "marker-named exception budget exceeded; later exceptions were dropped"
		}
		p.provenanceMu.Unlock()
		if ex.MarkerIdentifier && ex.ClassName == "ReferenceError" {
			// Execution is established; stop pausing so a string timer that
			// throws on every tick cannot turn the first hit into a slow page.
			_, _ = session.Send("Debugger.setPauseOnExceptions", map[string]any{"state": "none"})
		}
	})
	session.On("Runtime.consoleAPICalled", func(v map[string]any) {
		if initScript == "" {
			return
		}
		p.provInflight.Add(1)
		defer p.provInflight.Add(-1)
		var event struct {
			Context int `json:"executionContextId"`
			Args    []struct {
				Value    any    `json:"value"`
				ObjectID string `json:"objectId"`
			} `json:"args"`
			Stack cdpStack `json:"stackTrace"`
		}
		decodeCDP(v, &event)
		if len(event.Args) == 0 || len(event.Stack.Frames) < 2 {
			return
		}
		text, ok := event.Args[0].Value.(string)
		if !ok || !strings.HasPrefix(text, "__INDAGO_DOMXSS__") {
			return
		}
		top := event.Stack.Frames[0]
		code, ok := source(top.ScriptID)
		if !ok || !isInstalledInitScript(code, initScript) {
			return
		}
		rep := InstrumentationReport{Text: text, Location: location(top.ScriptID, top.Line, top.Column)}
		// Skip harness internals to retain the application's real caller.
		for _, frame := range event.Stack.Frames[1:] {
			if frame.ScriptID != top.ScriptID {
				rep.Caller = location(frame.ScriptID, frame.Line, frame.Column)
				break
			}
		}
		for _, arg := range event.Args[1:] {
			if id := nodeID(arg.ObjectID); id != 0 {
				rep.NodeIDs = append(rep.NodeIDs, id)
			}
		}
		p.provenanceMu.Lock()
		duplicate := false
		for _, kept := range p.provenance.Reports {
			if kept.Text == rep.Text {
				duplicate = true
				break
			}
		}
		if duplicate {
			// A page that re-renders the same value in a loop repeats one report.
		} else if len(p.provenance.Reports) < provenanceEventLimit {
			p.provenance.Reports = append(p.provenance.Reports, rep)
		} else if p.provenance.Note == "" {
			p.provenance.Note = "sink report budget exceeded; later distinct reports were dropped"
		}
		p.provenanceMu.Unlock()
	})
	// Available is set BEFORE the domains are enabled so a later fail() (for
	// example a metadata problem observed during enable) cannot be overwritten.
	p.provenanceMu.Lock()
	p.provenance.Available = true
	p.provenanceMu.Unlock()
	for _, method := range []string{"Page.enable", "Runtime.enable", "Debugger.enable"} {
		if _, err = session.Send(method, nil); err != nil {
			fail("enable runtime provenance: " + err.Error())
			return fmt.Errorf("enable runtime provenance: %w", err)
		}
	}
	// frameNavigated only fires on navigation; read the initial main frame now.
	if raw, e := session.Send("Page.getFrameTree", nil); e == nil {
		var tree struct {
			FrameTree struct {
				Frame struct {
					ID string `json:"id"`
				} `json:"frame"`
			} `json:"frameTree"`
		}
		decodeCDP(raw, &tree)
		if tree.FrameTree.Frame.ID != "" {
			p.provenanceMu.Lock()
			if p.provenance.MainFrameID == "" {
				p.provenance.MainFrameID = tree.FrameTree.Frame.ID
			}
			p.provenanceMu.Unlock()
		}
	}
	if _, err = session.Send("Debugger.setPauseOnExceptions", map[string]any{"state": "uncaught"}); err != nil {
		fail("enable runtime provenance: " + err.Error())
		return err
	}
	// Closing the page owns/destroys this session. Never synchronously detach
	// while an exception/route event may be awaiting its protocol response.
	return nil
}

// noteProvenance records a non-fatal limitation once.
func (p *pwPage) noteProvenance(note string) {
	p.provenanceMu.Lock()
	if p.provenance.Note == "" {
		p.provenance.Note = note
	}
	p.provenanceMu.Unlock()
}

// firstLine returns the error message without the stack CDP appends to it.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
