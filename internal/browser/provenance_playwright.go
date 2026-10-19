package browser

import (
	"encoding/json"
	"fmt"
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

func decodeCDP(v any, out any) { b, _ := json.Marshal(v); _ = json.Unmarshal(b, out) }

func (p *pwPage) RuntimeObservations() RuntimeObservations {
	for deadline := time.Now().Add(provenanceDrainWait); p.provInflight.Load() > 0 && time.Now().Before(deadline); {
		time.Sleep(5 * time.Millisecond)
	}
	p.provenanceMu.Lock()
	defer p.provenanceMu.Unlock()
	r := p.provenance
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
		defer stateMu.Unlock()
		if len(scripts) >= provenanceScriptLimit {
			p.noteProvenance("script metadata budget exceeded; later scripts cannot be attributed")
			return
		}
		scripts[s.ID] = s
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
