package detection

// Generated families from PortSwigger's XSS cheat sheet (2026 edition).
//
// The JSON next to this file is the extracted table: one entry per event
// handler family the sheet documents, with the sheet's own example vector,
// rewritten so the dialog call is replaced by {{marker}}. Extraction rules:
//
//   - only self-contained vectors: no network callbacks, no cookie access, no
//     lab-only media files (validvideo/validaudio never load, so their load
//     events would never fire);
//   - the marker is a bare identifier, so firing the handler throws
//     ReferenceError and the verifier sees a signal instead of a dialog;
//   - needs is computed from the characters the vector actually uses, so a
//     site that encodes one of them drops the family before a request.
//
// Obfuscation and encoding sections are NOT copied here: those variants belong
// to the separately gated evasion pack, and copying them would turn a detection
// library into a bypass dump.

import (
	_ "embed"
	"encoding/json"
	"strings"
)

//go:embed library_cheatsheet.json
var cheatSheetJSON []byte

type cheatSheetEntry struct {
	ID       string   `json:"id"`
	Contexts []string `json:"contexts"`
	Trigger  string   `json:"trigger"`
	Needs    string   `json:"needs"`
	Template string   `json:"template"`
	Why      string   `json:"why"`
}

func init() {
	var entries []cheatSheetEntry
	if err := json.Unmarshal(cheatSheetJSON, &entries); err != nil {
		// A malformed embedded table is a build-time defect, not a runtime
		// condition: failing loudly here is better than silently planning a
		// partial library.
		panic("detection: parse embedded cheat-sheet library: " + err.Error())
	}
	for i, e := range entries {
		tpl := e.Template
		v := LibraryVector{
			ID:      e.ID,
			Trigger: e.Trigger,
			Needs:   e.Needs,
			Why:     e.Why,
			Rank:    i,
			Build:   func(m string) string { return strings.ReplaceAll(tpl, "{{marker}}", m) },
		}
		for _, c := range e.Contexts {
			v.Contexts = append(v.Contexts, Context(c))
		}
		Library = append(Library, v)
	}
}
