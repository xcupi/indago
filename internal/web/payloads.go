package web

// Read-only view of the cheat-sheet payload library. The library is a data
// table in internal/detection; this endpoint exists so an operator can see what
// a scan with `enable_xss_library` may send, and why a family exists, without
// reading Go source. It never plans or sends anything.

import (
	"net/http"
	"strings"

	"github.com/indago/indago/internal/detection"
)

type libraryEntry struct {
	ID       string   `json:"id"`
	Contexts []string `json:"contexts"`
	Trigger  string   `json:"trigger"`
	Needs    string   `json:"needs"`
	Example  string   `json:"example"`
	Why      string   `json:"why"`
	Source   string   `json:"source"`
}

type libraryResponse struct {
	Source    string         `json:"source"`
	Updated   string         `json:"source_updated"`
	NeedsNote string         `json:"needs_note"`
	Count     int            `json:"count"`
	Entries   []libraryEntry `json:"entries"`
}

func (s *Server) handleListPayloadLibrary(w http.ResponseWriter, r *http.Request) {
	resp := libraryResponse{
		Source:    "https://portswigger.net/web-security/cross-site-scripting/cheat-sheet",
		Updated:   "2026-10-21",
		NeedsNote: "needs lists the characters a vector cannot work without; if the target provably encodes one of them at the reflection site, the vector is dropped before a request is spent.",
	}
	for _, v := range detection.Library {
		ctxs := make([]string, 0, len(v.Contexts))
		for _, c := range v.Contexts {
			ctxs = append(ctxs, string(c))
		}
		resp.Entries = append(resp.Entries, libraryEntry{
			ID: v.ID, Contexts: ctxs, Trigger: v.Trigger, Needs: v.Needs,
			Example: strings.ReplaceAll(v.Build("MARKER"), "MARKER", "{{marker}}"),
			Why:     v.Why, Source: resp.Source,
		})
	}
	resp.Count = len(resp.Entries)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, resp)
}
