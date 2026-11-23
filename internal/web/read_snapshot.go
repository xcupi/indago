package web

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/scan"
)

func (s *Server) handleReadSnapshot(w http.ResponseWriter, r *http.Request) {
	if !s.ctrl.ReadOnlyTargets() {
		writeError(w, http.StatusNotImplemented, "read-only capture is not configured")
		return
	}
	var req struct {
		URL      string    `json:"url"`
		Approved bool      `json:"approved_read_only"`
		Profile  domain.ID `json:"auth_profile_id"`
	}
	if err := readJSON(r, &req); err != nil {
		writeJSONBodyError(w, err)
		return
	}
	resp, err := s.ctrl.ReadSnapshot(r.Context(), domain.ID(r.PathValue("id")), req.URL, req.Approved, req.Profile)
	if errors.Is(err, scan.ErrSnapshotFetch) {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if err != nil {
		s.writeScanError(w, err)
		return
	}
	kind, _, _ := mime.ParseMediaType(resp.Headers.Get("Content-Type"))
	text := ""
	textType := strings.HasPrefix(kind, "text/") || kind == "application/json" ||
		strings.HasSuffix(kind, "+json") || kind == "application/xml" || strings.HasSuffix(kind, "+xml")
	if textType && utf8.Valid(resp.Body) {
		text = string(resp.Body)
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{
		"source": "target_read_only", "method": http.MethodGet, "url": resp.FinalURL,
		"status": resp.Status, "captured_at": resp.ReceivedAt,
		"size": len(resp.Body), "truncated": resp.Truncated, "media_type": kind,
		"sha256": fmt.Sprintf("%x", sha256.Sum256(resp.Body)), "body_text": text,
		"redirect_not_followed": resp.Status >= 300 && resp.Status < 400 && resp.Headers.Get("Location") != "",
	})
}
