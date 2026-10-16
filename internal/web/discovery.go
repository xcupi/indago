package web

import (
	"net/http"

	"github.com/indago/indago/internal/domain"
)

// --- discovered endpoints ---

// endpointListItem is an Endpoint plus the Parameters discovered on it, for
// an operator debugging why an authenticated scan went Inconclusive (e.g.
// looking for a crawled logout/account-switch link, or a dynamic-token
// parameter) without reaching into the sqlite file by hand.
type endpointListItem struct {
	*domain.Endpoint
	Parameters []*domain.Parameter `json:"parameters"`
}

// handleListEndpoints lists every endpoint discovered so far for a scan
// (crawling runs continuously, so this reflects a live, possibly-partial
// snapshot while a scan is still running), each with its own parameters.
func (s *Server) handleListEndpoints(w http.ResponseWriter, r *http.Request) {
	scanID := domain.ID(r.PathValue("id"))
	if _, err := s.store.Scans().Get(r.Context(), scanID); err != nil {
		s.writeLookupError(w, err)
		return
	}
	endpoints, err := s.store.Endpoints().ListByScan(r.Context(), scanID)
	if err != nil {
		s.writeInternalError(w, "list endpoints", err)
		return
	}
	items := make([]endpointListItem, 0, len(endpoints))
	for _, ep := range endpoints {
		params, err := s.store.Parameters().ListByEndpoint(r.Context(), ep.ID)
		if err != nil {
			s.writeInternalError(w, "list parameters", err)
			return
		}
		items = append(items, endpointListItem{Endpoint: ep, Parameters: params})
	}
	writeJSON(w, http.StatusOK, items)
}
