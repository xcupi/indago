package discovery

import (
	"context"

	"github.com/indago/indago/internal/domain"
)

// emitScriptDeclaredRequests registers the request shapes a page's own inline
// scripts declare but a crawl never observes (see ExtractScriptRequests for why
// a static read is needed at all).
//
// Registration is passive: no request is sent here. The method still decides
// which guards apply, exactly as for a form target — a destructive-looking GET
// is refused, while a body-carrying method is kept for the executor's
// state-changing opt-in, which remains the only thing that can send it.
func emitScriptDeclaredRequests(ctx context.Context, in Input, sink Sink, baseURL, html string) error {
	for _, req := range ExtractScriptRequests(html) {
		info, err := NormalizeRef(baseURL, req.URL)
		if err != nil || !in.Scope.Permits(info.Canonical).Allowed {
			continue
		}
		method := req.Method
		if method == "" {
			method = domain.MethodGET
		}
		if !method.IsValid() {
			continue
		}
		if !allowFetch(sink, info.Canonical, domain.SourceScriptLiteral, method) {
			continue
		}
		if _, err := sink.AddEndpoint(ctx, EndpointCandidate{
			URL:         info.Canonical,
			Method:      method,
			Source:      domain.SourceScriptLiteral,
			ContentType: req.ContentType,
			RequestBody: req.Body,
		}); err != nil {
			return err
		}
	}
	return nil
}
