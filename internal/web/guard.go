package web

import (
	"net"
	"net/http"
	"net/url"
	"strings"
)

// ClientHeader must be present on every state-changing request. Browsers cannot
// attach a custom header to a cross-origin request without a CORS preflight,
// which this server never approves — so a malicious page the operator happens to
// visit cannot drive the local control API (CSRF). The bundled UI and the CLI
// send it.
const ClientHeader = "X-Indago-Client"

// guard applies the request protections that matter for a local control plane
// that can start scans:
//
//  1. CSRF: state-changing methods require ClientHeader, and an Origin header,
//     if present, must name this server's own host.
//  2. DNS rebinding: when allowedHosts is set, the Host header must be one of
//     them (an attacker's domain rebound to 127.0.0.1 arrives with the attacker's
//     Host and is refused). It is set when the server binds a specific address.
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.allowedHosts != nil && !s.allowedHosts[strings.ToLower(hostOnly(r.Host))] {
			writeError(w, http.StatusForbidden, "host not allowed")
			return
		}
		if isMutating(r.Method) {
			if r.Header.Get(ClientHeader) == "" {
				writeError(w, http.StatusForbidden, "missing "+ClientHeader+" header")
				return
			}
			if origin := r.Header.Get("Origin"); origin != "" {
				u, err := url.Parse(origin)
				if err != nil || !strings.EqualFold(u.Host, r.Host) {
					writeError(w, http.StatusForbidden, "cross-origin request refused")
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

func isMutating(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	default:
		return true
	}
}

// hostOnly strips the port from a Host header value.
func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return strings.Trim(hostport, "[]")
}

// hostsForListenAddr returns the Host values a server bound to addr should
// accept: the loopback names plus the host it is bound to. It returns nil (no
// restriction) for wildcard binds, where the valid hostnames are unknowable; the
// CSRF guard still applies there.
func hostsForListenAddr(addr string) map[string]bool {
	host := hostOnly(addr)
	switch host {
	case "", "0.0.0.0", "::":
		return nil
	}
	hosts := map[string]bool{"localhost": true, "127.0.0.1": true, "::1": true}
	hosts[strings.ToLower(host)] = true
	return hosts
}
