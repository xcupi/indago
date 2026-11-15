package main

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/indago/indago/internal/oast"
)

// oastConfigFromFlags turns `indago serve`'s OAST flags into an oast.Config in
// local listener mode. requested is false when no collaborator was asked for —
// the default — in which case nothing is started and scan behaviour is
// unchanged.
//
// The public URL is optional and only meaningful together with a listener: it
// is the address a TARGET can reach (a tunnel or reverse proxy in front of
// -oast-addr), so a target on another host can call back at all. Without it the
// base URL is the listener's own address, which only a target on this host can
// reach — enough for a local test corpus, not for a remote scan.
func oastConfigFromFlags(addr, publicURL string, allowExternalBind bool) (oast.Config, bool, error) {
	addr = strings.TrimSpace(addr)
	publicURL = strings.TrimSpace(publicURL)
	if addr == "" {
		if publicURL != "" {
			return oast.Config{}, false, errors.New("-oast-public-url requires -oast-addr: there is no listener to publish")
		}
		return oast.Config{}, false, nil
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return oast.Config{}, false, fmt.Errorf("-oast-addr %q must be host:port: %w", addr, err)
	}
	return oast.Config{
		Mode:              oast.ModeLocal,
		ListenAddr:        addr,
		PublicBaseURL:     publicURL,
		AllowExternalBind: allowExternalBind,
	}, true, nil
}
