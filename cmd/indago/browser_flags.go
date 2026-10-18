package main

import (
	"errors"

	"github.com/indago/indago/internal/browser"
)

// browserConfigFromFlags builds the browser configuration for `serve`.
//
// Chromium's process sandbox stays ON unless the operator passes
// -browser-no-sandbox. That opt-out is refused without -browser so it can never
// look accepted while doing nothing.
func browserConfigFromFlags(useBrowser, noSandbox bool, chromium string) (browser.Config, error) {
	if noSandbox && !useBrowser {
		return browser.Config{}, errors.New("-browser-no-sandbox only applies together with -browser")
	}
	return browser.Config{Headless: true, ExecutablePath: chromium, DisableSandbox: noSandbox}, nil
}
