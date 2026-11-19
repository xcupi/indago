package main

// The control API token can be supplied as a flag as well as through the
// INDAGO_API_TOKEN environment variable. The environment variable is the safer
// default (a flag value is visible in shell history and in `ps`), so the flag
// exists for convenience and for wrappers that already inject arguments — not
// as the recommended path. The flag wins when both are present.

import (
	"errors"
	"flag"
	"fmt"
	"strconv"
	"strings"

	"github.com/indago/indago/internal/web"
)

// apiTokenFlagName is the flag's spelling, used in messages and as the log
// source label.
const apiTokenFlagName = "-api-token"

// apiTokenFlagState is the target of a -api-token flag. It records whether the
// operator actually passed the flag, so an unset flag never overrides
// $INDAGO_API_TOKEN, and an explicitly empty value is refused instead of
// silently disabling authentication.
//
// String never returns the token: flag.PrintDefaults calls it, so a configured
// token would otherwise appear in `indago serve -h` or `indago scan create -h`
// output and in anything that captures usage text.
type apiTokenFlagState struct {
	value string
	set   bool
}

func (t *apiTokenFlagState) String() string { return "" }

func (t *apiTokenFlagState) Set(v string) error {
	if strings.TrimSpace(v) == "" {
		return errors.New(apiTokenFlagName + " must not be empty: set a random token, or omit the flag to use $" + apiTokenEnv + "/no token")
	}
	t.value, t.set = v, true
	return nil
}

// register adds the -api-token flag to fs.
func (t *apiTokenFlagState) register(fs *flag.FlagSet, usage string) {
	fs.Var(t, "api-token", usage)
}

// apiTokenServeUsage is the -api-token description shown by `indago serve -h`.
// It deliberately contains no backticks: flag.UnquoteUsage treats the first
// backquoted word as the flag's value NAME, so "`ps`" turned the help line into
// "-api-token ps".
func apiTokenServeUsage() string {
	return "control API token (overrides $" + apiTokenEnv + "); at least " +
		strconv.Itoa(web.MinAPITokenLen) + " characters. Prefer the environment variable: a flag is visible in shell history and ps"
}

// resolveAPIToken picks the server's control API token: the -api-token flag
// wins over $INDAGO_API_TOKEN when both are set. It returns the token plus a
// source label for the startup log; neither the returned error nor the log
// line ever contains the token.
func resolveAPIToken(flagVal apiTokenFlagState, envVal string) (token, source string, err error) {
	switch {
	case flagVal.set:
		token, source = flagVal.value, apiTokenFlagName
	case envVal != "":
		token, source = envVal, apiTokenEnv
	default:
		return "", "", nil
	}
	if err := web.ValidateAPIToken(token); err != nil {
		return "", "", fmt.Errorf("%s: %w", source, err)
	}
	return token, source, nil
}
