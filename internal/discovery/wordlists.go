package discovery

import (
	_ "embed"
	"fmt"
	"strings"
	"sync"
)

// ReconLevel selects which built-in wordlist recon runs. It is opt-in: the
// zero value is ReconOff, so a scan that says nothing behaves exactly as it did
// before recon existed (no wordlist requests at all).
type ReconLevel string

const (
	// ReconOff disables built-in content/parameter discovery. An explicitly
	// supplied Config.Wordlist/ParamWordlist (operator or test data) still
	// runs: that is programmatic intent, not the built-in default.
	ReconOff ReconLevel = "off"
	// ReconSafe probes the core path list only: no parameter mining, no
	// extension probes, no recursion.
	ReconSafe ReconLevel = "safe"
	// ReconStandard adds parameter mining and the extension probes.
	ReconStandard ReconLevel = "standard"
	// ReconAggressive also probes the extended path list and recurses one
	// level into discovered directories.
	ReconAggressive ReconLevel = "aggressive"
)

// ParseReconLevel parses a level name. The empty string means off, so an older
// scan row (no recon_level field) never gains requests it did not ask for.
func ParseReconLevel(s string) (ReconLevel, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", string(ReconOff):
		return ReconOff, nil
	case string(ReconSafe):
		return ReconSafe, nil
	case string(ReconStandard):
		return ReconStandard, nil
	case string(ReconAggressive):
		return ReconAggressive, nil
	default:
		return ReconOff, fmt.Errorf("unknown recon level %q (want off|safe|standard|aggressive)", s)
	}
}

// Level ordering helpers. Every capability is additive: a higher level only
// adds work, it never removes a lower level's probes. The empty (zero) value is
// treated exactly like ReconOff.

func (l ReconLevel) Enabled() bool {
	return l == ReconSafe || l == ReconStandard || l == ReconAggressive
}
func (l ReconLevel) UsesParams() bool     { return l == ReconStandard || l == ReconAggressive }
func (l ReconLevel) UsesExtensions() bool { return l == ReconStandard || l == ReconAggressive }
func (l ReconLevel) UsesRecursion() bool  { return l == ReconAggressive }

// Paths returns the path wordlist for the level: the core list for safe and
// standard, core+extended for aggressive. Off returns nil.
func (l ReconLevel) Paths() []string {
	switch l {
	case ReconSafe, ReconStandard:
		return corePaths()
	case ReconAggressive:
		return append(append([]string(nil), corePaths()...), extendedPaths()...)
	default:
		return nil
	}
}

// Request-cost bounds. They are constants (not config knobs) on purpose: the
// recon budget must not be tunable into something that hammers a target, and a
// fixed ceiling keeps the arithmetic in docs/recon-wordlists.md honest.
const (
	// DefaultMaxReconRequests is the hard per-scan ceiling on HTTP requests
	// made by the recon source (calibration + every probe + every mining
	// request). The budget is claimed BEFORE each request, so a level that
	// would exceed it simply stops probing rather than overshooting.
	DefaultMaxReconRequests = 600

	// calibrationProbes is how many random non-existent paths are requested
	// to fingerprint a wildcard/soft-404 responder (see soft404.go).
	calibrationProbes = 3

	// maxParamMineEndpoints bounds how many endpoints parameter mining may
	// spend requests on per scan.
	maxParamMineEndpoints = 4
	// maxParamProbesPerEndpoint bounds the parameter names tried on one
	// endpoint. The list is 200 names but one request per name per endpoint
	// would be wasteful; endpoints rotate through the list instead (see
	// paramNamesForEndpoint), so the whole list is still covered across the
	// endpoints that are mined.
	maxParamProbesPerEndpoint = 25

	// maxExtensionBases bounds how many discovered file-like paths get the
	// extension probes applied (each base costs len(extensions) requests).
	maxExtensionBases = 5

	// maxRecursiveDirs bounds how many discovered directories are recursed
	// into, maxRecursiveWords how many words are tried under each, and
	// maxRecursionRequests caps the whole recursion phase.
	maxRecursiveDirs     = 2
	maxRecursiveWords    = 25
	maxRecursionRequests = 60
)

// Embedded wordlists. They ship in the binary: recon works with no network
// access and no external files. Provenance comments live at the top of each
// file.
var (
	//go:embed wordlists/paths.txt
	corePathsRaw string
	//go:embed wordlists/paths_extended.txt
	extendedPathsRaw string
	//go:embed wordlists/params.txt
	paramNamesRaw string
	//go:embed wordlists/extensions.txt
	extensionsRaw string
)

var (
	corePathsOnce     sync.Once
	corePathsList     []string
	extendedPathsOnce sync.Once
	extendedPathsList []string
	paramNamesOnce    sync.Once
	paramNamesList    []string
	extensionsOnce    sync.Once
	extensionsList    []string
)

func corePaths() []string {
	corePathsOnce.Do(func() { corePathsList = parseWordlist(corePathsRaw) })
	return corePathsList
}

func extendedPaths() []string {
	extendedPathsOnce.Do(func() { extendedPathsList = parseWordlist(extendedPathsRaw) })
	return extendedPathsList
}

func builtinParamNames() []string {
	paramNamesOnce.Do(func() { paramNamesList = parseWordlist(paramNamesRaw) })
	return paramNamesList
}

func builtinExtensions() []string {
	extensionsOnce.Do(func() { extensionsList = parseWordlist(extensionsRaw) })
	return extensionsList
}

// parseWordlist parses one-entry-per-line text: blank lines and '#' comments are
// ignored, entries are trimmed, and duplicates are dropped in first-seen order
// so the plan is deterministic.
func parseWordlist(raw string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if _, dup := seen[line]; dup {
			continue
		}
		seen[line] = struct{}{}
		out = append(out, line)
	}
	return out
}

// reconBudget is the per-scan request ceiling for recon. take reserves one
// request and reports whether there was budget left; callers must not send a
// request when take returns false.
type reconBudget struct {
	mu   sync.Mutex
	used int
	max  int
}

func newReconBudget(max int) *reconBudget {
	if max <= 0 {
		max = DefaultMaxReconRequests
	}
	return &reconBudget{max: max}
}

func (b *reconBudget) take() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.used >= b.max {
		return false
	}
	b.used++
	return true
}

func (b *reconBudget) usedCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.used
}

// paramNamesForEndpoint rotates the parameter list per endpoint so a scan with
// several mined endpoints covers different slices of the list instead of
// retrying the same first N names everywhere. Deterministic for a given
// endpoint index.
func paramNamesForEndpoint(names []string, endpointIndex int) []string {
	if len(names) == 0 || endpointIndex < 0 {
		return nil
	}
	start := (endpointIndex * maxParamProbesPerEndpoint) % len(names)
	n := maxParamProbesPerEndpoint
	if n > len(names) {
		n = len(names)
	}
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, names[(start+i)%len(names)])
	}
	return out
}
