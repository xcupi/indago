# Wordlist recon: content and parameter discovery

Status: implemented in `internal/discovery` (`recon.go`, `soft404.go`,
`wordlists.go`, `wordlists/*.txt`). Opt-in per scan, off by default.

Before this, `contentSource` iterated an empty list and `applyParamWordlist`
looped over nil: nothing in the repository ever populated `Config.Wordlist` or
`Config.ParamWordlist`, so a scan only ever found what the seed happened to
link to. `/admin`, `/api/v1/users`, `?debug=1`, `/swagger.json`, `/.git/HEAD`
were never probed — invisible on lab targets that link their own injection
point, decisive on real ones.

## Levels

`-recon-level off|safe|standard|aggressive` (`POST /api/scans` field
`recon_level`, stored in `domain.ScanConfig.ReconLevel`). The default is
**off**, so every existing scan and client is unchanged: with no level and no
explicitly supplied wordlist the content source returns immediately, before any
request.

| Level | Paths | Extensions | Param mining | Recursion |
|---|---|---|---|---|
| `off` | — | — | — | — |
| `safe` | core list (162) | no | no | no |
| `standard` | core list (162) | yes (8 suffixes, ≤5 bases) | yes | no |
| `aggressive` | core + extended (252) | yes | yes | one level, depth ≤ 2 |

An explicitly supplied `Config.Wordlist`/`Config.ParamWordlist` (programmatic
use, tests) is still honoured at `off`, exactly as before. At `standard` and
above an explicit `ParamWordlist` is merged into the mined name list rather than
registered blindly.

## Embedded lists

`//go:embed` from `internal/discovery/wordlists/` — no network access and no
external files at runtime.

| File | Entries | Used by |
|---|---|---|
| `paths.txt` | 162 | safe, standard, aggressive |
| `paths_extended.txt` | 90 | aggressive only (adds to the 162) |
| `params.txt` | 200 | standard, aggressive |
| `extensions.txt` | 8 | standard, aggressive |

The union of the two path files is 252 entries (band: 150–300). Each file
carries a provenance header: hand-curated for this project from publicly
documented conventions (framework defaults, RFC 8615 well-known URIs, common
deployment artefact names). No scraped data, no vendor corpus.

Selection rule: an entry earns its place only if finding it is actionable on an
authorized engagement — an exposed admin surface, an API root, config/backup
material, developer tooling, or a status/metrics endpoint.

## Hard request cap

`DefaultMaxReconRequests = 600` per scan, covering **every** request this source
sends: calibration, path probes, extension probes, parameter baselines and
probes, recursion. The budget is claimed *before* each request
(`reconBudget.take()`), so a level whose nominal cost exceeds the cap simply
stops probing instead of overshooting. Requests are also paced and
scope-checked by the scan's `scopedEngine`, exactly like crawl traffic.

Arithmetic for one seed origin (worst case):

| Phase | Requests |
|---|---|
| soft-404 calibration | 3 |
| safe path probes | 162 |
| **safe total** | **165** |
| extension probes (5 bases × 8) | 40 |
| parameter mining (4 endpoints × (2 baselines + 25 probes)) | 108 |
| **standard total** | **313** |
| aggressive path probes | 252 |
| recursion (2 directories × 25 words; sub-cap 60) | 50 |
| **aggressive total** | **453** |

600 > 453, so one origin at the highest level fits entirely. With several seed
origins the phases repeat per origin and the cap — not the level — becomes the
binding constraint. The cap is a constant, not a config knob: it must not be
tunable into something that hammers a target.

## Soft-404 calibration (mandatory)

Before probing an origin, three deterministic but certainly-absent paths
(`/indago-<10 hex>`, derived from `sha256(origin|index)` so the sequence is
reproducible from evidence) are requested and their signatures recorded:
status, body length, SHA-256 of the body, content type.

A probe is recorded only if it "exists" (2xx, 3xx, 401, 403) **and** the
calibration cannot explain it:

1. 404/400/5xx is never an endpoint;
2. same status + same body hash as a sample → the wildcard page → not an
   endpoint;
3. same status + body length within tolerance (2% of the baseline, floor 64
   bytes) → treated as the same page (wildcard pages often echo the requested
   path; the fixed-length random tokens keep that echo the same size);
4. anything else — a different status, or a materially different body — is
   recorded.

If calibration fails (network error), the origin is skipped entirely: without a
baseline there is no honest way to distinguish a real path from a wildcard, and
probing blind would flood the scan with false endpoints. Test:
`TestReconWildcardSiteRecordsNoEndpoints` (fixed-body and echoed-path variants)
asserts zero endpoints against a fixture that returns 200 for every path.

## Parameter mining (real signal only)

A name is recorded only when a request carrying it changes the response in a way
the probe's own text cannot explain:

- the page is baselined **twice**; if the two responses differ (CSRF token,
  live counter, rotating nonce) the endpoint is skipped, because every probe
  would look like a change;
- the baseline must be 2xx, otherwise there is nothing meaningful to compare;
- the probe value is a unique alphanumeric marker (`indago` + 10 hex);
- a change is: different status, different/new `Set-Cookie`, a different
  application header (volatile headers such as `Date`, `ETag`, `Server`,
  `X-Request-Id` are ignored), or a body-length delta greater than 32 bytes
  **after** stripping the echoed `name=marker`, `?name=marker`,
  `&name=marker` and bare marker text.

Targets: the seed URL first, then wordlist-discovered HTML endpoints, capped at
4 per scan, deterministic order. The 200-name list is rotated per endpoint
(25 names each) so several endpoints cover different slices instead of repeating
the same prefix. Test: `TestReconParamMiningRecordsOnlyChangedName` — a fixture
where `?debug` changes the body and `?nope` does not yields exactly `debug`;
`TestReconParamMiningSkipsUnstableBaseline` yields nothing on a page whose body
changes every request.

## Recursion (aggressive only)

A discovered directory — its path ends in `/`, or it redirects to one — is
probed one level deeper with the first 25 core list words. The discovered
directory is depth 1, its children are depth 2; the source never goes to depth
3. Bounds: 2 directories, 25 words each, sub-cap 60 requests, plus the shared
budget.

## Scope, methods, provenance

- Every request goes through the scan's scope-enforcing engine: same rate
  limiter, same host-only scope, fail-closed redirects. `GET` only — no HEAD, no
  body-carrying method, no state-changing request.
- Out-of-scope probe results are never recorded: `TestReconDoesNotFollowOrRecordOutOfScopeRedirect`
  (with an in-scope redirect as positive control).
- `EndpointCandidate.Provenance` / `ParamCandidate.Provenance`
  (`ReconProvenance{List, Level}`) carries which list produced a guess. The
  collector logs it per endpoint and tallies it per run
  (`RunResult.Recon`, keyed `list/level`), and the scan's "discovery complete"
  log line prints the tally. Persisted `Endpoint.Source` remains
  `content_discovery` (guessed) vs `crawler`/`sitemap`/`robots` (linked), which
  is what report provenance already distinguishes. A per-endpoint persisted
  `list`/`level` column would need a domain/store migration and is out of this
  slice.

## Commands

```bash
# off (default): no wordlist requests at all
indago scan create -project P -target T -name baseline

# safe: core path list only
indago scan create -project P -target T -name safe -recon-level safe

# standard: paths + parameters + extensions
indago scan create -project P -target T -name standard -recon-level standard

# aggressive: extended paths + one level of directory recursion
indago scan create -project P -target T -name aggressive -recon-level aggressive
```

Then `indago scan start <id>`. The level is chosen at creation (like the crawl
controls) and read when discovery starts.

## Limitations (honest)

- Parameter mining is capped at 4 endpoints × 25 names: a large application will
  see a sample, not exhaustive coverage. That is deliberate; the alternative is
  hundreds of requests per endpoint.
- Extension probes apply to file-like paths the wordlist itself found (plus a
  file-like seed path). Paths discovered by the crawler are not extended in this
  slice — the sources run concurrently and the crawler's results are not handed
  to this source.
- Soft-404 detection is statistical: a site whose wildcard page varies by more
  than 2%/64 bytes between requests can still produce false endpoints. Such a
  site also tends to vary per path, where no calibration can help.
- Recursion is one level by design. Content inside `admin/` is probed; content
  inside `admin/user/` is not.
