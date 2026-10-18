# P1 CI layout follow-up

## Failure and cause

Remote run [39021370056](https://github.com/xcupi/indago/actions/runs/39021370056),
HEAD `9bf5943609ecc9f9b202acad24440937a4806dee`, failed the full race gate at
`TestUILayoutFooterStaysAfterTallContentAndLongTextWraps` (420px Findings).
The six runtime preflight tests passed. Both runner and developer Chrome were
155.0.8059.39; Node was 24.21.0 on runner versus 26.7.0 locally. Go was 1.26.0
on runner versus 1.26.8 locally.

The offending report table is **visible**, in the Findings tab's Generate
report card; it is not an obsolete/hidden Reports panel. Its six nowrap
headers have a font-dependent minimum width. On this machine Noto Sans is the
system-ui font, which fits. Changing only the font to installed DejaVu Sans
reproduced the exact remote violations, after waiting for both report list
and preview readiness:

- `a card scrolls horizontally (content wider than the card)`
- `<TH> crosses its card: Open`
- `<TD> crosses its card: No reports yet.`

Measured phone viewport: 420px; card outer width: 388px; usable table area:
350px; old table min-content width: 385.171875px (right edge 420.171875px,
card right edge 404px). Card scroll/client widths were 403/386px.
The runner's actual resolved system font was not logged in the old run;
DejaVu is the deterministic reproduction, not an invented remote font claim.

The original test passed locally 10 consecutive times before the fix with
local default fonts. A font probe tested system-ui, Arial, Liberation Sans,
DejaVu Sans, Noto Sans, Ubuntu and sans-serif; only DejaVu caused the exact
failure. Readiness and hidden-panel explanations were falsified by the
loaded list/preview and nonzero visible table rect.

## Change and regression

Reports now use the existing phone labelled-row layout at <=720px, with all
six values/actions retained and labelled. Desktop remains a six-column table.
No clipping, new overflow hiding, tolerance changes, test skips or assertion
weakening. Findings/evidence layout behavior is unchanged.

`TestUILayoutReportsWrapAtPhoneWidth` failed before the asset change with the
exact three assertions above, then passed. It uses real API-generated report
data and covers empty/populated lists, Findings and explicit Reports tabs,
desktop and 420px, DejaVu Sans, visible desktop headings and all six mobile
labels, readable view/download actions, list/preview readiness, plus the
existing shared footer/overlap/no-overflow checker without changing it.

After the fix the mobile table is 350px and card scroll/client widths are
386/386px. Desktop stays 976px wide without card scrolling. The original
long-finding/evidence regression is retained unchanged.

## Local validation

- Original and new real-Chrome regression: 20 repeated passes each, then
  another 10 repeated passes each after adding label/desktop assertions and
  screenshot controls; every invocation used `-count`, not test caching.
- `node --test internal/web/testdata/ui_cooldown_test.cjs`: 20 pass, zero skips.
- `INDAGO_CHROMIUM_PATH=/usr/bin/google-chrome python3 scripts/ci-browser-check.py`:
  all six required tests passed, no skips; Node controlled-clock 20 pass.
- First uncached full `make check`: web passed (32.044s), but unrelated
  `TestRandomizeTLSFingerprint_RealHandshake` failed with
  `tls: CurvePreferences includes unsupported curve`. No TLS files modified.
  The later [randomized TLS investigation](randomized-tls-validation.md)
  identifies and fixes this hybrid-key-share error and the independent h2
  ALPN mismatch; this line preserves the original failed-run history.
- Second uncached `INDAGO_CHROMIUM_PATH=/usr/bin/google-chrome make check`:
  exit 0, gofmt/vet clean and every package passed under `-race -p 1`.

Safe screenshots and full logs are retained outside the repository under
`$HOME/.hermes/cache/scratch/indago-ci-evidence/`: `red/empty-findings-420px.png`,
`green/populated-reports-420px.png`, `green/populated-reports-desktop.png`,
`red.log`, `font-probe.log`, `repeat-final.log`, `preflight.log`,
`make-check.log` (including the unrelated failure) and `make-check-second.log`.
Screenshots were visually inspected; mobile shows all six labelled fields
and both actions; unobstructed desktop retains normal table headings.

## Remote and image completion

Implementation commit `73c37ac8f55097c945ab08a7aa7355a9fed4e9a7`:
[GitHub run 39022613312](https://github.com/xcupi/indago/actions/runs/39022613312)
completed **success**. Verified with `gh run watch --exit-status`, then an
independent `gh run view --json headSha,conclusion,status,jobs,url` and full log.
Both required-runtime preflight (six passes, no skips) and clean-cache full
`make check` plus `make build` succeeded; web race package took 33.105s.
This supersedes the earlier deployment report's unsuccessful-GitHub limit,
without deleting the historical failed runs.

Rebuilt `indago:p1-deployment` **after** that remote success, using the same
Dockerfile and source revision `73c37ac8f55097c945ab08a7aa7355a9fed4e9a7`:

- Image ID: `sha256:3815b3398c52142eeb39ebd9a2224c6c2b7c270c1087b2e94176fdcfbfcdc584`.
- Image version command confirms that exact source commit; built
  `2026-10-17T09:55:51Z`, linux/amd64, user `10001:10001`; actual `id -u` 10001.
- Read-only rootfs, cap-drop ALL, NNP, own disposable volume and ephemeral
  loopback TLS port. Dummy one-day SAN certificate and random env-only token.
  Strict CA verification: health 200; API/metrics 401 without bearer and 200
  with bearer; container health **healthy**. Missing token/TLS fail closed.
- Real image Chromium 155.0.8059.79 started and replayed container-loopback lab
  scans: positive `3413e545-6491-48ab-ac92-9a826972972a` completed, one Confirmed
  with screenshot/DOM/browser-log metadata and actual unresolved-marker error;
  escaped control `46a0a302-81da-407d-9b8a-25e2286fd276` completed, one Rejected,
  zero Confirmed. This is actual browser execution, not only startup flags.
- Graceful stop/restart preserved the disposable project; both stops exit 0.
  Logs contained no dummy API token, private key or session content.
- Own container/volume/lab and dummy cert/key/token/config/database removed;
  published port verified closed. Independent Docker listings found no own
  remaining containers/volumes and scratch had no remaining fixture dirs.
  Safe build/smoke logs and result JSON are in the evidence directory above.

The tag now contains the corrected embedded assets, replacing the old image
`sha256:f60a258ef43821280986d3cfc2f4b2964999b46c43a5e8d982f281a31d5c9205`.
No registry push or host service installation. This final documentation update
changes no embedded source; the image intentionally identifies the tested code
commit above, not a subsequent docs-only commit. The docs-only push's own
completed CI URL/SHA is verified and supplied in the delivery summary rather
than guessed before its commit exists.
