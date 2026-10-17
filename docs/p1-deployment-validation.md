# P1 deployment validation

Validation on Linux/amd64, 2026-10-17. Only disposable scratch data is used;
repository `data/` is never used. No releases, host services, settings changes,
main-branch changes or PR creation are part of this work.

## CI

- Contract-first RED: `go test ./deploy -run TestCIContract -v` failed because
  `.github/workflows/ci.yml` did not exist. Same test GREEN after implementation.
- Action commit IDs were resolved with `git ls-remote` from the actual upstream
  repositories: checkout v5.1.0, setup-go v6.5.0, setup-node v6.5.0 and
  upload-artifact v4.6.2. No guessed SHAs.
- Scratch-only `go install github.com/rhysd/actionlint/cmd/actionlint@v1.7.7`;
  `actionlint .github/workflows/ci.yml` exit 0 (no diagnostics).
- Actual local runtime: Go 1.26.8, Node v26.7.0, Google Chrome 155.0.8059.39.
  Workflow requests Go from go.mod, Node 24 and runner system Chrome.
- Documented driver command, with `PLAYWRIGHT_NODEJS_PATH` pointing at installed
  Node: `go run github.com/mxschmitt/playwright-go/cmd/playwright@v0.6201.1 --version`
  printed `Version 1.62.1`.
- `go mod verify`: `all modules verified`.
- `INDAGO_CHROMIUM_PATH=/usr/bin/google-chrome python3 scripts/ci-browser-check.py`:
  **all 6 required tests passed, no skips**. Includes real rendering, positive
  verification, benign rejected control, full corpus, UI navigation and Node's
  controlled-clock tests (20 passed). Missing executable/Node or a skipped or
  missing required test is an explicit error, independent of developer skips.
- `go clean -testcache` then `INDAGO_CHROMIUM_PATH=/usr/bin/google-chrome make check`:
  exit 0; gofmt clean, vet clean, every package passed under `-race -p 1`.
  Scan package 62.873s, web 33.695s, verification 10.276s (not cached).
- `make build`: exit 0; binary built with Makefile version/commit/date metadata.

GitHub execution is **not yet verified** in this checkpoint. A local pass is
not a GitHub Actions pass. A subsequent section records remote availability.

## Docker

Pending the separate Docker deliverable.

## systemd

Pending the separate systemd deliverable.
