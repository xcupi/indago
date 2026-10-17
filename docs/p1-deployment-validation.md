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

- RED: `go test ./deploy -run TestDockerContract -v` failed on missing
  `Dockerfile`; GREEN after Dockerfile/ignore/strict healthcheck were added.
- Actual `docker build --platform linux/amd64 --build-arg VERSION=p1-deployment
  --build-arg COMMIT=949bf7f --build-arg BUILD_DATE=2026-10-17T09:07:17Z
  -t indago:p1-deployment .` exit 0; module verification passed and driver printed
  `Version 1.62.1`. Tag is retained for operator use, not published to a registry.
- Image ID:
  `sha256:f60a258ef43821280986d3cfc2f4b2964999b46c43a5e8d982f281a31d5c9205`.
  `docker image inspect`: user `10001:10001`, architecture `amd64`.
  `docker exec ... id -u`: **10001**.
- Real runtime used read-only rootfs, cap-drop ALL, no-new-privileges, 2 GiB
  memory, 256 MiB shm, writable tmpfs `/tmp` and `/var/cache/indago`, a disposable
  owned named data volume and scratch-only TLS bind mount. No socket/privileged
  flags. Distro Chromium: **155.0.8059.79, Debian 12**.
- Generated a one-day EC self-signed SAN certificate and random 64-character
  environment token, never printed. Strict `curl --cacert` returned healthz 200,
  projects 401 without bearer / 200 with bearer (bearer in 0600 curl config,
  not argv). UI `/` and actual static asset `/app.js` returned 200. `/metrics`
  returned 401 without / 200 with bearer. Docker health reached **healthy**.
- Default startup with mounted TLS but no token exited **1**, explicitly refusing
  remote bind without token. With token but missing TLS exited **1**, certificate
  load failure; neither silently downgraded.
- Real host CLI created project `e4c29175-dfd9-49a4-ad38-3119be3f2bc4` over strict
  HTTPS. API set scope to container-local `127.0.0.1`, paths `/vulnerable` and
  `/safe`, and created targets/scans. A temporary Node lab listened only on
  container loopback `:8989`; it is not an external target.
- Positive scan `9d76f167-7f0b-4206-bc42-bcaa49f1800b` completed with **1 confirmed**.
  Screenshot/DOM/browser-log metadata existed; fetched actual browser-log bytes
  included `playwright: ind64f6c46855fff00b is not defined`. Thus browser replay
  genuinely ran, not merely accepted a `-browser` flag. An out-of-scope invalid
  image resource was blocked by the existing scope gate.
- Escaped benign control scan `74991f40-6992-4d93-9ace-46837b0e0215` completed with
  **1 rejected, 0 confirmed**. No false vulnerability confirmation.
- `docker stop -t 60` exited **0**, no OOM/forced kill; restart preserved the
  prior project via authenticated GET; final SIGTERM stop also exited **0**.
  Logs were checked for the exact disposable API token and private-key/session
  indicators: absent. Scans here were anonymous (no real session used).
- Harness corrections, not product fixes: static assets live at `/app.js`, not
  `/assets/app.js`; Docker's ephemeral host port must be re-read after restart.
  Every failed harness run cleaned its own resources before retrying.
- Own named containers, data volumes, loopback lab, token/curl config, TLS
  certificate/key and dummy database/evidence tree removed. Published port
  verified closed. Safe result JSON and harness retained only in scratch.

`INDAGO_CHROMIUM_PATH=/usr/bin/google-chrome make check` passed again after the
Docker additions: gofmt clean, vet clean, all race-test packages passed
(existing packages cached, deployment contract rerun in 1.012s). Only native
Linux/amd64 is verified; other platforms, a Chromium sandbox and
digest-reproducible apt builds are not.

## systemd

Pending the separate systemd deliverable.
