# Local Playwright runtime patch

Source: `github.com/mxschmitt/playwright-go v0.6201.1` (unchanged driver
version 1.62.1). `UPSTREAM-SHA256.json` records every copied upstream file.
Only runtime sources, module metadata and the upstream MIT license are copied;
upstream examples, tools and tests are not included. The upstream CLI can still
install the **same** pinned driver. This is a local module replacement, not a
claim of an upstream release/fix.

## Why this copy exists

Rejecting a popup's first request via `BrowserContext.Route` exercises an
upstream data race: `newPage` writes `frame.page` while `Request.Frame` and
`Request.safePage` (also used internally by `Route.Abort`) read it. The early
request is legitimately observable before its page exists. Application-side
nil handling alone does not cure `Abort`'s internal race. Waiting for a page
event risks a cycle: the popup cannot finish creation until its paused request
is resolved. Sleeping, suppressing the race detector, or editing a module cache
is not an acceptable fix.

## Narrow patch

- `request.go`: synchronize early `Frame` and internal `safePage` reads using
  the frame's existing mutex; keep nil-before-publication behavior.
- `frame.go`: synchronize the public `Page` accessor.
- `page.go`: publish the fully initialized page under that mutex at the end
  of `newPage`; synchronize child-frame owner publication too. No lock spans
  protocol I/O. No routing, sandbox, navigation or driver behavior is changed.

Real popup scope tests reproduce the original race and exercise this patch
under `-race`. Keep this copy until an upstream pinned release supplies an
equivalent fix. Compare the manifest when updating; do not silently replace it
with the unpatched module. Nested-module tests need an explicit command (the
root's `go test ./...` does not traverse this module).
