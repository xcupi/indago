# UI — audit and the new control-plane dashboard

## What existed

`internal/web/assets/` shipped a hand-written vanilla-JS hash SPA (app.js, scans.js,
views.js, app.css — ~3.1k lines) embedded into the Go binary. It covers the core
flows (projects, targets, scope, scans, findings, evidence, reports, settings) but
has three problems:

1. **Backend gaps.** Three endpoints had no surface: `GET /api/scans/{id}/stats`
   (the numbers were duplicated from the scan object), `GET /api/scans/{id}/idor/candidates`,
   and the richer `GET /api/scans/{id}/explorer` (gap flags, DOM sinks, parameter
   provenance) was only used as a plain endpoint list. `POST /api/auth/login`
   (interactive login) was also unreachable from the UI; auth was configured at
   scan creation only.
2. **No build step or types.** Every field name is a string in 3k lines of
   DOM-building code; the API shape is nowhere checked.
3. **No design system.** Tables, dialogs and buttons were bespoke CSS with
   inconsistent focus/hover states and no dark-mode tokens.

## What was built

`web/` is a Vite + React 19 + TypeScript SPA with Tailwind CSS v4 and shadcn/ui-style
primitives (Radix + cva, vendored as source under `web/src/components/ui/`).

- **Build wiring.** `make ui` builds into `internal/web/assets/next/`, which the Go
  server already serves from the same embedded tree. The SPA is reachable at
  **`/next/`**; the legacy dashboard keeps `/` until the cutover below.
- **Typed API client** (`src/lib/api.ts`): JSON in/out, `X-Indago-Client: ui` on every
  request (the server's CSRF guard), optional bearer token from
  `localStorage["indago.token"]`, one `useApi` hook with refresh events and polling.
- **Routing** (`src/lib/router.tsx`): hash routes, query string separated from the
  path so `#/scans/<id>?tab=findings` resolves the id correctly.

## Coverage matrix

| Backend | New UI |
| --- | --- |
| `GET/POST /api/projects`, `GET /api/projects/{id}` | Projects list, create dialog, project page |
| `GET/POST /api/projects/{id}/targets`, `.../{tid}` | Project page → Targets |
| `GET/PUT /api/projects/{id}/scope` | Project page → Scope editor (hosts, prefixes, subdomains) |
| `GET/POST /api/scans`, `GET /api/scans/{id}` | Scans list + create/start dialog, scan page |
| `GET /api/scans/{id}/status`, `.../stats` | Scan header + Overview tab |
| `POST /api/scans/{id}/{start,pause,resume,cancel}` | Scan header actions |
| `POST /api/scans/{id}/config` | "Tune" dialog (concurrency, rate) |
| `GET /api/scans/{id}/coverage` | Coverage tab (with every fallback skip reason) |
| `GET /api/scans/{id}/explorer` | Explorer tab (search, gap filter, DOM sinks) |
| `GET /api/scans/{id}/endpoints` | Endpoints tab |
| `GET /api/scans/{id}/tests` | Tests tab (class filter) |
| `GET /api/scans/{id}/findings`, `.../findings/{fid}` | Findings tab + detail dialog |
| `GET /api/scans/{id}/evidence`, `/api/evidence/{id}/content` | Evidence tab with blob links |
| `GET/POST /api/scans/{id}/reports`, `.../preview`, `/api/reports/{id}/content` | Reports tab |
| `GET /api/scans/{id}/idor/candidates` | IDOR tab |
| `GET/PUT/DELETE /api/llm/config`, `POST /api/llm/test` | Settings → AI Gateway |
| `GET /api/capabilities`, `/api/version` | Settings → Server |

Not yet in the new UI: `POST /api/auth/login` (interactive login) — sessions are
still configured at scan creation or supplied as a storage-state path.

## Legacy tests

`internal/web/ui_*_test.go` drives the legacy dashboard by its DOM ids and globals
(`#view`, `#refreshNow`, `prefs`, `defineRoute`). They stay green because the legacy
assets are untouched. The asset contract test now walks every emitted `.js`, so it
covers whichever bundle is embedded.

## Cutover checklist (when the legacy UI is removed)

1. Port the browser tests in `internal/web/ui_integration_test.go`,
   `ui_findings_test.go` and `ui_cooldown_test.go` to the SPA's public DOM
   (headings, tables, tab labels) and to `src/lib/cooldown.ts` for the 429 clock.
2. Build the SPA into `internal/web/assets/` directly (change `vite.config.ts`
   `outDir`), delete `app.js`/`scans.js`/`views.js`/`app.css`.
3. Add the interactive-login modal (`POST /api/auth/login`) and, if wanted, a
   `/api/scans/{id}/stats` card that reads the endpoint instead of the scan object.

## Theming

The SPA is light by default and dark on request. Colours are semantic tokens
defined in `web/src/index.css` (`--background`, `--card`, `--muted`,
`--border`, `--accent`, …) and exposed to Tailwind through `@theme inline`;
components use `bg-background` / `text-muted-foreground` / `border-border`
rather than palette steps, so one class renders correctly in both themes.
Dark mode is an explicit class (`@custom-variant dark (&:where(.dark, .dark *))`),
not `prefers-color-scheme`, because the operator picks it.

- The header has a sun/moon toggle. It flips `.dark` on `<html>` and stores the
  choice in `localStorage["indago.theme"]`.
- `web/index.html` applies the stored choice in an inline script before the
  first paint, so a reload never flashes the wrong background.
- Accent utilities that need a different step per theme use the `dark:` variant
  (e.g. `text-emerald-600 dark:text-emerald-400`); neutral surfaces never do.
- New components must use the semantic tokens. A raw `zinc-*`/`emerald-*`
  surface in a component is a theming bug, not a style preference.
