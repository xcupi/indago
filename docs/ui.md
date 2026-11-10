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
  server embeds. The SPA is served at **`/`** (the root); its relative asset URLs
  are mapped from `/assets/` to the embedded `next/assets/` tree. `/next/`
  remains an alias. The old dashboard stays at `/legacy/` only for the legacy
  integration tests.
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
| `GET /api/scans/{id}` (polled) | Scan header + Overview tab (state and stats are read from the scan object; `/status` and `/stats` are not called) |
| `POST /api/scans/{id}/{start,pause,resume,cancel}` | Scan header actions |
| `POST /api/scans/{id}/config` | "Tune" dialog (concurrency, rate) |
| `PUT /api/scans/{id}/capabilities` | "Capabilities" dialog on a draft scan (attack engine selection) |
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

## Backend coverage (verified by diffing routes and request fields)

Every `mux` route that backs an operator screen has a caller in `web/src`.
The gaps this section used to list are closed, each verified against the live
server rather than by reading code:

| Capability | Where it lives | Verification |
| --- | --- | --- |
| Interactive login (`POST /api/auth/login`) | Project → Auth sessions → "Login now"; targets inherit the profile, and scans read it from the target | endpoint returns 400 with the scope message for an out-of-scope URL and for a missing project (request shape accepted) |
| Model discovery (`POST /api/llm/models`) | Settings → AI Gateway → "Discover", or pick ChatGPT/Claude to load versions automatically; AI advisory has a per-call Model picker | ChatGPT returns its OAuth model list and Claude returns its OAuth model list; provider errors are shown in the note instead of throwing |
| Finding PoC (`GET .../findings/{fid}/poc`) | Finding detail dialog → "download PoC" | `200`, `Content-Disposition: attachment`, 2.1 KB artifact |
| Selective report (`finding_ids`) | Reports tab → mode "selected findings" + checkbox list | report generated from the UI contains exactly the one selected finding |
| AI summary (`ai_summary`) | Reports tab → "AI summary" switch | sent in the create body alongside `format`/`mode` |
| `proxy_pool`, `stop{mode,confirmed_limit}`, `max_candidates`, `login_*_selector` | Scan create form | intercepted create payload carries all of them with the entered values |
| Concurrency at create (`config`) | Scan create form (four fields, 0 = profile) | the same payload carries `config.{discovery,http,browser}_concurrency` and `requests_per_second` |

Backend-only options that the legacy UI also never exposed (CLI-only by
design, not gaps): `idor_candidates`, `idor_enumerate(_n)`,
`enable_role_param`, `enable_access_control_pages`, `enable_role_write`,
`enable_admin_step_probe`, `enable_object_family_probe`, `enable_xss_library`,
`randomize_tls_fingerprint`.

Operational endpoints with no screen by design: `GET /healthz`, `GET /metrics`
(Prometheus scrape, not an operator screen).

## UX pass (2026-11)

- Scope is manual-first: every project has an editable scope (hosts, path
  prefixes, subdomains) on its page. Importing a platform program fills the
  same fields; it is a shortcut, not a requirement.
- Scan dialog shows the selected project's scope and warns when the target host
  falls outside it, with a link to edit the scope.
- Bug bounty: explicit Load, ten-minute cache, pagination (Previous/Next with
  `page`/`total`/`has_more`), scope+rules preview per program without a
  credential, connected-state badge with Replace credential, duplicate imports
  skipped, path-scoped assets honoured.
- Destructive actions: delete scan (cascades findings, evidence rows and blobs,
  reports and files, AI tasks, test cases, jobs, injection points, parameters,
  endpoints), delete target, delete project (only when no scans remain), edit
  target. Running scans refuse deletion.
- Mobile: tables scroll inside their card, filter selects no longer force the
  page wider than the viewport; the sidebar collapses below `md`.

## Report and AI polish

- AI advisory is its own scan tab (`AI advisory`) instead of a panel stacked
  under Overview; the panel, provider picker and token usage are unchanged.
- Reports rows now offer `preview` and `download`. PDF and HTML preview inline
  in a dialog iframe; Markdown and JSON are fetched and shown as source. The
  download link keeps `?download`, so the file is still saved with its
  filename.

## Settings layout

Settings is grouped into three collapsible sections, not one long card wall:

- **Providers** — the default AI gateway form plus a scrollable list of every
  provider, with a `ready/total` count and a per-provider test button. The list
  is height-capped so ten providers do not push the form off screen.
- **Sessions** — Claude OAuth and ChatGPT OAuth side by side, with connection
  state, expiry, and connect/disconnect actions.
- **Workspace** — the browser control-plane token and the running server build;
  closed by default because it is rarely changed.

Providers and Sessions default open; each section can be collapsed
independently. The header badge summarises state without expanding the section.
