# Changelog

All notable changes to Indago are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases use
[Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-11-10

First public pre-release of the local-first hunting platform.

### Added

- Scope-enforced HTTP and browser discovery with a persistent job queue.
- Reflected XSS detection and browser-confirmed verification with a bounded
  benign-marker bypass fallback.
- DOM XSS source/sink modelling for `location.*`, `document.referrer`,
  `window.name`, `postMessage` and `JSON.parse` taint; HTML, navigation,
  element `src`, cookie and string-timer sinks.
- DOM clobbering detection and confirmation.
- Access-control differential testing, IDOR enumeration, information
  disclosure, and server/client-side open redirect detection.
- Evidence capture, per-finding provenance, standalone PoC artifacts, and
  JSON/Markdown/HTML/PDF reports with technical, pentest, bug-bounty and
  YesWeHack templates.
- YesWeHack program search, public scope/rules import, and submission template.
- Optional nine-provider AI advisory with token accounting, Claude OAuth,
  ChatGPT OAuth, and collapsible Settings sections.
- React/Vite SPA with project scope editor, project-level scan login, scan
  detail tabs, findings explorer, and report preview.
- Docker image, CI quality gate, Chromium sandbox check, and deployment docs.

### Known limits

- Stored XSS, cookie theft and CSRF exploit chains are out of scope.
- Seven XSS/exploit-chain entries in the 55-lab PortSwigger catalogue remain
  gaps; see `docs/feature-review.md`.
- Bug-bounty submission is prepared, not posted automatically.
