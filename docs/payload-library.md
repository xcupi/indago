# XSS payload library

Indago's cheat-sheet library carries **137 families**: 24 hand-declared ones for
contexts the planner needed (attribute breakouts, JS-string breakouts, URL
schemes, comment breakout) and 113 generated from every event-handler family the
sheet documents, one representative vector each. It is derived from
PortSwigger's XSS cheat sheet
(https://portswigger.net/web-security/cross-site-scripting/cheat-sheet, 2026
edition). It is a top-up for the canonical planner, not a second scanner: the
same planner decides what is planned, the same profile caps what is sent, and
only a browser execution signal confirms a finding.

Every payload carries the scan's benign marker as a bare identifier. When the
handler runs, the browser resolves the identifier, throws `ReferenceError`, and
the verifier sees the signal. There is no `alert()`, no network callback and no
cookie access.

## Enabling it

- UI: New scan → **XSS payload library (PortSwigger families)**.
- API: `"enable_xss_library": true` on scan creation.
- Off by default: every family costs requests, and only the operator can decide
  a target needs the wider net.

`GET /api/payload-library` lists the families (`id`, `contexts`, `trigger`,
`needs`, example with `{{marker}}`, rationale) — currently 137.

How the generated table was built (`library_cheatsheet.json`): one entry per
event-handler family from the sheet's two event sections, the sheet's own
example vector, dialog calls replaced by the marker, and the entries that need
external assets or network callbacks dropped (a `validvideo.mp4` that never
loads would never fire its load event). Obfuscation and encoding sections are
deliberately excluded: those are evasion variants and belong to the separately
gated evasion pack.

## How requests are chosen (not one by one)

Sending all 700+ sheet vectors at every parameter would be noisy and pointless.
Four gates decide what is actually sent, in order:

1. **Context gate.** Each family declares the reflection contexts it can land
   in (`html_text`, `html_attr_value`, `js_string`, `js_code`, `url`,
   `html_comment`). A vector is never sent to a site where it cannot parse —
   `<video><source onerror=…>` is not sent into a JavaScript string.
2. **Character gate (the "certain responses rule this out" rule).** Each family
   declares the metacharacters it cannot work without (`needs`). The planner
   already records, per site, which characters come back raw versus encoded or
   stripped. If the site provably encodes `<`, every family that needs `<` is
   dropped **before** a request is spent. This is why a target that HTML-encodes
   the reflection does not get 22 rejected payloads: it gets only the families
   that do not need angle brackets (attribute breakouts, JS string breakouts,
   URL schemes).
3. **Trigger gate.** Load-triggering families (an element that fires by itself:
   `video/source onerror`, `object onerror`, `iframe srcdoc`, `svg onload`)
   outrank interaction families (`javascript:` links, form actions, `onmouseover`
   breakouts), because the verifier needs no click to prove them.
4. **Budget gate.** The candidate profile caps how many candidates a single
   injection point may send (`minimal` 3, `standard` 8, `thorough` more), a hard
   library cap allows at most 12 library candidates per injection point
   (`MaxLibraryCandidatesPerInjectionPoint`, recorded as `library_capped`), and
   the library sits *below* every canonical candidate in priority. A capped
   profile therefore spends its budget on the canonical shapes first and only
   reaches the library when the profile allows it. Families left unsent are
   counted (`dropped`) rather than silently forgotten.

## Failure signals → what happens next

| Observed at the site | Meaning | Action |
| --- | --- | --- |
| Value not reflected | The parameter does not reach the page | No payload is sent; the whole injection point is dropped |
| Reflected with `<` → `&lt;` | Angle brackets encoded | Families needing `<` dropped; only attribute/JS/URL families remain |
| Reflected with quotes → `&quot;` | Quotes encoded | Quote-breakout families dropped; unquoted attribute family remains |
| Tag present but event attribute stripped | Naive tag/attribute filter | Families with a different tag/attribute shape remain |
| Status 403/406/429 or a challenge page | Edge/WAF block | Scan notes a suspected block; the evasion pack (separate opt-in) is the right tool, not more library families |
| `Content-Security-Policy` forbids inline script | Inline handlers cannot run | Event-style families cannot execute; the CSP-specific planning paths decide (Angular CSP bypass, dangling markup, report-uri injection) |
| Handler ran but the node was detached (`connected:false`) | Sink parsed the markup into a fragment that never entered the document | Choose families that fire during parsing/attachment: `ontoggle`, autofocus `onfocus`, SMIL `onbegin` — this is the case the AI diagnosis explains in detail |

When every eligible family has been tried and nothing fired, that is the point
to ask the model (Payload doctor) — not before. The diagnosis reads the stored
evidence, explains the failure, and returns new candidates that are filtered
against everything already sent.

## Adding a family

Add an entry to `internal/detection/library.go` only if the canonical planner
does **not** already carry that shape; a duplicate spends a request on a payload
the scanner already sent. Declare the contexts honestly, declare every character
the vector needs, choose the cheapest trigger that works, and keep the marker as
the only executable token.

## Coverage audit (why the sheet is not copied 1:1)

The sheet documents 141 event families; 113 are carried here. The remaining 28
are excluded on purpose, and the reason is mechanical, not editorial:

| Group | Count | Why it cannot become a detection probe here |
| --- | --- | --- |
| Media success events (`oncanplay`, `onloadedmetadata`, `onplay`, `ontimeupdate`, …) | 21 | The sheet fires them with `validvideo.mp4`/`validaudio.wav`. A missing file only fires *error* events, and headless Chromium in this environment has no media codecs, so a `data:` clip does not reach `readyState` either (verified). A family that can never fire is a wasted request, not coverage. |
| Navigation/unload events (`onbeforeunload`, `onunload`, `onpagehide`, `onpageswap`) | 4 | They need a navigation the verifier does not perform; the sheet's own proof uses `sendBeacon`, which is exactly the callback this scanner refuses to send. |
| `onbeforeprint`, `onunhandledrejection` | 2 | Need a print dialog or an extra script that itself executes. |
| `onanimationcancel` | 1 | The sheet's vector needs a `:target` match, i.e. navigating to `#x`. |

Other sections: **consuming tags** contributed two new families
(`noembed`/`noframes` breakouts); `xmp`/`plaintext`/`title` consume markup
without executing anything, and `select`/`textarea`/`style`/`script`/`iframe`
are already carried. **Protocols**: `javascript:` is carried; `data:` executes
in a new document the verifier does not inspect. **Other useful attributes**:
`href`, `formaction`, `action`, `srcdoc` are already carried. **Special tags**
(`meta` refresh to `javascript:`) is legacy and blocked by modern browsers.
**Restricted characters**, **encoding** and **obfuscation** are bypass
techniques and belong to the evasion pack, not to a detection library.
