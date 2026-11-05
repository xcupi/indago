# Access control (function- and object-level authorization)

Indago's access-control capability answers one question per candidate surface:
**can this caller reach a privileged surface, and does that surface expose a
privileged ACTION?** A `200` on an admin-looking path is never a finding on its
own — a soft-routed page, a login page, or a value that only changes page text
proves nothing. Every verdict is a pure function of stored request/response
evidence; no LLM is involved.

## Cases

| Case | Mode | What proves it |
| --- | --- | --- |
| 19 | `panel` | An administrative path (disclosed by `robots.txt`/sitemap) answers **anonymously** with admin actions. |
| 19 | `page` | A page's own scripts disclose an "unpredictable" admin path; the same anonymous probe reaches it. |
| 20 | `role_flag` | A client-controlled flag (cookie or query parameter) decides authorization: the privileged endpoint is denied with the flag absent and **reachable with an admin-like value**. |
| 21 | `role_field` | A profile update accepts a role field it should not; a surface denied BEFORE the write is reachable AFTER it. |
| 22 | IDOR | An object-level read returns another principal's data (own engine, `internal/scan/idor.go`). |

## Case 20 — the flag differential

This is the case that ports most directly to real applications and bounty
programs: a role or admin flag carried in a cookie or query parameter that the
client can set.

### How the probe value is chosen

Two sources, merged and capped (`accesscontrol.DeriveFlags`, `MaxFlags = 6`):

1. **The target's own literal, flipped.** Whatever value the application used is
   inverted: `false→true`, `0→1`, `no→yes`, `off→on`, `disabled→enabled`,
   `unverified→verified`, `guest|user|member|basic|standard|customer|free|
   trial|none|anonymous→admin`. When the observed literal is capitalized
   (`False`), the capitalized counterpart (`True`) is tried first, because
   case-sensitive comparisons are common. An unrecognized literal derives
   nothing — an unknown value never turns into a guess.
2. **A closed name vocabulary.** `admin`, `is_admin`, `admin_flag`, `admin_mode`,
   `administrator`, `superuser`, `root`, `privileged`, `elevated`, `staff`,
   `role`, `user_role`, `account_role`, `usertype`, `access_level`, `auth_level`,
   `privilege`, `permission`, `moderator`, `manager`, `owner`, `support`,
   `agent`, `editor`, `operator`, `supervisor`, `approver`, `reviewer`,
   `developer`, `internal`, `god_mode`, `impersonate`, plus the suffixes
   `role`, `role_id`, `flag`, `mode`, `level`. It is a fixed list, never a
   wordlist; billing-only names (`plan`, `tier`, `price`) and generic
   identifiers are deliberately excluded.

### Where the observed value comes from

- role-shaped query parameters on the privileged endpoints;
- role-shaped **non-session** cookies the scan's own session carries;
- **cookies the target itself issues.** Before probing, the engine asks up to
  two non-privileged pages discovery already knows (then the origin root) and
  records every non-session `Set-Cookie`. This is what makes the capability
  usable on a real target, where the application — not the operator — hands out
  `Admin=false` / `is_staff=no` / `access=basic`. Cookie names matching
  `sess|sid|auth|token|jwt|csrf|xsrf` are excluded: flipping a session cookie
  would break the session instead of testing an authorization decision.

### Bounds and safety

- GET only. No administrative action is ever invoked — the panel is read, and
  the capability it *offers* (a user list, a delete form) is what confirms.
- Same-origin only; every request goes through the scan's scope-enforcing,
  paced engine with its limiter, proxy and session policy.
- A bounded probe budget per scan (`maxAccessControlFlagProbesPerScan`), and at
  most `MaxFlags` values per privileged endpoint plus one baseline.
- Every `Cookie` and `Set-Cookie` value in access-control evidence is redacted
  (names and scope metadata are kept), including explicitly supplied session
  headers.

### Running it

```bash
indago scan create -project <pid> -target <tid> \
  -seed https://target/app \
  -auth existing -auth-state session.json \
  -role-param            # opt in: case 20
```

`-role-param` is OFF by default. It requires an authenticated session for the
typical case (a flag that only matters once logged in), but an anonymous scan
also works when the privileged surface is anonymous.

A confirmed finding reads like:

```
Access control: the cookie "Admin" grants administrative access to /admin
severity: high
setting cookie "Admin"="<redacted>" made the privileged surface reachable
(baseline HTTP 401 → HTTP 200) and exposed delete_user
```

## What is deliberately NOT covered

- POST/PUT-driven flags: case 20 sends GET only; a flag that requires a
  state-changing request is out of scope by design.
- Header-carried flags (`X-Admin: true`) are not derived yet.
- Object-level authorization (IDOR) is case 22 in its own engine, not here.
- A flag whose membership test cannot be demonstrated from the response (for
  example, admin UI that renders identically for every role) stays
  `inconclusive` — never `confirmed`.

## Validation record

- PortSwigger "User role controlled by request parameter": confirmed by the
  engine (`baseline 401 → 200`, `delete_user` exposed); the published solution
  describes the same mechanism (`Admin=false` → `Admin=true`), which the engine
  reaches from the target's own cookie rather than a hardcoded payload.
- Loopback fixture with a different real-world spelling (`is_staff=no` on
  `/login`, panel at `/admin`): confirmed via the observed-literal flip, not via
  the name vocabulary.
