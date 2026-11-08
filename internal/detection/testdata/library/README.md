# Live validation harness for the cheat-sheet library

`target.py` is a throwaway HTTP target used to prove that a confirmed finding can
come from a **library** family and not from the canonical set.

It reflects `?q=` into element content, but neutralises:

- every tag the canonical planner builds (`script`, `img`, `svg`, `a`, `iframe`,
  `object`, `embed`, `link`, `meta`, `body`, `details`, `input`, `select`,
  `textarea`, `marquee`);
- the `autofocus` / `tabindex` attributes (the canonical auto-focus mechanism).

Only the library-only families survive (`<video><source onerror>`,
`<audio src=x onerror>`, `<iframe srcdoc=...>`, `<form action=javascript:>`).

## Run

    python3 target.py 19600                       # terminal 1
    indago serve -data /tmp/libval -addr 127.0.0.1:19602 -browser

    # library ON
    indago scan create ... -candidate-profile thorough -xss-library -seed http://127.0.0.1:19600/s?q=hello
    # control: same command WITHOUT -xss-library

## Observed (2026-11-08)

| scan | flag | result |
| --- | --- | --- |
| `7e808a5d-f036-4f84-8df2-a969fd3c2ca7` | `-xss-library` | **confirmed** (high), 3 execution-verified cases |
| `1aa1ba77-63e3-4330-9349-e3c61bfafc31` | off | **rejected**, 0 execution-verified cases |

Execution-verified payloads in the confirmed scan:

    q=<video><source onerror=ind7937860d03b0fee2>
    q=<iframe srcdoc="<audio src=x onerror=ind7937860d03b0fee2>"></iframe>
    q=<audio src=x onerror=ind7937860d03b0fee2>

The control matters: it shows the same target, profile and seeds produce no
finding without the flag, so the confirmation is attributable to the library.
