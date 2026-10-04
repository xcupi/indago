# Indago — Reflection Context Analyzer

For every place the injected marker is reflected, the analyzer answers one
question: **what syntactic context is the marker in?** It does not say whether
that is exploitable. Code: `internal/detection/context*.go`.

## Guarantees

| Property | How it is enforced |
|----------|--------------------|
| **Pure** — no network, browser execution, LLM, payload generation, clock, or randomness | `TestContextAnalyzerIsPure` parses the analyzer's real imports and fails on `net`, `os`, `time`, `math/rand`, other internal modules, … |
| **Deterministic** | `TestContextDeterministic`: 20 runs serialize byte-identically |
| **Grounded in the actual bytes** | a real HTML tokenizer is driven through the response to the site's exact offset — not substring matching (e.g. a quote inside a JS regex or comment does not open a string; `</script>` ends JS even mid-string) |
| **Per-site independence** | each site gets its own classification; sites do not influence one another's result |
| **Never panics** | `TestContextClassifyAtEveryOffsetNeverPanics` classifies every byte offset of a hostile document, plus truncations and out-of-range offsets |
| **Descriptive, not a verdict** | no field says "vulnerable"; `Straddles` etc. describe parsing only |

## Contexts

`html_text` (element content, plus RCDATA/RAWTEXT: `title`, `textarea`, `iframe`, `xmp`,
`noscript`…) · `html_attr_value` · `html_attr_name` · `html_tag_name` · `html_comment`
(comment, bogus comment, CDATA) · `js_string` (quoted strings and template literals) ·
`js_code` · `js_comment` · `js_regex` · `url` · `css` · `unknown` · `mixed`.

`Context` is the **innermost (effective)** context; `Chain` lists the nesting
outer→inner, e.g. an inline handler string is `[html_attr_value, js_string]` and a
`javascript:` href string is `[html_attr_value, url, js_string]`.

Embedded languages are located by lexing the relevant prefix: the `<script>` body
(raw, no entity decoding), an event-handler / `style` / `srcdoc` attribute value
(**HTML entities decoded first**, as a browser does), a `javascript:` URL body
(**percent-decoded**), and `<style>` content.

## Each site's record (`ContextAnalysis`)

`Context`, `Sub`, `Chain`, `Element`, `Attribute`, `Quote` · `Confidence`
(`high|medium|low`), `Reason` (human-readable), `Signals` (stable machine tags),
`Alternatives` · `Form` (**raw / encoded / transformed / stripped / unknown**,
from the encoding analysis) · exact `Offset`, `TokenEnd`, `TailOffset`,
`ConstructStart/Kind` · `ContextAtTail` / `Straddles`.

`Straddles` is true when the reflected canary itself moves the parser into a
different context (e.g. a raw `"` closes the attribute). It is descriptive only.

## Offsets and evidence

Offsets are relative to the mutated response **body**. The report's
`evidence` block gives the evidence IDs and `mutated_body_offset`, the position of
the body inside the stored response blob (an HTTP/1.1 message), so a site is at
`mutated_body_offset + offset` in the blob (`ReflectionEvidence.BlobOffset`). A
test reads the blob back and checks that the token is there.

## Confidence and ambiguity

Confidence is `high` for a definite tokenizer state and is lowered, with a reason
and signal, when the model is approximate:

- **medium**: no `Content-Type` (HTML assumed) or XML/SVG; foreign (SVG/MathML)
  content; `<noscript>` (parsed differently with scripting off); `srcdoc` nested
  HTML; non-JS `<script type>`; `srcset`; earlier markup irregularities
  (`tokenizer_anomalies:N`) or JS/CSS error recovery; attribute-name recovery states.
- **low / `mixed`**: a `/` after `)`, `}` or `++`/`--` can be regex or division
  and the two readings put the site in different contexts. The lexer is run
  **both ways**; if they disagree the site is `mixed` with both readings in
  `Alternatives` — it never guesses.
- **`unknown`**: non-HTML response (JSON, plain text, images — `non_html_response`,
  high confidence that there is no markup context), DOCTYPE, an offset that does
  not address the token.

## Known approximations

The tokenizer implements the states that determine context, not the full WHATWG
tree builder; script "double-escape" (`<!--<script>`) is not modelled; foreign
content is detected, not parsed as foreign; the JS/CSS lexers are tokenizers, not
parsers. Each is reflected in confidence rather than hidden.
