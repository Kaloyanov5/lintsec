# Context-Aware Reflected XSS — Design

Date: 2026-06-11
Module: `com.lintsec.scanner.modules.ReflectedXssModule`

## Problem

The current `ReflectedXssModule` injects `<lintsec_canary_{nonce}>` and flags the
finding only if that literal string (angle brackets included) reflects in the
response body. That single check only ever detects **raw-HTML-tag** reflection.
Reflections that land in other executing contexts are silent false negatives:

- inside a quoted/unquoted HTML attribute value,
- inside a `<script>` block (JS string or raw JS),
- inside an HTML comment,
- inside a `href`/`src`/`action` URL attribute (where a `javascript:` scheme
  executes without any angle bracket),
- inside `<style>`,
- in tag-name position.

In each of these, the right injection is *not* `<…>` — it is the metacharacter
that breaks out of that specific context (a quote, a `</script>`, a `-->`, etc.).

## Goal

Replace the single literal check with a **two-probe, context-classified
confirmation**: locate the reflection and classify its context, then inject a
context-specific breakout payload and confirm the distinguishing metacharacters
survive unencoded. Report only confirmed-exploitable reflections; suppress
reflections that are safely encoded.

This is the false-positive/false-negative-reduction analogue, for XSS, of the
SQLi/Cmdi baseline-diff work — it follows the same "pure `confirmInjection()`
function + unit tests" pattern. Baseline-diffing itself is **not** used here: the
nonce is unique and never collides with baseline content.

## Flow (per URL param, per form field)

1. **Probe 1 — locate + classify.** Inject a plain alphanumeric canary
   `lintsec{nonce}` (no metacharacters). Fetch. If the canary is absent → no
   reflection, skip. Otherwise classify the context of each reflection via a raw
   string scan around the offset. Collect the **set of distinct contexts**.
2. **Probe 2 — breakout.** For each distinct context, inject the context-specific
   breakout payload and fetch (one breakout request per distinct context).
3. **Confirm.** If the context's distinguishing metacharacters reflect
   **unencoded**, emit a finding; otherwise suppress.

Request cost ≈ 2× the current per-param count (one locate + typically one
breakout). Both vectors are covered: URL params via `UrlParams`, forms via
`FormSubmitter` (unchanged helpers).

## Context taxonomy and breakout payloads

| Context | Breakout payload | Confirmed when | Severity |
|---|---|---|---|
| HTML text / body | `<lintsec{nonce}>` | `<` and `>` both reflect raw | HIGH |
| Double-quoted attribute | `lintsec{nonce}"x` | `"` reflects raw | HIGH |
| Single-quoted attribute | `lintsec{nonce}'x` | `'` reflects raw | HIGH |
| Unquoted attribute | `lintsec{nonce} x` | space reflects raw (enables `onmouseover=`) | HIGH |
| Inside `<script>` | `</script>` (primary), matching quote (secondary) | `</script>` or the JS-string quote reflects raw | HIGH |
| Inside `<style>` | `</style>` | `</style>` reflects raw | MEDIUM |
| HTML comment | `--><lintsec{nonce}>` | `-->` and `<` reflect raw | HIGH |
| `href`/`src`/`action` URL attribute | `javascript:lintsec{nonce}` | value reflects raw with `javascript:` scheme intact | HIGH |
| Tag-name (right after `<`) | `<lintsec{nonce} ` | `<` reflects raw | HIGH |
| Encoded / stripped | — | metacharacters escaped or absent | **suppressed** |

`UNKNOWN` context falls back to the HTML-text breakout (`<lintsec{nonce}>`) as a
best-effort.

`<style>` is MEDIUM because modern browsers do not execute CSS `expression()`; it
can break out of the style element but rarely yields direct script execution.

## Code shape

Mirrors the established pure-function pattern (`ErrorBasedSqliModule.confirmInjection`,
`CommandInjectionModule.detect/confirmInjection`).

### New: `ReflectionContext` (enum, `com.lintsec.scanner`)
The context kinds above:
`HTML_TEXT, ATTR_DOUBLE, ATTR_SINGLE, ATTR_UNQUOTED, ATTR_URL, SCRIPT, STYLE,
COMMENT, TAG_NAME, UNKNOWN`.

(`ATTR_URL` is a refinement of an attribute context when the attribute name is a
URL-bearing attribute such as `href`/`src`/`action`/`formaction`.)

### New: `XssContextAnalyzer` (pure static methods, package-private, `com.lintsec.scanner`)
- `ReflectionContext classify(String body, int canaryOffset)` — raw scan backward
  from the offset:
  1. Enclosure: is the offset inside `<script>…</script>`, `<style>…</style>`, or
     `<!-- … -->` (last opener before offset has no matching closer before offset)?
     → `SCRIPT` / `STYLE` / `COMMENT`.
  2. In-tag: find the last `<` and last `>` before the offset; if `<` is later we
     are inside a tag. Walk from that `<` to the offset tracking quote state to
     decide `ATTR_DOUBLE` / `ATTR_SINGLE` / `ATTR_UNQUOTED`, refine to `ATTR_URL`
     if the attribute name is URL-bearing, or `TAG_NAME` if still in the
     tag-name/attribute-name region.
  3. Otherwise `HTML_TEXT`. Empty/garbage → `UNKNOWN`.
- `String breakoutPayload(ReflectionContext ctx, String nonce)` — returns the
  Probe-2 injection value per the table.
- `Optional<Breakout> confirmBreakout(ReflectionContext ctx, String body, String nonce)`
  — locate the nonce in the Probe-2 body and check whether the context's
  distinguishing metacharacters survive unencoded adjacent to it; return
  `Breakout(Severity severity, String detail)` or empty.
- `record Breakout(Severity severity, String detail)`.

### `PayloadCatalog` / `PayloadId`
- Add `XSS_CANARY_PLAIN` → `lintsec{nonce}` (Probe 1).
- Reuse existing `XSS_CANARY_REFLECTED` → `<lintsec_canary_{nonce}>` as the
  HTML-text breakout payload. The finding's `payloadId` stays
  `XSS_CANARY_REFLECTED`.
- Add `descriptionFor` text for `XSS_CANARY_PLAIN`.

Context-specific breakout strings other than the HTML-text one are built inside
`XssContextAnalyzer.breakoutPayload` (they are context-dependent and do not fit
the flat `PayloadId → String` map).

### `ReflectedXssModule` (rewritten)
For each URL param and each fuzzable form field:
1. Probe 1 with `XSS_CANARY_PLAIN`; if not reflected, skip.
2. Compute the set of distinct contexts across all reflections.
3. For each distinct context: build the breakout payload, Probe 2, run
   `confirmBreakout`. On confirmation, emit a `ScanFinding` whose `detail` names
   the context and the surviving breakout character; severity from `Breakout`.
4. Suppress when no breakout confirms.

Finding title/location/remediation keep their current shape; titles continue to
read `Reflected XSS via parameter: {name}` / `via form field: {name}`. The
`detail` string is the part that gains the context and surviving-char description.

## Testing

Unit tests for `XssContextAnalyzer` (the only new pure logic):
- `classify` across every context using hand-written HTML fixtures (including the
  enclosure and quote-state edge cases, and `UNKNOWN`).
- `breakoutPayload` returns the documented payload per context.
- `confirmBreakout` positive (raw metachar survives) and negative (HTML-encoded
  metachar) for each context.

Target ≈ 15–20 new tests. Run via `./mvnw.cmd -o test`.

No controller/integration tests are added (that gap is tracked separately). A live
end-to-end scan against a known-reflecting target after the backend restart is
recommended before trusting in prod, but is not a unit-test deliverable.

## Deliberate limitations

- One breakout probe per *distinct* context per param (bounded request count);
  pages with many distinct contexts are capped at the number of distinct contexts.
- DOM-based XSS and stored XSS remain out of scope — this is reflected,
  server-rendered XSS only.
- `<style>` breakout is reported MEDIUM (no direct script execution in modern
  browsers).
