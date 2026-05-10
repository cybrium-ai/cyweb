# Sprint v0.8.3 — Raw HTTP request format

**Status:** delivered
**Goal:** convert templates that ship their request as a `raw:` block
(full HTTP wire format) instead of structured method/path/headers/body.
Roughly 10% of upstream community templates use this — often the
high-value CVE chains where exact byte-level request control matters.

## What's in this release

`src/template_convert.rs::convert_request_step()` now detects a
`raw:` field on each request step. For each raw HTTP block, the
parser:

1. Splits the request line from headers
2. Pulls method + path from the request line
3. Parses headers as `Name: Value` lines
4. Collects body bytes after the first blank line (`\r\n\r\n` or `\n\n`)

Output is cyweb's structured format — method/path/body/headers —
so existing template-execution code runs them unchanged.

`{{Hostname}}`, `{{BaseURL}}`, `{{username}}` etc. variable
placeholders are preserved verbatim — cyweb's runtime expander
handles them at scan time.

Multiple raw entries in the same step become multiple paths under
the first entry's method (matching the upstream semantic of
"check this path AND that path").

## Tests

5 unit tests in `src/template_convert.rs::raw_http_tests`:
- Simple GET with two headers
- POST with form-urlencoded body
- LF-only line endings (`\n\n`)
- Malformed input → returns None gracefully
- Variable placeholders preserved

All passing.

## Expected KPI lift

- v0.8.1 baseline: 11,011 / ~14,000 = 78.6%
- v0.8.2: 11,011 (no change — DSL helpers don't affect conversion)
- v0.8.3 expected: +800–1,400 templates as `raw:` templates now go
  through the parser instead of failing the HTTP-detection check.

The next release run prints the new number.

## Still deferred

- v0.8.4 — workflow chaining (`workflows:` block)
- v0.9.0 — drop standalone external scanner from platform
