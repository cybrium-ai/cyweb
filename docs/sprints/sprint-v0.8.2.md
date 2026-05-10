# Sprint v0.8.2 — DSL helpers (md5/sha1/sha256/base64/url_encode/...)

**Status:** delivered
**Goal:** unblock the ~10-15% of upstream community templates whose
`dsl:` matcher expressions use cryptographic-hash, encoding, or
header-lookup helper functions cyweb's DSL evaluator didn't support
at v0.8.1.

## What's in this release

`src/templates.rs::evaluate_dsl()` previously matched a small fixed
set of patterns (`status_code == N`, `contains(body, "x")`,
`len(body) > N`, `&&`/`||`). The evaluator is now a recursive
value-expression evaluator that handles function calls and nested
arguments.

### New helper functions

| Helper | Implementation | Returns |
|---|---|---|
| `md5(x)` | `md5` crate | hex string |
| `sha1(x)` | `sha1` crate | hex string |
| `sha256(x)` | `sha2` crate | hex string |
| `base64(x)` | `base64` crate (already a dep) | base64 string |
| `base64_decode(x)` | `base64` crate | utf-8 string |
| `url_encode(x)` | `urlencoding` crate | percent-encoded |
| `url_decode(x)` | `urlencoding` crate | decoded string |
| `header("Name")` | reqwest header lookup, case-insensitive | header value |
| `concat(a, b, …)` | string join | concatenated string |
| `len(x)` | string length (was body-only) | usize |

Hashes return their hex digest as a string so an upstream template
that compares like `md5(body) == "5d41402a…"` works as written.

### Argument parsing improvements

`call_args(expr, name)` now does proper balanced-paren parsing with
string-literal awareness, so:

```
concat(md5(body), "abc, def")
```

correctly resolves to two arguments (`md5(body)` and `"abc, def"`),
not three. Nested function calls and commas inside string literals
are handled.

### Comparison expansion

`status_code` now accepts `==`, `!=`, `>`, `>=`, `<`, `<=` (was
only `==`/`!=`). `len(...)` now accepts the same operators (was
only `>`/`<`).

A general value-equality check `LHS == RHS` (or `!=`) at the end
of the evaluator handles arbitrary helper-call comparisons:

```
md5(body) == "5d41402abc4b2a76b9719d911017c592"
header("Server") == "nginx/1.21"
base64(body) == "aGVsbG8="
```

Both sides evaluate as values; the comparison is string equality
on the resolved values.

## Test fixture

15 unit tests in `src/templates.rs::dsl_tests` cover every helper
plus compound expressions and the parser edge cases (nested
function calls, commas inside string literals, balanced parens).
All passing.

## What's still NOT supported (tracked for v0.8.3+)

- **Raw HTTP request format** (`raw:` block with the full HTTP
  wire-format) — ~10% of upstream templates use it. v0.8.3.
- **Workflow chaining** (`workflows:` block referencing other
  templates by id) — ~3-5% of templates, but they're often the
  most interesting (chained CVE exploits). v0.8.4.
- **Multi-step variable carryover** (`{{interactsh-url}}`,
  cross-step extractor passing) — partial support exists; some
  edge cases fail.
- **`unix_time()`, `rand_int()`, `gen_random()`, `repeat()`** —
  add as needed; low priority.

## KPI delta

After v0.8.1 the conversion success rate (logged in the release
build's "Converted N templates" line) was the baseline. v0.8.2's
expected lift is **~5-10 percentage points** because the helpers
in this release are common but not universal — `md5`/`sha1` show
up frequently in CMS-detection templates; `base64` shows up in
default-credentials templates; `header()` shows up everywhere.

The next release run will print the new number; we track the trend
across v0.8.x to decide when v0.9.0 ships (target: ≥95%).

## Verification

```bash
cargo test --bin cyweb dsl_tests
# Expected: 15 passed; 0 failed
```
