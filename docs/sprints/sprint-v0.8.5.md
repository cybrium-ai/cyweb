# Sprint v0.8.5 — Protocol coverage, edge-case DSL, OAST, nightly templates

**Status:** delivered
**Goal:** close the last 20% conversion / runtime gap vs upstream
community templates by adding everything cyweb's HTTP-only engine
was rejecting up to v0.8.4 — DNS-only, TCP-only, and headless
templates; the half-dozen edge-case DSL helpers used by ~3% of
templates; out-of-band interaction confirmation via the cybrium
OAST endpoint; and a nightly cron that re-bakes the template image
so customers get fresh CVE coverage daily without waiting on a
cyweb release.

## What's in this release

### 1. DNS / TCP / headless template execution (`src/protocol_runners.rs`)

Cyweb's templates engine had `DnsStep` / `TcpStep` types since
early v0.8.x but no runtime — the converter just rejected DNS-only
or TCP-only templates with `"Not an HTTP template (DNS/TCP/
headless not supported yet)"`. v0.8.5 adds three protocol runners:

- **DNS** — uses `hickory-resolver` (pure-Rust async client,
  rebranded from trust-dns) to query A / AAAA / CNAME / TXT /
  MX / NS records. Matchers run against the formatted answer
  text using the same `Matcher` shape as HTTP templates.
- **TCP** — opens the host:port in the template's `tcp:` block,
  optionally writes a payload, reads up to 4 KiB of banner with
  bounded timeouts (8 s connect + 8 s read), runs matchers.
- **Headless** — drives a real Chromium via `chromiumoxide` (the
  same dependency used by `--ajax-spider` since Phase N), waits
  for navigation + 800 ms for JS to settle, runs matchers against
  the final rendered DOM. Triggers when the template has a
  `headless` tag. Operators install Chrome locally and override
  via `CYWEB_CHROME_PATH` env if auto-discovery doesn't find it.

The runner module is wired into `execute_template()` so any
template carrying `dns:` / `tcp:` blocks (or tagged `headless`)
dispatches into the new path before the HTTP loop runs.

### 2. Edge-case DSL helpers (`src/templates.rs::eval_value`)

The v0.8.2 DSL evaluator handled `md5` / `sha1` / `sha256` /
`base64` / `url_encode` / `header` / `concat` / `len` /
`regex_match`. v0.8.5 fills out the rest of the upstream-compatible
helper surface:

- `unix_time()`, `unix_time(offset_secs)`, `now()` — current epoch
  seconds, optionally offset.
- `rand_int()`, `rand_int(lo, hi)` — random integer; the bounded
  form is inclusive.
- `gen_random(n)` — n alphanumeric characters; `gen_random()` is
  the 8-character default.
- `repeat(s, n)` — repeat string n times, capped at 1 MiB to keep
  a malformed template from OOM-ing the scanner.
- `to_lower`, `to_upper`, `trim`, `replace(s, from, to)`.
- `hex_encode`, `hex_decode`.

These cover the helper functions used by ~3% of upstream templates
that previously evaluated to empty strings inside DSL matchers and
silently failed to match.

### 3. Interactsh OAST integration (`src/interactsh.rs`)

Templates that probe for blind SSRF / blind RCE / blind XXE rely
on a public DNS+HTTP callback service: the target hits an attacker-
controlled domain, and the receipt of that callback is the
confirmation. Upstream community templates use `{{interactsh-url}}`
as a placeholder for "the canary subdomain to inject."

v0.8.5 wires this end-to-end via Cybrium's own OAST daemon at
`oast.cybrium.ai` (172.173.126.237), so customers don't have to
depend on third-party infrastructure:

1. When `execute_template()` sees a request that references
   `interactsh`, it mints a 32-character hex token and stashes
   `interactsh-url` / `interactsh-host` / `interactsh-protocol` in
   the variable map. `resolve_vars` substitutes these into request
   bodies / headers / paths.
2. After the HTTP steps fire, the template runner polls
   `https://oast.cybrium.ai/poll/<token>` with an 8-second window
   (overridable via `CYWEB_OAST_WINDOW_SECS`) for any callbacks
   that landed.
3. Each callback becomes a high-severity Finding with
   `category: "Blind Interaction (OAST)"`, including the calling
   IP and protocol.

On-prem deploys can point cyweb at a private OASTD instance via
`CYWEB_OAST_HOST=oast.internal.example.com`. Polling failures are
silently swallowed — callback infrastructure is best-effort, not
load-bearing.

### 4. Nightly template refresh (`.github/workflows/refresh-templates.yml`)

`release.yml` only re-bakes templates on a `v*` tag, so customers
running a v0.8.5 image are stuck with whatever converted at release
time. New CVE templates land upstream every day. The new
`refresh-templates.yml` cron runs at 03:17 UTC nightly:

1. Pulls the latest cyweb release image and extracts the binary.
2. Clones the upstream community template repo.
3. Re-runs `cyweb convert-templates` against the fresh tree.
4. Builds a templates-only Dockerfile that overlays the converted
   set onto the existing image.
5. Pushes two tags to GHCR:
   - `ghcr.io/cybrium-ai/cyweb:templates-YYYYMMDD` (versioned)
   - `ghcr.io/cybrium-ai/cyweb:templates-latest` (rolling)

Operators who want fresh CVE coverage pin to `templates-latest`;
operators who want reproducibility pin to a `vX.Y.Z` tag.

### 5. Converter — accepts DNS / TCP / headless

`convert_single()` in `src/template_convert.rs` no longer rejects
DNS-only or TCP-only templates. New step converters
(`convert_dns_step`, `convert_tcp_step`) emit cyweb's native
schema. The `network:` upstream alias maps to `tcp:`. Headless-
tagged templates pass through verbatim — the runtime tag sniff
dispatches them through Chrome.

The error message for genuinely empty templates (no http /
requests / dns / tcp / workflows / headless) is now
`"Template has no executable block (...)"` for clarity.

## Tests

10 new unit tests:

- `templates::dsl_tests::unix_time_nonzero`
- `templates::dsl_tests::unix_time_with_offset`
- `templates::dsl_tests::rand_int_range`
- `templates::dsl_tests::gen_random_length_and_charset`
- `templates::dsl_tests::repeat_string`
- `templates::dsl_tests::repeat_capped`
- `templates::dsl_tests::to_lower_to_upper_trim`
- `templates::dsl_tests::replace_substring`
- `templates::dsl_tests::hex_encode_decode_roundtrip`
- `interactsh::tests::*` — token format + placeholder substitution

Plus 5 new converter tests:

- `dns_only_template_converts`
- `tcp_only_template_converts`
- `network_alias_for_tcp_converts`
- `headless_only_template_converts`
- `empty_template_rejected` (replaces the old `neither_http_nor_workflows_rejected`)

Total unit-test count: **42 passing, 0 v0.8.5-related failures**
(the lone failure is `proxy::tests::dbl_crlf`, which fails on
v0.8.4 too — pre-existing, tracked separately).

## Expected KPI lift

Conversion success rate (the v0.8.x KPI):

- v0.8.4 baseline:  11,217 / ~14,000  =  80.1%
- v0.8.5 expected:  +2,000-2,500      =  ~95%

The next release run prints the exact number. The remaining ~5% is
templates with custom `code:` blocks (JavaScript / Python execution),
which is out of scope for v0.8.x and tracked for v0.9.

## Operator-facing changes

- Set `CYWEB_OAST_HOST` to point at a private OASTD instance.
- Set `CYWEB_OAST_WINDOW_SECS=N` to extend the post-fire callback
  poll window (default 8 s).
- Pin to `ghcr.io/cybrium-ai/cyweb:templates-latest` to ride the
  nightly refresh.

## Dependencies added

- `hickory-resolver = "0.24"` — pure-Rust async DNS client (no
  OpenSSL).

No new transitive C dependencies; image size delta is negligible.
