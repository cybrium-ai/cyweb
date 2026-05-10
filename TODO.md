# cyweb v0.8.x — deferred work

Tracked here so we don't lose anything when v0.8.0 ships. Each item
has a clear scope so picking one up later is a self-contained PR
rather than a fishing expedition.

## Phase Q — Live progress updates (polling-based)

**What it is:** GUI updates as scan phases complete instead of
appearing all-at-once when the scan finishes. Operator sees the
findings count, spider node count, and active-scan request count
tick up while the scan runs.

**Why deferred:** Started during v0.8 final push, hit a refactor
boundary (need to thread a writer through every phase boundary in
scanner.rs), backed off rather than ship half-done.

**Concrete plan when it's picked up:**

1. Add `pub struct LiveState { scanning: bool, current_phase: String,
   partial: ScanResult }` to scanner.rs.
2. Add `pub async fn run_scan_with_live_writer(config,
   Arc<RwLock<LiveState>>)` wrapper around the existing run_scan.
3. Internally, run_scan takes an `Option<Arc<RwLock<LiveState>>>` and
   updates partial state at each phase boundary (Phase 8 spider,
   8.5 passive, 8.7 vulnerable-JS, 12 fuzz, completion). About 5-7
   touchpoints, each ~3 lines.
4. main.rs: when `--gui` is passed, spawn the GUI server FIRST with
   the shared LiveState, then run the scan. Currently it's reversed
   (scan completes, then GUI starts).
5. New `/api/status` endpoint returns `{scanning, current_phase,
   duration_ms}`.
6. GUI JS: poll `/api/status` every 1.5s; while scanning, also
   re-fetch `/api/result` and re-render the active panel. Stop
   polling when scanning flips false.

**Estimated effort:** 1.5-2 hours. Mostly mechanical wiring.

## HTTPS MITM in `cyweb proxy`

**What it is:** Decrypt HTTPS bodies in the proxy mode so the
History tab shows the request/response payload, not just the
CONNECT line.

**Why deferred:** Requires generating a CA cert + key on first run,
documenting how to install it in the operator's browser/system
trust store, and dynamic per-host leaf cert generation. Real
engineering + docs work; the dedicated `cyproxy` tool already
covers this surface, so cyweb's proxy stays a quick-capture mode.

**Concrete plan:**
- Use `rcgen` to generate a CA cert at `~/.cyweb/ca.pem` on first
  run.
- Print install instructions to stderr.
- Use `tokio-rustls` to terminate TLS in the proxy with a leaf
  cert signed by the local CA (cached per-host).
- Surface decrypted body in the History tab.

OR: drop `cyweb proxy` entirely and route operators to `cyproxy`.
Decision deferred to whoever picks this up.

## Live HUD overlay / browser plugin

**What it is:** Heads-up display overlay on the operator's browser
as they manually browse the target, showing findings/alerts in
real time.

**Why deferred:** Requires a browser extension or content-script
injection through the proxy. Niche; most operators use the GUI
tab flow.

## Deeper authentication context manager

**What it is:** Session re-authentication when a session expires
mid-scan. Right now `--login-user`/`--login-pass` does form login
once at the start; if the session times out during a 2-hour scan,
subsequent requests are unauthenticated.

**Concrete plan:**
- Add a `--auth-check-url` flag — cyweb periodically GETs this URL
  and inspects the response for a logged-out indicator.
- On detection, re-run the login flow.
- Single regex / "logged-out indicator" string match.

**Estimated effort:** half a day.

## Forced-Browse / dictionary path discovery

**What it is:** Wordlist-driven path discovery (admin panels,
backup files, common config paths). cyweb's `--mutate` mode covers
some of this; richer rule sets use larger wordlists (millions of
paths).

**Concrete plan:**
- Bundle a curated wordlist (~20K paths from
  RobotsDisallowed + CommonPaths) at compile time.
- New `--forced-browse` flag.
- Reuse the existing path-discovery phase.

## Scan comparison / diff

**What it is:** Compare two scan runs to see what changed —
"this PR introduced 3 new findings, fixed 2."

**Concrete plan:**
- New subcommand: `cyweb diff <baseline.json> <current.json>`
- Outputs a 3-section report: new findings / fixed findings /
  changed (severity bumped).

## i18n

**What it is:** Translate the GUI to languages other than English.

**Why deferred:** No customer demand yet. Adds maintenance burden.

## ~~Per-rule strength selectors~~ — done v0.8.7

Shipped as `--strength low|medium|high` plus a paired `--threshold`
axis (rule confidence). Rule YAML schema gained `strength:` /
`threshold:` fields; filter applied at scan-config build time in
scanner.rs. See `signatures::rules::policy_tests`.

The "Insane" multiplier idea is NOT in v0.8.7 — strength there
gates *which* rules run, it doesn't fan out more payloads per rule.
If the multiplier behaviour is still wanted, that's a separate
small patch (add `payload_multiplier` field to the fuzz payload
selector).

## Rule-level enable/disable from CLI

**What it is:** Toggle individual active-scan rules on/off. Right
now `--tuning` is category-level (passive, fuzz, retirejs, etc.)
— finer-grained per-rule selection would help when a customer
can't run certain rule classes (e.g. avoid SQLi probes on a
production DB).

**Concrete plan:**
- New flag: `--rules-include <rule-id-glob>` /
  `--rules-exclude <rule-id-glob>`. e.g.
  `--rules-exclude 'sqli-*'`.

## Rate-limiting awareness

**What it is:** Detect 429 / 503 / Cloudflare challenges during
scan and back off automatically.

**Concrete plan:**
- After each request, if status is 429 or response body matches
  known WAF fingerprints, double the delay between subsequent
  requests for that host. Reset on first 200 OK.

---

# Carried forward from v0.8.7 sprint review

These are the ONLY items that survived the v0.8.6 → v0.8.7
"close all soft deferrals" sweep. Every other gap from the
MEGA3 (ZAP / Nikto / Nuclei) audit is shipped.

## `code:` / `flow:` / `javascript:` template kinds

**What it is:** ~5% of upstream community templates carry a
`code:` block (JavaScript or Python execution) or a `flow:`
block (ECMAScript-style request orchestration, newer than
`workflows:`). Templates of this kind get rejected at conversion
today — they cover bespoke runtime logic that can't be expressed
purely as matchers + extractors.

**Why deferred:** Real engineering — needs a sandboxed runtime
embedded in cyweb. Two viable approaches:
- **wasmtime** — operator-supplied JS/Python compiled to WASM,
  loaded into a wasmtime instance per template. Cleanest sandbox
  story (capability-based, no filesystem / network by default).
- **Deno embed** — easier to author for (most upstream templates
  are JavaScript), but Deno's "secure-by-default" still gives the
  embedded code wide capability and pulls in a bigger runtime.

**Concrete plan when picked up:**
1. New `Template.code: Option<CodeBlock>` field (script + language).
2. New `src/code_runner.rs` with `run_code(code: &CodeBlock,
   step_state: &StepState) -> Result<Vec<Finding>>`.
3. Sandbox: wasmtime with no WASI host imports — code can only
   read pre-staged variables and emit findings via a host-imported
   `emit(json)` callback.
4. Converter accepts `code:` blocks; runtime dispatches to
   `code_runner::run_code` after the HTTP path.
5. CI gate: any code template that calls a non-allowlisted host
   import is rejected at conversion.

**Estimated effort:** 1.5-2 weeks. Sandbox security needs review.

**KPI delta:** Closing this lifts conversion success from ~95%
to ~99%+. The remaining ~1% is intentionally-broken templates
upstream uses for testing.

## HTTP/3 (QUIC) support

**What it is:** Some modern Cloudflare-fronted targets only
serve HTTP/3 over QUIC (no h2 fallback). cyweb v0.8.7 does h1 +
h2; h3 isn't reachable today.

**Why deferred:** Requires the `quinn` crate (QUIC reference
impl) and reqwest's experimental h3 feature, which has been in
preview for 18+ months. Not as drop-in as the h2 patch.

**Concrete plan when picked up:**
1. Add `reqwest` feature `http3` (currently behind a `--cfg
   reqwest_unstable` flag — needs RUSTFLAGS in CI).
2. Extend `--http-version` to accept `3` / `h3`.
3. `Client::builder().http3_prior_knowledge()` when the operator
   forces h3.
4. Smoke test against a known h3-only endpoint (cloudflare-quic.com
   or similar).

**Estimated effort:** 4-6 hours, mostly CI plumbing for the
unstable feature flag.

## GraphQL active fuzzing

**What it is:** ZAP and Burp both have GraphQL-aware modes:
introspect the schema, mutate queries by depth / type / batch
size, probe for IDOR / authz bypass / DoS via deep nesting.
cyweb's `fuzz.rs` doesn't know what GraphQL is.

**Why deferred:** Distinct enough surface area that bolting it
into the existing fuzzer is the wrong shape. Wants its own
module.

**Concrete plan when picked up:**
1. New `src/graphql.rs` — introspection client, query mutator,
   batch / nesting / alias-rename probes.
2. New CLI flag `--graphql` triggers GraphQL phase after the
   server fingerprinting phase IF `__schema` returns a result
   at any of `/graphql`, `/api/graphql`, `/v1/graphql`.
3. Findings tagged `vuln_class: webservice` so the v0.8.6
   tuning surface picks them up.

**Estimated effort:** 3-5 days. Schema-driven fuzzing is well-
understood; the time goes into building a useful payload set,
not into infrastructure.
