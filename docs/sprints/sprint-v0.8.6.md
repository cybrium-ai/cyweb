# Sprint v0.8.6 — Scripted auth, session re-login, workflow execution, full Nikto tuning

**Status:** scoped (not yet shipped)
**Goal:** close the highest-leverage remaining MEGA3 gaps after v0.8.5.
The four pieces in this sprint are the items a real pentester hits
first when they switch from ZAP / Nikto / Nuclei to cyweb. None of
them are theoretical — each maps to a customer pain point.

The order matters: **Nikto tuning first** (smallest surface, biggest
parity-claim win), then workflow execution (closes the last conversion-
KPI gap), then session re-login, then scripted auth.

---

## 1. Full Nikto-equivalent tuning surface (do first)

### Why first
Smallest code change. Lets us claim explicit Nikto parity in marketing
copy and the docs site. Customers asking "does cyweb cover Nikto's
`-Tuning`?" get a one-line "yes" answer.

### Current state (v0.8.5)
13 implicit categories in `src/scanner.rs`:
`headers, methods, paths, server, ajax-spider, passive, mixed-content,
retirejs, mutate, fuzz, templates, race, websocket`

These are *phase* names — they don't line up with Nikto's
vulnerability-class taxonomy. Customers comparing cyweb to Nikto have
to mentally translate.

### v0.8.6 plan

Add a SECOND tuning axis — **vulnerability class** — alongside the
existing phase axis. Both work simultaneously: `--tuning paths,sqli`
runs the path-discovery phase but ONLY emits findings tagged `sqli`.

New vuln-class taxonomy (Nikto's -Tuning + cyweb extensions):

| Slot | Class | Nikto equiv | Source |
|------|-------|-------------|--------|
| `upload` | File upload vulnerabilities | `0` | paths + fuzz + templates |
| `interesting` | Interesting files / logs / backups | `1` | paths + mutate |
| `misconfig` | Misconfiguration / default files | `2` | paths + headers + server |
| `infodisc` | Information disclosure | `3` | passive + headers + paths |
| `injection-xss` | XSS / HTML / script injection | `4` | fuzz + templates |
| `rfi-local` | Remote file retrieval (inside web root) | `5` | paths + fuzz |
| `dos` | Denial of service signatures | `6` | templates (annotated) |
| `rfi-global` | Remote file retrieval (server wide) | `7` | paths + fuzz |
| `rce` | Command execution / remote shell | `8` | fuzz + templates |
| `sqli` | SQL injection | `9` | fuzz + templates |
| `authbypass` | Authentication bypass | `a` | templates + paths |
| `softwareid` | Software identification | `b` | server + retirejs |
| `rsi` | Remote source inclusion | `c` | fuzz + templates |
| `webservice` | WebService / SOAP / WSDL | `d` | paths + templates |
| `admin` | Administrative console exposure | `e` | paths + templates |
| `ssrf` | Server-side request forgery | (cyweb ext.) | fuzz + OAST |
| `xxe` | XML external entity | (cyweb ext.) | fuzz + OAST |
| `ssti` | Server-side template injection | (cyweb ext.) | fuzz |
| `tls` | TLS / cert / cipher issues | (cyweb ext.) | tls module |
| `secrets` | Leaked secrets / API keys | (cyweb ext.) | passive + js scan |

That's 20 vuln-class categories on top of the 13 phase categories =
**33 tuning slots**. Documented superset of Nikto.

### Files

- `src/scanner.rs` — split `tuning` parsing into two sets: `phase_tuning`
  and `class_tuning`. The phase gate stays as-is. Class filter applies
  to findings before they enter `all_findings`.
- `src/signatures/mod.rs` — add `vuln_class: Option<&'static str>`
  field to `Finding` (already exists from earlier sprints — verify).
  Backfill `vuln_class` on every signature emit site.
- `src/templates.rs` — every Finding emit site gets a `vuln_class`
  derived from the template's `info.tags` (mapping table at top of
  file).
- New `src/tuning.rs` — taxonomy table + `Finding::matches_class()`
  helper + parser that accepts Nikto-style numeric slots
  (`--tuning 0,1,2,9` → `upload,interesting,misconfig,sqli`).
- `src/main.rs` — extend `--tuning` doc string; add `--tuning-list`
  flag that prints the full taxonomy.
- Tests: `tuning::tests` — 8 unit tests covering numeric-slot parsing,
  multi-class filtering, phase+class combo, unknown class warning.

### Acceptance
- `cyweb scan https://x --tuning 9` runs full scan, emits only SQLi
  findings.
- `cyweb scan https://x --tuning sqli,xss` works (named).
- `cyweb scan https://x --tuning paths,sqli` runs only the paths
  phase, filtered to SQLi findings.
- `cyweb --tuning-list` prints the 33-row taxonomy table.

---

## 2. Workflow execution (registry-threaded)

### Why
Sprint v0.8.4 noted explicitly: *"the runner emits one Finding per
workflow step describing the chain. The current implementation
surfaces the chain structure without recursively executing referenced
templates inline — that requires threading the templates registry
through the runner."* That bigger refactor is the v0.8.6 work.

This is the last piece of nuclei-template runtime parity. Without it,
templates that gate exploit chains on detection-template matches
(common pattern for high-value CVE-2024 templates) only print "this
workflow points at template X" instead of actually firing X.

### Plan

Refactor `execute_template()` to take the full templates registry
(or a closure that resolves template-name → Template) so workflow
steps can recursively dispatch:

```rust
// src/templates.rs — new signature
pub async fn run_templates_with_registry(
    client: &Client,
    target: &str,
    templates: &[Template],
    concurrency: usize,
) -> Vec<Finding> {
    // Build path-and-tag indexes once
    let by_path: HashMap<&str, &Template> = ...;
    let by_tag:  HashMap<&str, Vec<&Template>> = ...;
    let registry = TemplateRegistry { by_path, by_tag };
    // Pass to each execute_template
    ...
}

struct TemplateRegistry<'a> {
    by_path: HashMap<&'a str, &'a Template>,
    by_tag:  HashMap<&'a str, Vec<&'a Template>>,
}

async fn execute_template(
    client: &Client,
    target: &str,
    tpl: &Template,
    registry: &TemplateRegistry<'_>,  // NEW
) -> Vec<Finding> { ... }
```

Workflow path becomes:

```rust
if !tpl.workflows.is_empty() {
    for wf in &tpl.workflows {
        // 1. Resolve referenced template(s) via registry
        let parents: Vec<&Template> = if !wf.template.is_empty() {
            registry.by_path.get(wf.template.as_str()).copied().into_iter().collect()
        } else {
            wf.tags.iter()
                .flat_map(|t| registry.by_tag.get(t.as_str()).cloned().unwrap_or_default())
                .collect()
        };
        // 2. Run each parent — capture findings
        let parent_findings: Vec<Finding> = ...;
        // 3. Evaluate workflow matchers against parent findings
        //    (matcher.name correlates to a named matcher in the parent)
        let matched = parent_findings.iter().any(|f|
            wf.matchers.is_empty() ||
            wf.matchers.iter().any(|m| f.id.contains(&m.name) || f.title.contains(&m.name))
        );
        // 4. If matched, fire subtemplates recursively
        if matched {
            for sub in &wf.subtemplates {
                // Recursively walk subtemplates (depth-limited to 5)
                ...
            }
        }
        findings.extend(parent_findings);
    }
    return findings;
}
```

**Cycle protection:** track a `visited: HashSet<&str>` of template
IDs in the call chain so a workflow that points back at its parent
doesn't infinitely recurse.

**Depth limit:** hard-cap at 5 levels (matches upstream nuclei).

### Files

- `src/templates.rs` — refactor `run_templates`, `execute_template`,
  add `TemplateRegistry` struct.
- `src/scanner.rs` — call site swaps to `run_templates_with_registry`.
- Tests: 4 new tests in `templates::workflow_exec_tests`:
  - parent matches → subtemplate fires
  - parent does not match → subtemplate does not fire
  - cycle detection (A → B → A returns without infinite loop)
  - depth limit (chain longer than 5 truncates)

### Acceptance
- A two-template chain (detection + exploit) runs as a unit; the
  exploit finding only emits when detection matched.
- Cycle templates don't hang the scanner.
- Workflow-execution KPI: every upstream `workflows/` template that
  references a path that converted cleanly now produces inline
  child findings, not just a placeholder.

---

## 3. Session re-login on expiry

### Why
ZAP's killer feature for long-running auth scans. cyweb's
`form_login.rs` runs once at scan start; if the session cookie expires
mid-scan (default Django session: 14 days, but JWT scans + memory-
session apps die in 5-30 minutes), every subsequent request comes
back as an anonymous 401 / 302 → /login. Pentest is silently void.

### Plan

Add a session-monitor middleware to the HTTP client:

1. `src/session.rs` — new module. `SessionMonitor` wraps a `reqwest::
   Client` plus the `LoginResult` from form_login. Exposes
   `request_with_relogin(req: RequestBuilder) -> Response` that:
   - Sends the request.
   - Checks response: if status `401` / `403`, OR redirect to a
     URL matching `--login-redirect-pattern` (auto-detected from
     the original login URL), OR the response contains a configured
     "session-expired" sentinel string — re-runs `form_login()`
     and replays the original request.
   - Bounded: max 3 re-login attempts per scan; if exceeded, emits
     a `Severity::Info` Finding ("Session expired and could not be
     restored — auth-gated paths from this point are unscanned")
     and continues unauthenticated.

2. `src/scanner.rs` — every `client.get(...).send()` site that runs
   *after* form_login has succeeded swaps to
   `session_monitor.request_with_relogin(...)`. ~30 sites; mechanical.

3. Detection heuristics:
   - HTTP status: 401, 403 (configurable; some apps use 302 →
     /login).
   - Redirect target match: any 3xx where Location ∈ login-page-set.
   - Body sentinel: `session expired`, `please log in`,
     `Authentication required` (case-insensitive).
   - JWT-specific: response with header `WWW-Authenticate: Bearer
     error="invalid_token"`.

4. CLI surface:
   - `--session-relogin` (default `auto` — heuristics enabled when
     form-login was used).
   - `--session-expired-pattern <REGEX>` (override sentinel).
   - `--session-max-relogins <N>` (default 3).

### Files

- `src/session.rs` — new (~180 lines).
- `src/scanner.rs` — wire `SessionMonitor` into the request path.
- `src/main.rs` — 3 new CLI flags.
- Tests: `session::tests` — 5 unit tests using `wiremock` (or
  `httpmock` — pick whichever is already in dev-deps):
  - 401 triggers re-login + replay
  - 302 to /login triggers re-login
  - sentinel match triggers re-login
  - 3-attempt cap fires Info finding
  - heuristic disabled when no form-login → no-op

### Acceptance (v0.8.6 PR scope — what ships now)
- `src/session.rs` module landed with `SessionMonitor`,
  `SessionConfig`, `request_with_relogin`, `body_indicates_expired`,
  full unit-test coverage of expiry-signal heuristics.
- 3 CLI flags: `--session-max-relogins`, `--session-expired-pattern`,
  `--session-expired-sentinel`.
- Fields propagated through `ScanConfig`.

### Deferred to v0.8.7 (call-site sweep)
The wide refactor — switching every `client.get(...).send()` site
across `scanner.rs` and `signatures/*.rs` (~30 sites) to
`monitor.request_with_relogin(|c| c.get(url))` — is mechanical but
wide. Splitting that into its own PR keeps v0.8.6's blast radius
manageable. Once the sweep lands, the acceptance criteria become:

- Run cyweb against a deliberately-short-session test app (Django
  with `SESSION_COOKIE_AGE=60`); scan continues past the 60s mark
  with auth-gated routes still being scanned authenticated.
- Re-login Findings appear in the report with timestamps.

---

## 4. Scripted auth (multi-step / OAuth / SAML POST)

### Why
The single biggest gap. ZAP's authentication-script API supports:
- multi-step forms (e.g., username page → password page)
- OAuth2 PKCE / authorization-code flows
- SAML POST binding
- header-token auth (extract Bearer from a JSON response)
- CAPTCHA-bypass via dev session-token endpoint

cyweb's `--login-user` / `--login-pass` can't model any of this.

### Plan

Implement scripted auth via a simple YAML auth-script schema —
readable, no new sandbox needed:

```yaml
# Example: examples/auth/oauth-pkce.yaml
name: "Acme OAuth2 PKCE"
steps:
  - name: get-login-page
    method: GET
    url: "https://idp.acme.com/oauth2/authorize?client_id={{client_id}}&response_type=code&code_challenge={{pkce_challenge}}&code_challenge_method=S256"
    extract:
      csrf: 'name="_csrf" value="([^"]+)"'

  - name: post-credentials
    method: POST
    url: "https://idp.acme.com/login"
    body: "username={{user}}&password={{pass}}&_csrf={{csrf}}"
    follow_redirects: false
    extract:
      auth_code: 'location: .*[?&]code=([^&]+)'   # case-insensitive header match

  - name: exchange-code
    method: POST
    url: "https://api.acme.com/oauth2/token"
    body: "grant_type=authorization_code&code={{auth_code}}&code_verifier={{pkce_verifier}}"
    extract:
      access_token: '"access_token":"([^"]+)"'

apply:
  # Headers / cookies to attach to every subsequent scan request
  headers:
    Authorization: "Bearer {{access_token}}"
```

Driver:

- `src/auth_script.rs` — new (~250 lines):
  - `pub struct AuthScript { steps: Vec<AuthStep>, apply: ApplyConfig }`
  - `pub async fn run(client: &Client) -> Result<AuthArtifacts, AuthError>`
  - Variable substitution via the existing `resolve_vars` helper
    from `templates.rs` (extract to a shared `vars.rs` module).
  - PKCE helpers: `pkce_challenge()` / `pkce_verifier()` baked into
    the helper-function set so scripts can use them as `{{pkce_*}}`.
  - Extractors: same shape as template extractors — regex with
    capture group. Headers (`location:`, `set-cookie:`), body, JSON.
  - Bearer-token mode: `apply.headers` get baked into a fresh
    `reqwest::Client` builder (via `default_headers`).
  - Cookie mode: cookies from any step's response join the cookie
    jar.

- `src/main.rs` — new CLI flag:
  `--auth-script <PATH>` (mutually exclusive with `--login-user`).

- `examples/auth/` — ship 4 working examples:
  1. `form-multi-step.yaml` — username-then-password flow
  2. `oauth-pkce.yaml` — OAuth2 PKCE
  3. `saml-post.yaml` — SAML POST binding
  4. `bearer-from-json.yaml` — POST creds → extract JWT from JSON

- `src/session.rs` — re-login on expiry now invokes the auth script
  if one is configured (instead of `form_login()`).

- Tests: `auth_script::tests` — 6 unit tests covering each example
  schema parsing + variable substitution + extractor regex. Live
  HTTP test gated behind `--ignored` flag (operator runs against
  a real IdP).

### Acceptance
- All 4 example scripts parse and execute cleanly against a
  test-IdP fixture (Keycloak-in-Docker).
- A scan with `--auth-script oauth-pkce.yaml` lands on auth-gated
  routes with `Authorization: Bearer ...` populated.

---

## KPI / Acceptance — sprint-level

| Metric | v0.8.5 | v0.8.6 target |
|---|---|---|
| Template conversion rate | ~95% | unchanged |
| Workflow templates **executed** (not just structured) | 0% | ≥80% of converted workflow templates |
| Tuning categories | 13 | 33 |
| Auth modes supported | basic / bearer / form (1-step) | + scripted YAML (multi-step / OAuth2 / SAML) |
| Session-resilience | none | 3 retries with heuristic detection |

## Dependencies

- No new heavy crates. PKCE helpers use existing `rand` + `sha2` +
  `base64`. YAML parsing already in via `serde_yaml`.
- `httpmock` may need to land in `[dev-dependencies]` if not there
  (preferred over `wiremock` for synchronous test simplicity).

## Out of scope (deferred to v0.8.7)

- `code:` / `flow:` / `javascript:` template kinds (need a sandbox
  — `wasmtime` or a Deno embed; security-sensitive, separate sprint)
- HTTP/2 + HTTP/3 enablement (mostly reqwest config + quinn for h3)
- GraphQL active fuzzing
- Per-rule policy strength/threshold tuning (the ZAP "policy editor"
  surface — needs a config file format design)
- Rich HTML/PDF reports from cyweb itself (platform handles this)

## Sequencing within the sprint

Strictly serial dependencies:

1. **Tuning taxonomy** (smallest, ships first — independent)
2. **Workflow execution** (independent, but touches templates.rs
   so do it before scripted-auth which adds new modules)
3. **Session re-login** (depends on form_login.rs surface — depends
   on nothing in this sprint)
4. **Scripted auth** (re-uses session module's re-login hook)

Parallel-safe pairings: (1) + (3), (2) + (4). If we want to
landed-PR-per-week cadence: PR1 = tuning + session, PR2 = workflow
execution, PR3 = scripted auth.
