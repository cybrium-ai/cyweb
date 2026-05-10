# Sprint v0.8.1 — Bundled upstream community templates

**Status:** in progress
**Goal:** every release of cyweb ships with a fresh-converted copy of
the upstream community template library (`projectdiscovery/nuclei-templates`)
baked into the docker image, so `cyweb scan` covers the same product-CVE
breadth a separate Nuclei deployment does — without the operator
running a second tool.

## Why

After v0.8.0 the platform's DAST tool list looks like:

```
("cyweb",  "Web Scanner"),       ← integrated scanner + GUI
("nuclei", "Nuclei"),            ← still here for the 14k-template breadth
```

Nuclei's value is the daily-refreshed template library, not the
runtime engine. Cyweb already has a templates engine
(`src/templates.rs`) and a converter (`cyweb convert-templates`).
Wiring them together at release time gets us most of Nuclei's
coverage baked into the cyweb image.

## What ships in this sprint

### 1. Release-time template conversion

`.github/workflows/release.yml` gains a new step before the docker
build:

- `git clone --depth 1 projectdiscovery/nuclei-templates`
- Run the just-built `cyweb-linux-amd64` binary against it:
  `cyweb convert-templates --input … --output templates-converted/`
- Whatever converts cleanly gets baked into the image at
  `/opt/cyweb/templates/`
- Conversion failures are logged but don't fail the build —
  cyweb's engine doesn't yet support every DSL helper or
  workflow-chaining feature, so a meaningful percentage of
  templates won't convert. We ship what works.

### 2. Runtime auto-load

`src/templates.rs:load_templates()` now checks three sources in
order, with later ones winning ties:

1. `$CYWEB_TEMPLATES_DIR` (defaults to `/opt/cyweb/templates`) —
   image-baked converted templates.
2. `~/.cyweb/templates/` — operator-local overrides.
3. `--templates <dir>` — explicit CLI path.

Cyweb prints a load-summary line at scan start showing the count
loaded from each source so the operator can confirm fresh
templates are being used.

### 3. `Dockerfile` change

```Dockerfile
COPY templates-converted /opt/cyweb/templates
ENV CYWEB_TEMPLATES_DIR=/opt/cyweb/templates
```

`templates-converted/` is generated in CI and is in `.gitignore` —
it never gets committed.

## What's NOT in this sprint

These are the v0.8.x DSL gaps that prevent ~25-40% of upstream
templates from converting cleanly. Each is a small targeted change;
they get knocked off in subsequent v0.8.x patches based on what
gets logged at conversion time.

- `md5()`, `sha1()`, `sha256()` DSL helpers
- `base64()`, `base64_decode()`, `url_encode()`, `url_decode()`
- `regex()` matcher composition
- Workflow chaining (`workflows:` block referencing other templates)
- Raw HTTP request format (`raw:` instead of structured method/path/headers)
- Multi-step request variable carryover (`{{interactsh-url}}`,
  per-step extractors feeding into next step's body)
- Helper functions: `unix_time()`, `rand_int()`, `gen_random()`,
  `repeat()`, `concat()`, `len()`

Tracking the conversion success rate over time will tell us which
helpers to prioritize.

## Conversion-success metric

Each release run logs:

```
Converted N templates from upstream community repo.
```

Watching this number climb from release to release is the sprint's
KPI. Goal for v0.9.0: ≥95% of upstream templates converting and
running cleanly, at which point the platform can drop Nuclei
entirely.

## Verification

After v0.8.1 lands:

```bash
docker pull ghcr.io/cybrium-ai/cyweb:0.8.1
docker run --rm ghcr.io/cybrium-ai/cyweb:0.8.1 \
  scan https://httpbin.org --output text 2>&1 | grep "Loaded.*templates"

# Expect: Loaded N templates from:
#           - /opt/cyweb/templates  (~9000 templates)
```

## Follow-up sprint candidates (v0.8.2+)

- DSL helper batch 1 — `md5/sha1/sha256/base64/url_encode` (5 fns).
  Should lift conversion success rate by ~5pp.
- Raw HTTP request support. Roughly 10-15% of upstream templates
  use `raw:` blocks; supporting it lifts coverage proportionally.
- Workflow chaining. ~3-5% of templates use it but they're often
  the highest-severity ones (chained CVE exploits).
- Drop Nuclei from the platform once conversion success ≥95%.
