# cyweb

Fast, accurate web vulnerability scanner built in Rust by [Cybrium AI](https://cybrium.ai).

Scans web applications for security misconfigurations, exposed files, missing headers, outdated software, and known vulnerabilities. Outputs findings in text, JSON, or SARIF format.

## Install

```bash
cargo install --git https://github.com/cybrium-ai/cyweb
```

Or download a pre-built binary from [Releases](https://github.com/cybrium-ai/cyweb/releases).

## Usage

```bash
# Basic scan
cyweb scan https://example.com

# JSON output
cyweb scan https://example.com --output json

# SARIF output (GitHub, Azure DevOps, Cybrium platform)
cyweb scan https://example.com --output sarif -f report.sarif

# With spider/crawler
cyweb scan https://example.com --spider --spider-depth 3

# Custom threads and timeout
cyweb scan https://example.com --threads 20 --timeout 15
```

### Scoped fast scans (v0.10+)

cyweb's Phase 13 template engine iterates 9,000+ YAML templates against the
target and can take 1–3 hours on a real-world site. For CI scans + per-MITRE-
technique workflows that need ~30–120s scans, v0.10 adds the surface to
scope and bound a run:

```bash
# Skip Phase 13 entirely (Phases 1-12 only — ~5 min on a real target)
cyweb scan https://example.com --skip-templates --output jsonl

# Hard time limit. On expiry: stop, flush whatever's been found, exit 0.
# The output sets `"incomplete": true` + `"stopped_phase": <name>`.
cyweb scan https://example.com --max-duration 60 --output jsonl

# Per-tag template scoping. Same contract as the old `nuclei -tags` flag —
# only templates whose info.tags matches at least one of the comma-separated
# substrings will run. Perfect for per-technique adversary scans.
cyweb scan https://example.com --templates-include "xss,sqli,ssti" --output jsonl

# All three compose. Adversary-engine-style scoped probe:
cyweb scan https://example.com \
    --templates-include "xss,sqli,ssti,injection,lfi" \
    --max-duration 90 \
    --output jsonl
```

JSONL output emits one self-contained JSON object per line — each finding +
a final `{"type":"scan_complete",...}` event with summary stats. Plays
cleanly with `jq`, OpenSearch ingest, and the Cybrium platform's finding
ingestor.

## Web UI (v0.8+)

cyweb ships with a local single-page UI for browsing findings and triggering scans — no separate install, no external dependencies. The server binds to `127.0.0.1` only (no auth, no TLS) and is meant for an operator on their own machine.

### Post-scan view (`--gui` flag, v0.8+)

Append `--gui` to a `cyweb scan` invocation. Once the scan completes, cyweb starts a local web server and prints a URL:

```bash
cyweb scan https://example.com --gui

# Optional: override the default port (8990)
cyweb scan https://example.com --gui --gui-port 9000
```

The UI shows:
- Severity tiles (critical / high / medium / low / info counts)
- Searchable, filterable findings table with per-row detail panel
- Spider tree (URLs the crawler observed)
- Active-scan request log (when `--fuzz` was enabled)
- Output log (every phase line, timestamped + searchable)
- Exports: JSON · CSV · Markdown · HTML · SARIF · XML

The server keeps running until Ctrl-C — refilter, re-export, replay individual requests without re-scanning.

### Trigger-scan view (`cyweb gui`, v0.9+)

Launch the UI **before** running a scan. The page opens in idle mode with a target-URL input and options form; click **Start scan** and the page polls progress until findings render in the same table the `--gui` flag produces.

```bash
cyweb gui

# Optional: override the default port (8990)
cyweb gui --port 9000

# Then open http://127.0.0.1:8990 in your browser.
```

Options exposed in the launcher form:
- Spider (with depth selector)
- Active fuzzing
- Full scan mode
- TLS check
- Follow redirects
- Threads / max paths / timeout

Same UI, same exports — just launched from the browser instead of the shell. Useful for demos, OSS users who prefer a UI over flags, and operators who want a stand-alone scanner without spinning up the full Cybrium platform.

API endpoints (same server, useful for scripting):
- `POST /api/scan` — start a scan; body: `{"target": "https://example.com", ...options}`. Returns `{scan_id, status: "running", target}`.
- `GET  /api/scan/:scan_id` — current state. Returns `{scan_id, state: {status: "running" | "completed" | "failed", result?, error?}}`.
- `GET  /api/scans` — list every scan in this session.
- `GET  /api/result` — latest active result (legacy `--gui` mode).
- `GET  /api/export.{json,csv,markdown,html,sarif,xml}` — download the latest result.

## What it checks

### Security Headers
- Strict-Transport-Security (HSTS)
- Content-Security-Policy (CSP)
- X-Frame-Options (clickjacking)
- X-Content-Type-Options (MIME sniffing)
- Referrer-Policy, Permissions-Policy
- Cookie security flags (HttpOnly, Secure, SameSite)
- CORS misconfiguration

### Path Discovery
- Version control exposure (`.git`, `.svn`, `.hg`)
- Environment files (`.env`, `.env.production`)
- Database files (`db.sqlite3`, `dump.sql`, `backup.sql`)
- Admin panels (`/admin`, `/wp-admin`, `/phpmyadmin`)
- Debug endpoints (`/debug`, `/actuator`, `/_profiler`, `/__debug__`)
- API documentation (`/swagger.json`, `/graphql`, `/api-docs`)
- Backup archives (`backup.tar.gz`, `backup.zip`)
- Cloud metadata endpoints

### Server Analysis
- Server version detection and outdated version warnings
- Technology fingerprinting (Apache, Nginx, IIS, PHP, WordPress, etc.)
- Default error page detection
- Stack trace / debug info in error responses

### HTTP Methods
- TRACE method (Cross-Site Tracing)
- Dangerous methods via OPTIONS (PUT, DELETE, PATCH)

### Spider/Crawler
- Link extraction and recursive crawling
- Login form security (HTTP submission, autocomplete)
- HTML comment scanning for sensitive keywords
- Scope-aware (same-origin only)

## Output Formats

### Text (default)
Colored terminal output with severity badges, CWE references, and evidence.

### JSON
```json
{
  "target": "https://example.com",
  "duration_ms": 1154,
  "summary": { "total": 12, "critical": 2, "high": 3, "medium": 4, "low": 2, "info": 1 },
  "findings": [...]
}
```

### SARIF 2.1.0
Standard format supported by GitHub Code Scanning, Azure DevOps, and the Cybrium platform.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No findings |
| 1 | Findings detected |
| 2 | Scan error |

## Cybrium Platform Integration

cyweb integrates natively with the [Cybrium](https://cybrium.ai) security platform. Findings flow directly into dashboards, compliance scorecards, and remediation workflows via SARIF output.

## License

MIT -- see [LICENSE](LICENSE).

## Related

- [cyscan](https://github.com/cybrium-ai/cyscan) -- Rust SAST engine
- [cyprobe](https://github.com/cybrium-ai/cyprobe) -- Rust OT/SCADA scanner
