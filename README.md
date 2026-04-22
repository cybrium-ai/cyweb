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
