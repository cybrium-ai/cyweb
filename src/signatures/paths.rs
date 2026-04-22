//! Path/file discovery with false-positive reduction.
//!
//! Strategy: first request a known-nonexistent path to get the "baseline" 404
//! response (body hash + length). Any path that returns the same body is a
//! soft-404 from an SPA or catch-all route and is ignored.
//!
//! Additionally, certain paths require content validation — e.g. `.env` must
//! contain `=`, `.git/config` must contain `[core]`.

use super::{Finding, Severity};
use futures::stream::{self, StreamExt};
use reqwest::Client;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// What to look for in the response body to confirm a true positive.
#[derive(Clone)]
enum Validator {
    /// Any 200 that differs from the baseline is a finding.
    StatusOnly,
    /// Body must contain this substring (case-insensitive).
    BodyContains(&'static str),
    /// Body must match this regex.
    BodyRegex(&'static str),
    /// Body must NOT look like HTML (for binary/config file checks).
    NotHtml,
}

#[derive(Clone)]
struct PathCheck {
    path: &'static str,
    id: &'static str,
    title: &'static str,
    severity: Severity,
    description: &'static str,
    cwe: &'static str,
    validator: Validator,
}

const PATHS: &[PathCheck] = &[
    // ── Version control ─────────────────────────────────────────────────
    PathCheck { path: "/.git/config", id: "CYWEB-PTH-001", title: "Git repository exposed", severity: Severity::Critical,
        description: "Git configuration file is publicly accessible. Attackers can download the entire source code.",
        cwe: "CWE-538", validator: Validator::BodyContains("[core]") },
    PathCheck { path: "/.git/HEAD", id: "CYWEB-PTH-002", title: "Git HEAD file exposed", severity: Severity::Critical,
        description: "Git HEAD reference is accessible, confirming .git exposure.",
        cwe: "CWE-538", validator: Validator::BodyContains("ref:") },
    PathCheck { path: "/.svn/entries", id: "CYWEB-PTH-003", title: "SVN repository exposed", severity: Severity::Critical,
        description: "Subversion metadata is publicly accessible.",
        cwe: "CWE-538", validator: Validator::BodyRegex(r"^\d+") },
    PathCheck { path: "/.hg/store", id: "CYWEB-PTH-004", title: "Mercurial repository exposed", severity: Severity::Critical,
        description: "Mercurial repository data is publicly accessible.",
        cwe: "CWE-538", validator: Validator::BodyContains("data") },

    // ── Environment and config ──────────────────────────────────────────
    PathCheck { path: "/.env", id: "CYWEB-PTH-010", title: "Environment file exposed (.env)", severity: Severity::Critical,
        description: "The .env file typically contains database passwords, API keys, and secrets.",
        cwe: "CWE-200", validator: Validator::BodyContains("=") },
    PathCheck { path: "/.env.local", id: "CYWEB-PTH-011", title: "Local environment file exposed", severity: Severity::Critical,
        description: "Local environment overrides may contain sensitive development credentials.",
        cwe: "CWE-200", validator: Validator::BodyContains("=") },
    PathCheck { path: "/.env.production", id: "CYWEB-PTH-012", title: "Production environment file exposed", severity: Severity::Critical,
        description: "Production environment file with live credentials is accessible.",
        cwe: "CWE-200", validator: Validator::BodyContains("=") },
    PathCheck { path: "/config.yml", id: "CYWEB-PTH-013", title: "Configuration file exposed", severity: Severity::High,
        description: "YAML configuration file may contain secrets.",
        cwe: "CWE-200", validator: Validator::BodyContains(":") },
    PathCheck { path: "/config.json", id: "CYWEB-PTH-014", title: "Configuration file exposed (JSON)", severity: Severity::High,
        description: "JSON configuration file may contain API keys or connection strings.",
        cwe: "CWE-200", validator: Validator::BodyContains("{") },

    // ── Database files ──────────────────────────────────────────────────
    PathCheck { path: "/db.sqlite3", id: "CYWEB-PTH-020", title: "SQLite database exposed", severity: Severity::Critical,
        description: "A SQLite database file is directly downloadable.",
        cwe: "CWE-200", validator: Validator::BodyContains("SQLite") },
    PathCheck { path: "/dump.sql", id: "CYWEB-PTH-021", title: "SQL dump file exposed", severity: Severity::Critical,
        description: "Database dump containing tables and data.",
        cwe: "CWE-200", validator: Validator::BodyRegex(r"(?i)(CREATE TABLE|INSERT INTO|DROP TABLE)") },
    PathCheck { path: "/backup.sql", id: "CYWEB-PTH-022", title: "SQL backup exposed", severity: Severity::Critical,
        description: "Database backup file is publicly accessible.",
        cwe: "CWE-200", validator: Validator::BodyRegex(r"(?i)(CREATE TABLE|INSERT INTO|DROP TABLE)") },

    // ── Admin panels ────────────────────────────────────────────────────
    PathCheck { path: "/admin", id: "CYWEB-PTH-030", title: "Admin panel accessible", severity: Severity::Medium,
        description: "An admin panel is accessible.",
        cwe: "CWE-284", validator: Validator::StatusOnly },
    PathCheck { path: "/admin/login", id: "CYWEB-PTH-031", title: "Admin login page found", severity: Severity::Low,
        description: "Admin login page is discoverable.",
        cwe: "CWE-284", validator: Validator::BodyRegex(r"(?i)(password|login|sign.in)") },
    PathCheck { path: "/wp-admin", id: "CYWEB-PTH-032", title: "WordPress admin panel", severity: Severity::Low,
        description: "WordPress admin interface is accessible.",
        cwe: "CWE-284", validator: Validator::BodyContains("wp-") },
    PathCheck { path: "/wp-login.php", id: "CYWEB-PTH-033", title: "WordPress login page", severity: Severity::Info,
        description: "WordPress login page confirms WordPress is in use.",
        cwe: "CWE-200", validator: Validator::BodyContains("wp-login") },
    PathCheck { path: "/phpmyadmin", id: "CYWEB-PTH-034", title: "phpMyAdmin exposed", severity: Severity::High,
        description: "phpMyAdmin is accessible — high-value target.",
        cwe: "CWE-284", validator: Validator::BodyRegex(r"(?i)(phpmyadmin|pma)") },
    PathCheck { path: "/adminer.php", id: "CYWEB-PTH-035", title: "Adminer database tool exposed", severity: Severity::High,
        description: "Adminer database management tool is publicly accessible.",
        cwe: "CWE-284", validator: Validator::BodyContains("adminer") },

    // ── Debug and development ───────────────────────────────────────────
    PathCheck { path: "/debug", id: "CYWEB-PTH-040", title: "Debug endpoint accessible", severity: Severity::High,
        description: "Debug endpoint may expose stack traces or internal state.",
        cwe: "CWE-200", validator: Validator::StatusOnly },
    PathCheck { path: "/_profiler", id: "CYWEB-PTH-041", title: "Profiler endpoint accessible", severity: Severity::High,
        description: "Application profiler is accessible and may leak internal data.",
        cwe: "CWE-200", validator: Validator::BodyRegex(r"(?i)(profiler|symfony|debug)") },
    PathCheck { path: "/elmah.axd", id: "CYWEB-PTH-042", title: "ELMAH error log exposed", severity: Severity::High,
        description: "ASP.NET ELMAH error logging is publicly accessible.",
        cwe: "CWE-200", validator: Validator::BodyContains("elmah") },
    PathCheck { path: "/actuator", id: "CYWEB-PTH-044", title: "Spring Actuator endpoints exposed", severity: Severity::High,
        description: "Spring Boot Actuator may expose health, env, beans endpoints.",
        cwe: "CWE-200", validator: Validator::BodyContains("_links") },
    PathCheck { path: "/actuator/env", id: "CYWEB-PTH-045", title: "Spring Actuator env endpoint", severity: Severity::Critical,
        description: "Actuator env exposes all environment variables including secrets.",
        cwe: "CWE-200", validator: Validator::BodyContains("propertySources") },
    PathCheck { path: "/__debug__/", id: "CYWEB-PTH-047", title: "Django Debug Toolbar exposed", severity: Severity::High,
        description: "Django Debug Toolbar is accessible in production.",
        cwe: "CWE-200", validator: Validator::BodyContains("djdt") },

    // ── API documentation ───────────────────────────────────────────────
    PathCheck { path: "/swagger.json", id: "CYWEB-PTH-050", title: "Swagger/OpenAPI spec exposed", severity: Severity::Low,
        description: "API specification reveals all endpoints and data models.",
        cwe: "CWE-200", validator: Validator::BodyContains("swagger") },
    PathCheck { path: "/swagger-ui.html", id: "CYWEB-PTH-051", title: "Swagger UI accessible", severity: Severity::Low,
        description: "Interactive API documentation is publicly accessible.",
        cwe: "CWE-200", validator: Validator::BodyContains("swagger") },
    PathCheck { path: "/openapi.json", id: "CYWEB-PTH-053", title: "OpenAPI spec exposed", severity: Severity::Low,
        description: "OpenAPI specification file is publicly accessible.",
        cwe: "CWE-200", validator: Validator::BodyContains("openapi") },
    PathCheck { path: "/graphql", id: "CYWEB-PTH-054", title: "GraphQL endpoint found", severity: Severity::Low,
        description: "GraphQL endpoint found. Check if introspection is enabled.",
        cwe: "CWE-200", validator: Validator::BodyRegex(r"(?i)(graphql|query|mutation)") },

    // ── Backup files ────────────────────────────────────────────────────
    PathCheck { path: "/backup.tar.gz", id: "CYWEB-PTH-060", title: "Backup archive exposed", severity: Severity::Critical,
        description: "A backup archive is publicly downloadable.",
        cwe: "CWE-530", validator: Validator::NotHtml },
    PathCheck { path: "/backup.zip", id: "CYWEB-PTH-061", title: "Backup ZIP exposed", severity: Severity::Critical,
        description: "A backup ZIP file is publicly downloadable.",
        cwe: "CWE-530", validator: Validator::NotHtml },

    // ── Common info files ───────────────────────────────────────────────
    PathCheck { path: "/robots.txt", id: "CYWEB-PTH-070", title: "robots.txt found", severity: Severity::Info,
        description: "robots.txt may reveal hidden paths.",
        cwe: "CWE-200", validator: Validator::BodyRegex(r"(?i)(user-agent|disallow|allow|sitemap)") },
    PathCheck { path: "/sitemap.xml", id: "CYWEB-PTH-071", title: "Sitemap found", severity: Severity::Info,
        description: "XML sitemap reveals site structure.",
        cwe: "CWE-200", validator: Validator::BodyContains("<urlset") },
    PathCheck { path: "/.well-known/security.txt", id: "CYWEB-PTH-074", title: "security.txt found", severity: Severity::Info,
        description: "Security contact information (RFC 9116).",
        cwe: "CWE-200", validator: Validator::BodyRegex(r"(?i)(contact:|expires:)") },

    // ── Server status ───────────────────────────────────────────────────
    PathCheck { path: "/server-status", id: "CYWEB-PTH-080", title: "Apache server-status exposed", severity: Severity::High,
        description: "Apache mod_status reveals active connections and requests.",
        cwe: "CWE-200", validator: Validator::BodyContains("Apache") },
    PathCheck { path: "/server-info", id: "CYWEB-PTH-081", title: "Apache server-info exposed", severity: Severity::High,
        description: "Apache mod_info reveals full server configuration.",
        cwe: "CWE-200", validator: Validator::BodyContains("Apache") },
    PathCheck { path: "/nginx_status", id: "CYWEB-PTH-082", title: "Nginx status page exposed", severity: Severity::Medium,
        description: "Nginx stub_status module is accessible.",
        cwe: "CWE-200", validator: Validator::BodyContains("Active connections") },

    // ── Cloud metadata ──────────────────────────────────────────────────
    PathCheck { path: "/latest/meta-data/", id: "CYWEB-PTH-090", title: "Cloud metadata endpoint accessible", severity: Severity::Critical,
        description: "Cloud instance metadata accessible — may expose IAM credentials.",
        cwe: "CWE-918", validator: Validator::BodyContains("ami-id") },
];

/// Get a hash of the baseline 404 response for soft-404 detection.
async fn get_baseline(client: &Client, target: &str) -> (u64, usize) {
    let canary = format!("{}/cyweb-nonexistent-path-{}", target, uuid::Uuid::new_v4().as_simple());
    match client.get(&canary).send().await {
        Ok(resp) => {
            if let Ok(body) = resp.text().await {
                let len = body.len();
                let mut hasher = DefaultHasher::new();
                // Hash a normalized version (strip dynamic tokens like nonces)
                let normalized = body
                    .chars()
                    .filter(|c| c.is_alphanumeric() || c.is_whitespace())
                    .collect::<String>();
                normalized.hash(&mut hasher);
                (hasher.finish(), len)
            } else {
                (0, 0)
            }
        }
        Err(_) => (0, 0),
    }
}

fn hash_body(body: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    let normalized = body
        .chars()
        .filter(|c| c.is_alphanumeric() || c.is_whitespace())
        .collect::<String>();
    normalized.hash(&mut hasher);
    hasher.finish()
}

fn validate(body: &str, validator: &Validator) -> bool {
    match validator {
        Validator::StatusOnly => true,
        Validator::BodyContains(needle) => body.to_lowercase().contains(&needle.to_lowercase()),
        Validator::BodyRegex(pattern) => {
            regex::Regex::new(pattern).map_or(false, |re| re.is_match(body))
        }
        Validator::NotHtml => {
            !body.trim_start().starts_with("<!") && !body.trim_start().starts_with("<html")
        }
    }
}

pub async fn check_paths(
    client: &Client,
    target: &str,
    concurrency: usize,
    max_paths: usize,
) -> (Vec<Finding>, usize) {
    // Step 1: Establish baseline for soft-404 detection
    let (baseline_hash, baseline_len) = get_baseline(client, target).await;

    let checks: Vec<&PathCheck> = PATHS.iter().take(max_paths).collect();
    let total = checks.len();

    let findings: Vec<Finding> = stream::iter(checks)
        .map(|check| {
            let client = client.clone();
            let target = target.to_string();
            let validator = check.validator.clone();
            async move {
                let url = format!("{}{}", target, check.path);
                match client.get(&url).send().await {
                    Ok(resp) => {
                        let status = resp.status().as_u16();

                        if status == 200 {
                            // Read body for validation
                            let body = resp.text().await.unwrap_or_default();

                            // Soft-404 check: if body matches baseline, it's a catch-all
                            let body_hash = hash_body(&body);
                            let is_soft_404 = baseline_hash != 0
                                && body_hash == baseline_hash
                                && (body.len() as i64 - baseline_len as i64).unsigned_abs() < 100;

                            if is_soft_404 {
                                return None;
                            }

                            // Content validation
                            if !validate(&body, &validator) {
                                return None;
                            }

                            Some(Finding {
                                id: check.id.into(),
                                title: check.title.into(),
                                severity: check.severity,
                                category: "Path Discovery".into(),
                                description: check.description.into(),
                                evidence: format!("GET {} -> HTTP {} ({}B, validated)", check.path, status, body.len()),
                                url,
                                cwe: Some(check.cwe.into()),
                                remediation: format!("Remove or restrict access to {}", check.path),
                            })
                        } else if (status == 301 || status == 302) && !matches!(validator, Validator::StatusOnly) {
                            // Redirects on specific-content paths are usually real
                            Some(Finding {
                                id: check.id.into(),
                                title: format!("{} (redirect)", check.title),
                                severity: Severity::Info,
                                category: "Path Discovery".into(),
                                description: check.description.into(),
                                evidence: format!("GET {} -> HTTP {}", check.path, status),
                                url,
                                cwe: Some(check.cwe.into()),
                                remediation: format!("Verify access to {}", check.path),
                            })
                        } else if status == 403 && check.severity as u8 <= Severity::High as u8 {
                            Some(Finding {
                                id: format!("{}-403", check.id),
                                title: format!("{} (access denied)", check.title),
                                severity: Severity::Info,
                                category: "Path Discovery".into(),
                                description: format!("{} Path exists but returns 403.", check.description),
                                evidence: format!("GET {} -> HTTP 403", check.path),
                                url,
                                cwe: Some(check.cwe.into()),
                                remediation: "Verify that this resource is properly secured.".into(),
                            })
                        } else {
                            None
                        }
                    }
                    Err(_) => None,
                }
            }
        })
        .buffer_unordered(concurrency)
        .filter_map(|f| async { f })
        .collect()
        .await;

    (findings, total)
}
