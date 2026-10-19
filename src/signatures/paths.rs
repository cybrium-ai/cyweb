//! Path/file discovery with false-positive reduction.
//!
//! Strategy: the caller captures a [`SoftError`] fingerprint (from random
//! nonexistent paths) once per host and passes it in. Any 200 whose response
//! is indistinguishable from that catch-all fingerprint is a soft-404 from an
//! SPA or catch-all route and is ignored.
//!
//! Additionally, certain paths require content validation — e.g. `.env` must
//! contain `=`, `.git/config` must contain `[core]` — and structured-file
//! paths that return an HTML document are rejected as the SPA shell.

use super::soft404::{self, SoftError};
use super::{Finding, Severity};
use futures::stream::{self, StreamExt};
use reqwest::Client;

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

/// Paths whose response is expected to be a specific NON-HTML file type
/// (git/svn/hg metadata, env, config, JSON, SQL, SQLite, archive). If such a
/// path returns something that looks like an HTML document it is the SPA shell
/// / an error page, never the file we asked for — so a loose body validator
/// (e.g. `.env` → contains `=`, `config.json` → contains `{`) must not fire on
/// it. This is the content-type sanity guard that complements the soft-404
/// fingerprint comparison.
fn expects_non_html(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    p.contains("/.git/")
        || p.contains("/.svn/")
        || p.contains("/.hg/")
        || p.starts_with("/.env")
        || p.ends_with(".env")
        || p.ends_with(".json")
        || p.ends_with(".yml")
        || p.ends_with(".yaml")
        || p.ends_with(".sql")
        || p.ends_with(".sqlite")
        || p.ends_with(".sqlite3")
        || p.ends_with(".zip")
        || p.ends_with(".tar.gz")
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
    soft: &SoftError,
) -> (Vec<Finding>, usize) {
    // v0.9 — collect by-clone (owned `PathCheck`) so the closure
    // doesn't carry a lifetime to `PATHS`. Same reason as rules.rs:
    // borrowed iterator items break `tokio::spawn` HRTB inference
    // when the run_scan future is sent across the spawn boundary.
    let checks: Vec<PathCheck> = PATHS.iter().take(max_paths).cloned().collect();
    let total = checks.len();

    let findings: Vec<Finding> = stream::iter(checks)
        .map(|check| {
            let client = client.clone();
            let target = target.to_string();
            let validator = check.validator.clone();
            let soft = soft.clone();
            async move {
                let url = format!("{}{}", target, check.path);
                match client.get(&url).send().await {
                    Ok(resp) => {
                        let status = resp.status().as_u16();

                        if status == 200 {
                            // Read body for validation
                            let body = resp.text().await.unwrap_or_default();

                            // Soft-404 / catch-all check: if the response is
                            // indistinguishable from the fingerprint captured
                            // from a random nonexistent path, this host serves
                            // index.html (or a fixed error page) for everything
                            // — a 200 proves nothing. Suppress.
                            if soft.matches(status, &body) {
                                return None;
                            }

                            // Content-type sanity: a check for a structured
                            // non-HTML file (git/env/json/sql/...) that comes
                            // back as an HTML document is the SPA shell, not
                            // the file. Don't let a loose body validator fire.
                            if expects_non_html(check.path) && soft404::looks_like_html(&body) {
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
                                vuln_class: None,
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
                                vuln_class: None,
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
                                vuln_class: None,
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

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::soft404::{looks_like_html, normalized_hash, SoftError};

    const SPA_INDEX: &str = "<!doctype html><html><head><title>Cybrium</title>\
        <script src=\"/assets/index-a1b2c3.js\"></script></head>\
        <body><div id=\"root\"></div></body></html>";

    fn catch_all() -> SoftError {
        SoftError { is_catch_all: true, status: 200, body_hash: normalized_hash(SPA_INDEX), body_len: SPA_INDEX.len() }
    }

    // Structured-file paths are correctly classified.
    #[test]
    fn expects_non_html_covers_structured_files() {
        assert!(expects_non_html("/.git/config"));
        assert!(expects_non_html("/.env"));
        assert!(expects_non_html("/.env.production"));
        assert!(expects_non_html("/config.json"));
        assert!(expects_non_html("/db.sqlite3"));
        assert!(expects_non_html("/backup.tar.gz"));
        // Admin panels / HTML pages are NOT structured-file checks.
        assert!(!expects_non_html("/admin"));
        assert!(!expects_non_html("/wp-login.php"));
    }

    // The /config.json FP path: catch-all serves index.html (contains `{` in a
    // script? no — but the loose `{` validator would match any inline JSON).
    // Both the soft-404 fingerprint AND the html content-type guard suppress it.
    #[test]
    fn spa_index_on_structured_path_is_suppressed_two_ways() {
        let soft = catch_all();
        // (1) fingerprint match — identical body.
        assert!(soft.matches(200, SPA_INDEX));
        // (2) content-type guard — the path expects JSON, body is HTML.
        assert!(expects_non_html("/config.json"));
        assert!(looks_like_html(SPA_INDEX));
    }

    // A genuinely exposed /.git/config with git-looking content still validates
    // and is NOT suppressed: it isn't the catch-all body and isn't HTML.
    #[test]
    fn real_git_config_still_fires() {
        let soft = catch_all();
        let git = "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\
                   [remote \"origin\"]\n\turl = git@github.com:acme/secret.git\n";
        assert!(!soft.matches(200, git), "real git config is not the catch-all body");
        assert!(!looks_like_html(git), "git config is not HTML");
        assert!(validate(git, &Validator::BodyContains("[core]")), "git config validates");
    }

    // A real exposed .env on a non-catch-all host (server returns true 404s)
    // fires: matches() is a no-op, validator passes.
    #[test]
    fn real_env_on_normal_server_still_fires() {
        let no_catch_all = SoftError { is_catch_all: false, status: 404, body_hash: 0, body_len: 0 };
        let env = "SECRET_KEY=supersecret\nDATABASE_URL=postgres://u:p@db/app\n";
        assert!(!no_catch_all.matches(200, env));
        assert!(!looks_like_html(env));
        assert!(validate(env, &Validator::BodyContains("=")));
    }
}
