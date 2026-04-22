//! Path/file discovery — check for common sensitive files and endpoints.

use super::{Finding, Severity};
use futures::stream::{self, StreamExt};
use reqwest::Client;

struct PathCheck {
    path: &'static str,
    id: &'static str,
    title: &'static str,
    severity: Severity,
    description: &'static str,
    cwe: &'static str,
}

const PATHS: &[PathCheck] = &[
    // Version control
    PathCheck { path: "/.git/config", id: "CYWEB-PTH-001", title: "Git repository exposed", severity: Severity::Critical, description: "Git configuration file is publicly accessible. Attackers can download the entire source code repository.", cwe: "CWE-538" },
    PathCheck { path: "/.git/HEAD", id: "CYWEB-PTH-002", title: "Git HEAD file exposed", severity: Severity::Critical, description: "Git HEAD reference is accessible, confirming a .git directory is exposed.", cwe: "CWE-538" },
    PathCheck { path: "/.svn/entries", id: "CYWEB-PTH-003", title: "SVN repository exposed", severity: Severity::Critical, description: "Subversion metadata is publicly accessible.", cwe: "CWE-538" },
    PathCheck { path: "/.hg/store", id: "CYWEB-PTH-004", title: "Mercurial repository exposed", severity: Severity::Critical, description: "Mercurial repository data is publicly accessible.", cwe: "CWE-538" },

    // Environment and config
    PathCheck { path: "/.env", id: "CYWEB-PTH-010", title: "Environment file exposed (.env)", severity: Severity::Critical, description: "The .env file typically contains database passwords, API keys, and secrets.", cwe: "CWE-200" },
    PathCheck { path: "/.env.local", id: "CYWEB-PTH-011", title: "Local environment file exposed", severity: Severity::Critical, description: "Local environment overrides may contain sensitive development credentials.", cwe: "CWE-200" },
    PathCheck { path: "/.env.production", id: "CYWEB-PTH-012", title: "Production environment file exposed", severity: Severity::Critical, description: "Production environment file with live credentials is accessible.", cwe: "CWE-200" },
    PathCheck { path: "/config.yml", id: "CYWEB-PTH-013", title: "Configuration file exposed", severity: Severity::High, description: "YAML configuration file is publicly accessible and may contain secrets.", cwe: "CWE-200" },
    PathCheck { path: "/config.json", id: "CYWEB-PTH-014", title: "Configuration file exposed (JSON)", severity: Severity::High, description: "JSON configuration file may contain API keys or database connection strings.", cwe: "CWE-200" },

    // Database files
    PathCheck { path: "/db.sqlite3", id: "CYWEB-PTH-020", title: "SQLite database exposed", severity: Severity::Critical, description: "A SQLite database file is directly downloadable.", cwe: "CWE-200" },
    PathCheck { path: "/dump.sql", id: "CYWEB-PTH-021", title: "SQL dump file exposed", severity: Severity::Critical, description: "Database dump file containing tables, data, and potentially credentials.", cwe: "CWE-200" },
    PathCheck { path: "/backup.sql", id: "CYWEB-PTH-022", title: "SQL backup exposed", severity: Severity::Critical, description: "Database backup file is publicly accessible.", cwe: "CWE-200" },

    // Admin panels
    PathCheck { path: "/admin", id: "CYWEB-PTH-030", title: "Admin panel accessible", severity: Severity::Medium, description: "An admin panel is accessible. Ensure it requires strong authentication.", cwe: "CWE-284" },
    PathCheck { path: "/admin/login", id: "CYWEB-PTH-031", title: "Admin login page found", severity: Severity::Low, description: "Admin login page is discoverable. Consider hiding or IP-restricting it.", cwe: "CWE-284" },
    PathCheck { path: "/wp-admin", id: "CYWEB-PTH-032", title: "WordPress admin panel", severity: Severity::Low, description: "WordPress admin interface is accessible.", cwe: "CWE-284" },
    PathCheck { path: "/wp-login.php", id: "CYWEB-PTH-033", title: "WordPress login page", severity: Severity::Info, description: "WordPress login page confirms WordPress is in use.", cwe: "CWE-200" },
    PathCheck { path: "/phpmyadmin", id: "CYWEB-PTH-034", title: "phpMyAdmin exposed", severity: Severity::High, description: "phpMyAdmin is accessible. This is a high-value target for attackers.", cwe: "CWE-284" },
    PathCheck { path: "/adminer.php", id: "CYWEB-PTH-035", title: "Adminer database tool exposed", severity: Severity::High, description: "Adminer database management tool is publicly accessible.", cwe: "CWE-284" },

    // Debug and development
    PathCheck { path: "/debug", id: "CYWEB-PTH-040", title: "Debug endpoint accessible", severity: Severity::High, description: "Debug endpoint may expose stack traces, environment variables, or internal state.", cwe: "CWE-200" },
    PathCheck { path: "/_profiler", id: "CYWEB-PTH-041", title: "Profiler endpoint accessible", severity: Severity::High, description: "Application profiler (Symfony/Laravel) is accessible and may leak internal data.", cwe: "CWE-200" },
    PathCheck { path: "/elmah.axd", id: "CYWEB-PTH-042", title: "ELMAH error log exposed", severity: Severity::High, description: "ASP.NET ELMAH error logging is publicly accessible, revealing stack traces and errors.", cwe: "CWE-200" },
    PathCheck { path: "/trace.axd", id: "CYWEB-PTH-043", title: "ASP.NET trace exposed", severity: Severity::High, description: "ASP.NET trace handler is accessible, leaking request details and server internals.", cwe: "CWE-200" },
    PathCheck { path: "/actuator", id: "CYWEB-PTH-044", title: "Spring Actuator endpoints exposed", severity: Severity::High, description: "Spring Boot Actuator may expose health, env, beans, and other sensitive endpoints.", cwe: "CWE-200" },
    PathCheck { path: "/actuator/env", id: "CYWEB-PTH-045", title: "Spring Actuator env endpoint", severity: Severity::Critical, description: "Spring Actuator environment endpoint exposes all environment variables including secrets.", cwe: "CWE-200" },
    PathCheck { path: "/actuator/health", id: "CYWEB-PTH-046", title: "Spring Actuator health endpoint", severity: Severity::Info, description: "Health endpoint is accessible. Usually safe but confirms Spring Boot.", cwe: "CWE-200" },
    PathCheck { path: "/__debug__/", id: "CYWEB-PTH-047", title: "Django Debug Toolbar exposed", severity: Severity::High, description: "Django Debug Toolbar is accessible in production, leaking SQL queries and settings.", cwe: "CWE-200" },

    // API documentation
    PathCheck { path: "/swagger.json", id: "CYWEB-PTH-050", title: "Swagger/OpenAPI spec exposed", severity: Severity::Low, description: "API specification is publicly accessible, revealing all endpoints and data models.", cwe: "CWE-200" },
    PathCheck { path: "/swagger-ui.html", id: "CYWEB-PTH-051", title: "Swagger UI accessible", severity: Severity::Low, description: "Interactive API documentation is publicly accessible.", cwe: "CWE-200" },
    PathCheck { path: "/api-docs", id: "CYWEB-PTH-052", title: "API documentation exposed", severity: Severity::Low, description: "API documentation endpoint is accessible.", cwe: "CWE-200" },
    PathCheck { path: "/openapi.json", id: "CYWEB-PTH-053", title: "OpenAPI spec exposed", severity: Severity::Low, description: "OpenAPI specification file is publicly accessible.", cwe: "CWE-200" },
    PathCheck { path: "/graphql", id: "CYWEB-PTH-054", title: "GraphQL endpoint found", severity: Severity::Low, description: "GraphQL endpoint is accessible. Check if introspection is enabled.", cwe: "CWE-200" },

    // Backup files
    PathCheck { path: "/backup.tar.gz", id: "CYWEB-PTH-060", title: "Backup archive exposed", severity: Severity::Critical, description: "A backup archive is publicly downloadable and may contain source code and secrets.", cwe: "CWE-530" },
    PathCheck { path: "/backup.zip", id: "CYWEB-PTH-061", title: "Backup ZIP exposed", severity: Severity::Critical, description: "A backup ZIP file is publicly downloadable.", cwe: "CWE-530" },
    PathCheck { path: "/site.tar.gz", id: "CYWEB-PTH-062", title: "Site archive exposed", severity: Severity::Critical, description: "Full site archive is publicly downloadable.", cwe: "CWE-530" },

    // Common info files
    PathCheck { path: "/robots.txt", id: "CYWEB-PTH-070", title: "robots.txt found", severity: Severity::Info, description: "robots.txt may reveal hidden paths and directories not intended for public access.", cwe: "CWE-200" },
    PathCheck { path: "/sitemap.xml", id: "CYWEB-PTH-071", title: "Sitemap found", severity: Severity::Info, description: "XML sitemap reveals the site structure.", cwe: "CWE-200" },
    PathCheck { path: "/crossdomain.xml", id: "CYWEB-PTH-072", title: "crossdomain.xml found", severity: Severity::Low, description: "Flash cross-domain policy file may allow cross-origin data access.", cwe: "CWE-942" },
    PathCheck { path: "/security.txt", id: "CYWEB-PTH-073", title: "security.txt found", severity: Severity::Info, description: "Security contact information is published (RFC 9116). Good practice.", cwe: "CWE-200" },
    PathCheck { path: "/.well-known/security.txt", id: "CYWEB-PTH-074", title: "security.txt (well-known)", severity: Severity::Info, description: "Security contact information at RFC 9116 standard path.", cwe: "CWE-200" },

    // Server status/info
    PathCheck { path: "/server-status", id: "CYWEB-PTH-080", title: "Apache server-status exposed", severity: Severity::High, description: "Apache mod_status is accessible, revealing active connections and request details.", cwe: "CWE-200" },
    PathCheck { path: "/server-info", id: "CYWEB-PTH-081", title: "Apache server-info exposed", severity: Severity::High, description: "Apache mod_info reveals full server configuration.", cwe: "CWE-200" },
    PathCheck { path: "/nginx_status", id: "CYWEB-PTH-082", title: "Nginx status page exposed", severity: Severity::Medium, description: "Nginx stub_status module is accessible.", cwe: "CWE-200" },

    // Cloud metadata
    PathCheck { path: "/latest/meta-data/", id: "CYWEB-PTH-090", title: "Cloud metadata endpoint accessible", severity: Severity::Critical, description: "AWS/cloud instance metadata is accessible via SSRF-like path. May expose IAM credentials.", cwe: "CWE-918" },
];

pub async fn check_paths(
    client: &Client,
    target: &str,
    concurrency: usize,
    max_paths: usize,
) -> (Vec<Finding>, usize) {
    let checks: Vec<&PathCheck> = PATHS.iter().take(max_paths).collect();
    let total = checks.len();

    let findings: Vec<Finding> = stream::iter(checks)
        .map(|check| {
            let client = client.clone();
            let target = target.to_string();
            async move {
                let url = format!("{}{}", target, check.path);
                match client.get(&url).send().await {
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        // 200, 301, 302, 403 are interesting (403 = exists but forbidden)
                        if status == 200 || status == 301 || status == 302 {
                            Some(Finding {
                                id: check.id.into(),
                                title: check.title.into(),
                                severity: check.severity,
                                category: "Path Discovery".into(),
                                description: check.description.into(),
                                evidence: format!("GET {} → HTTP {}", check.path, status),
                                url,
                                cwe: Some(check.cwe.into()),
                                remediation: format!("Remove or restrict access to {}", check.path),
                            })
                        } else if status == 403 && check.severity as u8 >= Severity::High as u8 {
                            Some(Finding {
                                id: format!("{}-403", check.id),
                                title: format!("{} (access denied)", check.title),
                                severity: Severity::Info,
                                category: "Path Discovery".into(),
                                description: format!("{} Path exists but returns 403 Forbidden.", check.description),
                                evidence: format!("GET {} → HTTP 403", check.path),
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
