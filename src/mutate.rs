//! Mutate — guess additional file/directory names by brute-force patterns.
//!
//! Modes (matching Nikto):
//!   1 — Test all files with common extensions (.bak, .old, .tmp, etc.)
//!   2 — Guess password/credential file names
//!   3 — Enumerate usernames via Apache ~user
//!   4 — Enumerate usernames via cgiwrap
//!   5 — Guess directory names from a built-in dictionary
//!   6 — All of the above

use crate::signatures::{Finding, Severity};
use futures::stream::{self, StreamExt};
use reqwest::Client;

const BACKUP_EXTENSIONS: &[&str] = &[
    ".bak", ".old", ".orig", ".tmp", ".save", ".swp", ".swo",
    "~", ".copy", ".backup", ".dist", ".disabled",
    ".1", ".2", "_backup", "_old", "_bak",
];

const PASSWORD_FILES: &[&str] = &[
    "/etc/passwd", "/etc/shadow", "/.htpasswd", "/.htaccess",
    "/wp-config.php.bak", "/config.php.bak", "/settings.py.bak",
    "/credentials.txt", "/passwords.txt", "/secrets.txt",
    "/users.txt", "/admin.txt", "/login.txt",
    "/.pgpass", "/.my.cnf", "/.netrc",
    "/web.config.bak", "/appsettings.json.bak",
];

const COMMON_USERNAMES: &[&str] = &[
    "admin", "root", "test", "user", "webmaster", "www",
    "ftp", "guest", "info", "mail", "mysql", "operator",
    "nobody", "apache", "nginx", "www-data",
];

const COMMON_DIRS: &[&str] = &[
    "admin", "backup", "backups", "config", "conf", "data", "database",
    "db", "debug", "dev", "docs", "files", "hidden", "images", "img",
    "includes", "internal", "log", "logs", "media", "old", "private",
    "secret", "secrets", "staging", "static", "temp", "test", "tests",
    "tmp", "upload", "uploads", "users", "var", "vendor", "web",
    "api", "v1", "v2", "assets", "build", "dist", "public",
    "src", "lib", "bin", "etc", "opt", "srv",
];

pub async fn run_mutate(
    client: &Client,
    target: &str,
    mode: u8,
    concurrency: usize,
    baseline_hash: u64,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    if mode == 1 || mode == 6 {
        findings.extend(check_backup_extensions(client, target, concurrency, baseline_hash).await);
    }
    if mode == 2 || mode == 6 {
        findings.extend(check_password_files(client, target, concurrency, baseline_hash).await);
    }
    if mode == 3 || mode == 6 {
        findings.extend(enumerate_users_apache(client, target, concurrency).await);
    }
    if mode == 4 || mode == 6 {
        findings.extend(enumerate_users_cgiwrap(client, target, concurrency).await);
    }
    if mode == 5 || mode == 6 {
        findings.extend(guess_directories(client, target, concurrency, baseline_hash).await);
    }

    findings
}

async fn check_backup_extensions(
    client: &Client,
    target: &str,
    concurrency: usize,
    baseline_hash: u64,
) -> Vec<Finding> {
    // Common files that might have backup copies
    let base_files = [
        "/index.html", "/index.php", "/config.php", "/settings.py",
        "/web.config", "/.htaccess", "/wp-config.php", "/application.yml",
        "/database.yml", "/secrets.yml", "/config.yml", "/app.py",
        "/manage.py", "/server.js", "/app.js", "/package.json",
    ];

    let mut urls: Vec<(String, String)> = Vec::new();
    for file in &base_files {
        for ext in BACKUP_EXTENSIONS {
            urls.push((format!("{target}{file}{ext}"), format!("{file}{ext}")));
        }
    }

    check_urls(client, urls, concurrency, baseline_hash, "Backup File", Severity::High, "CWE-530").await
}

async fn check_password_files(
    client: &Client,
    target: &str,
    concurrency: usize,
    baseline_hash: u64,
) -> Vec<Finding> {
    let urls: Vec<(String, String)> = PASSWORD_FILES
        .iter()
        .map(|p| (format!("{target}{p}"), p.to_string()))
        .collect();

    check_urls(client, urls, concurrency, baseline_hash, "Credential File", Severity::Critical, "CWE-798").await
}

async fn enumerate_users_apache(
    client: &Client,
    target: &str,
    concurrency: usize,
) -> Vec<Finding> {
    let urls: Vec<(String, String)> = COMMON_USERNAMES
        .iter()
        .map(|u| (format!("{target}/~{u}/"), format!("/~{u}/")))
        .collect();

    let findings: Vec<Finding> = stream::iter(urls)
        .map(|(url, path)| {
            let client = client.clone();
            async move {
                match client.get(&url).send().await {
                    Ok(resp) if resp.status().as_u16() == 200 || resp.status().as_u16() == 301 => {
                        Some(Finding {
                            id: format!("CYWEB-MUT-USR-{}", path.replace('/', "").replace('~', "")),
                            title: format!("Apache user directory found: {path}"),
                            severity: Severity::Medium,
                            category: "User Enumeration".into(),
                            description: format!("Apache mod_userdir is enabled and user '{path}' exists."),
                            evidence: format!("GET {path} -> HTTP {}", resp.status()),
                            url,
                            cwe: Some("CWE-200".into()),
                            remediation: "Disable mod_userdir or restrict it to specific users.".into(),
                        })
                    }
                    _ => None,
                }
            }
        })
        .buffer_unordered(concurrency)
        .filter_map(|f| async { f })
        .collect()
        .await;

    findings
}

async fn enumerate_users_cgiwrap(
    client: &Client,
    target: &str,
    concurrency: usize,
) -> Vec<Finding> {
    let urls: Vec<(String, String)> = COMMON_USERNAMES
        .iter()
        .map(|u| (format!("{target}/cgi-bin/cgiwrap/~{u}"), format!("/cgi-bin/cgiwrap/~{u}")))
        .collect();

    let findings: Vec<Finding> = stream::iter(urls)
        .map(|(url, path)| {
            let client = client.clone();
            async move {
                match client.get(&url).send().await {
                    Ok(resp) if resp.status().as_u16() == 200 => {
                        Some(Finding {
                            id: format!("CYWEB-MUT-CGI-{}", path.split('~').last().unwrap_or("")),
                            title: format!("CGI user found: {path}"),
                            severity: Severity::Medium,
                            category: "User Enumeration".into(),
                            description: format!("CGIWrap user enumeration: user exists at {path}."),
                            evidence: format!("GET {path} -> HTTP 200"),
                            url,
                            cwe: Some("CWE-200".into()),
                            remediation: "Disable cgiwrap or restrict user enumeration.".into(),
                        })
                    }
                    _ => None,
                }
            }
        })
        .buffer_unordered(concurrency)
        .filter_map(|f| async { f })
        .collect()
        .await;

    findings
}

async fn guess_directories(
    client: &Client,
    target: &str,
    concurrency: usize,
    baseline_hash: u64,
) -> Vec<Finding> {
    let urls: Vec<(String, String)> = COMMON_DIRS
        .iter()
        .map(|d| (format!("{target}/{d}/"), format!("/{d}/")))
        .collect();

    check_urls(client, urls, concurrency, baseline_hash, "Directory Found", Severity::Info, "CWE-200").await
}

async fn check_urls(
    client: &Client,
    urls: Vec<(String, String)>,
    concurrency: usize,
    baseline_hash: u64,
    category: &str,
    severity: Severity,
    cwe: &str,
) -> Vec<Finding> {
    let category = category.to_string();
    let cwe = cwe.to_string();

    stream::iter(urls)
        .map(|(url, path)| {
            let client = client.clone();
            let category = category.clone();
            let cwe = cwe.clone();
            async move {
                match client.get(&url).send().await {
                    Ok(resp) if resp.status().as_u16() == 200 => {
                        let body = resp.text().await.unwrap_or_default();

                        // Soft-404 check
                        if baseline_hash != 0 {
                            use std::collections::hash_map::DefaultHasher;
                            use std::hash::{Hash, Hasher};
                            let mut hasher = DefaultHasher::new();
                            body.chars().filter(|c| c.is_alphanumeric() || c.is_whitespace())
                                .collect::<String>().hash(&mut hasher);
                            if hasher.finish() == baseline_hash {
                                return None;
                            }
                        }

                        Some(Finding {
                            id: format!("CYWEB-MUT-{}", path.replace('/', "_").replace('.', "_").trim_matches('_')),
                            title: format!("{category}: {path}"),
                            severity,
                            category: category.clone(),
                            description: format!("File or directory accessible: {path}"),
                            evidence: format!("GET {path} -> HTTP 200 ({}B)", body.len()),
                            url,
                            cwe: Some(cwe.clone()),
                            remediation: format!("Remove or restrict access to {path}"),
                        })
                    }
                    _ => None,
                }
            }
        })
        .buffer_unordered(concurrency)
        .filter_map(|f| async { f })
        .collect()
        .await
}

pub fn describe(mode: u8) -> &'static str {
    match mode {
        1 => "Backup file extensions (.bak, .old, .tmp, etc.)",
        2 => "Password/credential file names",
        3 => "Apache ~user enumeration",
        4 => "CGIWrap ~user enumeration",
        5 => "Common directory names",
        6 => "All mutate modes",
        _ => "None",
    }
}
