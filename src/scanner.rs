//! Core scan engine — orchestrates all checks against a target.

use crate::signatures::{self, Finding, Severity};
use colored::Colorize;
use reqwest::Client;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub target: String,
    pub threads: usize,
    pub timeout_secs: u64,
    pub max_paths: usize,
    pub follow_redirects: bool,
    pub user_agent: String,
    pub spider_enabled: bool,
    pub spider_depth: usize,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ScanResult {
    pub target: String,
    pub started_at: String,
    pub completed_at: String,
    pub duration_ms: u64,
    pub findings: Vec<Finding>,
    pub summary: ScanSummary,
    pub server_info: ServerInfo,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ScanSummary {
    pub total: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub paths_checked: usize,
    pub requests_made: usize,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct ServerInfo {
    pub server: Option<String>,
    pub powered_by: Option<String>,
    pub technologies: Vec<String>,
    pub status_code: u16,
    pub redirect_url: Option<String>,
    pub ip_address: Option<String>,
}

pub async fn run_scan(config: ScanConfig) -> ScanResult {
    let start = Instant::now();
    let started_at = chrono::Utc::now().to_rfc3339();

    let client = Client::builder()
        .timeout(Duration::from_secs(config.timeout_secs))
        .connect_timeout(Duration::from_secs(config.timeout_secs))
        .redirect(if config.follow_redirects {
            reqwest::redirect::Policy::limited(10)
        } else {
            reqwest::redirect::Policy::none()
        })
        .user_agent(&config.user_agent)
        .danger_accept_invalid_certs(true)
        .cookie_store(true)
        .pool_max_idle_per_host(config.threads)
        .build()
        .expect("Failed to build HTTP client");

    // Normalize target URL
    let target = normalize_url(&config.target);
    let mut all_findings: Vec<Finding> = Vec::new();
    let mut requests_made: usize = 0;

    // Phase 1: Initial probe — get server info
    eprintln!("{}", "Phase 1: Server fingerprinting...".cyan());
    let server_info = probe_server(&client, &target).await;
    if let Some(ref s) = server_info.server {
        eprintln!("  Server: {}", s.yellow());
    }
    if let Some(ref p) = server_info.powered_by {
        eprintln!("  Powered-By: {}", p.yellow());
    }
    requests_made += 1;

    // Phase 2: Security header analysis
    eprintln!("{}", "Phase 2: Security header analysis...".cyan());
    let header_findings = signatures::headers::check_headers(&client, &target).await;
    eprintln!("  {} issues found", header_findings.len());
    requests_made += 1;
    all_findings.extend(header_findings);

    // Phase 3: HTTP method testing
    eprintln!("{}", "Phase 3: HTTP method testing...".cyan());
    let method_findings = signatures::methods::check_methods(&client, &target).await;
    eprintln!("  {} issues found", method_findings.len());
    requests_made += method_findings.len().max(1);
    all_findings.extend(method_findings);

    // Phase 4: Path discovery
    eprintln!(
        "{}",
        format!("Phase 4: Path discovery ({} paths)...", config.max_paths).cyan()
    );
    let (path_findings, paths_checked) =
        signatures::paths::check_paths(&client, &target, config.threads, config.max_paths).await;
    eprintln!(
        "  {} paths checked, {} findings",
        paths_checked,
        path_findings.len()
    );
    requests_made += paths_checked;
    all_findings.extend(path_findings);

    // Phase 5: Server-specific checks
    eprintln!("{}", "Phase 5: Server-specific checks...".cyan());
    let server_findings = signatures::server::check_server(&client, &target, &server_info).await;
    eprintln!("  {} issues found", server_findings.len());
    requests_made += server_findings.len().max(1);
    all_findings.extend(server_findings);

    // Phase 6: YAML signature rules (CMS, WAF, services, info disclosure)
    let rules = signatures::rules::load_rules(None);
    eprintln!(
        "{}",
        format!("Phase 6: Signature rules ({} rules)...", rules.len()).cyan()
    );
    // Reuse baseline hash from path discovery phase for soft-404 detection
    let baseline_hash = {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let canary = format!("{}/cyweb-baseline-{}", target, uuid::Uuid::new_v4().as_simple());
        match client.get(&canary).send().await {
            Ok(r) => {
                let body = r.text().await.unwrap_or_default();
                let mut h = DefaultHasher::new();
                body.chars().filter(|c| c.is_alphanumeric() || c.is_whitespace()).collect::<String>().hash(&mut h);
                h.finish()
            }
            Err(_) => 0,
        }
    };
    let rule_findings =
        signatures::rules::check_rules(&client, &target, &rules, config.threads, baseline_hash).await;
    eprintln!("  {} findings from {} rules", rule_findings.len(), rules.len());
    requests_made += rules.len();
    all_findings.extend(rule_findings);

    // Phase 7: Spider/Crawler (if enabled)
    if config.spider_enabled {
        eprintln!(
            "{}",
            format!("Phase 6: Spider (depth={})...", config.spider_depth).cyan()
        );
        let (spider_findings, spider_requests) =
            crate::crawler::crawl(&client, &target, config.spider_depth, config.threads).await;
        eprintln!(
            "  {} pages crawled, {} findings",
            spider_requests, spider_findings.len()
        );
        requests_made += spider_requests;
        all_findings.extend(spider_findings);
    }

    // Deduplicate findings
    all_findings.sort_by(|a, b| a.id.cmp(&b.id));
    all_findings.dedup_by(|a, b| a.id == b.id);

    let duration_ms = start.elapsed().as_millis() as u64;
    let completed_at = chrono::Utc::now().to_rfc3339();

    let summary = ScanSummary {
        total: all_findings.len(),
        critical: all_findings.iter().filter(|f| matches!(f.severity, Severity::Critical)).count(),
        high: all_findings.iter().filter(|f| matches!(f.severity, Severity::High)).count(),
        medium: all_findings.iter().filter(|f| matches!(f.severity, Severity::Medium)).count(),
        low: all_findings.iter().filter(|f| matches!(f.severity, Severity::Low)).count(),
        info: all_findings.iter().filter(|f| matches!(f.severity, Severity::Info)).count(),
        paths_checked,
        requests_made,
    };

    ScanResult {
        target,
        started_at,
        completed_at,
        duration_ms,
        findings: all_findings,
        summary,
        server_info,
    }
}

async fn probe_server(client: &Client, target: &str) -> ServerInfo {
    match client.get(target).send().await {
        Ok(resp) => {
            let headers = resp.headers();
            ServerInfo {
                server: headers
                    .get("server")
                    .and_then(|v| v.to_str().ok())
                    .map(String::from),
                powered_by: headers
                    .get("x-powered-by")
                    .and_then(|v| v.to_str().ok())
                    .map(String::from),
                technologies: detect_technologies(headers),
                status_code: resp.status().as_u16(),
                redirect_url: headers
                    .get("location")
                    .and_then(|v| v.to_str().ok())
                    .map(String::from),
                ip_address: None,
            }
        }
        Err(_) => ServerInfo::default(),
    }
}

fn detect_technologies(headers: &reqwest::header::HeaderMap) -> Vec<String> {
    let mut techs = Vec::new();
    if let Some(server) = headers.get("server").and_then(|v| v.to_str().ok()) {
        let s = server.to_lowercase();
        if s.contains("nginx") { techs.push("nginx".into()); }
        if s.contains("apache") { techs.push("Apache".into()); }
        if s.contains("iis") { techs.push("IIS".into()); }
        if s.contains("cloudflare") { techs.push("Cloudflare".into()); }
        if s.contains("litespeed") { techs.push("LiteSpeed".into()); }
    }
    if let Some(pb) = headers.get("x-powered-by").and_then(|v| v.to_str().ok()) {
        let p = pb.to_lowercase();
        if p.contains("php") { techs.push("PHP".into()); }
        if p.contains("asp.net") { techs.push("ASP.NET".into()); }
        if p.contains("express") { techs.push("Express.js".into()); }
        if p.contains("next.js") { techs.push("Next.js".into()); }
    }
    if headers.get("x-drupal-cache").is_some() { techs.push("Drupal".into()); }
    if headers.get("x-generator").and_then(|v| v.to_str().ok()).map_or(false, |v| v.contains("WordPress")) {
        techs.push("WordPress".into());
    }
    techs
}

fn normalize_url(url: &str) -> String {
    let u = if !url.starts_with("http://") && !url.starts_with("https://") {
        format!("https://{url}")
    } else {
        url.to_string()
    };
    u.trim_end_matches('/').to_string()
}
