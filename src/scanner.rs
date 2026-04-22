//! Core scan engine — orchestrates all checks against a target.

use crate::signatures::{self, Finding, Severity};
use colored::Colorize;
use reqwest::Client;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

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
    pub auth_bearer: Option<String>,
    pub auth_cookie: Option<String>,
    pub auth_basic: Option<String>,
    pub custom_headers: Vec<String>,
    pub proxy: Option<String>,
    pub rate_limit: u32,
    pub tls_check: bool,
    pub rules_file: Option<String>,
    pub openapi_url: Option<String>,
    pub resume: bool,
    pub full_scan: bool,
    pub vhost: Option<String>,
    pub client_cert: Option<String>,
    pub client_key: Option<String>,
    pub tuning: Option<String>,
    pub save_dir: Option<String>,
    pub no_lookup: bool,
    pub platform: String,
    pub evasion_mode: u8,
    pub mutate_mode: u8,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_info: Option<TlsInfo>,
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
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TlsInfo {
    pub subject: String,
    pub issuer: String,
    pub valid_from: String,
    pub valid_to: String,
    pub days_remaining: i64,
    pub san: Vec<String>,
    pub protocol: String,
}

/// Rate limiter — wraps a semaphore with a timed release.
pub struct RateLimiter {
    semaphore: Arc<Semaphore>,
    _interval_ms: u64,
}

impl RateLimiter {
    pub fn new(rps: u32) -> Option<Self> {
        if rps == 0 {
            return None;
        }
        let interval_ms = 1000 / rps as u64;
        Some(Self {
            semaphore: Arc::new(Semaphore::new(rps as usize)),
            _interval_ms: interval_ms,
        })
    }

    pub async fn acquire(&self) {
        let permit = self.semaphore.clone().acquire_owned().await.unwrap();
        let interval = self._interval_ms;
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(interval)).await;
            drop(permit);
        });
    }
}

pub async fn run_scan(config: ScanConfig) -> ScanResult {
    let start = Instant::now();
    let started_at = chrono::Utc::now().to_rfc3339();

    // Build HTTP client with auth + proxy
    let mut builder = Client::builder()
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
        .pool_max_idle_per_host(config.threads);

    // Proxy
    if let Some(ref proxy_url) = config.proxy {
        if let Ok(proxy) = reqwest::Proxy::all(proxy_url) {
            builder = builder.proxy(proxy);
            eprintln!("  {} {}", "Proxy:".dimmed(), proxy_url.yellow());
        }
    }

    // Client certificate auth
    if let (Some(ref cert_path), Some(ref key_path)) = (&config.client_cert, &config.client_key) {
        if let (Ok(cert_pem), Ok(key_pem)) = (std::fs::read(cert_path), std::fs::read(key_path)) {
            let mut combined = cert_pem;
            combined.extend_from_slice(b"\n");
            combined.extend_from_slice(&key_pem);
            if let Ok(identity) = reqwest::Identity::from_pem(&combined) {
                builder = builder.identity(identity);
                eprintln!("  {} client cert", "Auth:".dimmed());
            }
        }
    }

    // DNS override (no-lookup mode)
    if config.no_lookup {
        builder = builder.no_proxy();
    }

    let client = builder.build().expect("Failed to build HTTP client");

    // Build default headers with auth
    let mut default_headers = reqwest::header::HeaderMap::new();
    if let Some(ref token) = config.auth_bearer {
        default_headers.insert(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        eprintln!("  {} Bearer token", "Auth:".dimmed());
    }
    if let Some(ref cookie) = config.auth_cookie {
        default_headers.insert(
            reqwest::header::COOKIE,
            cookie.parse().unwrap(),
        );
        eprintln!("  {} Cookie", "Auth:".dimmed());
    }
    if let Some(ref basic) = config.auth_basic {
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode(basic);
        default_headers.insert(
            reqwest::header::AUTHORIZATION,
            format!("Basic {encoded}").parse().unwrap(),
        );
        eprintln!("  {} Basic", "Auth:".dimmed());
    }
    // Virtual host
    if let Some(ref vhost) = config.vhost {
        if let Ok(v) = reqwest::header::HeaderValue::from_str(vhost) {
            default_headers.insert(reqwest::header::HOST, v);
            eprintln!("  {} {}", "VHost:".dimmed(), vhost);
        }
    }

    for hdr in &config.custom_headers {
        if let Some((name, value)) = hdr.split_once(':') {
            if let (Ok(n), Ok(v)) = (
                reqwest::header::HeaderName::from_bytes(name.trim().as_bytes()),
                reqwest::header::HeaderValue::from_str(value.trim()),
            ) {
                default_headers.insert(n, v);
            }
        }
    }

    // Build an authed client if we have headers
    let client = if default_headers.is_empty() {
        client
    } else {
        Client::builder()
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
            .default_headers(default_headers)
            .build()
            .expect("Failed to build authenticated HTTP client")
    };

    // Rate limiter
    let rate_limiter = RateLimiter::new(config.rate_limit);
    if config.rate_limit > 0 {
        eprintln!("  {} {}/s", "Rate limit:".dimmed(), config.rate_limit);
    }

    // Normalize target URL
    let target = normalize_url(&config.target);
    let mut all_findings: Vec<Finding> = Vec::new();
    let mut requests_made: usize = 0;

    // ── Target info block ────────────────────────────────────────────
    let parsed = url::Url::parse(&target).ok();
    let hostname = parsed.as_ref().and_then(|u| u.host_str()).unwrap_or("unknown");
    let port = parsed.as_ref().and_then(|u| u.port_or_known_default()).unwrap_or(443);
    let is_ssl = target.starts_with("https");

    // Resolve IP
    let target_ip = {
        use std::net::ToSocketAddrs;
        format!("{}:{}", hostname, port)
            .to_socket_addrs()
            .ok()
            .and_then(|mut addrs| addrs.next())
            .map(|a| a.ip().to_string())
            .unwrap_or_else(|| "unresolved".into())
    };

    eprintln!("{}", "───────────────────────────────────────────────────".dimmed());
    eprintln!("  {} {}", "Target IP:".white().bold(), target_ip);
    eprintln!("  {} {}", "Hostname:".white().bold(), hostname);
    eprintln!("  {} {}", "Port:".white().bold(), port);
    if is_ssl {
        eprintln!("  {} {}", "SSL:".white().bold(), "yes".green());
    }
    if config.proxy.is_some() {
        eprintln!("  {} {}", "Proxy:".white().bold(), config.proxy.as_deref().unwrap_or(""));
    }
    eprintln!("  {} {}", "Start Time:".white().bold(), chrono::Local::now().format("%Y-%m-%d %H:%M:%S (%Z)"));
    eprintln!("{}", "───────────────────────────────────────────────────".dimmed());
    eprintln!();

    // Parse tuning filter
    let tuning: std::collections::HashSet<String> = config.tuning.as_deref()
        .map(|t| t.split(',').map(|s| s.trim().to_lowercase()).collect())
        .unwrap_or_default();
    let run_phase = |phase: &str| -> bool {
        tuning.is_empty() || tuning.contains(phase)
    };

    // Create save directory if needed
    if let Some(ref dir) = config.save_dir {
        std::fs::create_dir_all(dir).ok();
    }

    // Phase 1: Initial probe
    eprintln!("{}", "Phase 1: Server fingerprinting...".cyan());
    let server_info = probe_server(&client, &target).await;
    if let Some(ref s) = server_info.server {
        eprintln!("  Server: {}", s.yellow());
    }
    if let Some(ref p) = server_info.powered_by {
        eprintln!("  Powered-By: {}", p.yellow());
    }
    if !server_info.technologies.is_empty() {
        eprintln!("  Stack: {}", server_info.technologies.join(", ").dimmed());
    }
    requests_made += 1;

    // Phase 2: Security header analysis
    if run_phase("headers") {
        eprintln!("{}", "Phase 2: Security header analysis...".cyan());
        let header_findings = signatures::headers::check_headers(&client, &target).await;
        eprintln!("  {} issues found", header_findings.len());
        requests_made += 1;
        all_findings.extend(header_findings);
    }

    // Phase 3: HTTP method testing
    if run_phase("methods") {
        eprintln!("{}", "Phase 3: HTTP method testing...".cyan());
        let method_findings = signatures::methods::check_methods(&client, &target).await;
        eprintln!("  {} issues found", method_findings.len());
        requests_made += method_findings.len().max(1);
        all_findings.extend(method_findings);
    }

    // Phase 4: Path discovery
    let mut paths_checked = 0;
    if run_phase("paths") {
        eprintln!(
            "{}",
            format!("Phase 4: Path discovery ({} paths)...", config.max_paths).cyan()
        );
        let (path_findings, pc) =
            signatures::paths::check_paths(&client, &target, config.threads, config.max_paths).await;
        paths_checked = pc;
        eprintln!(
            "  {} paths checked, {} findings",
            paths_checked,
            path_findings.len()
        );
        requests_made += paths_checked;
        // Save positive responses
        if let Some(ref dir) = config.save_dir {
            for f in &path_findings {
                let fname = f.id.replace('/', "_").replace(':', "_");
                let path = std::path::Path::new(dir).join(format!("{fname}.txt"));
                std::fs::write(&path, format!("{}\n{}\n\n{}", f.url, f.evidence, f.description)).ok();
            }
        }
        all_findings.extend(path_findings);
    }

    // Phase 5: Server-specific checks
    if run_phase("server") {
        eprintln!("{}", "Phase 5: Server-specific checks...".cyan());
        let server_findings = signatures::server::check_server(&client, &target, &server_info).await;
        eprintln!("  {} issues found", server_findings.len());
        requests_made += server_findings.len().max(1);
        all_findings.extend(server_findings);
    }

    // Phase 6: YAML signature rules
    let rules = if config.full_scan {
        signatures::rules::load_rules(config.rules_file.as_deref(), true)
    } else {
        signatures::rules::load_rules(config.rules_file.as_deref(), false)
    };
    eprintln!(
        "{}",
        format!("Phase 6: Signature rules ({} rules{})...", rules.len(), if config.full_scan { " — full" } else { "" }).cyan()
    );
    let baseline_hash = compute_baseline(&client, &target).await;
    let rule_findings =
        signatures::rules::check_rules(&client, &target, &rules, config.threads, baseline_hash).await;
    eprintln!("  {} findings from {} rules", rule_findings.len(), rules.len());
    requests_made += rules.len();
    all_findings.extend(rule_findings);

    // Phase 7: TLS analysis
    let mut tls_info = None;
    if config.tls_check && target.starts_with("https") {
        eprintln!("{}", "Phase 7: TLS certificate analysis...".cyan());
        let (tls, tls_findings) = check_tls(&target).await;
        if let Some(ref t) = tls {
            eprintln!("  Issuer: {}", t.issuer.dimmed());
            eprintln!("  Expires: {} ({} days)", t.valid_to.dimmed(), t.days_remaining);
        }
        eprintln!("  {} issues found", tls_findings.len());
        all_findings.extend(tls_findings);
        tls_info = tls;
        requests_made += 1;
    }

    // Phase 8: Spider/Crawler (if enabled)
    if config.spider_enabled {
        eprintln!(
            "{}",
            format!("Phase 8: Spider (depth={})...", config.spider_depth).cyan()
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

    // Phase 9: CVE matching
    eprintln!("{}", "Phase 9: CVE matching...".cyan());
    let cve_findings = signatures::cves::match_cves(&server_info);
    if !cve_findings.is_empty() {
        eprintln!("  {} known CVEs matched!", cve_findings.len().to_string().red().bold());
    } else {
        eprintln!("  No version-specific CVEs matched");
    }
    all_findings.extend(cve_findings);

    // Phase 10: Mutate/bruteforce
    if config.mutate_mode > 0 && run_phase("mutate") {
        eprintln!(
            "{}",
            format!("Phase 10: Mutate — {} ...", crate::mutate::describe(config.mutate_mode)).cyan()
        );
        let mutate_findings = crate::mutate::run_mutate(
            &client, &target, config.mutate_mode, config.threads, baseline_hash,
        ).await;
        eprintln!("  {} findings", mutate_findings.len());
        requests_made += mutate_findings.len().max(1);
        all_findings.extend(mutate_findings);
    }

    // Evasion info (applied at request level, not a separate phase)
    if config.evasion_mode > 0 {
        eprintln!(
            "  {} Evasion mode {}: {}",
            "Note:".dimmed(),
            config.evasion_mode,
            crate::evasion::describe(config.evasion_mode),
        );
    }

    // Phase 11: OpenAPI/Swagger scanning
    if let Some(ref spec_url) = config.openapi_url {
        eprintln!("{}", format!("Phase 10: OpenAPI spec scanning ({spec_url})...").cyan());
        let api_findings = crate::openapi::scan_openapi(&client, spec_url, &target).await;
        eprintln!("  {} findings from API spec", api_findings.len());
        all_findings.extend(api_findings);
        requests_made += 10;
    } else {
        // Auto-discover OpenAPI spec
        let auto_spec = crate::openapi::scan_openapi(&client, &format!("{target}/openapi.json"), &target).await;
        if !auto_spec.is_empty() {
            eprintln!("{}", "Phase 10: OpenAPI spec auto-discovered...".cyan());
            eprintln!("  {} findings from API spec", auto_spec.len());
            all_findings.extend(auto_spec);
            requests_made += 5;
        }
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
        tls_info,
    }
}

async fn compute_baseline(client: &Client, target: &str) -> u64 {
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
}

async fn probe_server(client: &Client, target: &str) -> ServerInfo {
    match client.get(target).send().await {
        Ok(resp) => {
            let headers = resp.headers();
            ServerInfo {
                server: headers.get("server").and_then(|v| v.to_str().ok()).map(String::from),
                powered_by: headers.get("x-powered-by").and_then(|v| v.to_str().ok()).map(String::from),
                technologies: detect_technologies(headers),
                status_code: resp.status().as_u16(),
                redirect_url: headers.get("location").and_then(|v| v.to_str().ok()).map(String::from),
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
    if headers.get("x-generator").and_then(|v| v.to_str().ok()).is_some_and(|v| v.contains("WordPress")) {
        techs.push("WordPress".into());
    }
    techs
}

/// TLS certificate analysis.
async fn check_tls(target: &str) -> (Option<TlsInfo>, Vec<Finding>) {
    use std::process::Command;
    let mut findings = Vec::new();

    let host = target
        .replace("https://", "")
        .replace("http://", "")
        .split('/')
        .next()
        .unwrap_or("")
        .to_string();

    if host.is_empty() {
        return (None, findings);
    }

    // Use openssl s_client to get cert info
    let output = Command::new("openssl")
        .args(["s_client", "-connect", &format!("{host}:443"), "-servername", &host])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output();

    let output = match output {
        Ok(o) => o,
        Err(_) => return (None, findings),
    };

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{stdout}\n{stderr}");

    // Parse cert details with openssl x509
    let cert_output = Command::new("openssl")
        .args(["x509", "-noout", "-subject", "-issuer", "-dates", "-ext", "subjectAltName"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output();

    // Simpler approach: extract from s_client output
    let mut subject = String::new();
    let mut issuer = String::new();
    let mut valid_from = String::new();
    let mut valid_to = String::new();
    let mut protocol = String::new();
    let san: Vec<String> = Vec::new();

    for line in combined.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("subject=") || trimmed.starts_with("subject =") {
            subject = trimmed.splitn(2, '=').nth(1).unwrap_or("").trim().to_string();
        }
        if trimmed.starts_with("issuer=") || trimmed.starts_with("issuer =") {
            issuer = trimmed.splitn(2, '=').nth(1).unwrap_or("").trim().to_string();
        }
        if trimmed.contains("Protocol") && trimmed.contains("TLS") {
            protocol = trimmed.split(':').last().unwrap_or("").trim().to_string();
        }
        if trimmed.starts_with("notBefore=") || trimmed.starts_with("Not Before:") {
            valid_from = trimmed.splitn(2, '=').nth(1).or(trimmed.splitn(2, ':').nth(1)).unwrap_or("").trim().to_string();
        }
        if trimmed.starts_with("notAfter=") || trimmed.starts_with("Not After :") {
            valid_to = trimmed.splitn(2, '=').nth(1).or(trimmed.splitn(2, ':').nth(1)).unwrap_or("").trim().to_string();
        }
    }

    // Parse expiry for days remaining
    let days_remaining = parse_days_remaining(&valid_to);

    // Findings
    if days_remaining >= 0 && days_remaining <= 30 {
        findings.push(Finding {
            id: "CYWEB-TLS-001".into(),
            title: format!("TLS certificate expires in {} days", days_remaining),
            severity: if days_remaining <= 7 { Severity::Critical } else { Severity::High },
            category: "TLS/SSL".into(),
            description: format!("The TLS certificate expires on {valid_to}. Renew it before expiry to avoid service disruption."),
            evidence: format!("Expires: {valid_to} ({days_remaining} days remaining)"),
            url: target.into(),
            cwe: Some("CWE-295".into()),
            remediation: "Renew the TLS certificate before expiry.".into(),
        });
    }

    if days_remaining < 0 && days_remaining != i64::MAX {
        findings.push(Finding {
            id: "CYWEB-TLS-002".into(),
            title: "TLS certificate has expired".into(),
            severity: Severity::Critical,
            category: "TLS/SSL".into(),
            description: format!("The TLS certificate expired on {valid_to}."),
            evidence: format!("Expired: {valid_to}"),
            url: target.into(),
            cwe: Some("CWE-295".into()),
            remediation: "Replace the expired TLS certificate immediately.".into(),
        });
    }

    if protocol.contains("TLSv1.0") || protocol.contains("TLSv1.1") || protocol.contains("SSLv") {
        findings.push(Finding {
            id: "CYWEB-TLS-003".into(),
            title: format!("Weak TLS protocol: {protocol}"),
            severity: Severity::High,
            category: "TLS/SSL".into(),
            description: "The server supports deprecated TLS protocols vulnerable to known attacks.".into(),
            evidence: format!("Protocol: {protocol}"),
            url: target.into(),
            cwe: Some("CWE-326".into()),
            remediation: "Disable TLS 1.0, TLS 1.1, and SSLv3. Use TLS 1.2+ only.".into(),
        });
    }

    let tls = TlsInfo {
        subject,
        issuer,
        valid_from,
        valid_to,
        days_remaining,
        san,
        protocol,
    };

    (Some(tls), findings)
}

fn parse_days_remaining(date_str: &str) -> i64 {
    let trimmed = date_str.trim();
    if trimmed.is_empty() {
        return i64::MAX; // Unknown — don't flag
    }
    let formats = [
        "%b %d %H:%M:%S %Y GMT",
        "%b %e %H:%M:%S %Y GMT",
        "%b %d %H:%M:%S %Y",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%d %H:%M:%S",
        "%b %d %T %Y %Z",
    ];
    for fmt in &formats {
        if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(trimmed, fmt) {
            let expiry = dt.and_utc();
            return (expiry - chrono::Utc::now()).num_days();
        }
    }
    i64::MAX // Unknown — don't flag
}

fn normalize_url(url: &str) -> String {
    let u = if !url.starts_with("http://") && !url.starts_with("https://") {
        format!("https://{url}")
    } else {
        url.to_string()
    };
    u.trim_end_matches('/').to_string()
}
