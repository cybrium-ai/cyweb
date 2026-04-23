//! Active fuzzing engine — YAML-driven, context-aware injection testing.
//!
//! Phase 12 of the cyweb scan pipeline. Loads payloads from `payloads/` YAML
//! files, selects applicable payloads based on context gathered from Phases 1-11,
//! then fires them against discovered injection points and analyzes responses.
//!
//! Payload YAML files can be:
//!   - Embedded in the binary (compiled from payloads/ at build time)
//!   - Loaded from ~/.cyweb/payloads/ (user-supplied)
//!   - Loaded from --payloads <dir> (custom directory)

use crate::scanner::ServerInfo;
use crate::signatures::{Finding, Severity};
use colored::Colorize;
use reqwest::Client;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::path::Path;

// ── YAML payload schema ─────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Clone)]
pub struct PayloadFile {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub context: PayloadContext,
    pub payloads: Vec<YamlPayload>,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct PayloadContext {
    /// If true, payloads apply regardless of detected tech stack.
    #[serde(default)]
    pub any: bool,
    /// Match if Server header contains any of these (case-insensitive).
    #[serde(default)]
    pub server: Vec<String>,
    /// Match if X-Powered-By contains any of these.
    #[serde(default)]
    pub powered_by: Vec<String>,
    /// Match if any detected technology matches.
    #[serde(default)]
    pub technologies: Vec<String>,
    /// Match if Content-Type of responses contains these.
    #[serde(default)]
    pub content_type: Vec<String>,
    /// Match if these paths exist on target.
    #[serde(default)]
    pub paths: Vec<String>,
    /// Match if target listens on these ports.
    #[serde(default)]
    pub ports: Vec<u16>,
    /// Match if WAF is detected.
    #[serde(default)]
    pub waf_detected: bool,
    /// Match if specific response headers are present.
    #[serde(default)]
    pub headers: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct YamlPayload {
    pub value: String,
    pub detect: DetectConfig,
    pub id: String,
    pub title: String,
    pub severity: String,
    pub cwe: String,
    /// Where to inject: "query" (default), "header", "body", "raw_body"
    #[serde(default = "default_inject_as")]
    pub inject_as: String,
    /// Header name when inject_as=header.
    #[serde(default)]
    pub header_name: String,
    /// Prefix before payload when injecting into header.
    #[serde(default)]
    pub header_prefix: String,
    /// Content-Type when inject_as=body.
    #[serde(default)]
    pub content_type: String,
    /// Body template — PAYLOAD is replaced with the value.
    #[serde(default)]
    pub body_template: String,
    /// Extra headers to send with this payload.
    #[serde(default)]
    pub extra_headers: HashMap<String, String>,
}

fn default_inject_as() -> String {
    "query".into()
}

#[derive(Debug, Deserialize, Clone)]
pub struct DetectConfig {
    #[serde(default)]
    pub body_contains: Option<String>,
    #[serde(default)]
    pub body_regex: Option<String>,
    #[serde(default)]
    pub status_change: Option<bool>,
    #[serde(default)]
    pub status_error: Option<bool>,
    #[serde(default)]
    pub time_based_ms: Option<u64>,
    #[serde(default)]
    pub header_contains: Option<HashMap<String, String>>,
}

// ── Scan context (gathered from Phases 1-11) ─────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct FuzzContext {
    pub server: String,
    pub powered_by: String,
    pub technologies: Vec<String>,
    pub crawled_urls: Vec<String>,
    pub has_forms: bool,
    pub has_graphql: bool,
    pub has_jwt: bool,
    pub waf_detected: bool,
    pub content_types_seen: Vec<String>,
}

impl FuzzContext {
    pub fn from_scan(server_info: &ServerInfo, crawled_urls: &[String]) -> Self {
        let server = server_info.server.clone().unwrap_or_default().to_lowercase();
        let powered_by = server_info.powered_by.clone().unwrap_or_default().to_lowercase();
        let technologies: Vec<String> = server_info.technologies.iter().map(|t| t.to_lowercase()).collect();

        let has_graphql = crawled_urls.iter().any(|u| u.contains("graphql") || u.contains("/gql"));
        let has_jwt = powered_by.contains("express") || technologies.iter().any(|t| t.contains("jwt"));

        Self {
            server,
            powered_by,
            technologies,
            crawled_urls: crawled_urls.to_vec(),
            has_forms: false,
            has_graphql,
            has_jwt,
            waf_detected: false,
            content_types_seen: Vec::new(),
        }
    }
}

// ── Payload loading ──────────────────────────────────────────────────────────

/// Embedded payloads compiled into the binary.
const EMBEDDED_PAYLOADS: &[(&str, &str)] = &[
    ("sqli/error-based", include_str!("../payloads/sqli/error-based.yaml")),
    ("sqli/union-based", include_str!("../payloads/sqli/union-based.yaml")),
    ("sqli/time-based", include_str!("../payloads/sqli/time-based.yaml")),
    ("sqli/context-php", include_str!("../payloads/sqli/context-php.yaml")),
    ("xss/reflected", include_str!("../payloads/xss/reflected.yaml")),
    ("xss/waf-bypass", include_str!("../payloads/xss/waf-bypass.yaml")),
    ("ssti/generic", include_str!("../payloads/ssti/generic.yaml")),
    ("nosqli/mongodb", include_str!("../payloads/nosqli/mongodb.yaml")),
    ("ldap/injection", include_str!("../payloads/ldap/injection.yaml")),
    ("xxe/external-entity", include_str!("../payloads/xxe/external-entity.yaml")),
    ("jwt/manipulation", include_str!("../payloads/jwt/manipulation.yaml")),
    ("graphql/introspection", include_str!("../payloads/graphql/introspection.yaml")),
    ("cors/misconfiguration", include_str!("../payloads/cors/misconfiguration.yaml")),
    ("smuggling/cl-te", include_str!("../payloads/smuggling/cl-te.yaml")),
    ("cache-poison/host-header", include_str!("../payloads/cache-poison/host-header.yaml")),
    ("ssrf/cloud-metadata", include_str!("../payloads/ssrf/cloud-metadata.yaml")),
    ("cmdi/os-command", include_str!("../payloads/cmdi/os-command.yaml")),
    ("lfi/path-traversal", include_str!("../payloads/lfi/path-traversal.yaml")),
    ("ot/modbus", include_str!("../payloads/ot/modbus.yaml")),
    ("medical/hl7-fhir", include_str!("../payloads/medical/hl7-fhir.yaml")),
    ("medical/dicom", include_str!("../payloads/medical/dicom.yaml")),
    ("ai-prompt/injection", include_str!("../payloads/ai-prompt/injection.yaml")),
];

fn load_embedded_payloads() -> Vec<PayloadFile> {
    EMBEDDED_PAYLOADS
        .iter()
        .filter_map(|(name, yaml)| {
            serde_yaml::from_str::<PayloadFile>(yaml)
                .map_err(|e| eprintln!("  Warning: failed to parse embedded payload {}: {}", name, e))
                .ok()
        })
        .collect()
}

fn load_external_payloads(dir: &Path) -> Vec<PayloadFile> {
    let mut files = Vec::new();
    if !dir.exists() {
        return files;
    }
    if let Ok(entries) = walkdir(dir) {
        for path in entries {
            if path.extension().map(|e| e == "yaml" || e == "yml").unwrap_or(false) {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    match serde_yaml::from_str::<PayloadFile>(&content) {
                        Ok(pf) => files.push(pf),
                        Err(e) => eprintln!("  Warning: failed to parse {}: {}", path.display(), e),
                    }
                }
            }
        }
    }
    files
}

fn walkdir(dir: &Path) -> Result<Vec<std::path::PathBuf>, std::io::Error> {
    let mut results = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            results.extend(walkdir(&path)?);
        } else {
            results.push(path);
        }
    }
    Ok(results)
}

// ── Context matching ─────────────────────────────────────────────────────────

fn context_matches(ctx: &PayloadContext, fuzz_ctx: &FuzzContext) -> bool {
    if ctx.any {
        return true;
    }

    let mut matched = false;

    if !ctx.server.is_empty() {
        if ctx.server.iter().any(|s| fuzz_ctx.server.contains(&s.to_lowercase())) {
            matched = true;
        }
    }

    if !ctx.powered_by.is_empty() {
        if ctx.powered_by.iter().any(|p| fuzz_ctx.powered_by.contains(&p.to_lowercase())) {
            matched = true;
        }
    }

    if !ctx.technologies.is_empty() {
        if ctx.technologies.iter().any(|t| {
            let tl = t.to_lowercase();
            fuzz_ctx.technologies.iter().any(|ft| ft.contains(&tl))
        }) {
            matched = true;
        }
    }

    if ctx.waf_detected && fuzz_ctx.waf_detected {
        matched = true;
    }

    // If no context filters were specified at all, treat as "any"
    if ctx.server.is_empty()
        && ctx.powered_by.is_empty()
        && ctx.technologies.is_empty()
        && ctx.content_type.is_empty()
        && ctx.paths.is_empty()
        && ctx.ports.is_empty()
        && !ctx.waf_detected
        && ctx.headers.is_empty()
    {
        matched = true;
    }

    matched
}

fn parse_severity(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

// ── Injection point discovery ────────────────────────────────────────────────

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct InjectionPoint {
    url: String,
    param: String,
}

fn discover_injection_points(target: &str, crawled_urls: &[String]) -> Vec<InjectionPoint> {
    let mut points: HashSet<InjectionPoint> = HashSet::new();

    for url_str in crawled_urls {
        if let Ok(parsed) = url::Url::parse(url_str) {
            for (key, _val) in parsed.query_pairs() {
                points.insert(InjectionPoint {
                    url: url_str.clone(),
                    param: key.to_string(),
                });
            }
        }
    }

    if points.is_empty() {
        for param in &[
            "id", "q", "search", "page", "url", "file", "path", "name",
            "user", "email", "redirect", "next", "callback", "query",
            "sort", "order", "filter", "lang", "view", "action", "type",
        ] {
            points.insert(InjectionPoint {
                url: target.to_string(),
                param: param.to_string(),
            });
        }
    }

    points.into_iter().collect()
}

// ── Core fuzzer ──────────────────────────────────────────────────────────────

pub async fn run_fuzz(
    client: &Client,
    target: &str,
    server_info: &ServerInfo,
    crawled_urls: &[String],
    baseline_hash: u64,
    custom_payloads_dir: Option<&str>,
) -> Vec<Finding> {
    let fuzz_ctx = FuzzContext::from_scan(server_info, crawled_urls);

    // Load payloads
    let mut all_files = load_embedded_payloads();
    eprintln!("  Loaded {} embedded payload sets", all_files.len());

    // Load user payloads from ~/.cyweb/payloads/
    if let Some(home) = dirs::home_dir() {
        let user_dir = home.join(".cyweb").join("payloads");
        let user_files = load_external_payloads(&user_dir);
        if !user_files.is_empty() {
            eprintln!("  Loaded {} user payload sets from ~/.cyweb/payloads/", user_files.len());
            all_files.extend(user_files);
        }
    }

    // Load custom payloads directory
    if let Some(dir) = custom_payloads_dir {
        let custom_files = load_external_payloads(Path::new(dir));
        if !custom_files.is_empty() {
            eprintln!("  Loaded {} custom payload sets from {}", custom_files.len(), dir);
            all_files.extend(custom_files);
        }
    }

    // Filter by context
    let applicable: Vec<&PayloadFile> = all_files
        .iter()
        .filter(|f| context_matches(&f.context, &fuzz_ctx))
        .collect();

    let skipped = all_files.len() - applicable.len();
    let total_payloads: usize = applicable.iter().map(|f| f.payloads.len()).sum();

    eprintln!(
        "  {} applicable sets ({} skipped by context), {} total payloads",
        applicable.len(),
        skipped,
        total_payloads,
    );

    if !fuzz_ctx.server.is_empty() {
        eprintln!("  Server context: {}", fuzz_ctx.server.dimmed());
    }
    if !fuzz_ctx.powered_by.is_empty() {
        eprintln!("  Powered-by: {}", fuzz_ctx.powered_by.dimmed());
    }
    if !fuzz_ctx.technologies.is_empty() {
        eprintln!("  Technologies: {}", fuzz_ctx.technologies.join(", ").dimmed());
    }

    let injection_points = discover_injection_points(target, crawled_urls);
    let total_tests = injection_points.len() * total_payloads;
    eprintln!("  {} injection points x {} payloads = {} tests", injection_points.len(), total_payloads, total_tests);

    let mut findings: Vec<Finding> = Vec::new();
    let mut tested = 0usize;
    let mut found_ids: HashSet<String> = HashSet::new();

    // Get baseline status for status_change detection
    let baseline_status = client
        .get(target)
        .send()
        .await
        .map(|r| r.status().as_u16())
        .unwrap_or(200);

    for pf in &applicable {
        for payload in &pf.payloads {
            // For header/body injection, test once against the target directly
            if payload.inject_as == "header" || payload.inject_as == "body" {
                tested += 1;
                if let Some(finding) = test_special_injection(
                    client, target, payload, &pf.id, baseline_hash, baseline_status,
                ).await {
                    if !found_ids.contains(&finding.id) {
                        found_ids.insert(finding.id.clone());
                        print_finding(&finding);
                        findings.push(finding);
                    }
                }
                continue;
            }

            // Standard query parameter injection
            for point in &injection_points {
                tested += 1;
                if tested % 50 == 0 {
                    eprint!("\r  Progress: {}/{} ({} found)...", tested, total_tests, findings.len());
                }

                let finding_id = format!("CYWEB-FUZZ-{}-{}", payload.id, &point.param);
                if found_ids.contains(&finding_id) {
                    continue;
                }

                let fuzzed_url = inject_into_query(&point.url, &point.param, &payload.value);

                let start = std::time::Instant::now();
                let resp = match client.get(&fuzzed_url).send().await {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                let elapsed = start.elapsed().as_millis() as u64;
                let status = resp.status().as_u16();
                let headers = resp.headers().clone();
                let body = resp.text().await.unwrap_or_default();

                // Baseline check
                let body_hash = hash_body(&body);
                if body_hash == baseline_hash && baseline_hash != 0 {
                    continue;
                }

                if let Some(evidence) = evaluate_detection(&payload.detect, &body, &headers, status, elapsed, baseline_status) {
                    found_ids.insert(finding_id.clone());
                    let f = Finding {
                        id: finding_id,
                        title: payload.title.clone(),
                        severity: parse_severity(&payload.severity),
                        category: pf.id.clone(),
                        description: format!(
                            "Parameter '{}' at {} is vulnerable. Payload: {}",
                            point.param, point.url, payload.value
                        ),
                        evidence,
                        url: fuzzed_url,
                        cwe: Some(payload.cwe.clone()),
                        remediation: remediation_for(&pf.id),
                    };
                    print_finding(&f);
                    findings.push(f);
                }
            }
        }
    }

    eprintln!("\r  Completed: {}/{} tests, {} findings     ", tested, total_tests, findings.len());
    findings
}

// ── Special injection (headers, body) ────────────────────────────────────────

async fn test_special_injection(
    client: &Client,
    target: &str,
    payload: &YamlPayload,
    category: &str,
    baseline_hash: u64,
    baseline_status: u16,
) -> Option<Finding> {
    let finding_id = format!("CYWEB-FUZZ-{}", payload.id);

    let mut request = if payload.inject_as == "body" {
        let body = if payload.body_template.is_empty() {
            payload.value.clone()
        } else {
            payload.body_template.replace("PAYLOAD", &payload.value)
        };
        let mut req = client.post(target);
        if !payload.content_type.is_empty() {
            req = req.header("Content-Type", &payload.content_type);
        }
        req.body(body)
    } else {
        // Header injection
        let header_value = format!("{}{}", payload.header_prefix, payload.value);
        client
            .get(target)
            .header(&payload.header_name, &header_value)
    };

    // Add extra headers
    for (k, v) in &payload.extra_headers {
        request = request.header(k.as_str(), v.as_str());
    }

    let start = std::time::Instant::now();
    let resp = match request.send().await {
        Ok(r) => r,
        Err(_) => return None,
    };
    let elapsed = start.elapsed().as_millis() as u64;
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let body = resp.text().await.unwrap_or_default();

    let body_hash = hash_body(&body);
    if body_hash == baseline_hash && baseline_hash != 0 {
        return None;
    }

    evaluate_detection(&payload.detect, &body, &headers, status, elapsed, baseline_status).map(|evidence| {
        Finding {
            id: finding_id,
            title: payload.title.clone(),
            severity: parse_severity(&payload.severity),
            category: category.to_string(),
            description: format!("Vulnerable to {}. Payload: {}", payload.title, payload.value),
            evidence,
            url: target.to_string(),
            cwe: Some(payload.cwe.clone()),
            remediation: remediation_for(category),
        }
    })
}

// ── Detection evaluation ─────────────────────────────────────────────────────

fn evaluate_detection(
    detect: &DetectConfig,
    body: &str,
    headers: &reqwest::header::HeaderMap,
    status: u16,
    elapsed_ms: u64,
    baseline_status: u16,
) -> Option<String> {
    if let Some(ref needle) = detect.body_contains {
        if body.contains(needle.as_str()) {
            return Some(format!("Body contains: \"{}\"", truncate(needle, 80)));
        }
    }

    if let Some(ref pattern) = detect.body_regex {
        if let Ok(re) = regex::Regex::new(pattern) {
            if let Some(m) = re.find(body) {
                return Some(format!("Regex match: \"{}\"", truncate(m.as_str(), 80)));
            }
        }
    }

    if detect.status_error.unwrap_or(false) && status >= 500 {
        return Some(format!("HTTP {} error response", status));
    }

    if detect.status_change.unwrap_or(false) && status != baseline_status {
        return Some(format!("Status changed: {} -> {} (baseline: {})", baseline_status, status, baseline_status));
    }

    if let Some(threshold) = detect.time_based_ms {
        if elapsed_ms > threshold {
            return Some(format!("Response time: {}ms (threshold: {}ms)", elapsed_ms, threshold));
        }
    }

    if let Some(ref header_checks) = detect.header_contains {
        for (header_name, expected) in header_checks {
            if let Some(val) = headers.get(header_name.as_str()) {
                if let Ok(val_str) = val.to_str() {
                    if val_str.contains(expected.as_str()) {
                        return Some(format!("Header {}: contains \"{}\"", header_name, expected));
                    }
                }
            }
        }
    }

    None
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn inject_into_query(url: &str, param: &str, payload: &str) -> String {
    if let Ok(mut parsed) = url::Url::parse(url) {
        let mut pairs: Vec<(String, String)> = parsed
            .query_pairs()
            .map(|(k, v)| {
                if k == param {
                    (k.to_string(), payload.to_string())
                } else {
                    (k.to_string(), v.to_string())
                }
            })
            .collect();
        if !pairs.iter().any(|(k, _)| k == param) {
            pairs.push((param.to_string(), payload.to_string()));
        }
        parsed.set_query(None);
        let qs: String = pairs
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("&");
        format!("{}?{}", parsed.as_str().trim_end_matches('?'), qs)
    } else {
        format!("{}?{}={}", url, param, payload)
    }
}

fn hash_body(body: &str) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    body.chars()
        .filter(|c| c.is_alphanumeric() || c.is_whitespace())
        .collect::<String>()
        .hash(&mut h);
    h.finish()
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}...", &s[..max])
    } else {
        s.to_string()
    }
}

fn print_finding(f: &Finding) {
    let sev = match f.severity {
        Severity::Critical => "CRITICAL".red().bold(),
        Severity::High => "HIGH".red(),
        Severity::Medium => "MEDIUM".yellow(),
        Severity::Low => "LOW".blue(),
        Severity::Info => "INFO".dimmed(),
    };
    eprintln!("\n  {} {} — {}", "FOUND".red().bold(), sev, f.title);
    eprintln!("    {}", f.evidence.dimmed());
}

fn remediation_for(category: &str) -> String {
    match category {
        c if c.starts_with("sqli") => "Use parameterized queries / prepared statements. Never concatenate user input into SQL.".into(),
        c if c.starts_with("xss") => "Encode all output in HTML context. Use Content-Security-Policy. Sanitize input.".into(),
        c if c.starts_with("ssti") => "Never pass user input directly into template engines. Use sandboxed rendering.".into(),
        c if c.starts_with("cmdi") => "Never pass user input to shell commands. Use language-native APIs.".into(),
        c if c.starts_with("ssrf") => "Validate and allowlist URLs. Block internal/metadata endpoints.".into(),
        c if c.starts_with("lfi") => "Validate file paths against an allowlist. Never use user input in file operations.".into(),
        c if c.starts_with("nosqli") => "Use ORM methods instead of raw queries. Validate and sanitize input types.".into(),
        c if c.starts_with("ldap") => "Use parameterized LDAP queries. Escape special characters in search filters.".into(),
        c if c.starts_with("xxe") => "Disable external entity processing in XML parsers. Use JSON instead of XML.".into(),
        c if c.starts_with("jwt") => "Validate JWT signatures server-side. Reject alg:none. Use strong signing keys.".into(),
        c if c.starts_with("graphql") => "Disable introspection in production. Implement field-level authorization.".into(),
        c if c.starts_with("cors") => "Validate Origin against an explicit allowlist. Never reflect arbitrary origins.".into(),
        c if c.starts_with("http-smuggling") => "Normalize Transfer-Encoding handling. Use HTTP/2 end-to-end.".into(),
        c if c.starts_with("cache-poison") => "Ignore X-Forwarded-* headers from untrusted sources. Key caches on relevant headers.".into(),
        c if c.starts_with("ot") => "Implement Modbus/OT protocol authentication. Segment OT networks. Monitor write operations.".into(),
        c if c.starts_with("medical") => "Implement SMART on FHIR authentication. Restrict bulk operations. Audit all data access.".into(),
        c if c.starts_with("ai-prompt") => "Sanitize LLM inputs. Use system prompt guardrails. Never expose env vars to AI context.".into(),
        _ => "Review and remediate the identified vulnerability.".into(),
    }
}

/// Describe the fuzz engine for display.
pub fn describe() -> &'static str {
    "YAML-driven context-aware fuzzing"
}
