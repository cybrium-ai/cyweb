//! Advanced template engine — multi-step requests, extractors, matcher DSL.
//!
//! This is the Nuclei-equivalent engine. Templates define a sequence of HTTP
//! requests with extractors that pull values from responses and feed them into
//! subsequent requests. Matchers support AND/OR logic, regex, status, size,
//! word, binary, and DSL conditions.
//!
//! Templates are loaded from `templates/` (embedded) or `~/.cyweb/templates/`.

use crate::signatures::{Finding, Severity};
use colored::Colorize;
use futures::stream::{self, StreamExt};
use regex::Regex;
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;

// ── Template schema ──────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Clone)]
pub struct Template {
    pub id: String,
    pub info: TemplateInfo,
    #[serde(default)]
    pub variables: HashMap<String, String>,
    #[serde(default)]
    pub requests: Vec<RequestStep>,
    /// DNS protocol checks.
    #[serde(default)]
    pub dns: Vec<DnsStep>,
    /// Raw TCP checks.
    #[serde(default)]
    pub tcp: Vec<TcpStep>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TemplateInfo {
    pub name: String,
    pub severity: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub reference: Vec<String>,
    #[serde(default)]
    pub cwe: Vec<String>,
    #[serde(default)]
    pub remediation: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RequestStep {
    /// HTTP method (GET, POST, PUT, DELETE, etc.)
    #[serde(default = "default_method")]
    pub method: String,
    /// Path(s) to test — supports {{BaseURL}} and {{extracted_var}} placeholders.
    #[serde(default)]
    pub path: Vec<String>,
    /// Raw HTTP request body.
    #[serde(default)]
    pub body: String,
    /// Extra headers.
    #[serde(default)]
    pub headers: HashMap<String, String>,
    /// Matchers to evaluate against the response.
    #[serde(default)]
    pub matchers: Vec<Matcher>,
    /// How matchers combine: "and" (all must match) or "or" (any must match).
    #[serde(default = "default_condition")]
    pub matchers_condition: String,
    /// Extractors to pull values from the response.
    #[serde(default)]
    pub extractors: Vec<Extractor>,
    /// Redirect following for this step.
    #[serde(default = "default_true")]
    pub redirects: bool,
    /// Max redirects to follow.
    #[serde(default = "default_max_redirects")]
    pub max_redirects: u8,
    /// Cookie reuse from previous steps.
    #[serde(default = "default_true")]
    pub cookie_reuse: bool,
}

fn default_method() -> String { "GET".into() }
fn default_condition() -> String { "or".into() }
fn default_true() -> bool { true }
fn default_max_redirects() -> u8 { 10 }

#[derive(Debug, Deserialize, Clone)]
pub struct Matcher {
    /// Type: status, word, regex, size, binary, dsl
    #[serde(rename = "type")]
    pub matcher_type: String,
    /// Values to match against (interpretation depends on type).
    #[serde(default)]
    pub words: Vec<String>,
    /// Regex patterns.
    #[serde(default)]
    pub regex: Vec<String>,
    /// HTTP status codes.
    #[serde(default)]
    pub status: Vec<u16>,
    /// Response body size.
    #[serde(default)]
    pub size: Vec<usize>,
    /// Binary patterns (hex-encoded).
    #[serde(default)]
    pub binary: Vec<String>,
    /// DSL expressions (e.g., "status_code == 200 && contains(body, 'admin')").
    #[serde(default)]
    pub dsl: Vec<String>,
    /// Where to match: body, header, all (default: body).
    #[serde(default = "default_part")]
    pub part: String,
    /// Negate the match.
    #[serde(default)]
    pub negative: bool,
    /// Internal condition: and/or for multiple values within this matcher.
    #[serde(default = "default_condition")]
    pub condition: String,
}

fn default_part() -> String { "body".into() }

#[derive(Debug, Deserialize, Clone)]
pub struct Extractor {
    /// Type: regex, kval (key-value from headers), json, xpath
    #[serde(rename = "type")]
    pub extractor_type: String,
    /// Name of the variable to store the extracted value.
    pub name: String,
    /// Regex patterns with capture groups.
    #[serde(default)]
    pub regex: Vec<String>,
    /// JSON path expressions.
    #[serde(default)]
    pub json: Vec<String>,
    /// Header names to extract values from.
    #[serde(default)]
    pub kval: Vec<String>,
    /// Which capture group to use (default: 0 = full match).
    #[serde(default)]
    pub group: usize,
    /// Where to extract from: body, header, all.
    #[serde(default = "default_part")]
    pub part: String,
    /// Internal: is this extractor just for variable setting (true) or also finding evidence (false)?
    #[serde(default = "default_true")]
    pub internal: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DnsStep {
    pub name: String,
    #[serde(rename = "type")]
    pub query_type: String,
    #[serde(default)]
    pub matchers: Vec<Matcher>,
    #[serde(default)]
    pub extractors: Vec<Extractor>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TcpStep {
    pub host: String,
    #[serde(default)]
    pub data: String,
    #[serde(default)]
    pub matchers: Vec<Matcher>,
    #[serde(default)]
    pub extractors: Vec<Extractor>,
}

// ── Template loading ─────────────────────────────────────────────────────────

pub fn load_templates(extra_dir: Option<&str>) -> Vec<Template> {
    let mut templates = Vec::new();

    // Load from ~/.cyweb/templates/
    if let Some(home) = dirs::home_dir() {
        let tpl_dir = home.join(".cyweb").join("templates");
        templates.extend(load_from_dir(&tpl_dir));
    }

    // Load from custom directory
    if let Some(dir) = extra_dir {
        templates.extend(load_from_dir(std::path::Path::new(dir)));
    }

    templates
}

fn load_from_dir(dir: &std::path::Path) -> Vec<Template> {
    let mut templates = Vec::new();
    if !dir.exists() {
        return templates;
    }
    if let Ok(entries) = walkdir(dir) {
        for path in entries {
            if path.extension().map(|e| e == "yaml" || e == "yml").unwrap_or(false) {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    match serde_yaml::from_str::<Template>(&content) {
                        Ok(tpl) => templates.push(tpl),
                        Err(_) => {} // silently skip invalid templates
                    }
                }
            }
        }
    }
    templates
}

fn walkdir(dir: &std::path::Path) -> Result<Vec<std::path::PathBuf>, std::io::Error> {
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

// ── Template execution engine ────────────────────────────────────────────────

pub async fn run_templates(
    client: &Client,
    target: &str,
    templates: &[Template],
    concurrency: usize,
) -> Vec<Finding> {
    if templates.is_empty() {
        return Vec::new();
    }

    let findings: Vec<Finding> = stream::iter(templates.iter())
        .map(|tpl| {
            let client = client.clone();
            let target = target.to_string();
            async move {
                execute_template(&client, &target, tpl).await
            }
        })
        .buffer_unordered(concurrency)
        .flat_map(|v| stream::iter(v))
        .collect()
        .await;

    findings
}

async fn execute_template(client: &Client, target: &str, tpl: &Template) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut variables: HashMap<String, String> = tpl.variables.clone();
    variables.insert("BaseURL".to_string(), target.to_string());

    // Execute HTTP request steps in sequence (multi-step)
    for (step_idx, step) in tpl.requests.iter().enumerate() {
        let paths = if step.path.is_empty() {
            vec!["/".to_string()]
        } else {
            step.path.iter().map(|p| resolve_vars(p, &variables)).collect()
        };

        for path in &paths {
            let url = if path.starts_with("http") {
                path.clone()
            } else {
                format!("{}{}", target, path)
            };

            let method = match step.method.to_uppercase().as_str() {
                "POST" => reqwest::Method::POST,
                "PUT" => reqwest::Method::PUT,
                "DELETE" => reqwest::Method::DELETE,
                "PATCH" => reqwest::Method::PATCH,
                "HEAD" => reqwest::Method::HEAD,
                "OPTIONS" => reqwest::Method::OPTIONS,
                _ => reqwest::Method::GET,
            };

            let body = resolve_vars(&step.body, &variables);

            let mut req = client.request(method, &url);

            // Add headers with variable resolution
            for (k, v) in &step.headers {
                req = req.header(k.as_str(), resolve_vars(v, &variables).as_str());
            }

            if !body.is_empty() {
                req = req.body(body);
            }

            let resp = match req.send().await {
                Ok(r) => r,
                Err(_) => continue,
            };

            let status = resp.status().as_u16();
            let resp_headers = resp.headers().clone();
            let resp_body = resp.text().await.unwrap_or_default();

            // Run extractors — store values for subsequent steps
            for extractor in &step.extractors {
                if let Some(value) = run_extractor(extractor, &resp_body, &resp_headers) {
                    variables.insert(extractor.name.clone(), value);
                }
            }

            // Evaluate matchers
            let matched = evaluate_matchers(
                &step.matchers,
                &step.matchers_condition,
                &resp_body,
                &resp_headers,
                status,
                &variables,
            );

            if matched {
                let evidence = build_evidence(&step.matchers, &resp_body, &resp_headers, status);

                findings.push(Finding {
                    id: format!("{}-step{}", tpl.id, step_idx),
                    title: tpl.info.name.clone(),
                    severity: parse_severity(&tpl.info.severity),
                    category: tpl.info.tags.first().cloned().unwrap_or_else(|| "template".into()),
                    description: tpl.info.description.clone(),
                    evidence,
                    url,
                    cwe: tpl.info.cwe.first().cloned(),
                    remediation: tpl.info.remediation.clone(),
                });

                eprintln!(
                    "  {} {} — {}",
                    "MATCH".green().bold(),
                    tpl.id.yellow(),
                    tpl.info.name,
                );
            }
        }
    }

    findings
}

// ── Variable resolution ──────────────────────────────────────────────────────

fn resolve_vars(template: &str, vars: &HashMap<String, String>) -> String {
    let mut result = template.to_string();
    for (key, value) in vars {
        result = result.replace(&format!("{{{{{}}}}}", key), value);
    }
    // Built-in helpers
    result = result.replace("{{rand_int}}", &rand_int());
    result = result.replace("{{rand_text}}", &rand_text(8));
    result = result.replace("{{unix_time}}", &chrono::Utc::now().timestamp().to_string());
    result
}

fn rand_int() -> String {
    use rand::Rng;
    rand::thread_rng().gen_range(10000..99999).to_string()
}

fn rand_text(len: usize) -> String {
    use rand::Rng;
    let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyz0123456789".chars().collect();
    let mut rng = rand::thread_rng();
    (0..len).map(|_| chars[rng.gen_range(0..chars.len())]).collect()
}

// ── Extractor engine ─────────────────────────────────────────────────────────

fn run_extractor(
    extractor: &Extractor,
    body: &str,
    headers: &reqwest::header::HeaderMap,
) -> Option<String> {
    let source = match extractor.part.as_str() {
        "header" => headers_to_string(headers),
        _ => body.to_string(),
    };

    match extractor.extractor_type.as_str() {
        "regex" => {
            for pattern in &extractor.regex {
                if let Ok(re) = Regex::new(pattern) {
                    if let Some(caps) = re.captures(&source) {
                        let group = extractor.group;
                        if let Some(m) = caps.get(group) {
                            return Some(m.as_str().to_string());
                        } else if let Some(m) = caps.get(0) {
                            return Some(m.as_str().to_string());
                        }
                    }
                }
            }
            None
        }
        "kval" => {
            for header_name in &extractor.kval {
                if let Some(val) = headers.get(header_name.as_str()) {
                    if let Ok(s) = val.to_str() {
                        return Some(s.to_string());
                    }
                }
            }
            None
        }
        "json" => {
            for path in &extractor.json {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&source) {
                    if let Some(val) = json_path(&parsed, path) {
                        return Some(val);
                    }
                }
            }
            None
        }
        _ => None,
    }
}

fn json_path(value: &serde_json::Value, path: &str) -> Option<String> {
    let parts: Vec<&str> = path.trim_start_matches('.').split('.').collect();
    let mut current = value;
    for part in parts {
        match current {
            serde_json::Value::Object(map) => {
                current = map.get(part)?;
            }
            serde_json::Value::Array(arr) => {
                let idx: usize = part.parse().ok()?;
                current = arr.get(idx)?;
            }
            _ => return None,
        }
    }
    match current {
        serde_json::Value::String(s) => Some(s.clone()),
        other => Some(other.to_string()),
    }
}

fn headers_to_string(headers: &reqwest::header::HeaderMap) -> String {
    headers
        .iter()
        .map(|(k, v)| format!("{}: {}", k, v.to_str().unwrap_or("")))
        .collect::<Vec<_>>()
        .join("\n")
}

// ── Matcher engine ───────────────────────────────────────────────────────────

fn evaluate_matchers(
    matchers: &[Matcher],
    condition: &str,
    body: &str,
    headers: &reqwest::header::HeaderMap,
    status: u16,
    variables: &HashMap<String, String>,
) -> bool {
    if matchers.is_empty() {
        return false;
    }

    let results: Vec<bool> = matchers.iter().map(|m| {
        let matched = evaluate_single_matcher(m, body, headers, status, variables);
        if m.negative { !matched } else { matched }
    }).collect();

    match condition {
        "and" => results.iter().all(|&r| r),
        _ => results.iter().any(|&r| r), // "or" is default
    }
}

fn evaluate_single_matcher(
    matcher: &Matcher,
    body: &str,
    headers: &reqwest::header::HeaderMap,
    status: u16,
    _variables: &HashMap<String, String>,
) -> bool {
    let source = match matcher.part.as_str() {
        "header" => headers_to_string(headers),
        "all" => format!("{}\n{}", headers_to_string(headers), body),
        _ => body.to_string(),
    };

    match matcher.matcher_type.as_str() {
        "status" => matcher.status.contains(&status),

        "word" => {
            let results: Vec<bool> = matcher.words.iter().map(|w| source.contains(w.as_str())).collect();
            match matcher.condition.as_str() {
                "and" => results.iter().all(|&r| r),
                _ => results.iter().any(|&r| r),
            }
        }

        "regex" => {
            let results: Vec<bool> = matcher.regex.iter().map(|pattern| {
                Regex::new(pattern).map(|re| re.is_match(&source)).unwrap_or(false)
            }).collect();
            match matcher.condition.as_str() {
                "and" => results.iter().all(|&r| r),
                _ => results.iter().any(|&r| r),
            }
        }

        "size" => matcher.size.contains(&body.len()),

        "binary" => {
            matcher.binary.iter().any(|hex| {
                if let Ok(bytes) = hex::decode(hex.replace(" ", "")) {
                    body.as_bytes().windows(bytes.len()).any(|w| w == bytes.as_slice())
                } else {
                    false
                }
            })
        }

        "dsl" => {
            // Simple DSL evaluation for common patterns
            matcher.dsl.iter().any(|expr| evaluate_dsl(expr, body, headers, status))
        }

        _ => false,
    }
}

/// Simple DSL evaluator for common Nuclei DSL patterns.
fn evaluate_dsl(expr: &str, body: &str, headers: &reqwest::header::HeaderMap, status: u16) -> bool {
    let expr = expr.trim();

    // status_code == N
    if let Some(rest) = expr.strip_prefix("status_code") {
        let rest = rest.trim();
        if let Some(val) = rest.strip_prefix("==") {
            if let Ok(expected) = val.trim().parse::<u16>() {
                return status == expected;
            }
        }
        if let Some(val) = rest.strip_prefix("!=") {
            if let Ok(expected) = val.trim().parse::<u16>() {
                return status != expected;
            }
        }
    }

    // contains(body, "string")
    if expr.starts_with("contains(") {
        if let Some(inner) = expr.strip_prefix("contains(").and_then(|s| s.strip_suffix(")")) {
            let parts: Vec<&str> = inner.splitn(2, ',').collect();
            if parts.len() == 2 {
                let source = match parts[0].trim() {
                    "body" => body,
                    "header" | "all" => &headers_to_string(headers),
                    _ => body,
                };
                let needle = parts[1].trim().trim_matches('"').trim_matches('\'');
                return source.contains(needle);
            }
        }
    }

    // len(body) > N
    if expr.starts_with("len(body)") {
        let rest = expr.strip_prefix("len(body)").unwrap().trim();
        if let Some(val) = rest.strip_prefix(">") {
            if let Ok(n) = val.trim().parse::<usize>() {
                return body.len() > n;
            }
        }
        if let Some(val) = rest.strip_prefix("<") {
            if let Ok(n) = val.trim().parse::<usize>() {
                return body.len() < n;
            }
        }
    }

    // AND/OR compound expressions: expr1 && expr2
    if let Some(pos) = expr.find("&&") {
        let left = &expr[..pos];
        let right = &expr[pos + 2..];
        return evaluate_dsl(left, body, headers, status)
            && evaluate_dsl(right, body, headers, status);
    }
    if let Some(pos) = expr.find("||") {
        let left = &expr[..pos];
        let right = &expr[pos + 2..];
        return evaluate_dsl(left, body, headers, status)
            || evaluate_dsl(right, body, headers, status);
    }

    false
}

fn build_evidence(
    matchers: &[Matcher],
    body: &str,
    headers: &reqwest::header::HeaderMap,
    status: u16,
) -> String {
    let mut parts = Vec::new();
    parts.push(format!("HTTP {}", status));

    for m in matchers {
        match m.matcher_type.as_str() {
            "word" => {
                for w in &m.words {
                    if body.contains(w.as_str()) {
                        parts.push(format!("Body contains: \"{}\"", truncate(w, 60)));
                    }
                }
            }
            "regex" => {
                for pattern in &m.regex {
                    if let Ok(re) = Regex::new(pattern) {
                        if let Some(mat) = re.find(body) {
                            parts.push(format!("Regex match: \"{}\"", truncate(mat.as_str(), 60)));
                        }
                    }
                }
            }
            _ => {}
        }
    }

    parts.join(" | ")
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() > max { format!("{}...", &s[..max]) } else { s.to_string() }
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
