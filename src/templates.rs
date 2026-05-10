//! Advanced template engine — multi-step requests, extractors, matcher DSL.
//!
//! Templates define a sequence of HTTP requests with extractors that pull
//! values from responses and feed them into subsequent requests. Matchers
//! support AND/OR logic, regex, status, size, word, binary, and DSL
//! conditions. Compatible with the broad community template-YAML schema
//! (see `cyweb convert-templates`).
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
    /// v0.8.4 — workflow chaining. Templates with this block don't
    /// have their own `requests:` — they reference other templates
    /// by path / tag and conditionally fire subtemplates when the
    /// parent matches.
    #[serde(default)]
    pub workflows: Vec<WorkflowStep>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct WorkflowStep {
    /// Path to a referenced template, relative to the templates
    /// root. Mutually exclusive with `tags`.
    #[serde(default)]
    pub template: String,
    /// Tag selector — fire any template whose tag list contains
    /// any of these. Mutually exclusive with `template`.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Match conditions that gate subtemplates. Empty = always
    /// fire subtemplates if the parent ran (regardless of match).
    #[serde(default)]
    pub matchers: Vec<WorkflowMatcher>,
    /// Nested workflow steps that only fire when this step's
    /// matchers fire.
    #[serde(default)]
    pub subtemplates: Vec<WorkflowStep>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct WorkflowMatcher {
    pub name: String,
    /// "and" / "or" — how subtemplates are gated.
    #[serde(default = "default_condition")]
    pub condition: String,
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
    let mut sources: Vec<(String, usize)> = Vec::new();

    // Sprint v0.8.1 — image-baked templates take precedence. The
    // release image ships pre-converted templates at
    // /opt/cyweb/templates/ (refreshed by the nightly CI conversion
    // job — see .github/workflows/refresh-templates.yml). Operators
    // running cyweb from the binary can override the path via the
    // CYWEB_TEMPLATES_DIR env var, which lets a CI runner point at
    // a freshly-converted set without rebuilding the image.
    let bundled_dir = std::env::var("CYWEB_TEMPLATES_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("/opt/cyweb/templates"));
    if bundled_dir.exists() {
        let before = templates.len();
        templates.extend(load_from_dir(&bundled_dir));
        sources.push((bundled_dir.display().to_string(), templates.len() - before));
    }

    // Operator-local templates override / supplement the image-baked
    // set. Same-id templates win for whichever source loads last;
    // we load the local set after the bundled one so a hand-edited
    // override takes precedence over the upstream-converted version.
    if let Some(home) = dirs::home_dir() {
        let tpl_dir = home.join(".cyweb").join("templates");
        if tpl_dir.exists() {
            let before = templates.len();
            templates.extend(load_from_dir(&tpl_dir));
            sources.push((tpl_dir.display().to_string(), templates.len() - before));
        }
    }

    // --templates flag — explicit path. Loaded last, wins ties.
    if let Some(dir) = extra_dir {
        let before = templates.len();
        templates.extend(load_from_dir(std::path::Path::new(dir)));
        sources.push((dir.to_string(), templates.len() - before));
    }

    if !sources.is_empty() {
        eprintln!("  Loaded {} templates from:", templates.len());
        for (src, count) in &sources {
            eprintln!("    - {}  ({} templates)", src, count);
        }
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

    // v0.8.5 — interactsh OAST. If any step references
    // {{interactsh-url}} / {{interactsh-host}}, mint a per-template
    // token and stash it in `variables` so resolve_vars substitutes
    // the token-namespaced subdomain at render time. Callbacks for
    // this token are polled at the end of the template run.
    let needs_oast = tpl.requests.iter().any(|r|
        r.body.contains("interactsh")
        || r.path.iter().any(|p| p.contains("interactsh"))
        || r.headers.values().any(|v| v.contains("interactsh"))
    );
    let oast_token = if needs_oast {
        let token = crate::interactsh::mint_token();
        let host = crate::interactsh::oast_host();
        variables.insert("interactsh-url".into(), format!("{}.{}", token, host));
        variables.insert("interactsh-host".into(), format!("{}.{}", token, host));
        variables.insert("interactsh-protocol".into(), "http".into());
        Some(token)
    } else {
        None
    };

    // v0.8.5 — Non-HTTP protocol dispatch. DNS-only, TCP-only, and
    // headless templates run through their own module. We dispatch
    // BEFORE the HTTP path so a template that only carries `dns:`
    // or `tcp:` blocks doesn't fall through into the HTTP request
    // loop with zero requests.
    if !tpl.dns.is_empty() {
        findings.extend(crate::protocol_runners::run_dns(target, tpl).await);
    }
    if !tpl.tcp.is_empty() {
        findings.extend(crate::protocol_runners::run_tcp(target, tpl).await);
    }
    let is_headless = tpl.info.tags.iter().any(|t| t == "headless");
    if is_headless {
        findings.extend(crate::protocol_runners::run_headless(target, tpl).await);
        // Headless templates carry their HTTP `requests:` block but
        // it's been routed through Chrome — don't double-execute.
        return findings;
    }
    if !tpl.requests.is_empty() && (!tpl.dns.is_empty() || !tpl.tcp.is_empty()) && tpl.workflows.is_empty() {
        // Mixed templates (DNS + HTTP, TCP + HTTP) still continue to
        // the HTTP path below — DNS/TCP just augment what we found.
    }

    // v0.8.4 — Workflow templates execute differently from HTTP
    // templates: they reference other templates and chain
    // subtemplates conditionally. The full templates registry isn't
    // currently passed down to execute_template (it would be a
    // bigger refactor to thread through), so for v0.8.4 we surface
    // the workflow step as an INFO-level finding so the operator
    // can see "this workflow ran but its referenced templates need
    // to be loaded separately." Future work: thread the registry
    // through and execute referenced templates inline.
    if !tpl.workflows.is_empty() {
        for wf in &tpl.workflows {
            let target_label = if !wf.template.is_empty() {
                wf.template.clone()
            } else if !wf.tags.is_empty() {
                format!("tags={}", wf.tags.join(","))
            } else {
                "(unspecified)".into()
            };
            findings.push(Finding {
                id: format!("CYWEB-WORKFLOW-{}-{}", tpl.id, target_label),
                title: format!("Workflow chain: {} → {}", tpl.info.name, target_label),
                severity: parse_severity(&tpl.info.severity),
                category: "Workflow".into(),
                description: format!(
                    "Template `{}` is a workflow that references `{}`. {} subtemplate(s) chained on match.",
                    tpl.id, target_label, wf.subtemplates.len()
                ),
                evidence: format!("workflow step: {}", target_label),
                url: target.to_string(),
                cwe: None,
                remediation: tpl.info.remediation.clone(),
                vuln_class: None,
            });
        }
        return findings;
    }

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
                    vuln_class: None,
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

    // v0.8.5 — Poll OAST callbacks. If the template referenced
    // interactsh and any callback hit our token-namespaced
    // subdomain, that's a confirmed blind interaction (blind SSRF /
    // RCE / XXE). Each callback becomes a high-severity finding.
    if let Some(token) = oast_token {
        let callbacks = crate::interactsh::poll_callbacks(client, &token).await;
        for cb in callbacks {
            findings.push(Finding {
                id: format!("CYWEB-OAST-{}", tpl.id),
                title: format!("Out-of-band interaction confirmed: {}", tpl.info.name),
                severity: Severity::High,
                category: "Blind Interaction (OAST)".into(),
                description: format!(
                    "Target initiated a {} callback to the OAST canary subdomain — \
                     proves the injected payload reached a code path that performed \
                     network egress on attacker-controlled input. Caller: {}.",
                    cb.protocol, cb.remote_address,
                ),
                evidence: cb.raw_request,
                url: target.to_string(),
                cwe: tpl.info.cwe.first().cloned(),
                remediation: tpl.info.remediation.clone(),
                vuln_class: None,
            });
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

/// DSL evaluator for the common template-DSL patterns. v0.8.2 added
/// helper-function support (`md5`, `sha1`, `sha256`, `base64`,
/// `base64_decode`, `url_encode`, `url_decode`, `len(string)`,
/// `regex_match`) so upstream templates that use them in their
/// `dsl:` matcher expressions convert and run cleanly.
pub fn evaluate_dsl(expr: &str, body: &str, headers: &reqwest::header::HeaderMap, status: u16) -> bool {
    let expr = expr.trim();

    // AND/OR — short-circuit at the top so we don't accidentally
    // tokenise inside string literals further down. (Naive — doesn't
    // respect string-literal quoting yet; community templates rarely
    // put `&&` or `||` inside their literal strings.)
    if let Some(pos) = expr.find("&&") {
        return evaluate_dsl(&expr[..pos], body, headers, status)
            && evaluate_dsl(&expr[pos + 2..], body, headers, status);
    }
    if let Some(pos) = expr.find("||") {
        return evaluate_dsl(&expr[..pos], body, headers, status)
            || evaluate_dsl(&expr[pos + 2..], body, headers, status);
    }

    // status_code (==|!=|>=|<=|>|<) N
    if let Some(rest) = expr.strip_prefix("status_code") {
        let rest = rest.trim();
        for (op, want_eq, want_lt) in &[
            ("==", true,  false),
            ("!=", false, false),
            (">=", true,  false),
            ("<=", true,  false),
            (">",  false, false),
            ("<",  false, true),
        ] {
            if let Some(val) = rest.strip_prefix(op) {
                if let Ok(expected) = val.trim().parse::<u16>() {
                    return match *op {
                        "==" => status == expected,
                        "!=" => status != expected,
                        ">"  => status >  expected,
                        ">=" => status >= expected,
                        "<"  => status <  expected,
                        "<=" => status <= expected,
                        _    => *want_eq && !*want_lt,
                    };
                }
            }
        }
    }

    // contains(haystack, needle) — both args may be value expressions.
    if let Some(args) = call_args(expr, "contains") {
        if args.len() == 2 {
            let hay = eval_value(&args[0], body, headers, status);
            let needle = eval_value(&args[1], body, headers, status);
            return hay.contains(needle.as_str());
        }
    }

    // regex_match(pattern, source) → bool
    if let Some(args) = call_args(expr, "regex_match") {
        if args.len() == 2 {
            let pattern = eval_value(&args[0], body, headers, status);
            let source  = eval_value(&args[1], body, headers, status);
            return Regex::new(&pattern).map(|r| r.is_match(&source)).unwrap_or(false);
        }
    }

    // len(x) (==|!=|>=|<=|>|<) N — works for body, headers, or any
    // value expression.
    if expr.starts_with("len(") {
        // Find the closing paren of the len(...) call, then a comparator.
        if let Some(close) = expr.find(')') {
            let inner = &expr[4..close];
            let lhs_len = eval_value(inner, body, headers, status).len();
            let rest = expr[close + 1..].trim();
            for op in &["==", "!=", ">=", "<=", ">", "<"] {
                if let Some(val) = rest.strip_prefix(op) {
                    if let Ok(n) = val.trim().parse::<usize>() {
                        return match *op {
                            "==" => lhs_len == n,
                            "!=" => lhs_len != n,
                            ">"  => lhs_len >  n,
                            ">=" => lhs_len >= n,
                            "<"  => lhs_len <  n,
                            "<=" => lhs_len <= n,
                            _    => false,
                        };
                    }
                }
            }
        }
    }

    // Generic value-expression equality:
    //   md5(body) == "expected-hex"
    //   base64("hello") == "aGVsbG8="
    //   header("Server") == "nginx"
    for op in &["==", "!="] {
        if let Some(pos) = expr.find(op) {
            let lhs = expr[..pos].trim();
            let rhs = expr[pos + op.len()..].trim();
            let lv = eval_value(lhs, body, headers, status);
            let rv = eval_value(rhs, body, headers, status);
            return match *op {
                "==" => lv == rv,
                "!=" => lv != rv,
                _    => false,
            };
        }
    }

    false
}

/// Evaluate a value expression to a string.
///
/// Supported forms:
///   "literal"               → unquoted literal
///   123                     → "123"
///   body                    → response body
///   status_code             → status as decimal string
///   md5(x), sha1(x),        → hex digest of x
///     sha256(x)
///   base64(x), base64_decode(x)
///   url_encode(x),
///     url_decode(x)
///   header("Server")        → response header (case-insensitive)
///   concat(a, b, ...)       → string concatenation
///   <unknown>               → returned as-is so equality compares the
///                             raw token (covers identifiers that other
///                             templates might use).
fn eval_value(expr: &str, body: &str, headers: &reqwest::header::HeaderMap, status: u16) -> String {
    use base64::Engine;
    let expr = expr.trim();

    // String literal: "..." or '...'
    if (expr.starts_with('"') && expr.ends_with('"') && expr.len() >= 2)
        || (expr.starts_with('\'') && expr.ends_with('\'') && expr.len() >= 2)
    {
        return expr[1..expr.len() - 1].to_string();
    }

    // Bareword identifiers
    match expr {
        "body" | "all" => return body.to_string(),
        "status_code"  => return status.to_string(),
        ""             => return String::new(),
        _ => {}
    }

    // Function calls
    if let Some(args) = call_args(expr, "md5") {
        if args.len() == 1 {
            use md5::{Md5, Digest};
            let v = eval_value(&args[0], body, headers, status);
            return format!("{:x}", Md5::digest(v.as_bytes()));
        }
    }
    if let Some(args) = call_args(expr, "sha1") {
        if args.len() == 1 {
            use sha1::{Sha1, Digest};
            let v = eval_value(&args[0], body, headers, status);
            return format!("{:x}", Sha1::digest(v.as_bytes()));
        }
    }
    if let Some(args) = call_args(expr, "sha256") {
        if args.len() == 1 {
            use sha2::{Sha256, Digest};
            let v = eval_value(&args[0], body, headers, status);
            return format!("{:x}", Sha256::digest(v.as_bytes()));
        }
    }
    if let Some(args) = call_args(expr, "base64") {
        if args.len() == 1 {
            let v = eval_value(&args[0], body, headers, status);
            return base64::engine::general_purpose::STANDARD.encode(v.as_bytes());
        }
    }
    if let Some(args) = call_args(expr, "base64_decode") {
        if args.len() == 1 {
            let v = eval_value(&args[0], body, headers, status);
            return base64::engine::general_purpose::STANDARD
                .decode(v.as_bytes())
                .map(|b| String::from_utf8_lossy(&b).into_owned())
                .unwrap_or_default();
        }
    }
    if let Some(args) = call_args(expr, "url_encode") {
        if args.len() == 1 {
            let v = eval_value(&args[0], body, headers, status);
            return urlencoding::encode(&v).into_owned();
        }
    }
    if let Some(args) = call_args(expr, "url_decode") {
        if args.len() == 1 {
            let v = eval_value(&args[0], body, headers, status);
            return urlencoding::decode(&v)
                .map(|c| c.into_owned())
                .unwrap_or_default();
        }
    }
    if let Some(args) = call_args(expr, "header") {
        if args.len() == 1 {
            let name = eval_value(&args[0], body, headers, status);
            return headers
                .get(name.as_str())
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
        }
    }
    if let Some(args) = call_args(expr, "concat") {
        return args.iter()
            .map(|a| eval_value(a, body, headers, status))
            .collect::<Vec<_>>()
            .join("");
    }
    if let Some(args) = call_args(expr, "len") {
        if args.len() == 1 {
            return eval_value(&args[0], body, headers, status).len().to_string();
        }
    }

    // v0.8.5 — edge-case DSL helpers used by ~3% of upstream
    // templates. Each is a pure runtime expression — no side
    // effects, no I/O — so they're safe to evaluate inside the
    // matcher path.
    if expr == "unix_time()" || expr == "now()" {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs()).unwrap_or(0);
        return n.to_string();
    }
    if let Some(args) = call_args(expr, "unix_time") {
        // unix_time(offset_secs) — used by templates that want a
        // time stamp `N` seconds in the past/future.
        if args.len() == 1 {
            let offset: i64 = eval_value(&args[0], body, headers, status).parse().unwrap_or(0);
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64).unwrap_or(0);
            return (now + offset).to_string();
        }
    }
    if let Some(args) = call_args(expr, "rand_int") {
        // rand_int(min, max) — inclusive bounds. Templates use
        // this for cache-busting query params.
        use rand::Rng;
        if args.len() == 2 {
            let lo: i64 = eval_value(&args[0], body, headers, status).parse().unwrap_or(0);
            let hi: i64 = eval_value(&args[1], body, headers, status).parse().unwrap_or(lo + 1);
            if hi > lo {
                return rand::thread_rng().gen_range(lo..=hi).to_string();
            }
            return lo.to_string();
        }
        // rand_int() — full i32 range.
        if args.is_empty() {
            return rand::thread_rng().gen::<i32>().to_string();
        }
    }
    if let Some(args) = call_args(expr, "gen_random") {
        // gen_random(n) — n random alphanumeric characters.
        // Used heavily for blind-injection markers.
        use rand::Rng;
        let n: usize = if args.is_empty() {
            8
        } else {
            eval_value(&args[0], body, headers, status).parse().unwrap_or(8)
        };
        const ALPHA: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        let mut rng = rand::thread_rng();
        return (0..n).map(|_| ALPHA[rng.gen_range(0..ALPHA.len())] as char).collect();
    }
    if let Some(args) = call_args(expr, "repeat") {
        // repeat(s, n) — repeat the string n times. Buffer-overflow
        // probes use repeat("A", 5000).
        if args.len() == 2 {
            let s = eval_value(&args[0], body, headers, status);
            let n: usize = eval_value(&args[1], body, headers, status).parse().unwrap_or(0);
            // Cap at 1 MiB to keep a malformed template from OOM-ing
            // the scanner.
            let n = n.min(1_048_576 / s.len().max(1));
            return s.repeat(n);
        }
    }
    if let Some(args) = call_args(expr, "to_lower") {
        if args.len() == 1 {
            return eval_value(&args[0], body, headers, status).to_lowercase();
        }
    }
    if let Some(args) = call_args(expr, "to_upper") {
        if args.len() == 1 {
            return eval_value(&args[0], body, headers, status).to_uppercase();
        }
    }
    if let Some(args) = call_args(expr, "trim") {
        if args.len() == 1 {
            return eval_value(&args[0], body, headers, status).trim().to_string();
        }
    }
    if let Some(args) = call_args(expr, "replace") {
        if args.len() == 3 {
            let s = eval_value(&args[0], body, headers, status);
            let from = eval_value(&args[1], body, headers, status);
            let to = eval_value(&args[2], body, headers, status);
            return s.replace(&from, &to);
        }
    }
    if let Some(args) = call_args(expr, "hex_encode") {
        if args.len() == 1 {
            let v = eval_value(&args[0], body, headers, status);
            return hex::encode(v.as_bytes());
        }
    }
    if let Some(args) = call_args(expr, "hex_decode") {
        if args.len() == 1 {
            let v = eval_value(&args[0], body, headers, status);
            return hex::decode(v.as_bytes())
                .map(|b| String::from_utf8_lossy(&b).into_owned())
                .unwrap_or_default();
        }
    }

    // Number literal — return as-is (callers compare strings)
    if expr.parse::<i64>().is_ok() {
        return expr.to_string();
    }

    // Unknown identifier — return as-is so equality compares the raw
    // token (covers `foo == bar` template patterns where one side is
    // a known identifier we don't handle yet).
    expr.to_string()
}

/// Parse a function call `name(arg1, arg2, ...)` into its arg list.
/// Returns None if the input isn't a call to `name`. Handles balanced
/// parens and quoted strings so `concat(md5(body), "abc")` parses to
/// 2 args (`md5(body)` and `"abc"`), not 3.
fn call_args(expr: &str, name: &str) -> Option<Vec<String>> {
    let prefix = format!("{}(", name);
    let stripped = expr.strip_prefix(&prefix)?;
    let inner = stripped.strip_suffix(")")?;
    if inner.is_empty() {
        return Some(Vec::new());
    }

    let mut args: Vec<String> = Vec::new();
    let mut depth = 0i32;
    let mut in_str: Option<char> = None;
    let mut current = String::new();
    for ch in inner.chars() {
        if let Some(q) = in_str {
            current.push(ch);
            if ch == q { in_str = None; }
            continue;
        }
        match ch {
            '"' | '\'' => { in_str = Some(ch); current.push(ch); }
            '(' => { depth += 1; current.push(ch); }
            ')' => { depth -= 1; current.push(ch); }
            ',' if depth == 0 => {
                args.push(current.trim().to_string());
                current.clear();
            }
            c => current.push(c),
        }
    }
    if !current.is_empty() || !args.is_empty() {
        args.push(current.trim().to_string());
    }
    Some(args)
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

pub fn parse_severity(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

#[cfg(test)]
mod dsl_tests {
    use super::*;

    fn h() -> reqwest::header::HeaderMap {
        let mut m = reqwest::header::HeaderMap::new();
        m.insert("Server", "nginx/1.21".parse().unwrap());
        m.insert("Content-Type", "text/html".parse().unwrap());
        m
    }

    #[test] fn status_eq() {
        assert!( evaluate_dsl("status_code == 200", "", &h(), 200));
        assert!(!evaluate_dsl("status_code == 200", "", &h(), 404));
    }

    #[test] fn status_compare() {
        assert!( evaluate_dsl("status_code >= 400", "", &h(), 500));
        assert!( evaluate_dsl("status_code <  300", "", &h(), 200));
        assert!(!evaluate_dsl("status_code >= 400", "", &h(), 200));
    }

    #[test] fn contains_body() {
        assert!( evaluate_dsl("contains(body, \"hello\")", "hello world", &h(), 200));
        assert!(!evaluate_dsl("contains(body, \"goodbye\")", "hello world", &h(), 200));
    }

    #[test] fn md5_eq_literal() {
        // md5("hello") == "5d41402abc4b2a76b9719d911017c592"
        let e = "md5(\"hello\") == \"5d41402abc4b2a76b9719d911017c592\"";
        assert!(evaluate_dsl(e, "", &h(), 200));
    }

    #[test] fn sha1_eq_literal() {
        // sha1("hello") == "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
        let e = "sha1(\"hello\") == \"aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d\"";
        assert!(evaluate_dsl(e, "", &h(), 200));
    }

    #[test] fn sha256_eq_literal() {
        let e = "sha256(\"hello\") == \"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824\"";
        assert!(evaluate_dsl(e, "", &h(), 200));
    }

    #[test] fn base64_roundtrip() {
        assert!(evaluate_dsl("base64(\"hello\") == \"aGVsbG8=\"", "", &h(), 200));
        assert!(evaluate_dsl("base64_decode(\"aGVsbG8=\") == \"hello\"", "", &h(), 200));
    }

    #[test] fn url_encode_decode() {
        assert!(evaluate_dsl("url_encode(\"a b\") == \"a%20b\"", "", &h(), 200));
        assert!(evaluate_dsl("url_decode(\"a%20b\") == \"a b\"", "", &h(), 200));
    }

    #[test] fn header_lookup() {
        assert!(evaluate_dsl("header(\"Server\") == \"nginx/1.21\"", "", &h(), 200));
    }

    #[test] fn nested_md5_of_body() {
        // md5("hello") on the body
        let e = "md5(body) == \"5d41402abc4b2a76b9719d911017c592\"";
        assert!(evaluate_dsl(e, "hello", &h(), 200));
    }

    #[test] fn concat_with_md5() {
        // contains(concat(md5(body), "_suffix"), "_suffix")
        let e = "contains(concat(md5(body), \"_suffix\"), \"_suffix\")";
        assert!(evaluate_dsl(e, "hello", &h(), 200));
    }

    #[test] fn regex_match_works() {
        // Raw-string literals don't process escapes, so r#"\d+"# is
        // exactly four chars: \, d, +. Regex::new sees that as the
        // standard "one or more digits" pattern.
        assert!( evaluate_dsl(r#"regex_match("\d+", "abc 123 def")"#, "", &h(), 200));
        assert!(!evaluate_dsl(r#"regex_match("\d+", "abc def")"#,     "", &h(), 200));
    }

    #[test] fn len_string() {
        assert!(evaluate_dsl("len(\"hello\") == 5", "", &h(), 200));
        assert!(evaluate_dsl("len(body) >= 5", "hello world", &h(), 200));
    }

    #[test] fn compound_and() {
        let e = "status_code == 200 && contains(body, \"hello\")";
        assert!( evaluate_dsl(e, "hello", &h(), 200));
        assert!(!evaluate_dsl(e, "hello", &h(), 404));
        assert!(!evaluate_dsl(e, "world", &h(), 200));
    }

    #[test] fn call_args_balanced() {
        assert_eq!(
            call_args("foo(a, b, c)", "foo").unwrap(),
            vec!["a", "b", "c"]
        );
        // Nested parens stay grouped
        assert_eq!(
            call_args("concat(md5(body), \"x\")", "concat").unwrap(),
            vec!["md5(body)", "\"x\""]
        );
        // Comma inside string literal isn't a separator
        assert_eq!(
            call_args("contains(body, \"a, b\")", "contains").unwrap(),
            vec!["body", "\"a, b\""]
        );
    }

    // v0.8.5 — edge-case DSL helpers
    #[test] fn unix_time_nonzero() {
        let v = eval_value("unix_time()", "", &h(), 200);
        let n: u64 = v.parse().expect("unix_time should be numeric");
        assert!(n > 1_700_000_000, "unix_time should be a recent epoch second");
    }

    #[test] fn unix_time_with_offset() {
        let now: i64 = eval_value("unix_time()", "", &h(), 200).parse().unwrap();
        let plus_60: i64 = eval_value("unix_time(60)", "", &h(), 200).parse().unwrap();
        assert!(plus_60 >= now + 59 && plus_60 <= now + 61);
    }

    #[test] fn rand_int_range() {
        for _ in 0..50 {
            let v: i64 = eval_value("rand_int(10, 20)", "", &h(), 200).parse().unwrap();
            assert!(v >= 10 && v <= 20, "rand_int(10,20) returned {}", v);
        }
    }

    #[test] fn gen_random_length_and_charset() {
        let s = eval_value("gen_random(16)", "", &h(), 200);
        assert_eq!(s.len(), 16);
        assert!(s.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test] fn repeat_string() {
        let s = eval_value("repeat(\"AB\", 3)", "", &h(), 200);
        assert_eq!(s, "ABABAB");
    }

    #[test] fn repeat_capped() {
        // repeat with crazy counts must not blow memory — should cap.
        let s = eval_value("repeat(\"AAAA\", 99999999)", "", &h(), 200);
        assert!(s.len() <= 1_048_576);
    }

    #[test] fn to_lower_to_upper_trim() {
        assert_eq!(eval_value("to_lower(\"HELLO\")", "", &h(), 200), "hello");
        assert_eq!(eval_value("to_upper(\"hello\")", "", &h(), 200), "HELLO");
        assert_eq!(eval_value("trim(\"  hi  \")", "", &h(), 200), "hi");
    }

    #[test] fn replace_substring() {
        assert_eq!(
            eval_value("replace(\"hello world\", \"world\", \"cyweb\")", "", &h(), 200),
            "hello cyweb"
        );
    }

    #[test] fn hex_encode_decode_roundtrip() {
        let enc = eval_value("hex_encode(\"abc\")", "", &h(), 200);
        assert_eq!(enc, "616263");
        let dec = eval_value("hex_decode(\"616263\")", "", &h(), 200);
        assert_eq!(dec, "abc");
    }
}
