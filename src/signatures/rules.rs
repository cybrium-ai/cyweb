//! YAML-based signature rule engine.
//!
//! Rules are loaded from embedded defaults + optional external files.
//! Each rule defines a path, expected response conditions, and finding metadata.

use super::{Finding, Severity};
use futures::stream::{self, StreamExt};
use reqwest::Client;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub category: String,
    pub description: String,
    pub cwe: Option<String>,
    pub remediation: String,
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub match_status: Vec<u16>,
    #[serde(default)]
    pub match_body: Option<String>,
    #[serde(default)]
    pub match_header: Option<String>,
    #[serde(default)]
    pub match_header_value: Option<String>,
    #[serde(default)]
    pub not_match_body: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RuleSet {
    pub name: String,
    pub version: String,
    pub rules: Vec<Rule>,
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

const EMBEDDED_RULES: &str = include_str!("../../rules/default.yaml");
const EMBEDDED_NIKTO: &str = include_str!("../../rules/nikto.yaml");

pub fn load_rules(extra_path: Option<&str>, include_nikto: bool) -> Vec<Rule> {
    let mut all_rules = Vec::new();

    // Prefer ~/.cyweb/default.yaml (updated via `cyweb update-rules`) over embedded
    let home_rules = dirs::home_dir()
        .map(|h| h.join(".cyweb/default.yaml"))
        .filter(|p| p.exists());

    if let Some(ref path) = home_rules {
        if let Ok(content) = std::fs::read_to_string(path) {
            if let Ok(ruleset) = serde_yaml::from_str::<RuleSet>(&content) {
                all_rules.extend(ruleset.rules);
            }
        }
    } else {
        // Fall back to embedded rules
        if let Ok(ruleset) = serde_yaml::from_str::<RuleSet>(EMBEDDED_RULES) {
            all_rules.extend(ruleset.rules);
        }
    }

    // Full scan: include Nikto-converted rules (4,425 additional checks)
    if include_nikto {
        let home_nikto = dirs::home_dir()
            .map(|h| h.join(".cyweb/nikto.yaml"))
            .filter(|p| p.exists());

        if let Some(ref path) = home_nikto {
            if let Ok(content) = std::fs::read_to_string(path) {
                if let Ok(ruleset) = serde_yaml::from_str::<RuleSet>(&content) {
                    all_rules.extend(ruleset.rules);
                }
            }
        } else if let Ok(ruleset) = serde_yaml::from_str::<RuleSet>(EMBEDDED_NIKTO) {
            all_rules.extend(ruleset.rules);
        }
    }

    // Load external rules (additive)
    if let Some(path) = extra_path {
        if let Ok(content) = std::fs::read_to_string(path) {
            if let Ok(ruleset) = serde_yaml::from_str::<RuleSet>(&content) {
                all_rules.extend(ruleset.rules);
            }
        }
    }

    all_rules
}

pub async fn check_rules(
    client: &Client,
    target: &str,
    rules: &[Rule],
    concurrency: usize,
    baseline_hash: u64,
) -> Vec<Finding> {
    let findings: Vec<Finding> = stream::iter(rules.iter())
        .map(|rule| {
            let client = client.clone();
            let target = target.to_string();
            async move {
                let mut results = Vec::new();

                for path in &rule.paths {
                    let url = format!("{}{}", target, path);
                    let method = match rule.method.to_uppercase().as_str() {
                        "POST" => reqwest::Method::POST,
                        "PUT" => reqwest::Method::PUT,
                        "HEAD" => reqwest::Method::HEAD,
                        _ => reqwest::Method::GET,
                    };

                    let resp = match client.request(method, &url).send().await {
                        Ok(r) => r,
                        Err(_) => continue,
                    };

                    let status = resp.status().as_u16();
                    let headers = resp.headers().clone();
                    let body = resp.text().await.unwrap_or_default();

                    // Status match
                    let status_ok = rule.match_status.is_empty()
                        || rule.match_status.contains(&status);
                    if !status_ok {
                        continue;
                    }

                    // Body match
                    if let Some(ref pattern) = rule.match_body {
                        if let Ok(re) = regex::Regex::new(pattern) {
                            if !re.is_match(&body) {
                                continue;
                            }
                        }
                    }

                    // Negative body match
                    if let Some(ref pattern) = rule.not_match_body {
                        if let Ok(re) = regex::Regex::new(pattern) {
                            if re.is_match(&body) {
                                continue;
                            }
                        }
                    }

                    // Header match
                    if let Some(ref header_name) = rule.match_header {
                        let header_present = headers.get(header_name.as_str()).is_some();
                        if !header_present {
                            continue;
                        }
                        if let Some(ref expected_val) = rule.match_header_value {
                            let actual = headers
                                .get(header_name.as_str())
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("");
                            if !actual.to_lowercase().contains(&expected_val.to_lowercase()) {
                                continue;
                            }
                        }
                    }

                    // Soft-404 filter — only for rules with no body or header match
                    if rule.match_body.is_none() && rule.match_header.is_none() && baseline_hash != 0 {
                        use std::collections::hash_map::DefaultHasher;
                        use std::hash::{Hash, Hasher};
                        let mut hasher = DefaultHasher::new();
                        body.chars()
                            .filter(|c| c.is_alphanumeric() || c.is_whitespace())
                            .collect::<String>()
                            .hash(&mut hasher);
                        if hasher.finish() == baseline_hash {
                            continue;
                        }
                    }

                    results.push(Finding {
                        id: rule.id.clone(),
                        title: rule.title.clone(),
                        severity: parse_severity(&rule.severity),
                        category: rule.category.clone(),
                        description: rule.description.clone(),
                        evidence: format!("GET {} -> HTTP {} ({}B)", path, status, body.len()),
                        url: url.clone(),
                        cwe: rule.cwe.clone(),
                        remediation: rule.remediation.clone(),
                    });
                    break; // One hit per rule is enough
                }
                results
            }
        })
        .buffer_unordered(concurrency)
        .flat_map(|v| stream::iter(v))
        .collect()
        .await;

    findings
}
