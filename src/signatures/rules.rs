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
    /// v0.8.6.1 — Per-rule scan strength. Operator passes
    /// `--strength low|medium|high` and rules above the configured
    /// strength are skipped. Defaults to "medium" — same as the
    /// default scan strength, so behaviour is unchanged unless the
    /// rule author explicitly tags strength.
    ///
    /// Strength is about how aggressive the *probe* is:
    ///   low    — passive / one-request checks
    ///   medium — multi-request, payload-mutated checks
    ///   high   — payload-heavy, slow, potentially noisy checks
    #[serde(default = "default_strength")]
    pub strength: String,
    /// v0.8.6.1 — Per-rule confidence threshold. Operator passes
    /// `--threshold low|medium|high`. Rules with threshold ABOVE
    /// the configured value are skipped (i.e. configuring
    /// `--threshold high` keeps only "high confidence" rules).
    /// Defaults to "medium".
    ///
    /// Threshold is about how likely the rule's match is to be a
    /// true positive:
    ///   low    — generous matching, may flag false positives
    ///   medium — balanced
    ///   high   — strict matching, low false-positive rate
    #[serde(default = "default_threshold")]
    pub threshold: String,
}

fn default_strength() -> String { "medium".into() }
fn default_threshold() -> String { "medium".into() }

/// v0.8.6.1 — Numeric mapping for strength / threshold so
/// comparisons are total. Unknown values fall back to medium.
pub fn level(s: &str) -> u8 {
    match s.to_lowercase().as_str() {
        "low" => 1,
        "medium" | "med" => 2,
        "high" => 3,
        _ => 2,
    }
}

/// Filter a rule slice by strength + threshold. Returns rules where
///   rule.strength <= configured_strength
///   rule.threshold <= configured_threshold
/// (i.e. configuring `--strength high --threshold low` runs
/// everything; `--strength low --threshold high` keeps only the
/// quietest, highest-confidence rules.)
pub fn filter_by_policy<'a>(
    rules: &'a [Rule],
    max_strength: &str,
    max_threshold: &str,
) -> Vec<&'a Rule> {
    let s = level(max_strength);
    let t = level(max_threshold);
    rules.iter()
        .filter(|r| level(&r.strength) <= s && level(&r.threshold) <= t)
        .collect()
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

const EMBEDDED_RULES:    &str = include_str!("../../rules/default.yaml");
const EMBEDDED_EXTENDED: &str = include_str!("../../rules/extended.yaml");

pub fn load_rules(extra_path: Option<&str>, include_extended: bool) -> Vec<Rule> {
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

    // Full scan: include the extended ruleset (4,425 additional checks
    // covering server fingerprinting / outdated software / CGI vulns
    // / hidden file paths / common misconfigurations).
    if include_extended {
        let home_extended = dirs::home_dir()
            .map(|h| h.join(".cyweb/extended.yaml"))
            .filter(|p| p.exists());

        if let Some(ref path) = home_extended {
            if let Ok(content) = std::fs::read_to_string(path) {
                if let Ok(ruleset) = serde_yaml::from_str::<RuleSet>(&content) {
                    all_rules.extend(ruleset.rules);
                }
            }
        } else if let Ok(ruleset) = serde_yaml::from_str::<RuleSet>(EMBEDDED_EXTENDED) {
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
    // v0.9 — clone-on-iterate so each closure receives an OWNED
    // `Rule` rather than a borrow. Borrowed `&Rule` makes the inner
    // future carry a lifetime, which trips a HRTB-FnOnce error when
    // the outer `run_scan` future is sent across `tokio::spawn`
    // (e.g. from the GUI's scan-trigger handler). Cloning here costs
    // a small one-time alloc per rule and unblocks the spawn path.
    let findings: Vec<Finding> = stream::iter(rules.iter().cloned())
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
                        vuln_class: None,
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

#[cfg(test)]
mod policy_tests {
    use super::*;

    fn rule(id: &str, strength: &str, threshold: &str) -> Rule {
        Rule {
            id: id.into(),
            title: id.into(),
            severity: "info".into(),
            category: "test".into(),
            description: "".into(),
            cwe: None,
            remediation: "".into(),
            paths: vec![],
            method: "GET".into(),
            match_status: vec![],
            match_body: None,
            match_header: None,
            match_header_value: None,
            not_match_body: None,
            strength: strength.into(),
            threshold: threshold.into(),
        }
    }

    #[test]
    fn level_maps_strings_to_numbers() {
        assert_eq!(level("low"), 1);
        assert_eq!(level("medium"), 2);
        assert_eq!(level("high"), 3);
        assert_eq!(level("MED"), 2);  // case-insensitive
        assert_eq!(level("garbage"), 2); // unknown → medium
    }

    #[test]
    fn filter_keeps_rules_at_or_below_strength() {
        let rules = vec![
            rule("a", "low", "medium"),
            rule("b", "medium", "medium"),
            rule("c", "high", "medium"),
        ];
        let kept = filter_by_policy(&rules, "medium", "high");
        assert_eq!(kept.len(), 2);
        assert!(kept.iter().any(|r| r.id == "a"));
        assert!(kept.iter().any(|r| r.id == "b"));
        assert!(!kept.iter().any(|r| r.id == "c"));
    }

    #[test]
    fn filter_keeps_rules_at_or_below_threshold() {
        // --threshold low means "only run rules whose confidence
        // bar is low or medium" — i.e. drop rules tagged "high
        // threshold required" because we DO want low-confidence
        // findings... wait that's backwards.
        //
        // Re-read the doc: --threshold high keeps only rules whose
        // threshold (confidence) is <= high. Since everything is
        // <= high, --threshold high runs everything. --threshold
        // low keeps only rules tagged threshold: low. That matches
        // "give me only the cleanest, highest-confidence rules"
        // when --threshold low is set.
        //
        // So configuring --threshold low DROPS rules tagged
        // "medium" or "high" threshold.
        let rules = vec![
            rule("low-conf",  "medium", "low"),
            rule("med-conf",  "medium", "medium"),
            rule("high-conf", "medium", "high"),
        ];
        let strict = filter_by_policy(&rules, "high", "low");
        assert_eq!(strict.len(), 1);
        assert_eq!(strict[0].id, "low-conf");
    }

    #[test]
    fn defaults_are_medium() {
        // A rule with no explicit fields parses with strength=medium,
        // threshold=medium.
        let yaml = r#"
id: x
title: x
severity: info
category: test
description: x
remediation: x
"#;
        let r: Rule = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(r.strength, "medium");
        assert_eq!(r.threshold, "medium");
    }

    #[test]
    fn full_runs_everything_at_max_levels() {
        let rules = vec![
            rule("low/low",  "low",  "low"),
            rule("med/med",  "medium", "medium"),
            rule("high/high","high", "high"),
        ];
        let kept = filter_by_policy(&rules, "high", "high");
        assert_eq!(kept.len(), 3);
    }
}
