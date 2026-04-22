//! Server-specific vulnerability checks based on fingerprinted technology.

use super::{Finding, Severity};
use crate::scanner::ServerInfo;
use reqwest::Client;

pub async fn check_server(client: &Client, target: &str, info: &ServerInfo) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Check for outdated/vulnerable server versions
    if let Some(ref server) = info.server {
        let s = server.to_lowercase();

        // Apache version checks
        if s.starts_with("apache/") {
            if let Some(ver) = extract_version(server) {
                if version_lt(&ver, "2.4.58") {
                    findings.push(Finding {
                        id: "CYWEB-SRV-001".into(),
                        title: "Outdated Apache version".into(),
                        severity: Severity::High,
                        category: "Outdated Software".into(),
                        description: format!("Apache {ver} is outdated and may have known vulnerabilities. Latest stable is 2.4.62+."),
                        evidence: format!("Server: {server}"),
                        url: target.into(),
                        cwe: Some("CWE-1104".into()),
                        remediation: "Update Apache to the latest stable version.".into(),
                    });
                }
            }
        }

        // Nginx version checks
        if s.starts_with("nginx/") {
            if let Some(ver) = extract_version(server) {
                if version_lt(&ver, "1.25.0") {
                    findings.push(Finding {
                        id: "CYWEB-SRV-002".into(),
                        title: "Outdated Nginx version".into(),
                        severity: Severity::High,
                        category: "Outdated Software".into(),
                        description: format!("Nginx {ver} is outdated and may have known vulnerabilities."),
                        evidence: format!("Server: {server}"),
                        url: target.into(),
                        cwe: Some("CWE-1104".into()),
                        remediation: "Update Nginx to the latest stable version.".into(),
                    });
                }
            }
        }

        // IIS version checks
        if s.contains("iis/") {
            if let Some(ver) = extract_version(server) {
                if version_lt(&ver, "10.0") {
                    findings.push(Finding {
                        id: "CYWEB-SRV-003".into(),
                        title: "Outdated IIS version".into(),
                        severity: Severity::High,
                        category: "Outdated Software".into(),
                        description: format!("IIS {ver} is end-of-life or outdated."),
                        evidence: format!("Server: {server}"),
                        url: target.into(),
                        cwe: Some("CWE-1104".into()),
                        remediation: "Update to a supported IIS version.".into(),
                    });
                }
            }
        }
    }

    // Check for PHP version disclosure
    if let Some(ref pb) = info.powered_by {
        if pb.to_lowercase().starts_with("php/") {
            if let Some(ver) = extract_version(pb) {
                if version_lt(&ver, "8.2.0") {
                    findings.push(Finding {
                        id: "CYWEB-SRV-010".into(),
                        title: "Outdated PHP version".into(),
                        severity: Severity::High,
                        category: "Outdated Software".into(),
                        description: format!("PHP {ver} may be end-of-life. PHP 8.1 reached EOL in Nov 2024."),
                        evidence: format!("X-Powered-By: {pb}"),
                        url: target.into(),
                        cwe: Some("CWE-1104".into()),
                        remediation: "Update PHP to 8.2+ or later.".into(),
                    });
                }
            }
        }
    }

    // Check for default error pages
    if let Ok(resp) = client.get(&format!("{target}/this-page-does-not-exist-cyweb-test")).send().await {
        if let Ok(body) = resp.text().await {
            let lower = body.to_lowercase();
            if lower.contains("apache") && lower.contains("port") {
                findings.push(Finding {
                    id: "CYWEB-SRV-020".into(),
                    title: "Default Apache error page".into(),
                    severity: Severity::Low,
                    category: "Information Disclosure".into(),
                    description: "Default Apache error page reveals server information.".into(),
                    evidence: "404 page contains Apache default markup".into(),
                    url: target.into(),
                    cwe: Some("CWE-200".into()),
                    remediation: "Configure custom error pages that don't reveal server details.".into(),
                });
            }
            if lower.contains("iis") && lower.contains("microsoft") {
                findings.push(Finding {
                    id: "CYWEB-SRV-021".into(),
                    title: "Default IIS error page".into(),
                    severity: Severity::Low,
                    category: "Information Disclosure".into(),
                    description: "Default IIS error page reveals server technology.".into(),
                    evidence: "404 page contains IIS default markup".into(),
                    url: target.into(),
                    cwe: Some("CWE-200".into()),
                    remediation: "Configure custom error pages.".into(),
                });
            }
            if lower.contains("stack trace") || lower.contains("traceback") || lower.contains("exception") {
                findings.push(Finding {
                    id: "CYWEB-SRV-022".into(),
                    title: "Error page reveals stack trace".into(),
                    severity: Severity::High,
                    category: "Information Disclosure".into(),
                    description: "Error pages contain stack traces or exception details, revealing internal code structure.".into(),
                    evidence: "Error page contains debug information".into(),
                    url: target.into(),
                    cwe: Some("CWE-209".into()),
                    remediation: "Disable debug mode in production. Configure generic error pages.".into(),
                });
            }
        }
    }

    findings
}

fn extract_version(header: &str) -> Option<String> {
    let re = regex::Regex::new(r"[\w]+/([\d]+\.[\d]+\.?[\d]*)").ok()?;
    re.captures(header).map(|c| c[1].to_string())
}

fn version_lt(current: &str, minimum: &str) -> bool {
    let parse = |v: &str| -> Vec<u32> {
        v.split('.').filter_map(|p| p.parse().ok()).collect()
    };
    let cur = parse(current);
    let min = parse(minimum);
    for i in 0..min.len().max(cur.len()) {
        let c = cur.get(i).copied().unwrap_or(0);
        let m = min.get(i).copied().unwrap_or(0);
        if c < m { return true; }
        if c > m { return false; }
    }
    false
}
