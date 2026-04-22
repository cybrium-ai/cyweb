//! Security header analysis.

use super::{Finding, Severity};
use reqwest::Client;

pub async fn check_headers(client: &Client, target: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    let resp = match client.get(target).send().await {
        Ok(r) => r,
        Err(_) => return findings,
    };

    let headers = resp.headers();
    let url = target.to_string();

    // X-Frame-Options
    if headers.get("x-frame-options").is_none() {
        findings.push(Finding {
            id: "CYWEB-HDR-001".into(),
            title: "Missing X-Frame-Options header".into(),
            severity: Severity::Medium,
            category: "Security Headers".into(),
            description: "The X-Frame-Options header is not set. This can allow clickjacking attacks where an attacker embeds the page in an iframe.".into(),
            evidence: "Header X-Frame-Options not present in response".into(),
            url: url.clone(),
            cwe: Some("CWE-1021".into()),
            remediation: "Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN' to all responses.".into(),
        });
    }

    // Strict-Transport-Security
    if target.starts_with("https") && headers.get("strict-transport-security").is_none() {
        findings.push(Finding {
            id: "CYWEB-HDR-002".into(),
            title: "Missing Strict-Transport-Security (HSTS) header".into(),
            severity: Severity::High,
            category: "Security Headers".into(),
            description: "HSTS is not enabled. Browsers may connect via HTTP, allowing man-in-the-middle attacks and SSL stripping.".into(),
            evidence: "Header Strict-Transport-Security not present".into(),
            url: url.clone(),
            cwe: Some("CWE-319".into()),
            remediation: "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'.".into(),
        });
    }

    // Content-Security-Policy
    if headers.get("content-security-policy").is_none() {
        findings.push(Finding {
            id: "CYWEB-HDR-003".into(),
            title: "Missing Content-Security-Policy header".into(),
            severity: Severity::Medium,
            category: "Security Headers".into(),
            description: "No CSP header is set. This increases the risk of XSS and data injection attacks.".into(),
            evidence: "Header Content-Security-Policy not present".into(),
            url: url.clone(),
            cwe: Some("CWE-693".into()),
            remediation: "Implement a strict Content-Security-Policy. Start with: default-src 'self'; script-src 'self'".into(),
        });
    }

    // X-Content-Type-Options
    if headers.get("x-content-type-options").is_none() {
        findings.push(Finding {
            id: "CYWEB-HDR-004".into(),
            title: "Missing X-Content-Type-Options header".into(),
            severity: Severity::Low,
            category: "Security Headers".into(),
            description: "Without nosniff, browsers may MIME-sniff responses, potentially executing malicious content.".into(),
            evidence: "Header X-Content-Type-Options not present".into(),
            url: url.clone(),
            cwe: Some("CWE-693".into()),
            remediation: "Add 'X-Content-Type-Options: nosniff' to all responses.".into(),
        });
    }

    // Referrer-Policy
    if headers.get("referrer-policy").is_none() {
        findings.push(Finding {
            id: "CYWEB-HDR-005".into(),
            title: "Missing Referrer-Policy header".into(),
            severity: Severity::Low,
            category: "Security Headers".into(),
            description: "Without Referrer-Policy, the full URL including query parameters may be leaked to third parties.".into(),
            evidence: "Header Referrer-Policy not present".into(),
            url: url.clone(),
            cwe: Some("CWE-200".into()),
            remediation: "Add 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'.".into(),
        });
    }

    // Permissions-Policy
    if headers.get("permissions-policy").is_none() {
        findings.push(Finding {
            id: "CYWEB-HDR-006".into(),
            title: "Missing Permissions-Policy header".into(),
            severity: Severity::Low,
            category: "Security Headers".into(),
            description: "Permissions-Policy is not set. Browser features like camera, microphone, and geolocation are not restricted.".into(),
            evidence: "Header Permissions-Policy not present".into(),
            url: url.clone(),
            cwe: Some("CWE-693".into()),
            remediation: "Add 'Permissions-Policy: camera=(), microphone=(), geolocation=()'.".into(),
        });
    }

    // Server header information disclosure
    if let Some(server) = headers.get("server").and_then(|v| v.to_str().ok()) {
        if server.contains('/') {
            findings.push(Finding {
                id: "CYWEB-HDR-007".into(),
                title: "Server version disclosed".into(),
                severity: Severity::Low,
                category: "Information Disclosure".into(),
                description: "The Server header reveals version information, helping attackers identify known vulnerabilities.".into(),
                evidence: format!("Server: {server}"),
                url: url.clone(),
                cwe: Some("CWE-200".into()),
                remediation: "Configure the web server to remove or genericize the Server header.".into(),
            });
        }
    }

    // X-Powered-By disclosure
    if let Some(val) = headers.get("x-powered-by").and_then(|v| v.to_str().ok()) {
        findings.push(Finding {
            id: "CYWEB-HDR-008".into(),
            title: "X-Powered-By header exposes technology stack".into(),
            severity: Severity::Low,
            category: "Information Disclosure".into(),
            description: "The X-Powered-By header reveals the server-side technology, aiding targeted attacks.".into(),
            evidence: format!("X-Powered-By: {val}"),
            url: url.clone(),
            cwe: Some("CWE-200".into()),
            remediation: "Remove the X-Powered-By header from all responses.".into(),
        });
    }

    // Check Set-Cookie security flags
    for cookie_val in headers.get_all("set-cookie") {
        if let Ok(c) = cookie_val.to_str() {
            let lower = c.to_lowercase();
            if !lower.contains("httponly") {
                findings.push(Finding {
                    id: format!("CYWEB-HDR-009-{}", &c[..c.find('=').unwrap_or(8).min(20)]),
                    title: "Cookie missing HttpOnly flag".into(),
                    severity: Severity::Medium,
                    category: "Cookie Security".into(),
                    description: "A cookie is set without the HttpOnly flag, making it accessible via JavaScript and vulnerable to XSS-based theft.".into(),
                    evidence: format!("Set-Cookie: {}", &c[..c.len().min(80)]),
                    url: url.clone(),
                    cwe: Some("CWE-1004".into()),
                    remediation: "Add the HttpOnly flag to all session and sensitive cookies.".into(),
                });
            }
            if target.starts_with("https") && !lower.contains("secure") {
                findings.push(Finding {
                    id: format!("CYWEB-HDR-010-{}", &c[..c.find('=').unwrap_or(8).min(20)]),
                    title: "Cookie missing Secure flag".into(),
                    severity: Severity::Medium,
                    category: "Cookie Security".into(),
                    description: "A cookie is set without the Secure flag on an HTTPS site. The cookie may be transmitted over unencrypted HTTP.".into(),
                    evidence: format!("Set-Cookie: {}", &c[..c.len().min(80)]),
                    url: url.clone(),
                    cwe: Some("CWE-614".into()),
                    remediation: "Add the Secure flag to all cookies on HTTPS sites.".into(),
                });
            }
            if !lower.contains("samesite") {
                findings.push(Finding {
                    id: format!("CYWEB-HDR-011-{}", &c[..c.find('=').unwrap_or(8).min(20)]),
                    title: "Cookie missing SameSite attribute".into(),
                    severity: Severity::Low,
                    category: "Cookie Security".into(),
                    description: "A cookie lacks the SameSite attribute, potentially allowing CSRF attacks.".into(),
                    evidence: format!("Set-Cookie: {}", &c[..c.len().min(80)]),
                    url: url.clone(),
                    cwe: Some("CWE-352".into()),
                    remediation: "Add 'SameSite=Lax' or 'SameSite=Strict' to all cookies.".into(),
                });
            }
        }
    }

    // CORS misconfiguration
    if let Some(origin) = headers.get("access-control-allow-origin").and_then(|v| v.to_str().ok()) {
        if origin == "*" {
            findings.push(Finding {
                id: "CYWEB-HDR-012".into(),
                title: "Wildcard CORS policy".into(),
                severity: Severity::Medium,
                category: "CORS".into(),
                description: "Access-Control-Allow-Origin is set to '*', allowing any origin to read responses. This may expose sensitive data.".into(),
                evidence: format!("Access-Control-Allow-Origin: {origin}"),
                url: url.clone(),
                cwe: Some("CWE-942".into()),
                remediation: "Restrict CORS to specific trusted origins instead of using wildcard.".into(),
            });
        }
    }

    findings
}
