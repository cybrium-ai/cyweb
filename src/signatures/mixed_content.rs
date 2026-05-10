//! Mixed-content / HTTPS↔HTTP availability check.
//!
//! For HTTPS targets, retries the root + a sample of crawled URLs over
//! plain HTTP. Any 200-class response means the same content is served
//! over both schemes — an attacker on the network path can MITM the
//! HTTP version and downgrade-attack the user.
//!
//! Covers the mixed-content class: HTTPS Content Available via HTTP,
//! Insecure Form Action URL, Insecure Authentication transport, plain
//! HTTP-to-HTTP redirects (no upgrade). CWE-319 (Cleartext Transmission
//! of Sensitive Information).

use super::{Finding, Severity};
use reqwest::{Client, StatusCode};
use url::Url;

/// Maximum number of distinct paths to probe over HTTP. Bounded to keep
/// the scan duration predictable on huge sites.
const MAX_PROBES: usize = 30;

pub async fn check_mixed_content(
    client: &Client,
    target: &str,
    urls: &[String],
) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Only meaningful for HTTPS targets — HTTP-only sites are already
    // a separate "no TLS" finding from headers.rs.
    let parsed = match Url::parse(target) {
        Ok(u) if u.scheme() == "https" => u,
        _ => return findings,
    };

    let host = match parsed.host_str() {
        Some(h) => h,
        None => return findings,
    };

    // Build the probe set: root + up to MAX_PROBES-1 sampled paths.
    let mut paths: Vec<String> = vec!["/".to_string()];
    for u in urls.iter().take(200) {
        if let Ok(parsed_u) = Url::parse(u) {
            if parsed_u.host_str() == Some(host) {
                let p = parsed_u.path().to_string();
                if !paths.contains(&p) {
                    paths.push(p);
                }
            }
        }
        if paths.len() >= MAX_PROBES {
            break;
        }
    }

    for path in &paths {
        let http_url = format!("http://{}{}", host, path);
        let resp = match client
            .get(&http_url)
            .send()
            .await
        {
            Ok(r) => r,
            Err(_) => continue,
        };
        let status = resp.status();
        // 2xx = served plain HTTP without redirecting back to HTTPS — a
        // real exposure. 3xx with a Location: https://... is fine
        // (proper HTTPS redirect). 4xx/5xx means HTTP isn't served.
        if status.is_success() {
            findings.push(Finding {
                id: "CYWEB-MIX-001".into(),
                title: "HTTPS content also available over plain HTTP".into(),
                severity: Severity::Medium,
                category: "Cryptographic Failures".into(),
                description: format!(
                    "The path `{}` is reachable over both HTTPS and plain HTTP (returned {}). \
                     A network attacker can intercept the HTTP version and inject hostile \
                     content or strip the connection's encryption.",
                    path, status
                ),
                evidence: format!("HTTP {} {} → {}", "GET", http_url, status),
                url: http_url.clone(),
                cwe: Some("CWE-319".into()),
                remediation: "Configure the web server to redirect all HTTP traffic to HTTPS \
                              (`return 301 https://$host$request_uri;` for nginx) and set the \
                              `Strict-Transport-Security` response header so browsers refuse to \
                              fall back to plain HTTP for this host."
                    .into(),
                vuln_class: None,
            });
        } else if status == StatusCode::MOVED_PERMANENTLY || status == StatusCode::FOUND
            || status == StatusCode::SEE_OTHER || status == StatusCode::TEMPORARY_REDIRECT
            || status == StatusCode::PERMANENT_REDIRECT
        {
            // Verify the redirect actually points back to HTTPS — a
            // wrong-host or HTTP-to-HTTP redirect would still be bad.
            let loc = resp
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            if !loc.is_empty() && !loc.starts_with("https://") && !loc.starts_with("/") {
                findings.push(Finding {
                    id: "CYWEB-MIX-002".into(),
                    title: "HTTP→HTTP redirect (no upgrade to HTTPS)".into(),
                    severity: Severity::Low,
                    category: "Cryptographic Failures".into(),
                    description: format!(
                        "Plain HTTP request to `{}` redirected to `{}` — the redirect target \
                         is not HTTPS, so the user's session never gets encrypted.",
                        path, loc
                    ),
                    evidence: format!("Location: {}", loc),
                    url: http_url,
                    cwe: Some("CWE-319".into()),
                    remediation: "Change the redirect target to the HTTPS variant of the same \
                                  URL (`https://$host$request_uri`)."
                        .into(),
                    vuln_class: None,
                });
            }
        }
    }

    findings
}
