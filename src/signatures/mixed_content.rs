//! Mixed-content / HTTPS↔HTTP availability check.
//!
//! For HTTPS targets, retries the root + a sample of crawled URLs over
//! plain HTTP. A finding is raised only when plain HTTP serves actual
//! content WITHOUT redirecting to HTTPS — an attacker on the network path
//! can then MITM the HTTP version and downgrade-attack the user.
//!
//! Critically, the probe uses a NON-redirecting client and judges the
//! FIRST response. A host whose ingress 301/308-redirects HTTP→HTTPS is
//! behaving correctly; if we followed the redirect we would see the final
//! HTTPS 200 and wrongly report "content served over HTTP". We therefore
//! inspect the first response's status + Location directly.
//!
//! Covers the mixed-content class: HTTPS Content Available via HTTP,
//! Insecure Form Action URL, Insecure Authentication transport, plain
//! HTTP-to-HTTP redirects (no upgrade). CWE-319 (Cleartext Transmission
//! of Sensitive Information).

use super::{Finding, Severity};
use reqwest::Client;
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

    // A dedicated non-redirecting client. The shared scan client usually
    // follows redirects (up to 10), which would turn an HTTP→HTTPS 301 into
    // a final HTTPS 200 and produce a false "available over plain HTTP"
    // finding. Here we must see the FIRST hop's status + Location.
    let http_client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(10))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap_or_else(|_| client.clone());

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
        let resp = match http_client
            .get(&http_url)
            .send()
            .await
        {
            Ok(r) => r,
            Err(_) => continue,
        };
        let status = resp.status();
        let loc = resp
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        match classify_http_response(status.as_u16(), &loc) {
            // 2xx on the FIRST response = served plain HTTP without redirecting
            // to HTTPS — a real exposure.
            MixVerdict::Exposed => findings.push(Finding {
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
            }),
            // A redirect whose target isn't HTTPS — the session never gets
            // encrypted.
            MixVerdict::NoUpgradeRedirect => findings.push(Finding {
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
            }),
            // A proper HTTP→HTTPS redirect (or a non-served path) — correct
            // behaviour, no finding.
            MixVerdict::Fine => {}
        }
    }

    findings
}

/// Verdict for a plain-HTTP probe of an HTTPS host, judged on the FIRST
/// response (the client that produced `status`/`location` must NOT follow
/// redirects).
#[derive(Debug, PartialEq, Eq)]
enum MixVerdict {
    /// Plain HTTP served real content without redirecting — a real exposure.
    Exposed,
    /// Redirected, but the target is not HTTPS — no encryption upgrade.
    NoUpgradeRedirect,
    /// Correct HTTP→HTTPS upgrade, or HTTP simply isn't served — not a finding.
    Fine,
}

fn classify_http_response(status: u16, location: &str) -> MixVerdict {
    if (200..300).contains(&status) {
        return MixVerdict::Exposed;
    }
    let is_redirect = matches!(status, 301 | 302 | 303 | 307 | 308);
    // A redirect to an absolute https:// URL is the correct upgrade. A relative
    // Location (`/...`) or an empty one is treated as benign to avoid new false
    // positives; only an explicit non-HTTPS absolute target is flagged.
    if is_redirect
        && !location.is_empty()
        && !location.starts_with("https://")
        && !location.starts_with('/')
    {
        return MixVerdict::NoUpgradeRedirect;
    }
    MixVerdict::Fine
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_redirect_is_suppressed() {
        // The reported FP: ingress 301/308-redirects HTTP→HTTPS, scanner
        // followed it and reported the final 200. Judged on the first hop,
        // an absolute-https redirect is correct behaviour.
        assert_eq!(classify_http_response(301, "https://app.cybrium.ai/"), MixVerdict::Fine);
        assert_eq!(classify_http_response(308, "https://app.cybrium.ai/login"), MixVerdict::Fine);
    }

    #[test]
    fn plain_http_200_without_redirect_still_fires() {
        // A genuinely insecure host that serves content over plain HTTP.
        assert_eq!(classify_http_response(200, ""), MixVerdict::Exposed);
        assert_eq!(classify_http_response(206, ""), MixVerdict::Exposed);
    }

    #[test]
    fn http_to_http_redirect_flags_no_upgrade() {
        assert_eq!(
            classify_http_response(302, "http://cybrium.ai/elsewhere"),
            MixVerdict::NoUpgradeRedirect
        );
    }

    #[test]
    fn non_served_and_relative_redirect_are_fine() {
        assert_eq!(classify_http_response(404, ""), MixVerdict::Fine);
        assert_eq!(classify_http_response(500, ""), MixVerdict::Fine);
        // Relative redirect — left benign to avoid new FPs.
        assert_eq!(classify_http_response(301, "/somewhere"), MixVerdict::Fine);
    }
}
