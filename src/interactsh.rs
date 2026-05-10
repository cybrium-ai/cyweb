//! v0.8.5 — interactsh OAST integration via oast.cybrium.ai.
//!
//! "Interactsh" is the upstream community pattern of using a public
//! DNS / HTTP callback service to detect blind vulnerabilities (blind
//! SSRF, blind XXE, blind RCE) where the target hits an attacker-
//! controlled domain. Cybrium runs its own OAST daemon at
//! `oast.cybrium.ai` (172.173.126.237) so customers don't have to
//! depend on third-party callback infrastructure. This module:
//!
//! 1. Mints a token-namespaced subdomain per scan
//!    (`<scan-token>.oast.cybrium.ai`).
//! 2. Substitutes that subdomain anywhere a template uses
//!    `{{interactsh-url}}` / `{{interactsh-protocol}}` / dotted
//!    placeholders.
//! 3. After the template fires, polls the OASTD ingest endpoint
//!    for callbacks tagged with that token, and emits Findings for
//!    any that arrive in the post-fire window.
//!
//! All polling is bounded — we don't block scan completion on
//! callbacks that never come. Default window is 8 seconds, override
//! via `CYWEB_OAST_WINDOW_SECS`.

use serde::Deserialize;
use std::time::Duration;
use uuid::Uuid;

/// OAST host. Configurable so on-prem deploys can point cyweb at a
/// private OASTD instance rather than the shared cybrium endpoint.
pub fn oast_host() -> String {
    std::env::var("CYWEB_OAST_HOST").unwrap_or_else(|_| "oast.cybrium.ai".into())
}

/// Mint a fresh token. 16-byte hex, scoped per scan.
pub fn mint_token() -> String {
    let id = Uuid::new_v4();
    // Trim the dashes — most templates expect the token at the
    // leading label and many implementations of resolveable hostnames
    // dislike `-` runs.
    id.simple().to_string()
}

/// Substitute `{{interactsh-url}}` / `{{interactsh-protocol}}` /
/// `{{interactsh-host}}` placeholders with token-scoped values.
pub fn substitute(s: &str, token: &str) -> String {
    let host = oast_host();
    s.replace("{{interactsh-url}}", &format!("{}.{}", token, host))
        .replace("{{interactsh-host}}", &format!("{}.{}", token, host))
        .replace("{{interactsh-protocol}}", "http")
}

/// One callback record returned by OASTD ingest endpoint.
#[derive(Debug, Deserialize, Clone)]
pub struct OastCallback {
    pub protocol: String,
    pub remote_address: String,
    #[serde(default)]
    pub raw_request: String,
    #[serde(default)]
    pub timestamp: String,
}

/// Poll OASTD for callbacks tagged with `token`. Returns within the
/// configured window even if no callbacks arrive (so the scanner
/// doesn't block forever on a blind-SSRF template that didn't
/// trigger). Errors talking to OASTD are silently swallowed —
/// callback infrastructure is best-effort, not load-bearing.
pub async fn poll_callbacks(client: &reqwest::Client, token: &str) -> Vec<OastCallback> {
    let secs: u64 = std::env::var("CYWEB_OAST_WINDOW_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8);
    let host = oast_host();
    let url = format!("https://{}/poll/{}", host, token);
    match tokio::time::timeout(
        Duration::from_secs(secs),
        client.get(&url).send(),
    ).await {
        Ok(Ok(resp)) => resp.json::<Vec<OastCallback>>().await.unwrap_or_default(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substitute_replaces_url_placeholder() {
        let out = substitute("GET / HTTP/1.1\r\nX-Probe: {{interactsh-url}}\r\n", "abc123");
        assert!(out.contains("abc123.oast.cybrium.ai"));
        assert!(!out.contains("{{interactsh-url}}"));
    }

    #[test]
    fn substitute_replaces_host_and_protocol() {
        let out = substitute("{{interactsh-protocol}}://{{interactsh-host}}/x", "tok");
        assert_eq!(out, "http://tok.oast.cybrium.ai/x");
    }

    #[test]
    fn token_format_is_hex() {
        let t = mint_token();
        assert_eq!(t.len(), 32);
        assert!(t.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
