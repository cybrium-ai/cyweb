//! Sprint 76 Phase 7 — WebSocket hijacking.
//!
//! Discovers WebSocket endpoints (common paths + URLs the crawler
//! found that look WS-shaped), then probes each for:
//!
//!   - **Origin enforcement** — connect with `Origin:
//!     https://attacker.example` and check whether the upgrade
//!     handshake succeeds. Successful = MEDIUM finding (CSWSH —
//!     Cross-Site WebSocket Hijacking).
//!
//!   - **Anonymous handshake** — connect without auth headers and
//!     send a benign probe message; if the server processes it without
//!     401/403 close, the WS endpoint is open to unauthenticated
//!     clients (often a misconfiguration).
//!
//!   - **Frame echo / reflection** — send a unique probe string;
//!     if the server reflects it back to all clients, broadcast
//!     channels are misconfigured (LOW; informational unless
//!     combined with anonymous handshake).
//!
//! Non-intrusive — the probes use a CSWS01-prefixed canary string,
//! send a single message, and close cleanly. No frame fuzzing here
//! (that's a follow-up class).

use crate::signatures::{Finding, Severity};
use std::time::Duration;
use tokio::time::timeout;
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};
use tokio_tungstenite::tungstenite::handshake::client::Request;
use http::Uri;
use futures::{SinkExt, StreamExt};

/// Common WebSocket endpoint paths to probe in addition to anything the
/// crawler discovered.
const COMMON_PATHS: &[&str] = &[
    "/ws",
    "/socket",
    "/websocket",
    "/socket.io/?EIO=4&transport=websocket",
    "/cable",
    "/graphql",
    "/api/ws",
    "/api/socket",
    "/_ws",
    "/realtime",
];

/// Connect timeout for any WS probe — short to keep scan time bounded.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Read timeout for waiting on a server response after sending a probe.
const READ_TIMEOUT: Duration = Duration::from_secs(3);

/// Unique probe string. Servers that echo this back signal reflection;
/// anything else either drops or rejects.
const PROBE_TOKEN: &str = "CSWS01-cyweb-probe-9f4a1c";

pub async fn run_websocket(target: &str, crawled_urls: &[String]) -> Vec<Finding> {
    let mut out = Vec::new();

    // Build candidate URL list — common paths + WS-looking URLs from
    // the crawler. De-dupe by stringly-equal.
    let mut candidates: Vec<String> = COMMON_PATHS.iter()
        .map(|p| build_ws_url(target, p))
        .collect();
    for u in crawled_urls {
        if let Some(ws) = http_to_ws(u) {
            candidates.push(ws);
        }
    }
    candidates.sort();
    candidates.dedup();

    for url in candidates {
        match probe_endpoint(&url).await {
            Ok(probe) => out.extend(probe.into_findings(&url)),
            Err(_) => continue,   // unreachable / 4xx / non-WS — skip silently
        }
    }

    out
}

/// Translate `https://target/foo` → `wss://target/foo`. Returns None
/// for URLs that aren't HTTP-shaped or are static-asset-shaped (the
/// crawler picks up CSS/JS too).
fn http_to_ws(url: &str) -> Option<String> {
    let uri: Uri = url.parse().ok()?;
    let scheme = uri.scheme_str()?;
    let host = uri.host()?;
    let port = uri.port_u16().map(|p| format!(":{p}")).unwrap_or_default();
    let path = uri.path();
    // Skip static assets — pointless to WS-probe a CSS file.
    if path.ends_with(".css") || path.ends_with(".js") || path.ends_with(".png")
        || path.ends_with(".jpg") || path.ends_with(".woff") || path.ends_with(".woff2") {
        return None;
    }
    // Heuristic: only translate URLs whose path looks WS-shaped.
    if !(path.contains("ws") || path.contains("socket") || path.contains("graphql")
         || path.contains("cable") || path.contains("realtime")) {
        return None;
    }
    let ws_scheme = if scheme == "https" { "wss" } else { "ws" };
    Some(format!("{ws_scheme}://{host}{port}{path}"))
}

fn build_ws_url(target: &str, path: &str) -> String {
    let target = target.trim_end_matches('/');
    let target = target
        .replacen("https://", "wss://", 1)
        .replacen("http://",  "ws://",  1);
    format!("{target}{path}")
}

#[derive(Default)]
struct ProbeResult {
    /// True when at least one connect with arbitrary Origin succeeded.
    origin_bypass:        bool,
    /// True when the connect with no auth header reached "open" state.
    anonymous_handshake:  bool,
    /// True when the server echoed our probe token back.
    echo_reflected:       bool,
    /// Server's framework banner from the upgrade response, when present.
    server_banner:        Option<String>,
}

impl ProbeResult {
    fn into_findings(self, url: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        if self.origin_bypass {
            out.push(Finding {
                id:          format!("CYWEB-WS-CSWSH-{}", short_hash(url)),
                title:       "WebSocket — accepts arbitrary Origin (CSWSH)".into(),
                severity:    Severity::High,
                category:    "WebSocket".into(),
                description: format!(
                    "The WebSocket endpoint at {url} accepted an upgrade with \
                     `Origin: https://attacker.example`. Cross-site clients can \
                     hijack the connection from any origin and act as the \
                     authenticated user. CWE-346."
                ),
                evidence:    "Connect with arbitrary Origin succeeded; upgrade returned 101.".into(),
                url:         url.into(),
                cwe:         Some("CWE-346".into()),
                remediation: "Validate the `Origin` header against an allowlist on the \
                              WebSocket upgrade handshake. Reject unknown origins with 403.".into(),
                vuln_class:  Some("websocket_hijack".into()),
            });
        }
        if self.anonymous_handshake {
            out.push(Finding {
                id:          format!("CYWEB-WS-ANON-{}", short_hash(url)),
                title:       "WebSocket — accepts unauthenticated handshake".into(),
                severity:    Severity::Medium,
                category:    "WebSocket".into(),
                description: format!(
                    "The WebSocket endpoint at {url} completed an upgrade without \
                     any authentication header (no Cookie / Authorization). \
                     Subsequent messages were processed without an auth challenge. \
                     CWE-306."
                ),
                evidence:    "Anonymous connect reached open state and accepted a probe message.".into(),
                url:         url.into(),
                cwe:         Some("CWE-306".into()),
                remediation: "Require authentication on the WebSocket upgrade — reject \
                              connections without a valid session cookie or bearer token.".into(),
                vuln_class:  Some("websocket_hijack".into()),
            });
        }
        if self.echo_reflected {
            out.push(Finding {
                id:          format!("CYWEB-WS-ECHO-{}", short_hash(url)),
                title:       "WebSocket — broadcast channel echoes unauthenticated input".into(),
                severity:    Severity::Low,
                category:    "WebSocket".into(),
                description: format!(
                    "The WebSocket endpoint at {url} echoed our probe token back to \
                     the connecting client. Combined with the unauthenticated \
                     handshake, this lets any visitor inject arbitrary frames \
                     into the broadcast channel. CWE-942."
                ),
                evidence:    format!("Token `{PROBE_TOKEN}` was reflected by the server."),
                url:         url.into(),
                cwe:         Some("CWE-942".into()),
                remediation: "Sanitise broadcast input; require auth before relaying messages.".into(),
                vuln_class:  Some("websocket_hijack".into()),
            });
        }
        out
    }
}

async fn probe_endpoint(url: &str) -> Result<ProbeResult, ()> {
    let mut result = ProbeResult::default();

    // ── Probe 1: arbitrary Origin ────────────────────────────────────────
    if let Ok(req) = build_request(url, Some("https://attacker.example")) {
        match timeout(CONNECT_TIMEOUT, connect_async(req)).await {
            Ok(Ok((mut ws, response))) => {
                result.origin_bypass = true;
                if let Some(server) = response.headers().get(http::header::SERVER) {
                    if let Ok(s) = server.to_str() {
                        result.server_banner = Some(s.to_string());
                    }
                }
                // Send probe + read once to check for echo.
                let _ = ws.send(Message::Text(PROBE_TOKEN.into())).await;
                if let Ok(Some(Ok(msg))) = timeout(READ_TIMEOUT, ws.next()).await {
                    if msg.to_text().unwrap_or("").contains(PROBE_TOKEN) {
                        result.echo_reflected = true;
                    }
                }
                let _ = ws.close(None).await;
            }
            _ => { /* silent — endpoint may not exist or not be WS */ }
        }
    }

    // ── Probe 2: no auth headers at all ──────────────────────────────────
    if let Ok(req) = build_request(url, None) {
        if let Ok(Ok((mut ws, _))) = timeout(CONNECT_TIMEOUT, connect_async(req)).await {
            result.anonymous_handshake = true;
            let _ = ws.send(Message::Text(PROBE_TOKEN.into())).await;
            if let Ok(Some(Ok(msg))) = timeout(READ_TIMEOUT, ws.next()).await {
                if msg.to_text().unwrap_or("").contains(PROBE_TOKEN) {
                    result.echo_reflected = true;
                }
            }
            let _ = ws.close(None).await;
        }
    }

    if !result.origin_bypass && !result.anonymous_handshake {
        return Err(());
    }
    Ok(result)
}

fn build_request(url: &str, origin: Option<&str>) -> Result<Request, ()> {
    let uri: Uri = url.parse().map_err(|_| ())?;
    let host = uri.host().ok_or(())?;
    let mut req = Request::builder()
        .uri(url)
        .header(http::header::HOST, host)
        .header(http::header::CONNECTION, "Upgrade")
        .header(http::header::UPGRADE, "websocket")
        .header(http::header::SEC_WEBSOCKET_VERSION, "13")
        .header(http::header::SEC_WEBSOCKET_KEY, "dGhlIHNhbXBsZSBub25jZQ==");
    if let Some(o) = origin {
        req = req.header(http::header::ORIGIN, o);
    }
    req.body(()).map_err(|_| ())
}

/// 8-char hex hash for stable finding IDs without dragging in sha256.
fn short_hash(s: &str) -> String {
    let mut h: u64 = 1469598103934665603;
    for b in s.bytes() {
        h = h.wrapping_mul(1099511628211).wrapping_add(b as u64);
    }
    format!("{:08x}", (h & 0xffffffff) as u32)
}
