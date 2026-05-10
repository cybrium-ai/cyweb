//! v0.8 Phase D — local web GUI for browsing scan findings.
//!
//! Triggered by the `--gui` CLI flag. After the scan completes, cyweb
//! starts an axum HTTP server on `127.0.0.1:8990` (override with
//! `--gui-port`) serving a single-page UI:
//!
//!   - Cybrium-branded header
//!   - Severity tile summary (critical/high/medium/low/info counts)
//!   - Searchable / filterable findings table
//!   - Detail panel (click a row) with full description + evidence
//!     + remediation
//!   - Export buttons — JSON / CSV / Markdown
//!
//! Bound to localhost only — no auth, no TLS. The server keeps running
//! until the user hits Ctrl-C; that lets them browse / refilter / re-
//! export without re-scanning.

use crate::scanner::ScanResult;
use crate::report;
use axum::{
    extract::State,
    http::{header, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use std::net::SocketAddr;
use std::sync::Arc;

/// Static assets bundled at compile time.
const INDEX_HTML:    &str = include_str!("assets/gui_index.html");
const LOGO_SVG:      &str = include_str!("assets/cybrium-logo.svg");
const WORDMARK_SVG:  &str = include_str!("assets/cybrium-word.svg");

#[derive(Clone)]
struct AppState {
    result: Arc<ScanResult>,
    /// v0.8 Phase M — set when running `cyweb proxy`. The GUI's
    /// History tab reads this on each poll.
    proxy_events: Option<crate::proxy::ProxyState>,
}

pub async fn start_server(result: ScanResult, port: u16) -> std::io::Result<()> {
    start_server_inner(result, port, None).await
}

/// Phase M — run the GUI in proxy mode. Result is a stub (the page
/// still renders) and the History tab reads from the live
/// proxy_events vec.
pub async fn start_server_proxy(
    proxy_events: crate::proxy::ProxyState,
    port: u16,
) -> std::io::Result<()> {
    let stub = ScanResult {
        target: "(proxy mode)".into(),
        started_at: chrono::Utc::now().to_rfc3339(),
        completed_at: chrono::Utc::now().to_rfc3339(),
        duration_ms: 0,
        findings: Vec::new(),
        summary: crate::scanner::ScanSummary {
            total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0,
            paths_checked: 0, requests_made: 0,
        },
        server_info: Default::default(),
        tls_info: None,
        spider_nodes: Vec::new(),
        http_events: Vec::new(),
        log_lines: Vec::new(),
        rule_stats: Vec::new(),
    };
    start_server_inner(stub, port, Some(proxy_events)).await
}

async fn start_server_inner(
    result: ScanResult,
    port: u16,
    proxy_events: Option<crate::proxy::ProxyState>,
) -> std::io::Result<()> {
    let state = AppState {
        result: Arc::new(result),
        proxy_events,
    };

    let app = Router::new()
        .route("/",                    get(serve_index))
        .route("/logo.svg",            get(serve_logo))
        .route("/wordmark.svg",        get(serve_wordmark))
        .route("/api/result",          get(api_result))
        .route("/api/export.json",     get(export_json))
        .route("/api/export.csv",      get(export_csv))
        .route("/api/export.markdown", get(export_markdown))
        .route("/api/export.html",     get(export_html))   // Phase I
        .route("/api/export.sarif",    get(export_sarif))  // Phase I
        .route("/api/export.xml",      get(export_xml))    // Phase I
        .route("/api/replay",          post(api_replay))   // Phase L
        .route("/api/proxy_events",    get(api_proxy_events)) // Phase M
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;

    eprintln!();
    eprintln!("\x1b[1;35m  ╔══════════════════════════════════════════════════════════╗\x1b[0m");
    eprintln!("\x1b[1;35m  ║  Cybrium Web Scanner — local UI                          ║\x1b[0m");
    eprintln!("\x1b[1;35m  ╠══════════════════════════════════════════════════════════╣\x1b[0m");
    eprintln!("\x1b[1;35m  ║  \x1b[0;36mhttp://127.0.0.1:{}/\x1b[1;35m{:>40}║\x1b[0m", port, "");
    eprintln!("\x1b[1;35m  ║  \x1b[0mCtrl-C to stop\x1b[1;35m{:>43}║\x1b[0m", "");
    eprintln!("\x1b[1;35m  ╚══════════════════════════════════════════════════════════╝\x1b[0m");
    eprintln!();

    axum::serve(listener, app).await
}

async fn serve_index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

async fn serve_logo() -> Response {
    (
        [(header::CONTENT_TYPE, "image/svg+xml; charset=utf-8")],
        LOGO_SVG,
    )
        .into_response()
}

async fn serve_wordmark() -> Response {
    (
        [(header::CONTENT_TYPE, "image/svg+xml; charset=utf-8")],
        WORDMARK_SVG,
    )
        .into_response()
}

async fn api_result(State(s): State<AppState>) -> Json<ScanResult> {
    Json((*s.result).clone())
}

async fn export_json(State(s): State<AppState>) -> Response {
    let body = serde_json::to_string_pretty(&*s.result)
        .unwrap_or_else(|e| format!(r#"{{"error":"{}"}}"#, e));
    (
        [
            (header::CONTENT_TYPE, "application/json; charset=utf-8"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"cyweb-findings.json\"",
            ),
        ],
        body,
    )
        .into_response()
}

async fn export_csv(State(s): State<AppState>) -> Response {
    let mut out = String::from("severity,title,url,cwe,category,description\n");
    for f in &s.result.findings {
        let sev = format!("{:?}", f.severity).to_lowercase();
        out.push_str(&format!(
            "{},{},{},{},{},{}\n",
            csv_field(&sev),
            csv_field(&f.title),
            csv_field(&f.url),
            csv_field(f.cwe.as_deref().unwrap_or("")),
            csv_field(&f.category),
            csv_field(&f.description),
        ));
    }
    (
        [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"cyweb-findings.csv\"",
            ),
        ],
        out,
    )
        .into_response()
}

async fn export_markdown(State(s): State<AppState>) -> Response {
    let mut out = String::new();
    out.push_str(&format!("# Cyweb scan — {}\n\n", s.result.target));
    out.push_str(&format!(
        "_Started: {} · Completed: {} · Total findings: {}_\n\n",
        s.result.started_at, s.result.completed_at, s.result.findings.len()
    ));
    out.push_str(&format!(
        "Severity breakdown — critical: **{}** · high: **{}** · medium: **{}** · low: **{}** · info: **{}**\n\n",
        s.result.summary.critical, s.result.summary.high, s.result.summary.medium,
        s.result.summary.low, s.result.summary.info,
    ));
    for f in &s.result.findings {
        let sev = format!("{:?}", f.severity).to_uppercase();
        out.push_str(&format!("## [{}] {}\n\n", sev, f.title));
        out.push_str(&format!("- **URL:** `{}`\n", f.url));
        if let Some(c) = &f.cwe {
            out.push_str(&format!("- **CWE:** {}\n", c));
        }
        out.push_str(&format!("- **Category:** {}\n\n", f.category));
        if !f.description.is_empty() {
            out.push_str(&format!("{}\n\n", f.description));
        }
        if !f.evidence.is_empty() {
            out.push_str(&format!("**Evidence:**\n```\n{}\n```\n\n", f.evidence));
        }
        if !f.remediation.is_empty() {
            out.push_str(&format!("**Remediation:** {}\n\n", f.remediation));
        }
        out.push_str("---\n\n");
    }
    (
        [
            (header::CONTENT_TYPE, "text/markdown; charset=utf-8"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"cyweb-findings.md\"",
            ),
        ],
        out,
    )
        .into_response()
}

async fn api_proxy_events(State(s): State<AppState>) -> Json<Vec<crate::proxy::ProxyEvent>> {
    if let Some(state) = &s.proxy_events {
        let g = state.read().await;
        Json(g.clone())
    } else {
        Json(Vec::new())
    }
}

async fn export_html(State(s): State<AppState>) -> Response {
    let body = report::to_html(&*s.result);
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CONTENT_DISPOSITION, "attachment; filename=\"cyweb-findings.html\""),
        ],
        body,
    ).into_response()
}

async fn export_sarif(State(s): State<AppState>) -> Response {
    let body = report::to_sarif(&*s.result);
    (
        [
            (header::CONTENT_TYPE, "application/sarif+json; charset=utf-8"),
            (header::CONTENT_DISPOSITION, "attachment; filename=\"cyweb-findings.sarif\""),
        ],
        body,
    ).into_response()
}

async fn export_xml(State(s): State<AppState>) -> Response {
    let body = report::to_xml(&*s.result);
    (
        [
            (header::CONTENT_TYPE, "application/xml; charset=utf-8"),
            (header::CONTENT_DISPOSITION, "attachment; filename=\"cyweb-findings.xml\""),
        ],
        body,
    ).into_response()
}

/// Phase L — Manual Request Editor backend. The GUI sends a JSON
/// envelope describing the request to replay; we forward it via a
/// fresh reqwest::Client (separate from the scan's auth context to
/// avoid leaking session state) and return the response back as JSON.
#[derive(serde::Deserialize)]
struct ReplayRequest {
    method: String,
    url: String,
    #[serde(default)]
    headers: std::collections::HashMap<String, String>,
    #[serde(default)]
    body: String,
}

#[derive(serde::Serialize)]
struct ReplayResponse {
    status: u16,
    reason: String,
    headers: Vec<(String, String)>,
    body: String,
    rtt_ms: u64,
}

async fn api_replay(Json(req): Json<ReplayRequest>) -> Json<ReplayResponse> {
    let client = match reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return Json(ReplayResponse {
                status: 0, reason: format!("client build failed: {}", e),
                headers: Vec::new(), body: String::new(), rtt_ms: 0,
            })
        }
    };
    let mut builder = match req.method.to_ascii_uppercase().as_str() {
        "GET"     => client.get(&req.url),
        "POST"    => client.post(&req.url),
        "PUT"     => client.put(&req.url),
        "PATCH"   => client.patch(&req.url),
        "DELETE"  => client.delete(&req.url),
        "HEAD"    => client.head(&req.url),
        other     => client.request(
            reqwest::Method::from_bytes(other.as_bytes()).unwrap_or(reqwest::Method::GET),
            &req.url,
        ),
    };
    for (k, v) in &req.headers {
        builder = builder.header(k.as_str(), v.as_str());
    }
    if !req.body.is_empty() {
        builder = builder.body(req.body.clone());
    }
    let start = std::time::Instant::now();
    let resp = match builder.send().await {
        Ok(r) => r,
        Err(e) => {
            return Json(ReplayResponse {
                status: 0, reason: format!("request failed: {}", e),
                headers: Vec::new(), body: String::new(), rtt_ms: start.elapsed().as_millis() as u64,
            })
        }
    };
    let status = resp.status().as_u16();
    let reason = resp.status().canonical_reason().unwrap_or("").to_string();
    let headers: Vec<(String, String)> = resp.headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let body = resp.text().await.unwrap_or_default();
    Json(ReplayResponse {
        status, reason, headers, body,
        rtt_ms: start.elapsed().as_millis() as u64,
    })
}

fn csv_field(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

#[allow(dead_code)] // surfaced if we later want a 404 path
async fn not_found() -> impl IntoResponse {
    (StatusCode::NOT_FOUND, "404")
}
