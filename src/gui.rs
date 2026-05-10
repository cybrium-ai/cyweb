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
use axum::{
    extract::State,
    http::{header, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::get,
    Json, Router,
};
use std::net::SocketAddr;
use std::sync::Arc;

/// Static assets bundled at compile time.
const INDEX_HTML: &str = include_str!("assets/gui_index.html");
const LOGO_SVG:   &str = include_str!("assets/cybrium-logo.svg");

#[derive(Clone)]
struct AppState {
    result: Arc<ScanResult>,
}

pub async fn start_server(result: ScanResult, port: u16) -> std::io::Result<()> {
    let state = AppState {
        result: Arc::new(result),
    };

    let app = Router::new()
        .route("/",                    get(serve_index))
        .route("/logo.svg",            get(serve_logo))
        .route("/api/result",          get(api_result))
        .route("/api/export.json",     get(export_json))
        .route("/api/export.csv",      get(export_csv))
        .route("/api/export.markdown", get(export_markdown))
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
