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
//!
//! v0.9 — `cyweb gui` standalone mode. The GUI can now run without a
//! prior scan: the index page shows a "Start scan" panel, target +
//! options are POSTed to `/api/scan`, the scan runs as a tokio task,
//! and the page polls `/api/scan/:id` for progress. When complete,
//! findings render in the existing table. Multiple scans can be run
//! sequentially in one GUI session.

use crate::scanner::{ScanConfig, ScanResult};
use crate::report;
use axum::{
    extract::{Path as AxumPath, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Static assets bundled at compile time.
const INDEX_HTML:    &str = include_str!("assets/gui_index.html");
const LOGO_SVG:      &str = include_str!("assets/cybrium-logo.svg");
const WORDMARK_SVG:  &str = include_str!("assets/cybrium-word.svg");

/// v0.9 — Per-scan state surfaced to the GUI poller.
#[derive(Clone, serde::Serialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum ScanState {
    Running {
        target: String,
        started_at: String,
    },
    Completed {
        result: Box<ScanResult>,
    },
    Failed {
        target: String,
        error: String,
    },
}

/// v0.9 — Shared registry of scans started via `POST /api/scan`.
/// Stored in `AppState` so handlers can read/write it from any
/// concurrent task. RwLock is fine here: we read on every poll
/// (~once every 1-2s per client) and write twice per scan (insert
/// Running on start, replace with Completed/Failed when done).
type ScanRegistry = Arc<RwLock<HashMap<String, ScanState>>>;

#[derive(Clone)]
struct AppState {
    result: Arc<ScanResult>,
    /// v0.8 Phase M — set when running `cyweb proxy`. The GUI's
    /// History tab reads this on each poll.
    proxy_events: Option<crate::proxy::ProxyState>,
    /// v0.9 — scans started from the GUI itself (`POST /api/scan`).
    scans: ScanRegistry,
}

/// v0.9 — Body for `POST /api/scan`. Only `target` is required;
/// everything else has CLI-default semantics so a barebones request
/// `{"target":"https://example.com"}` does the same thing as
/// `cyweb scan https://example.com` from the shell.
#[derive(Deserialize)]
struct ScanRequest {
    target: String,
    #[serde(default = "default_threads")]
    threads: usize,
    #[serde(default = "default_timeout")]
    timeout: u64,
    #[serde(default = "default_max_paths")]
    max_paths: usize,
    #[serde(default)]
    spider: bool,
    #[serde(default = "default_spider_depth")]
    spider_depth: usize,
    #[serde(default)]
    full: bool,
    #[serde(default)]
    fuzz: bool,
    #[serde(default)]
    tls_check: bool,
    #[serde(default)]
    follow_redirects: bool,
    #[serde(default)]
    ajax_spider: bool,
    /// Optional comma-separated tuning slots, mirroring `--tuning`.
    #[serde(default)]
    tuning: Option<String>,
}

fn default_threads()       -> usize { 10 }
fn default_timeout()       -> u64   { 10 }
fn default_max_paths()     -> usize { 200 }
fn default_spider_depth()  -> usize { 2 }

pub async fn start_server(result: ScanResult, port: u16) -> std::io::Result<()> {
    start_server_inner(result, port, None).await
}

/// v0.9 — Idle GUI mode. Starts the server with no prior scan; the
/// frontend shows the scan-launcher form. Triggered by `cyweb gui`
/// CLI command. The empty result is a stub; the real findings land
/// in the per-scan registry once the operator kicks one off.
pub async fn start_server_idle(port: u16) -> std::io::Result<()> {
    let stub = ScanResult {
        target: "(no scan yet)".into(),
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
    start_server_inner(stub, port, None).await
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
        scans: Arc::new(RwLock::new(HashMap::new())),
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
        // v0.9 — scan-trigger endpoints. POST starts a scan in a
        // detached task and returns its scan_id immediately. GET
        // returns the current state (running / completed / failed)
        // — the frontend polls every 2s. /api/scans returns the
        // full registry for the history sidebar.
        .route("/api/scan",            post(api_start_scan))
        .route("/api/scan/:scan_id",   get(api_get_scan))
        .route("/api/scans",           get(api_list_scans))
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

// ── v0.9 scan-trigger handlers ────────────────────────────────────

/// POST /api/scan — Accept a scan request, register it as Running,
/// spawn the actual scan as a detached tokio task, return the
/// scan_id immediately. The frontend then polls /api/scan/:id every
/// 1-2s until status flips to Completed or Failed.
async fn api_start_scan(
    State(s): State<AppState>,
    Json(req): Json<ScanRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let target = req.target.trim().to_string();
    if target.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "target is required".into()));
    }
    // Normalize URL — add https:// if user typed bare host (mirrors
    // the lenient parsing the CLI flow does).
    let target = if target.starts_with("http://") || target.starts_with("https://") {
        target
    } else {
        format!("https://{}", target)
    };

    let scan_id = uuid::Uuid::new_v4().to_string();
    let started_at = chrono::Utc::now().to_rfc3339();

    // Insert the Running placeholder before we spawn so a fast
    // poller immediately sees it.
    {
        let mut reg = s.scans.write().await;
        reg.insert(
            scan_id.clone(),
            ScanState::Running {
                target: target.clone(),
                started_at: started_at.clone(),
            },
        );
    }

    let config = scan_config_from_request(&req, &target);
    // tokio::spawn'ing run_scan() trips a HRTB-lifetime error because
    // its body iterates over `&Rule` / `&Template` / `&PathCheck`
    // slices with closures that aren't `for<'a>` general. Boxing
    // the future before spawning forces a concrete `'static + Send`
    // type and lets the compiler accept the spawn boundary.
    let fut: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> =
        Box::pin(run_scan_task(s.scans.clone(), scan_id.clone(), config));
    tokio::spawn(fut);

    Ok(Json(serde_json::json!({
        "scan_id":    scan_id,
        "status":     "running",
        "started_at": started_at,
        "target":     target,
    })))
}

/// GET /api/scan/:scan_id — Return the current state. The frontend
/// polls this. Returns 404 if the id isn't in the registry (e.g.
/// server was restarted, or the id was made up).
async fn api_get_scan(
    State(s): State<AppState>,
    AxumPath(scan_id): AxumPath<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let reg = s.scans.read().await;
    let state = reg.get(&scan_id).ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(serde_json::json!({
        "scan_id": scan_id,
        "state":   state,
    })))
}

/// GET /api/scans — List every scan in the registry. The frontend
/// can use this to render a sidebar / history.
async fn api_list_scans(State(s): State<AppState>) -> Json<serde_json::Value> {
    let reg = s.scans.read().await;
    let mut scans: Vec<serde_json::Value> = reg
        .iter()
        .map(|(id, state)| {
            let (status, target) = match state {
                ScanState::Running { target, .. }   => ("running",   target.clone()),
                ScanState::Completed { result }     => ("completed", result.target.clone()),
                ScanState::Failed { target, .. }    => ("failed",    target.clone()),
            };
            serde_json::json!({
                "scan_id": id,
                "status":  status,
                "target":  target,
            })
        })
        .collect();
    // Stable order so the sidebar doesn't flicker between polls.
    scans.sort_by(|a, b| {
        a["scan_id"].as_str().unwrap_or("")
            .cmp(b["scan_id"].as_str().unwrap_or(""))
    });
    Json(serde_json::json!({ "scans": scans }))
}

/// Boxed wrapper around `scanner::run_scan` that erases the inner
/// future's generic / HRTB lifetimes through `Pin<Box<dyn Future>>`.
/// `tokio::spawn` rejects the raw `run_scan(...)` future because it
/// captures `for<'a>` closures over `&Rule` / `&Template` / `&PathCheck`
/// slices that the compiler can't prove are general enough across the
/// spawn boundary. Converting to a concrete trait-object future
/// removes the HRTB inference step entirely — the spawned future
/// only has to be `'static + Send + Future<Output = ScanResult>`,
/// which `Box::pin` guarantees.
fn run_scan_boxed(
    config: ScanConfig,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = ScanResult> + Send>> {
    Box::pin(async move { crate::scanner::run_scan(config).await })
}

/// Detached task that owns the scan future and stores the result
/// back into the shared registry. Owned-only args so the captured
/// future is `'static`.
async fn run_scan_task(scans: ScanRegistry, scan_id: String, config: ScanConfig) {
    let result = run_scan_boxed(config).await;
    let mut reg = scans.write().await;
    reg.insert(scan_id, ScanState::Completed {
        result: Box::new(result),
    });
}

/// Build a ScanConfig from the GUI-side ScanRequest, filling in
/// defaults for every field the GUI doesn't expose. Kept separate
/// from the handler so the field list is one place to audit when
/// ScanConfig grows.
fn scan_config_from_request(req: &ScanRequest, target: &str) -> ScanConfig {
    ScanConfig {
        target: target.to_string(),
        threads: req.threads,
        timeout_secs: req.timeout,
        max_paths: req.max_paths,
        follow_redirects: req.follow_redirects,
        user_agent: format!("cyweb/{} (https://cybrium.ai)", env!("CARGO_PKG_VERSION")),
        spider_enabled: req.spider,
        spider_depth: req.spider_depth,
        auth_bearer: None,
        auth_cookie: None,
        auth_basic: None,
        custom_headers: Vec::new(),
        proxy: None,
        rate_limit: 0,
        tls_check: req.tls_check,
        rules_file: None,
        openapi_url: None,
        resume: false,
        full_scan: req.full,
        vhost: None,
        client_cert: None,
        client_key: None,
        tuning: req.tuning.clone(),
        save_dir: None,
        no_lookup: false,
        platform: "auto".to_string(),
        evasion_mode: 0,
        mutate_mode: 0,
        fuzz_enabled: req.fuzz,
        payloads_dir: None,
        templates_dir: None,
        ajax_spider: req.ajax_spider,
        session_max_relogins: 0,
        session_expired_pattern: None,
        session_expired_sentinel: None,
        http_version: "auto".to_string(),
        strength: "medium".to_string(),
        threshold: "high".to_string(),
        login_user: None,
        login_pass: None,
        login_url_explicit: None,
    }
}
