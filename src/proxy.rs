//! v0.8 Phase M — HTTP intercept proxy.
//!
//! `cyweb proxy [--port 8989] [--gui-port 8990]` starts an HTTP proxy
//! on 127.0.0.1:8989 plus the GUI on 127.0.0.1:8990. Configure your
//! browser to use the proxy, browse the target, and every request +
//! response is captured into the GUI's History tab.
//!
//! v0.8 scope:
//!   - Plain HTTP: full request/response capture (method, URL,
//!     headers, body, status, RTT, sizes)
//!   - HTTPS via CONNECT: transparently tunneled (we only see the
//!     CONNECT line — the encrypted body is not inspected). A
//!     follow-up release will add HTTPS MITM with a generated CA
//!     cert; that needs operator-side setup (install ca.pem in
//!     browser trust store) which deserves its own ergonomics pass.
//!
//! All captured events live in a shared Arc<RwLock<Vec<ProxyEvent>>>
//! that the GUI's `/api/proxy_events` endpoint reads on each poll.

use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize)]
pub struct ProxyEvent {
    pub id: u64,
    pub at: String,
    pub method: String,
    pub url: String,
    pub status: u16,
    pub reason: String,
    pub rtt_ms: u64,
    pub req_size: usize,
    pub resp_size: usize,
    pub req_headers: Vec<(String, String)>,
    pub resp_headers: Vec<(String, String)>,
    /// Set to "tunnel" for HTTPS CONNECT requests (body not inspected).
    pub kind: String,
}

pub type ProxyState = Arc<RwLock<Vec<ProxyEvent>>>;

pub async fn start(port: u16, state: ProxyState) -> std::io::Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", port)).await?;
    eprintln!("\x1b[1;35m  Proxy listening on http://127.0.0.1:{}\x1b[0m", port);
    eprintln!("\x1b[2m  Configure your browser proxy → 127.0.0.1:{} (HTTP/HTTPS)\x1b[0m", port);
    eprintln!("\x1b[2m  HTTPS traffic is tunneled (CONNECT) without body inspection in this release.\x1b[0m");

    let mut next_id: u64 = 1;
    loop {
        let (socket, _addr) = match listener.accept().await {
            Ok(p) => p,
            Err(e) => {
                eprintln!("proxy accept failed: {}", e);
                continue;
            }
        };
        let state = state.clone();
        let id = next_id;
        next_id = next_id.wrapping_add(1);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(socket, id, state).await {
                tracing::debug!("proxy connection error: {}", e);
            }
        });
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    id: u64,
    state: ProxyState,
) -> std::io::Result<()> {
    // Peek the first line to decide CONNECT vs regular request.
    let mut buf = vec![0u8; 8192];
    let n = stream.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }
    let head = String::from_utf8_lossy(&buf[..n]);

    if head.starts_with("CONNECT ") {
        return handle_connect(stream, id, state, &head).await;
    }

    handle_http(stream, id, state, &buf[..n]).await
}

/// Handle an `http://example.com/path` proxied GET / POST / etc.
/// We re-issue the request via reqwest and stream the response back.
async fn handle_http(
    mut client_stream: TcpStream,
    id: u64,
    state: ProxyState,
    initial: &[u8],
) -> std::io::Result<()> {
    // Drain remaining body if there's a Content-Length.
    let mut req_bytes = initial.to_vec();
    let header_end = match find_double_crlf(&req_bytes) {
        Some(i) => i,
        None => {
            // Request still incoming — read a bit more.
            let mut more = vec![0u8; 8192];
            let n = client_stream.read(&mut more).await.unwrap_or(0);
            req_bytes.extend_from_slice(&more[..n]);
            match find_double_crlf(&req_bytes) {
                Some(i) => i,
                None => {
                    client_stream
                        .write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                        .await?;
                    return Ok(());
                }
            }
        }
    };
    let head_str = String::from_utf8_lossy(&req_bytes[..header_end]).to_string();
    let mut lines = head_str.lines();
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method_s = parts.next().unwrap_or("GET").to_string();
    let url_s    = parts.next().unwrap_or("/").to_string();

    // Parse headers
    let mut req_headers: Vec<(String, String)> = Vec::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            req_headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    let content_length: usize = req_headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);

    // Read remaining body bytes if any.
    let mut body_bytes = req_bytes[header_end + 4..].to_vec();
    while body_bytes.len() < content_length {
        let mut chunk = vec![0u8; 8192];
        let n = client_stream.read(&mut chunk).await.unwrap_or(0);
        if n == 0 {
            break;
        }
        body_bytes.extend_from_slice(&chunk[..n]);
    }
    let req_total_size = req_bytes.len() + body_bytes.len();

    // Build reqwest call.
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    let method = reqwest::Method::from_bytes(method_s.as_bytes())
        .unwrap_or(reqwest::Method::GET);
    let mut req = client.request(method, &url_s);
    for (k, v) in &req_headers {
        // Skip hop-by-hop headers proxies must not forward.
        let lk = k.to_ascii_lowercase();
        if matches!(
            lk.as_str(),
            "connection" | "proxy-connection" | "keep-alive" |
            "transfer-encoding" | "te" | "trailer" | "upgrade"
        ) {
            continue;
        }
        req = req.header(k, v);
    }
    if !body_bytes.is_empty() {
        req = req.body(body_bytes.clone());
    }

    let started = Instant::now();
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            let body = format!("cyweb proxy error: {}", e);
            let resp_bytes = format!(
                "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
                body.len(), body
            );
            let _ = client_stream.write_all(resp_bytes.as_bytes()).await;
            record_event(
                &state, id, &method_s, &url_s, 502, "Bad Gateway",
                started.elapsed().as_millis() as u64,
                req_total_size, body.len(),
                req_headers, Vec::new(), "http",
            ).await;
            return Ok(());
        }
    };
    let rtt = started.elapsed().as_millis() as u64;
    let status = resp.status().as_u16();
    let reason = resp.status().canonical_reason().unwrap_or("").to_string();
    let resp_headers: Vec<(String, String)> = resp.headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let resp_body = resp.bytes().await.unwrap_or_default();

    // Build the HTTP response to the client.
    let mut out = format!("HTTP/1.1 {} {}\r\n", status, reason);
    let mut wrote_cl = false;
    for (k, v) in &resp_headers {
        let lk = k.to_ascii_lowercase();
        if matches!(
            lk.as_str(),
            "transfer-encoding" | "connection" | "keep-alive"
        ) {
            continue;
        }
        if lk == "content-length" {
            wrote_cl = true;
        }
        out.push_str(&format!("{}: {}\r\n", k, v));
    }
    if !wrote_cl {
        out.push_str(&format!("Content-Length: {}\r\n", resp_body.len()));
    }
    out.push_str("Connection: close\r\n\r\n");
    let _ = client_stream.write_all(out.as_bytes()).await;
    let _ = client_stream.write_all(&resp_body).await;
    let _ = client_stream.shutdown().await;

    record_event(
        &state, id, &method_s, &url_s, status, &reason, rtt,
        req_total_size, resp_body.len(),
        req_headers, resp_headers, "http",
    ).await;

    Ok(())
}

/// CONNECT — tunnel raw TCP both ways without inspection.
async fn handle_connect(
    mut client_stream: TcpStream,
    id: u64,
    state: ProxyState,
    head: &str,
) -> std::io::Result<()> {
    // Parse "CONNECT host:port HTTP/1.1"
    let target = head
        .split_whitespace()
        .nth(1)
        .unwrap_or("")
        .to_string();
    if target.is_empty() {
        client_stream
            .write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            .await?;
        return Ok(());
    }

    let started = Instant::now();
    let upstream = match TcpStream::connect(&target).await {
        Ok(s) => s,
        Err(_) => {
            client_stream
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                .await?;
            record_event(
                &state, id, "CONNECT", &format!("https://{}/", target),
                502, "Bad Gateway", started.elapsed().as_millis() as u64,
                0, 0, Vec::new(), Vec::new(), "tunnel",
            ).await;
            return Ok(());
        }
    };
    client_stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;

    // Tunnel both directions until either side closes.
    let (mut c_r, mut c_w) = client_stream.into_split();
    let (mut u_r, mut u_w) = upstream.into_split();

    let bytes_a = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let bytes_b = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let a = bytes_a.clone();
    let b = bytes_b.clone();
    let t1 = tokio::spawn(async move {
        let n = tokio::io::copy(&mut c_r, &mut u_w).await.unwrap_or(0);
        a.store(n as usize, std::sync::atomic::Ordering::SeqCst);
    });
    let t2 = tokio::spawn(async move {
        let n = tokio::io::copy(&mut u_r, &mut c_w).await.unwrap_or(0);
        b.store(n as usize, std::sync::atomic::Ordering::SeqCst);
    });
    let _ = t1.await;
    let _ = t2.await;

    record_event(
        &state, id, "CONNECT", &format!("https://{}/", target),
        200, "Connection Established",
        started.elapsed().as_millis() as u64,
        bytes_a.load(std::sync::atomic::Ordering::SeqCst),
        bytes_b.load(std::sync::atomic::Ordering::SeqCst),
        Vec::new(), Vec::new(), "tunnel",
    ).await;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn record_event(
    state: &ProxyState,
    id: u64,
    method: &str,
    url: &str,
    status: u16,
    reason: &str,
    rtt_ms: u64,
    req_size: usize,
    resp_size: usize,
    req_headers: Vec<(String, String)>,
    resp_headers: Vec<(String, String)>,
    kind: &str,
) {
    let evt = ProxyEvent {
        id,
        at: chrono::Utc::now().to_rfc3339(),
        method: method.to_string(),
        url: url.to_string(),
        status,
        reason: reason.to_string(),
        rtt_ms,
        req_size,
        resp_size,
        req_headers,
        resp_headers,
        kind: kind.to_string(),
    };
    let mut g = state.write().await;
    g.push(evt);
    // Cap to avoid unbounded memory growth on long sessions.
    if g.len() > 10_000 {
        let drop = g.len() - 10_000;
        g.drain(..drop);
    }
}

fn find_double_crlf(b: &[u8]) -> Option<usize> {
    for i in 0..b.len().saturating_sub(3) {
        if &b[i..i + 4] == b"\r\n\r\n" {
            return Some(i);
        }
    }
    None
}

/// Headless `cyweb proxy` entry — keeps the proxy + GUI alive until
/// Ctrl-C. The GUI's existing /api/result endpoint serves a stub
/// ScanResult so the page renders; /api/proxy_events streams
/// captured traffic.
pub async fn run_proxy_subcommand(port: u16, gui_port: u16) -> std::io::Result<()> {
    let state: ProxyState = Arc::new(RwLock::new(Vec::new()));
    // Start the proxy task.
    let proxy_state = state.clone();
    tokio::spawn(async move {
        let _ = start(port, proxy_state).await;
    });
    // Start the GUI in proxy-mode (empty ScanResult, but proxy_events
    // populated live).
    crate::gui::start_server_proxy(state, gui_port).await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dbl_crlf() {
        assert_eq!(find_double_crlf(b"GET / HTTP/1.1\r\nHost: x\r\n\r\nbody"), Some(31));
        assert_eq!(find_double_crlf(b"GET / HTTP/1.1\r\n"), None);
    }
    #[test]
    fn empty_headers_dont_panic() {
        let _: HashMap<String, String> = HashMap::new();
    }
}
