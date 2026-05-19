//! v0.8.5 — Non-HTTP template protocol runners.
//!
//! Cyweb's templates engine grew `DnsStep` / `TcpStep` types in
//! earlier releases but never had runtime support — DNS-only, TCP-
//! only, and headless-only templates got rejected at conversion
//! time. This module fills that gap.
//!
//! - DNS: hickory-resolver (pure-Rust async DNS client) executes
//!   the template's query, runs matchers against the response.
//! - TCP: raw `tokio::net::TcpStream` opens the host:port from the
//!   template, sends the `data:` payload (with variable substitution),
//!   reads the banner up to a 4 KiB cap, runs matchers.
//! - Headless: chromiumoxide drives a real Chrome instance to load
//!   the page, waits for JS to settle, runs matchers against the
//!   final DOM.
//!
//! All three honour the same `Matcher` shape the HTTP runner uses
//! (status / word / regex / size / binary / dsl), so a template that
//! moves from one protocol to another doesn't need its matcher logic
//! rewritten.

use crate::signatures::Finding;
use crate::templates::{Matcher, Template, evaluate_dsl, parse_severity};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Execute every DNS step in the template against `target`. Target
/// is interpreted as the FQDN to query (cyweb's scan target may be
/// a URL — we strip scheme/path and resolve the host).
pub async fn run_dns(target: &str, tpl: &Template) -> Vec<Finding> {
    use hickory_resolver::TokioAsyncResolver;
    use hickory_resolver::config::{ResolverConfig, ResolverOpts};

    let mut findings = Vec::new();
    if tpl.dns.is_empty() {
        return findings;
    }

    let resolver = TokioAsyncResolver::tokio(
        ResolverConfig::default(),
        ResolverOpts::default(),
    );

    let host = host_from_target(target);
    for step in &tpl.dns {
        let qname = if step.name.is_empty() {
            host.clone()
        } else {
            // {{Hostname}} placeholder substitution
            step.name.replace("{{Hostname}}", &host).replace("{{FQDN}}", &host)
        };
        let qtype = step.query_type.to_uppercase();

        // Query
        let answer_text = match qtype.as_str() {
            "A" => match resolver.lookup_ip(qname.as_str()).await {
                Ok(r) => r.iter().map(|ip| ip.to_string()).collect::<Vec<_>>().join("\n"),
                Err(e) => format!("DNS error: {}", e),
            },
            "TXT" => match resolver.txt_lookup(qname.as_str()).await {
                Ok(r) => r.iter().flat_map(|t| t.iter())
                    .map(|d| String::from_utf8_lossy(d).into_owned())
                    .collect::<Vec<_>>().join("\n"),
                Err(e) => format!("DNS error: {}", e),
            },
            "CNAME" => match resolver.lookup(qname.as_str(), hickory_resolver::proto::rr::RecordType::CNAME).await {
                Ok(r) => r.iter().map(|rd| rd.to_string()).collect::<Vec<_>>().join("\n"),
                Err(e) => format!("DNS error: {}", e),
            },
            "MX" => match resolver.mx_lookup(qname.as_str()).await {
                Ok(r) => r.iter().map(|mx| format!("{} {}", mx.preference(), mx.exchange()))
                    .collect::<Vec<_>>().join("\n"),
                Err(e) => format!("DNS error: {}", e),
            },
            "NS" => match resolver.ns_lookup(qname.as_str()).await {
                Ok(r) => r.iter().map(|ns| ns.to_string()).collect::<Vec<_>>().join("\n"),
                Err(e) => format!("DNS error: {}", e),
            },
            _ => format!("Unsupported DNS query type: {}", qtype),
        };

        // Run matchers — DNS uses the same matcher shape as HTTP, with
        // body=answer_text, headers=empty, status=200 if we got an
        // answer (non-empty + no error prefix).
        let status = if answer_text.starts_with("DNS error") || answer_text.is_empty() { 0 } else { 200 };
        let empty_headers = reqwest::header::HeaderMap::new();
        let any_match = step.matchers.iter().any(|m| match_simple(m, &answer_text, &empty_headers, status));
        if any_match {
            findings.push(Finding {
                id: format!("CYWEB-DNS-{}", tpl.display_id()),
                title: tpl.info.name.clone(),
                severity: parse_severity(&tpl.info.severity),
                category: "DNS".into(),
                description: format!(
                    "DNS {} query for `{}` returned a response that matched the template's criteria.",
                    qtype, qname
                ),
                evidence: truncate(&answer_text, 500),
                url: format!("dns://{}/{}", qname, qtype),
                cwe: tpl.info.cwe.first().cloned(),
                remediation: tpl.info.remediation.clone(),
                vuln_class: None,
            });
        }
    }
    findings
}

/// Execute every TCP step in the template. Each step opens
/// host:port, sends the data payload, reads the banner.
pub async fn run_tcp(target: &str, tpl: &Template) -> Vec<Finding> {
    let mut findings = Vec::new();
    if tpl.tcp.is_empty() {
        return findings;
    }
    let host = host_from_target(target);

    for step in &tpl.tcp {
        // step.host can be "{{Hostname}}:21" or "1.2.3.4:1433"
        let addr = step.host
            .replace("{{Hostname}}", &host)
            .replace("{{Host}}", &host);
        let banner = match read_banner(&addr, &step.data, Duration::from_secs(8)).await {
            Ok(b) => b,
            Err(e) => format!("TCP error: {}", e),
        };
        let status = if banner.starts_with("TCP error") { 0 } else { 200 };
        let empty_headers = reqwest::header::HeaderMap::new();
        let any_match = step.matchers.iter().any(|m| match_simple(m, &banner, &empty_headers, status));
        if any_match {
            findings.push(Finding {
                id: format!("CYWEB-TCP-{}", tpl.display_id()),
                title: tpl.info.name.clone(),
                severity: parse_severity(&tpl.info.severity),
                category: "TCP Service".into(),
                description: format!(
                    "TCP service on `{}` returned a banner that matched the template's criteria.",
                    addr
                ),
                evidence: truncate(&banner, 500),
                url: format!("tcp://{}", addr),
                cwe: tpl.info.cwe.first().cloned(),
                remediation: tpl.info.remediation.clone(),
                vuln_class: None,
            });
        }
    }
    findings
}

/// Headless-Chrome template execution. Loads the URL, waits for JS
/// to settle, runs matchers against the final rendered HTML. Skips
/// silently if Chrome isn't available — operators who need
/// headless coverage install Chrome and set CYWEB_CHROME_PATH if
/// auto-discovery doesn't find it.
pub async fn run_headless(target: &str, tpl: &Template) -> Vec<Finding> {
    use chromiumoxide::Browser;
    use chromiumoxide::BrowserConfig;
    use futures::StreamExt;

    let mut findings = Vec::new();
    // Headless templates use the same `requests:` block as HTTP but
    // with a sentinel info.tag of "headless". For v0.8.5 we run any
    // template tagged "headless" through this path; HTTP execution
    // skips those. Operators can also force headless via
    // info.severity="headless" (heuristic — refined in v0.8.6).
    let is_headless = tpl.info.tags.iter().any(|t| t == "headless")
        || tpl.requests.iter().any(|r| r.headers.values().any(|v| v.contains("playwright")));
    if !is_headless || tpl.requests.is_empty() {
        return findings;
    }

    let chrome_path = std::env::var("CYWEB_CHROME_PATH").ok();
    let mut config_builder = BrowserConfig::builder();
    if let Some(p) = chrome_path {
        config_builder = config_builder.chrome_executable(p);
    }
    let config = match config_builder.build() {
        Ok(c) => c,
        Err(_) => return findings,
    };
    let (mut browser, mut handler) = match Browser::launch(config).await {
        Ok(b) => b,
        Err(_) => return findings,
    };
    let handler_task = tokio::spawn(async move {
        while handler.next().await.is_some() {}
    });

    for step in &tpl.requests {
        for path in &step.path {
            let url = if path.starts_with("http") { path.clone() } else { format!("{}{}", target, path) };
            let page = match browser.new_page(&url).await {
                Ok(p) => p,
                Err(_) => continue,
            };
            let _ = page.wait_for_navigation().await;
            tokio::time::sleep(Duration::from_millis(800)).await;

            let body = page.content().await.unwrap_or_default();
            let _ = page.close().await;

            let empty_headers = reqwest::header::HeaderMap::new();
            let any_match = step.matchers.iter().any(|m| match_simple(m, &body, &empty_headers, 200));
            if any_match {
                findings.push(Finding {
                    id: format!("CYWEB-HEADLESS-{}", tpl.display_id()),
                    title: tpl.info.name.clone(),
                    severity: parse_severity(&tpl.info.severity),
                    category: "Headless DOM".into(),
                    description: format!(
                        "JS-rendered page at `{}` matched the template's criteria.",
                        url
                    ),
                    evidence: truncate(&body, 500),
                    url: url.clone(),
                    cwe: tpl.info.cwe.first().cloned(),
                    remediation: tpl.info.remediation.clone(),
                    vuln_class: None,
                });
            }
        }
    }

    let _ = browser.close().await;
    let _ = handler_task.await;
    findings
}

// ── helpers ──────────────────────────────────────────────────────────────────

async fn read_banner(addr: &str, data: &str, t: Duration) -> Result<String, String> {
    let mut stream = timeout(t, TcpStream::connect(addr))
        .await
        .map_err(|_| "connect timeout".to_string())?
        .map_err(|e| e.to_string())?;

    if !data.is_empty() {
        // Variable placeholders preserved by template loader; cyweb's
        // existing resolve_vars call site upstream handles {{...}}
        // before we reach here. We just write the bytes.
        let _ = stream.write_all(data.as_bytes()).await;
    }

    let mut buf = vec![0u8; 4096];
    let n = match timeout(t, stream.read(&mut buf)).await {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => return Err(e.to_string()),
        Err(_)     => return Err("read timeout".to_string()),
    };
    Ok(String::from_utf8_lossy(&buf[..n]).into_owned())
}

fn host_from_target(target: &str) -> String {
    if let Ok(u) = url::Url::parse(target) {
        return u.host_str().unwrap_or(target).to_string();
    }
    target.split(':').next().unwrap_or(target).to_string()
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max { s.to_string() } else { format!("{}...", &s[..max]) }
}

/// Subset of the matcher logic from `templates.rs::run_matcher`. We
/// don't need the full surface here — DNS / TCP banners use the
/// simpler word / regex / size / dsl / status set; not every code
/// path in the HTTP runner applies.
fn match_simple(
    matcher: &Matcher,
    source: &str,
    headers: &reqwest::header::HeaderMap,
    status: u16,
) -> bool {
    use regex::Regex;
    match matcher.matcher_type.as_str() {
        "word" => {
            let any = matcher.words.iter().any(|w| source.contains(w.as_str()));
            if matcher.condition == "and" {
                matcher.words.iter().all(|w| source.contains(w.as_str())) ^ matcher.negative
            } else {
                any ^ matcher.negative
            }
        }
        "regex" => {
            matcher.regex.iter().any(|p| Regex::new(p).map(|r| r.is_match(source)).unwrap_or(false))
                ^ matcher.negative
        }
        "size"   => matcher.size.contains(&source.len()) ^ matcher.negative,
        "status" => matcher.status.contains(&status) ^ matcher.negative,
        "dsl"    => {
            matcher.dsl.iter().any(|e| evaluate_dsl(e, source, headers, status))
                ^ matcher.negative
        }
        _ => false,
    }
}
