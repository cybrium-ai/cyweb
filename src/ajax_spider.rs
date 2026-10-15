//! v0.8 Phase N — AJAX headless spider.
//!
//! Drives a headless Chromium via Chrome DevTools Protocol
//! (chromiumoxide). For SPAs (React/Vue/Angular) the static spider
//! misses 30-50% of routes because the page only assembles its nav
//! after JS executes. This module navigates the target in a real
//! browser, waits for the load event, then extracts every link the
//! DOM has at that point.
//!
//! Discovered URLs are folded into the existing crawler's URL list
//! so all subsequent phases (passive checks, retire.js, fuzz, …)
//! see them.

use crate::crawler::{CrawledNode, SeedSource};
use chromiumoxide::cdp::browser_protocol::network::{EnableParams, EventRequestWillBeSent};
use chromiumoxide::Browser;
use chromiumoxide::BrowserConfig;
use futures::StreamExt;
use std::time::Duration;

/// Path suffixes for static assets that carry no injectable surface — skipped
/// when folding captured network requests into the crawl list so the fuzzer
/// isn't handed fonts/images/stylesheets.
const STATIC_ASSET_EXTS: [&str; 13] = [
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
    ".woff", ".woff2", ".ttf", ".map",
];

fn is_static_asset(url: &str) -> bool {
    let path = url.split(['?', '#']).next().unwrap_or(url).to_ascii_lowercase();
    STATIC_ASSET_EXTS.iter().any(|ext| path.ends_with(ext))
}

/// Drive a headless Chrome at `target`, return additional URLs
/// discovered after JS rendered. Errors return empty vec — falling
/// back to the static spider is the right default rather than
/// failing the whole scan because the operator doesn't have Chrome
/// installed.
pub async fn ajax_crawl(target: &str, max_pages: usize) -> Vec<CrawledNode> {
    let chrome_path = std::env::var("CYWEB_CHROME_PATH").ok();

    // no_sandbox is required to launch Chrome as a non-root user inside a
    // container without the SUID sandbox / user-namespace caps (the K8s Job
    // case). DEFAULT_ARGS already carries --disable-dev-shm-usage.
    let mut config_builder = BrowserConfig::builder().no_sandbox();
    if let Some(p) = chrome_path {
        config_builder = config_builder.chrome_executable(p);
    }
    let config = match config_builder.build() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("  AJAX spider: chrome config build failed: {}", e);
            return Vec::new();
        }
    };

    let (mut browser, mut handler) = match Browser::launch(config).await {
        Ok(b) => b,
        Err(e) => {
            eprintln!(
                "  AJAX spider: failed to launch Chrome ({}). Set CYWEB_CHROME_PATH or install Chrome/Chromium to enable.",
                e
            );
            return Vec::new();
        }
    };

    // chromiumoxide requires a background task draining the handler.
    let handler_task = tokio::spawn(async move {
        while let Some(_) = handler.next().await {}
    });

    let nodes = match drive_crawl(&mut browser, target, max_pages).await {
        Ok(n) => n,
        Err(e) => {
            eprintln!("  AJAX spider: navigation error: {}", e);
            Vec::new()
        }
    };

    // Best-effort cleanup.
    let _ = browser.close().await;
    let _ = handler_task.await;

    nodes
}

async fn drive_crawl(
    browser: &mut Browser,
    target: &str,
    max_pages: usize,
) -> Result<Vec<CrawledNode>, Box<dyn std::error::Error + Send + Sync>> {
    let target_url = url::Url::parse(target)?;
    let target_host = target_url.host_str().unwrap_or("").to_string();

    let mut visited: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut queue:   Vec<String> = vec![target.to_string()];
    let mut out:     Vec<CrawledNode> = Vec::new();

    while let Some(url) = queue.pop() {
        if visited.len() >= max_pages {
            break;
        }
        if !visited.insert(url.clone()) {
            continue;
        }

        // Open a blank page first so the network listener is wired BEFORE
        // navigation — then drive it to the URL. This captures the XHR/fetch
        // endpoints the SPA calls as it boots (its real server-side attack
        // surface, e.g. /rest/products/search?q=), which a DOM <a href> scan
        // alone never sees.
        let page = match browser.new_page("about:blank").await {
            Ok(p) => p,
            Err(e) => {
                tracing::debug!("ajax blank page open failed: {}", e);
                continue;
            }
        };
        let _ = page.execute(EnableParams::default()).await;
        let mut req_stream = page.event_listener::<EventRequestWillBeSent>().await.ok();

        if let Err(e) = page.goto(&url).await {
            tracing::debug!("ajax navigate failed: {}", e);
            let _ = page.close().await;
            continue;
        }
        // Give the SPA time to settle while we drain the network events it
        // fires. wait_for_navigation returns once the load event fires; the
        // drain window lets the JS app populate its nav AND issue its API calls.
        let _ = page.wait_for_navigation().await;

        let mut captured: Vec<String> = Vec::new();
        if let Some(stream) = req_stream.as_mut() {
            let drain = async {
                while let Some(ev) = stream.next().await {
                    captured.push(ev.request.url.clone());
                }
            };
            let _ = tokio::time::timeout(Duration::from_millis(3500), drain).await;
        } else {
            tokio::time::sleep(Duration::from_millis(800)).await;
        }

        // Pull every <a href> from the rendered DOM.
        let result = page
            .evaluate(
                "Array.from(document.querySelectorAll('a[href]')).map(a => a.href)",
            )
            .await;
        let dom_links: Vec<String> = match result {
            Ok(eval) => eval.into_value().unwrap_or_default(),
            Err(_) => Vec::new(),
        };

        // Merge DOM links (tagged AJAX) with captured network requests (tagged
        // XHR). Static assets from the network capture are dropped — they carry
        // no injectable surface.
        let mut candidates: Vec<(String, &'static str)> = Vec::new();
        for l in dom_links {
            candidates.push((l, "AJAX"));
        }
        for r in captured {
            if !is_static_asset(&r) {
                candidates.push((r, "XHR"));
            }
        }

        let parent = url.clone();
        for (raw, tag) in candidates {
            // Resolve relative URLs in the unlikely case Chrome left
            // them un-resolved (it usually returns absolute).
            let abs = match url::Url::parse(&raw) {
                Ok(u) => u,
                Err(_) => match target_url.join(&raw) {
                    Ok(u) => u,
                    Err(_) => continue,
                },
            };
            if !matches!(abs.scheme(), "http" | "https") {
                continue;
            }
            let in_scope = abs.host_str() == Some(target_host.as_str());
            let abs_str = abs.to_string();
            out.push(CrawledNode {
                url: abs_str.clone(),
                method: "GET".into(),
                seed_source: SeedSource::Link,
                in_scope,
                processed: false,
                status_code: None,
                content_type: None,
                parent_url: Some(parent.clone()),
                req_timestamp: None,
                rtt_ms: 0,
                resp_header_size: 0,
                resp_body_size: 0,
                reason: None,
                tags: vec![tag.into()],
                highest_alert: None,
            });
            if in_scope && !visited.contains(&abs_str) && queue.len() + visited.len() < max_pages * 2 {
                queue.push(abs_str);
            }
        }

        let _ = page.close().await;
    }

    Ok(out)
}
