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
use chromiumoxide::Browser;
use chromiumoxide::BrowserConfig;
use futures::StreamExt;
use std::time::Duration;

/// Drive a headless Chrome at `target`, return additional URLs
/// discovered after JS rendered. Errors return empty vec — falling
/// back to the static spider is the right default rather than
/// failing the whole scan because the operator doesn't have Chrome
/// installed.
pub async fn ajax_crawl(target: &str, max_pages: usize) -> Vec<CrawledNode> {
    let chrome_path = std::env::var("CYWEB_CHROME_PATH").ok();

    let mut config_builder = BrowserConfig::builder();
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

        let page = match browser.new_page(&url).await {
            Ok(p) => p,
            Err(e) => {
                tracing::debug!("ajax page open failed: {}", e);
                continue;
            }
        };
        // Give the SPA up to 6 seconds to settle. wait_for_navigation
        // returns once load event fires; we add a small extra delay
        // for the JS app to populate its nav.
        let _ = page.wait_for_navigation().await;
        tokio::time::sleep(Duration::from_millis(800)).await;

        // Pull every <a href> from the rendered DOM.
        let result = page
            .evaluate(
                "Array.from(document.querySelectorAll('a[href]')).map(a => a.href)",
            )
            .await;
        let links: Vec<String> = match result {
            Ok(eval) => eval.into_value().unwrap_or_default(),
            Err(_) => Vec::new(),
        };

        let parent = url.clone();
        for raw in links {
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
                tags: vec!["AJAX".into()],
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
