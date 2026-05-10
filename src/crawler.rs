//! v0.8 Phase E — deeper spider with ZAP-equivalent feature set.
//!
//! Now seeds from `robots.txt` (disallow paths are admin-hidden hints),
//! `sitemap.xml` (declared site URLs), and the target itself. Tracks
//! every discovered URL as a `CrawledNode` carrying its method, scope
//! flag, status code, parent URL, and seed source — exposed through
//! both the existing flat URL list (for backward compat with the other
//! scan phases) and the richer node list which the GUI's Spider tab
//! renders.
//!
//! Out-of-scope URLs (different host) are *recorded but not followed*,
//! matching ZAP's behaviour. They show up flagged in the spider table
//! so an operator can confirm the site only links to the third-party
//! domains they expect.

use crate::signatures::{Finding, Severity};
use reqwest::Client;
use scraper::{Html, Selector};
use serde::Serialize;
use std::collections::{HashMap, HashSet};

/// Where this URL was first surfaced.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SeedSource {
    /// Original target URL passed to `cyweb scan ...`.
    Target,
    /// Disallow path lifted from `/robots.txt`.
    Robots,
    /// `<loc>` element in `/sitemap.xml`.
    Sitemap,
    /// `<a href>` link found while crawling.
    Link,
    /// `<form action>` discovered while crawling.
    Form,
}

/// One row of the spider table.
#[derive(Debug, Clone, Serialize)]
pub struct CrawledNode {
    pub url: String,
    pub method: String,
    pub seed_source: SeedSource,
    pub in_scope: bool,
    pub processed: bool,
    pub status_code: Option<u16>,
    pub content_type: Option<String>,
    pub parent_url: Option<String>,
}

/// Returned by `crawl()`. Findings + node list + flat URL list (for
/// downstream phases that just want strings) + total HTTP requests.
pub struct CrawlOutcome {
    pub findings: Vec<Finding>,
    pub nodes: Vec<CrawledNode>,
    pub crawled_urls: Vec<String>,
    pub requests_made: usize,
}

/// Drop-in compat shim — preserves the (findings, requests, urls)
/// shape the rest of cyweb already calls. Internally just unpacks the
/// CrawlOutcome.
pub async fn crawl(
    client: &Client,
    target: &str,
    max_depth: usize,
    concurrency: usize,
) -> (Vec<Finding>, usize, Vec<String>) {
    let outcome = crawl_with_nodes(client, target, max_depth, concurrency).await;
    (outcome.findings, outcome.requests_made, outcome.crawled_urls)
}

/// Full crawl entry point. Returns the rich CrawlOutcome.
pub async fn crawl_with_nodes(
    client: &Client,
    target: &str,
    max_depth: usize,
    _concurrency: usize,
) -> CrawlOutcome {
    let mut findings: Vec<Finding> = Vec::new();
    let mut requests = 0usize;

    let base_url = match url::Url::parse(target) {
        Ok(u) => u,
        Err(_) => {
            return CrawlOutcome {
                findings,
                nodes: Vec::new(),
                crawled_urls: Vec::new(),
                requests_made: 0,
            }
        }
    };
    let base_host = base_url.host_str().unwrap_or("").to_string();

    // ── Build the seed set ────────────────────────────────────────────────────
    // (1) the target itself, (2) discovered Disallow paths from
    // /robots.txt, (3) <loc> entries from /sitemap.xml. ZAP does the
    // same — admins often hide sensitive paths in robots.txt and you
    // want them surfaced as scan targets, not skipped.
    //
    // Per-node tracking — a single URL can have multiple discovery
    // sources; we keep the FIRST one seen. The HashMap is keyed on
    // `(url, method)` so e.g. GET /post and POST /post are distinct.
    let mut node_index: HashMap<(String, String), CrawledNode> = HashMap::new();
    let mut queue: Vec<(String, usize, Option<String>)> = Vec::new();

    // Seed: the target itself.
    upsert_node(
        &mut node_index,
        target,
        "GET",
        SeedSource::Target,
        true,
        None,
    );
    queue.push((target.to_string(), 0, None));

    // Seed: robots.txt
    if let Some(robots_url) = base_url
        .join("/robots.txt")
        .ok()
        .map(|u| u.to_string())
    {
        if let Ok(resp) = client.get(&robots_url).send().await {
            requests += 1;
            let status = resp.status().as_u16();
            // Always log the robots.txt fetch itself.
            upsert_node(
                &mut node_index,
                &robots_url,
                "GET",
                SeedSource::Robots,
                true,
                None,
            )
            .status_code = Some(status);
            if status < 400 {
                if let Ok(body) = resp.text().await {
                    for path in parse_robots_disallows(&body) {
                        if let Ok(joined) = base_url.join(&path) {
                            let s = joined.to_string();
                            upsert_node(
                                &mut node_index,
                                &s,
                                "GET",
                                SeedSource::Robots,
                                true,
                                Some(robots_url.clone()),
                            );
                            queue.push((s, 0, Some(robots_url.clone())));
                        }
                    }
                }
            }
        }
    }

    // Seed: sitemap.xml
    if let Some(sm_url) = base_url
        .join("/sitemap.xml")
        .ok()
        .map(|u| u.to_string())
    {
        if let Ok(resp) = client.get(&sm_url).send().await {
            requests += 1;
            let status = resp.status().as_u16();
            upsert_node(
                &mut node_index,
                &sm_url,
                "GET",
                SeedSource::Sitemap,
                true,
                None,
            )
            .status_code = Some(status);
            if status < 400 {
                if let Ok(body) = resp.text().await {
                    for loc in parse_sitemap_locs(&body) {
                        let in_scope = url::Url::parse(&loc)
                            .map(|u| u.host_str() == Some(&base_host))
                            .unwrap_or(false);
                        upsert_node(
                            &mut node_index,
                            &loc,
                            "GET",
                            SeedSource::Sitemap,
                            in_scope,
                            Some(sm_url.clone()),
                        );
                        if in_scope {
                            queue.push((loc, 0, Some(sm_url.clone())));
                        }
                    }
                }
            }
        }
    }

    // ── Selectors ─────────────────────────────────────────────────────────────
    let link_selector  = Selector::parse(r#"a[href], link[href], iframe[src], frame[src]"#)
        .expect("static selector");
    let form_selector  = Selector::parse("form").expect("static selector");
    let input_password = Selector::parse("input[type=password]").expect("static selector");
    let comment_re     = regex::Regex::new(r"<!--[\s\S]*?-->").expect("static regex");

    // ── BFS crawl ─────────────────────────────────────────────────────────────
    let mut visited: HashSet<String> = HashSet::new();

    while let Some((url, depth, parent)) = queue.pop() {
        if depth > max_depth {
            continue;
        }
        if !visited.insert(url.clone()) {
            // Already fetched this URL — but make sure the node entry
            // is marked processed.
            if let Some(n) = node_index.get_mut(&(url.clone(), "GET".to_string())) {
                n.processed = true;
            }
            continue;
        }
        // Out-of-scope: log and skip the fetch.
        let parsed_node = url::Url::parse(&url).ok();
        let is_in_scope = parsed_node
            .as_ref()
            .map(|u| u.host_str() == Some(&base_host))
            .unwrap_or(false);
        if !is_in_scope {
            if let Some(n) = node_index.get_mut(&(url.clone(), "GET".to_string())) {
                n.in_scope = false;
                n.processed = true;
            }
            continue;
        }

        let resp = match client.get(&url).send().await {
            Ok(r) => r,
            Err(_) => continue,
        };
        requests += 1;
        let status = resp.status().as_u16();
        let ctype  = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let final_url = resp.url().to_string();

        // Mark the requested URL as processed (status + content-type
        // observed).
        if let Some(n) = node_index.get_mut(&(url.clone(), "GET".to_string())) {
            n.processed = true;
            n.status_code = Some(status);
            n.content_type = ctype.clone();
        }

        let body = match resp.text().await {
            Ok(b) => b,
            Err(_) => continue,
        };

        // Skip HTML parsing for non-HTML content types.
        let is_html = ctype.as_deref().unwrap_or("").contains("html");
        if !is_html {
            continue;
        }

        let doc = Html::parse_document(&body);

        // ── Anchor / link / iframe / frame extraction ───────────────────────
        for element in doc.select(&link_selector) {
            let href = element
                .value()
                .attr("href")
                .or_else(|| element.value().attr("src"));
            let href = match href {
                Some(h) => h,
                None => continue,
            };
            let resolved = match base_url.join(href) {
                Ok(u) => u,
                Err(_) => continue,
            };
            // Skip mailto:, tel:, javascript:
            if !matches!(resolved.scheme(), "http" | "https") {
                continue;
            }
            let resolved_str = resolved.to_string();
            let in_scope = resolved.host_str() == Some(&base_host);
            upsert_node(
                &mut node_index,
                &resolved_str,
                "GET",
                SeedSource::Link,
                in_scope,
                Some(final_url.clone()),
            );
            if in_scope && !visited.contains(&resolved_str) {
                queue.push((resolved_str, depth + 1, Some(final_url.clone())));
            }
        }

        // ── Form discovery — record action URL with the form's method ───────
        for form in doc.select(&form_selector) {
            let action = form.value().attr("action").unwrap_or("");
            let method = form
                .value()
                .attr("method")
                .unwrap_or("GET")
                .to_ascii_uppercase();
            let action_url = if action.is_empty() {
                final_url.clone()
            } else {
                match base_url.join(action) {
                    Ok(u) => u.to_string(),
                    Err(_) => continue,
                }
            };
            let in_scope = url::Url::parse(&action_url)
                .map(|u| u.host_str() == Some(&base_host))
                .unwrap_or(false);
            upsert_node(
                &mut node_index,
                &action_url,
                &method,
                SeedSource::Form,
                in_scope,
                Some(final_url.clone()),
            );

            // Legacy login-form heuristics — preserved for backwards
            // compat with v0.7.x findings.
            let has_password = form.select(&input_password).next().is_some();
            if has_password {
                if action.starts_with("http://") {
                    findings.push(Finding {
                        id: format!("CYWEB-SPD-001-{}", node_index.len()),
                        title: "Login form submits over HTTP".into(),
                        severity: Severity::Critical,
                        category: "Authentication".into(),
                        description: "A login form with a password field submits credentials over unencrypted HTTP.".into(),
                        evidence: format!("Form action: {action} method: {method}"),
                        url: final_url.clone(),
                        cwe: Some("CWE-319".into()),
                        remediation: "Ensure all login forms submit over HTTPS.".into(),
                        vuln_class: None,
                    });
                }
                if form.value().attr("autocomplete").is_none() {
                    findings.push(Finding {
                        id: format!("CYWEB-SPD-002-{}", node_index.len()),
                        title: "Password form missing autocomplete=off".into(),
                        severity: Severity::Low,
                        category: "Authentication".into(),
                        description: "Login form does not disable autocomplete, allowing browsers to cache credentials.".into(),
                        evidence: format!("Form at {} lacks autocomplete attribute", final_url),
                        url: final_url.clone(),
                        cwe: Some("CWE-525".into()),
                        remediation: "Add autocomplete='off' to sensitive forms.".into(),
                        vuln_class: None,
                    });
                }
            }
        }

        // ── Sensitive HTML comments ─────────────────────────────────────────
        for comment in comment_re.find_iter(&body) {
            let text = comment.as_str().to_lowercase();
            if text.contains("password") || text.contains("api_key") || text.contains("secret")
                || text.contains("todo") || text.contains("hack") || text.contains("fixme")
                || text.contains("credentials")
            {
                findings.push(Finding {
                    id: format!("CYWEB-SPD-003-{}", node_index.len()),
                    title: "HTML comment contains sensitive keywords".into(),
                    severity: Severity::Low,
                    category: "Information Disclosure".into(),
                    description: "HTML comments may contain sensitive information like passwords, API keys, or developer notes.".into(),
                    evidence: format!("Comment: {}...", &comment.as_str()[..comment.as_str().len().min(100)]),
                    url: final_url.clone(),
                    cwe: Some("CWE-615".into()),
                    remediation: "Remove all HTML comments from production pages.".into(),
                    vuln_class: None,
                });
            }
        }
    }

    let nodes: Vec<CrawledNode> = node_index.into_values().collect();

    // Flat list for backward compat — only in-scope URLs we'd want
    // other phases to scan.
    let crawled_urls: Vec<String> = nodes
        .iter()
        .filter(|n| n.in_scope && n.method == "GET")
        .map(|n| n.url.clone())
        .collect();

    CrawlOutcome {
        findings,
        nodes,
        crawled_urls,
        requests_made: requests,
    }
}

/// Look up or create a node entry. Returns a mutable handle so the
/// caller can update status_code etc. after the request completes.
fn upsert_node<'a>(
    map: &'a mut HashMap<(String, String), CrawledNode>,
    url: &str,
    method: &str,
    seed: SeedSource,
    in_scope: bool,
    parent: Option<String>,
) -> &'a mut CrawledNode {
    let key = (url.to_string(), method.to_string());
    map.entry(key).or_insert_with(|| CrawledNode {
        url: url.to_string(),
        method: method.to_string(),
        seed_source: seed,
        in_scope,
        processed: false,
        status_code: None,
        content_type: None,
        parent_url: parent,
    })
}

/// Parse `Disallow:` lines from a robots.txt body. Returns the path
/// values (e.g. "/admin/", "/private/data"). Wildcards / globs are
/// returned as-is — the caller will url::join them and let reqwest
/// decide what to do.
fn parse_robots_disallows(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in body.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("Disallow:") {
            let path = rest.trim();
            if !path.is_empty() && path != "/" && !path.contains('*') {
                out.push(path.to_string());
            }
        } else if let Some(rest) = trimmed.strip_prefix("disallow:") {
            let path = rest.trim();
            if !path.is_empty() && path != "/" && !path.contains('*') {
                out.push(path.to_string());
            }
        }
    }
    out
}

/// Extract `<loc>` elements from a sitemap.xml body. Tolerates either
/// urlset (regular sitemap) or sitemapindex (index-of-sitemaps —
/// we just treat the inner sitemaps as URLs to seed too).
fn parse_sitemap_locs(body: &str) -> Vec<String> {
    let re = match regex::Regex::new(r"(?is)<loc>\s*([^<\s]+)\s*</loc>") {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    re.captures_iter(body)
        .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
        .collect()
}
