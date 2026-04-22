//! Spider/crawler — discovers links and checks for issues.

use crate::signatures::{Finding, Severity};
use reqwest::Client;
use scraper::{Html, Selector};
use std::collections::HashSet;

pub async fn crawl(
    client: &Client,
    target: &str,
    max_depth: usize,
    _concurrency: usize,
) -> (Vec<Finding>, usize) {
    let mut findings = Vec::new();
    let mut visited: HashSet<String> = HashSet::new();
    let mut queue: Vec<(String, usize)> = vec![(target.to_string(), 0)];
    let mut requests = 0;

    let base_url = url::Url::parse(target).unwrap_or_else(|_| url::Url::parse("https://example.com").unwrap());
    let base_host = base_url.host_str().unwrap_or("").to_string();

    let link_selector = Selector::parse("a[href]").unwrap();
    let form_selector = Selector::parse("form[action]").unwrap();
    let input_selector = Selector::parse("input[type=password]").unwrap();
    let comment_re = regex::Regex::new(r"<!--[\s\S]*?-->").unwrap();

    while let Some((url, depth)) = queue.pop() {
        if depth > max_depth || visited.contains(&url) {
            continue;
        }
        visited.insert(url.clone());

        let resp = match client.get(&url).send().await {
            Ok(r) => r,
            Err(_) => continue,
        };
        requests += 1;

        let final_url = resp.url().to_string();
        let body = match resp.text().await {
            Ok(b) => b,
            Err(_) => continue,
        };

        let doc = Html::parse_document(&body);

        // Extract links
        for element in doc.select(&link_selector) {
            if let Some(href) = element.value().attr("href") {
                if let Ok(resolved) = base_url.join(href) {
                    let resolved_str = resolved.to_string();
                    if resolved.host_str() == Some(&base_host) && !visited.contains(&resolved_str) {
                        queue.push((resolved_str, depth + 1));
                    }
                }
            }
        }

        // Check for forms with password fields (login pages)
        for form in doc.select(&form_selector) {
            let has_password = form.select(&input_selector).next().is_some();
            if has_password {
                let action = form.value().attr("action").unwrap_or("");
                let method = form.value().attr("method").unwrap_or("GET").to_uppercase();

                // Check if form submits over HTTP
                if action.starts_with("http://") {
                    findings.push(Finding {
                        id: format!("CYWEB-SPD-001-{}", visited.len()),
                        title: "Login form submits over HTTP".into(),
                        severity: Severity::Critical,
                        category: "Authentication".into(),
                        description: "A login form with a password field submits credentials over unencrypted HTTP.".into(),
                        evidence: format!("Form action: {action} method: {method}"),
                        url: final_url.clone(),
                        cwe: Some("CWE-319".into()),
                        remediation: "Ensure all login forms submit over HTTPS.".into(),
                    });
                }

                // Check for missing autocomplete=off
                if form.value().attr("autocomplete").is_none() {
                    findings.push(Finding {
                        id: format!("CYWEB-SPD-002-{}", visited.len()),
                        title: "Password form missing autocomplete=off".into(),
                        severity: Severity::Low,
                        category: "Authentication".into(),
                        description: "Login form does not disable autocomplete, allowing browsers to cache credentials.".into(),
                        evidence: format!("Form at {} lacks autocomplete attribute", final_url),
                        url: final_url.clone(),
                        cwe: Some("CWE-525".into()),
                        remediation: "Add autocomplete='off' to sensitive forms.".into(),
                    });
                }
            }
        }

        // Check for HTML comments that might contain sensitive info
        for comment in comment_re.find_iter(&body) {
            let text = comment.as_str().to_lowercase();
            if text.contains("password") || text.contains("api_key") || text.contains("secret")
                || text.contains("todo") || text.contains("hack") || text.contains("fixme")
                || text.contains("credentials") {
                findings.push(Finding {
                    id: format!("CYWEB-SPD-003-{}", visited.len()),
                    title: "HTML comment contains sensitive keywords".into(),
                    severity: Severity::Low,
                    category: "Information Disclosure".into(),
                    description: "HTML comments may contain sensitive information like passwords, API keys, or developer notes.".into(),
                    evidence: format!("Comment: {}...", &comment.as_str()[..comment.as_str().len().min(100)]),
                    url: final_url.clone(),
                    cwe: Some("CWE-615".into()),
                    remediation: "Remove all HTML comments from production pages.".into(),
                });
            }
        }
    }

    (findings, requests)
}
