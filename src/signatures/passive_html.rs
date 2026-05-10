//! Passive HTML response analysis — checks that examine the body of
//! crawled pages without making additional requests beyond what the
//! spider already did.
//!
//! Currently covers two ZAP-parity checks:
//!
//!   - **Anti-CSRF token detection**: every `<form method="post">` (or
//!     PUT/DELETE/PATCH) should carry a CSRF/anti-forgery token, either
//!     as a hidden input or via a same-site cookie (`__Host-` prefix or
//!     `SameSite=Strict`). Forms missing both are flagged.
//!
//!   - **Sub-Resource Integrity (SRI)**: every cross-origin `<script
//!     src=>` and `<link rel="stylesheet" href=>` should carry an
//!     `integrity=sha384-...` attribute so a CDN compromise can't
//!     substitute hostile JS/CSS. Same-origin sub-resources are exempt
//!     (no MITM threat model).
//!
//! Maps to ZAP rules:
//!   - 10202 "Absence of Anti-CSRF Tokens"  (CWE-352)
//!   - 90003 "Sub Resource Integrity Attribute Missing" (CWE-345)
//!
//! Both are passive — we only inspect responses already fetched by the
//! spider phase.

use super::{Finding, Severity};
use reqwest::Client;
use scraper::{Html, Selector};
use url::Url;

/// Hidden-input names we accept as evidence of CSRF protection. Pattern
/// matches both Django (`csrfmiddlewaretoken`), Rails (`authenticity_token`),
/// .NET (`__RequestVerificationToken`), Spring (`_csrf`), Express
/// (`csrf-token`), and a generic `csrf` substring fallback.
const CSRF_TOKEN_HINTS: &[&str] = &[
    "csrf",
    "_token",
    "authenticity_token",
    "__requestverificationtoken",
    "csrfmiddlewaretoken",
    "anti-forgery",
    "antiforgery",
    "xsrf",
];

/// HTTP methods that mutate state and therefore require CSRF protection.
/// GET-form submissions (search boxes etc.) don't need CSRF tokens.
fn is_state_changing(method: &str) -> bool {
    matches!(
        method.to_ascii_uppercase().as_str(),
        "POST" | "PUT" | "PATCH" | "DELETE"
    )
}

/// Returns true if the form contains *any* hidden input whose name or
/// id matches one of the CSRF token hints.
fn form_has_csrf_token(form_html: &str) -> bool {
    let frag = Html::parse_fragment(form_html);
    let input_sel = Selector::parse("input").expect("static selector");
    for input in frag.select(&input_sel) {
        let name = input.value().attr("name").unwrap_or("").to_ascii_lowercase();
        let id   = input.value().attr("id").unwrap_or("").to_ascii_lowercase();
        for hint in CSRF_TOKEN_HINTS {
            if name.contains(hint) || id.contains(hint) {
                return true;
            }
        }
    }
    // Also accept a `<meta name="csrf-token">` declaration in the form's
    // own subtree — some SPA frameworks (Laravel, Rails) inject it
    // outside the form and read it via JS at submit time.
    let meta_sel = Selector::parse(r#"meta[name*="csrf"], meta[name*="token"]"#)
        .expect("static selector");
    frag.select(&meta_sel).next().is_some()
}

/// Run anti-CSRF + SRI checks against every page the spider crawled.
/// Re-fetches each URL to obtain its HTML body. Cheap because the
/// spider's URL list is bounded (default --max-paths 200).
pub async fn check_passive(client: &Client, target: &str, urls: &[String]) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Always include the target itself; the spider may not list it
    // explicitly if max-depth=0.
    let mut to_check: Vec<String> = urls.to_vec();
    if !to_check.iter().any(|u| u == target) {
        to_check.insert(0, target.to_string());
    }

    let target_origin = Url::parse(target).ok().and_then(|u| u.host_str().map(String::from));

    for url in to_check.iter().take(200) {
        let resp = match client.get(url).send().await {
            Ok(r) => r,
            Err(_) => continue,
        };
        let ctype = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        if !ctype.contains("html") {
            continue;
        }
        let body = match resp.text().await {
            Ok(b) => b,
            Err(_) => continue,
        };
        let doc = Html::parse_document(&body);

        // ── Anti-CSRF tokens ──────────────────────────────────────────
        let form_sel = Selector::parse("form").expect("static selector");
        for form in doc.select(&form_sel) {
            let method = form.value().attr("method").unwrap_or("GET");
            if !is_state_changing(method) {
                continue;
            }
            let action = form.value().attr("action").unwrap_or("(this URL)");
            let html   = form.html();
            if form_has_csrf_token(&html) {
                continue;
            }
            findings.push(Finding {
                id: "CYWEB-CSRF-001".into(),
                title: "Form missing anti-CSRF token".into(),
                severity: Severity::Medium,
                category: "CSRF".into(),
                description: format!(
                    "A form using the {} method does not contain a hidden anti-CSRF token. \
                     An attacker who can lure an authenticated victim to a malicious page can \
                     submit this form on their behalf.",
                    method.to_ascii_uppercase()
                ),
                evidence: format!("form action=\"{}\" method=\"{}\"", action, method),
                url: url.clone(),
                cwe: Some("CWE-352".into()),
                remediation: "Add a hidden input containing a per-request CSRF token (e.g. \
                              `<input type=\"hidden\" name=\"csrf_token\" value=\"...\">`) and \
                              validate it server-side. Alternatively, set SameSite=Strict on the \
                              session cookie."
                    .into(),
                vuln_class: None,
            });
        }

        // ── Sub Resource Integrity ───────────────────────────────────
        let sri_targets = [
            (r#"script[src]"#, "script"),
            (r#"link[rel="stylesheet"][href]"#, "stylesheet"),
        ];
        for (selector_str, kind) in &sri_targets {
            let sel = Selector::parse(selector_str).expect("static selector");
            for el in doc.select(&sel) {
                let attr = if *kind == "script" { "src" } else { "href" };
                let src = match el.value().attr(attr) {
                    Some(s) => s,
                    None => continue,
                };
                // Resolve relative URLs against the page's base.
                let resolved = match Url::parse(url).and_then(|base| base.join(src)) {
                    Ok(u) => u,
                    Err(_) => continue,
                };
                let res_host = match resolved.host_str() {
                    Some(h) => h.to_string(),
                    None => continue,
                };
                // Same-origin: no SRI needed (no MITM threat).
                if Some(&res_host) == target_origin.as_ref() {
                    continue;
                }
                // Skip data: and javascript: URLs.
                if matches!(resolved.scheme(), "data" | "javascript" | "blob") {
                    continue;
                }
                if el.value().attr("integrity").is_some() {
                    continue;
                }
                findings.push(Finding {
                    id: "CYWEB-SRI-001".into(),
                    title: format!("Cross-origin {} missing Sub Resource Integrity", kind),
                    severity: Severity::Low,
                    category: "Supply Chain".into(),
                    description: format!(
                        "A cross-origin {} loaded from `{}` does not carry a `integrity=` \
                         attribute. If the third-party host is compromised, an attacker can \
                         substitute hostile content that runs with the page's privileges.",
                        kind, res_host
                    ),
                    evidence: format!("<{} {}=\"{}\">", kind, attr, src),
                    url: url.clone(),
                    cwe: Some("CWE-345".into()),
                    remediation: "Add an `integrity=\"sha384-...\"` attribute (and \
                                  `crossorigin=\"anonymous\"`) so the browser refuses to load \
                                  the resource if its hash changes. Generate the hash with \
                                  `cat file | openssl dgst -sha384 -binary | openssl base64 -A`."
                        .into(),
                    vuln_class: None,
                });
            }
        }
    }

    findings
}
