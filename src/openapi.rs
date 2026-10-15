//! OpenAPI/Swagger spec scanner.
//!
//! Parses an OpenAPI 3.x or Swagger 2.x spec and generates security checks
//! for every endpoint: auth requirements, input validation, response codes.

use crate::crawler::CrawledNode;
use crate::signatures::{Finding, Severity};
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Deserialize)]
struct OpenApiSpec {
    #[serde(alias = "swagger")]
    openapi: Option<String>,
    info: Option<ApiInfo>,
    paths: Option<HashMap<String, HashMap<String, Operation>>>,
    #[serde(default)]
    servers: Vec<Server>,
    #[serde(default, alias = "securityDefinitions")]
    security: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct ApiInfo {
    title: Option<String>,
    version: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Server {
    url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Operation {
    #[serde(default)]
    security: Vec<serde_json::Value>,
    #[serde(default)]
    parameters: Vec<Parameter>,
    #[serde(default)]
    responses: HashMap<String, serde_json::Value>,
    #[serde(alias = "operationId")]
    operation_id: Option<String>,
    summary: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Parameter {
    name: Option<String>,
    #[serde(rename = "in")]
    location: Option<String>,
    required: Option<bool>,
    schema: Option<serde_json::Value>,
}

/// Quick + robust check: does this body look like an OpenAPI/Swagger spec?
/// Cheap substring gate first, then a real parse so arbitrary JSON that merely
/// mentions "paths" doesn't register as a spec.
pub fn body_is_openapi(body: &str) -> bool {
    if body.len() > 4_000_000 {
        return false;
    }
    let head = body[..body.len().min(4096)].to_ascii_lowercase();
    if !(head.contains("openapi") || head.contains("swagger")) {
        return false;
    }
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
        return v.get("paths").map(|p| p.is_object()).unwrap_or(false)
            && (v.get("openapi").is_some() || v.get("swagger").is_some());
    }
    if let Ok(v) = serde_yaml::from_str::<serde_yaml::Value>(body) {
        return v.get("paths").map(|p| p.is_mapping()).unwrap_or(false)
            && (v.get("openapi").is_some() || v.get("swagger").is_some());
    }
    false
}

/// Does a crawled URL's path look like it might serve an API spec?
fn looks_like_spec_url(url: &str) -> bool {
    let full = url.to_ascii_lowercase();
    let path = full.split(['?', '#']).next().unwrap_or(&full);
    path.ends_with("openapi.json")
        || path.ends_with("swagger.json")
        || path.ends_with("openapi.yaml")
        || path.ends_with("openapi.yml")
        || path.contains("api-docs")
        || path.contains("/swagger/")
        || path.contains("/openapi")
}

/// Extract a spec URL referenced from a Swagger-UI / Redoc / RapiDoc HTML page
/// (`url: "..."`, `spec-url="..."`, `configUrl:`, `data-url="..."`), resolved
/// against the page's own URL.
fn extract_spec_ref(html: &str, base: &reqwest::Url) -> Option<String> {
    for key in ["url:", "spec-url=", "configurl:", "data-url="] {
        let hay = html.to_ascii_lowercase();
        if let Some(i) = hay.find(key) {
            let rest = html[i + key.len()..].trim_start();
            let mut chars = rest.chars();
            if let Some(q) = chars.next() {
                if q == '"' || q == '\'' {
                    if let Some(end) = rest[1..].find(q) {
                        let cand = &rest[1..1 + end];
                        let cl = cand.to_ascii_lowercase();
                        if cl.contains("json")
                            || cl.contains("yaml")
                            || cl.contains("api-docs")
                            || cl.contains("openapi")
                            || cl.contains("swagger")
                        {
                            if let Ok(joined) = base.join(cand) {
                                return Some(joined.to_string());
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

/// Fetch a URL and return its body when the GET succeeded.
async fn fetch_body(client: &Client, url: &str) -> Option<String> {
    match client.get(url).send().await {
        Ok(r) if r.status().is_success() => r.text().await.ok(),
        _ => None,
    }
}

/// Crawl-driven spec discovery. Given the spider's node list, locate any
/// OpenAPI/Swagger spec reachable via a deep or non-standard path — either a
/// crawled JSON/YAML body that parses as a spec, or a Swagger-UI/Redoc docs
/// page that references one — then scan it. Returns the spec URL (if found)
/// plus its findings. Bounded to at most `MAX_PROBE` candidate fetches so a
/// large crawl can't balloon into an unbounded second pass.
pub async fn discover_from_crawl(
    client: &Client,
    target: &str,
    nodes: &[CrawledNode],
) -> (Option<String>, Vec<Finding>) {
    const MAX_PROBE: usize = 40;

    let mut seen = std::collections::HashSet::new();
    let mut spec_like: Vec<&str> = Vec::new();
    let mut json_like: Vec<&str> = Vec::new();
    let mut html_like: Vec<&str> = Vec::new();

    for n in nodes {
        if !n.in_scope || !seen.insert(n.url.as_str()) {
            continue;
        }
        let ct = n.content_type.as_deref().unwrap_or("").to_ascii_lowercase();
        if looks_like_spec_url(&n.url) {
            spec_like.push(&n.url);
        } else if ct.contains("json")
            || ct.contains("yaml")
            || n.tags.iter().any(|t| t.eq_ignore_ascii_case("JSON"))
        {
            json_like.push(&n.url);
        } else if ct.contains("html") {
            html_like.push(&n.url);
        }
    }

    let mut probed = 0usize;

    // Direct spec candidates — spec-shaped paths first, then JSON/YAML bodies.
    for url in spec_like.iter().chain(json_like.iter()) {
        if probed >= MAX_PROBE {
            break;
        }
        probed += 1;
        if let Some(body) = fetch_body(client, url).await {
            if body_is_openapi(&body) {
                let f = scan_openapi_body(&body, url, target, client).await;
                return (Some((*url).to_string()), f);
            }
        }
    }

    // HTML docs viewers (Swagger-UI / Redoc / RapiDoc) that point at a spec.
    for url in html_like.iter() {
        if probed >= MAX_PROBE {
            break;
        }
        probed += 1;
        let Some(body) = fetch_body(client, url).await else {
            continue;
        };
        let low = body.to_ascii_lowercase();
        if !(low.contains("swagger")
            || low.contains("redoc")
            || low.contains("rapidoc")
            || low.contains("openapi"))
        {
            continue;
        }
        let Ok(base) = reqwest::Url::parse(url) else {
            continue;
        };
        if let Some(spec_url) = extract_spec_ref(&body, &base) {
            if probed >= MAX_PROBE {
                break;
            }
            probed += 1;
            if let Some(spec_body) = fetch_body(client, &spec_url).await {
                if body_is_openapi(&spec_body) {
                    let f = scan_openapi_body(&spec_body, &spec_url, target, client).await;
                    return (Some(spec_url), f);
                }
            }
        }
    }

    (None, Vec::new())
}

/// Fetch and parse an OpenAPI spec, then generate security findings.
pub async fn scan_openapi(client: &Client, spec_url: &str, target: &str) -> Vec<Finding> {
    // Fetch the spec (with the legacy well-known-path fallback).
    let body = match client.get(spec_url).send().await {
        Ok(resp) if resp.status().is_success() => resp.text().await.unwrap_or_default(),
        _ => {
            let paths = ["/openapi.json", "/swagger.json", "/api-docs", "/v3/api-docs"];
            let mut found = String::new();
            for p in &paths {
                let url = format!("{target}{p}");
                if let Ok(r) = client.get(&url).send().await {
                    if r.status().is_success() {
                        if let Ok(b) = r.text().await {
                            if b.contains("paths") || b.contains("swagger") {
                                found = b;
                                break;
                            }
                        }
                    }
                }
            }
            if found.is_empty() {
                return Vec::new();
            }
            found
        }
    };
    scan_openapi_body(&body, spec_url, target, client).await
}

/// Parse an already-fetched spec body and generate security findings.
async fn scan_openapi_body(body: &str, spec_url: &str, target: &str, client: &Client) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Parse spec (try JSON then YAML)
    let spec: OpenApiSpec = match serde_json::from_str(body) {
        Ok(s) => s,
        Err(_) => match serde_yaml::from_str(body) {
            Ok(s) => s,
            Err(_) => return findings,
        },
    };

    let version = spec.openapi.as_deref().unwrap_or("unknown");
    let title = spec.info.as_ref().and_then(|i| i.title.as_deref()).unwrap_or("API");

    findings.push(Finding {
        id: "CYWEB-OAS-001".into(),
        title: format!("OpenAPI spec found: {} ({})", title, version),
        severity: Severity::Info,
        category: "API Security".into(),
        description: format!("OpenAPI {version} specification for '{title}' is publicly accessible."),
        evidence: format!("Spec URL: {spec_url}"),
        url: spec_url.into(),
        cwe: Some("CWE-200".into()),
        remediation: "Consider restricting API documentation access to authenticated users.".into(),
        vuln_class: None,
    });

    let paths = match spec.paths {
        Some(p) => p,
        None => return findings,
    };

    let mut unauth_endpoints = 0;
    let mut no_rate_limit = 0;
    let mut sensitive_paths = 0;
    let mut total_endpoints = 0;

    let global_security = !spec.security.is_empty();

    for (path, methods) in &paths {
        for (method, op) in methods {
            total_endpoints += 1;
            let method_upper = method.to_uppercase();
            let endpoint = format!("{method_upper} {path}");

            // Check: endpoint has no security requirement
            let has_security = !op.security.is_empty() || global_security;
            if !has_security && method_upper != "OPTIONS" {
                unauth_endpoints += 1;
            }

            // Check: sensitive operations without auth
            let is_write = matches!(method_upper.as_str(), "POST" | "PUT" | "DELETE" | "PATCH");
            if is_write && !has_security {
                findings.push(Finding {
                    id: format!("CYWEB-OAS-010-{}", total_endpoints),
                    title: format!("Write endpoint without auth: {endpoint}"),
                    severity: Severity::High,
                    category: "API Security".into(),
                    description: format!("The {endpoint} endpoint allows write operations without any security requirement defined in the spec."),
                    evidence: endpoint.clone(),
                    url: format!("{target}{path}"),
                    cwe: Some("CWE-284".into()),
                    remediation: "Add security requirements to all write endpoints.".into(),
                    vuln_class: None,
                });
            }

            // Check: sensitive data paths
            let path_lower = path.to_lowercase();
            if path_lower.contains("password") || path_lower.contains("token")
                || path_lower.contains("secret") || path_lower.contains("admin")
                || path_lower.contains("user") || path_lower.contains("credential")
            {
                sensitive_paths += 1;
                if !has_security {
                    findings.push(Finding {
                        id: format!("CYWEB-OAS-020-{}", total_endpoints),
                        title: format!("Sensitive endpoint without auth: {endpoint}"),
                        severity: Severity::Critical,
                        category: "API Security".into(),
                        description: format!("The endpoint {path} handles sensitive data but has no security requirement."),
                        evidence: endpoint.clone(),
                        url: format!("{target}{path}"),
                        cwe: Some("CWE-306".into()),
                        remediation: "Require authentication for all sensitive endpoints.".into(),
                        vuln_class: None,
                    });
                }
            }

            // Check: parameters without validation
            for param in &op.parameters {
                let name = param.name.as_deref().unwrap_or("");
                let location = param.location.as_deref().unwrap_or("");

                // ID/path params that accept arbitrary input
                if location == "path" && param.schema.is_none() {
                    findings.push(Finding {
                        id: format!("CYWEB-OAS-030-{}-{}", total_endpoints, name),
                        title: format!("Path parameter without schema: {name} in {endpoint}"),
                        severity: Severity::Low,
                        category: "API Security".into(),
                        description: format!("Parameter '{name}' in {endpoint} has no schema validation defined."),
                        evidence: format!("Parameter: {name} (in: {location})"),
                        url: format!("{target}{path}"),
                        cwe: Some("CWE-20".into()),
                        remediation: "Define schema with type, format, and constraints for all parameters.".into(),
                        vuln_class: None,
                    });
                }
            }

            // Check: missing error responses (no 401/403)
            if has_security && !op.responses.contains_key("401") && !op.responses.contains_key("403") {
                no_rate_limit += 1;
            }
        }
    }

    // Summary findings
    if unauth_endpoints > 0 {
        findings.push(Finding {
            id: "CYWEB-OAS-040".into(),
            title: format!("{} of {} endpoints lack authentication", unauth_endpoints, total_endpoints),
            severity: if unauth_endpoints > total_endpoints / 2 { Severity::High } else { Severity::Medium },
            category: "API Security".into(),
            description: format!("{unauth_endpoints} API endpoints have no security requirement defined in the OpenAPI spec."),
            evidence: format!("{unauth_endpoints}/{total_endpoints} unauthenticated"),
            url: target.into(),
            cwe: Some("CWE-306".into()),
            remediation: "Add security schemes and require them on all endpoints.".into(),
            vuln_class: None,
        });
    }

    // Live endpoint testing — try a few endpoints to verify they respond
    let test_paths: Vec<&String> = paths.keys().take(5).collect();
    for path in test_paths {
        let url = format!("{target}{path}");
        if let Ok(resp) = client.get(&url).send().await {
            let status = resp.status().as_u16();
            if status == 500 {
                findings.push(Finding {
                    id: format!("CYWEB-OAS-050-{path}"),
                    title: format!("API endpoint returns 500: {path}"),
                    severity: Severity::Medium,
                    category: "API Security".into(),
                    description: format!("GET {path} returns HTTP 500, indicating a server error."),
                    evidence: format!("GET {path} -> HTTP {status}"),
                    url,
                    cwe: Some("CWE-209".into()),
                    remediation: "Investigate and fix server errors. Ensure error responses don't leak details.".into(),
                    vuln_class: None,
                });
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_is_openapi_accepts_real_spec() {
        let spec = r#"{"openapi":"3.0.0","info":{"title":"X"},"paths":{"/a":{"get":{}}}}"#;
        assert!(body_is_openapi(spec));
        let swagger = r#"{"swagger":"2.0","paths":{"/a":{"get":{}}}}"#;
        assert!(body_is_openapi(swagger));
    }

    #[test]
    fn body_is_openapi_rejects_arbitrary_json() {
        // Mentions neither openapi nor swagger — rejected at the cheap gate.
        assert!(!body_is_openapi(r#"{"paths":["/home","/about"],"menu":true}"#));
        // Mentions the word but isn't a spec object.
        assert!(!body_is_openapi(r#"{"note":"see our openapi docs","paths":42}"#));
        // Not JSON/YAML at all.
        assert!(!body_is_openapi("<html><body>swagger ui</body></html>"));
    }

    #[test]
    fn spec_url_heuristic() {
        assert!(looks_like_spec_url("https://x.io/internal/v2/openapi.json"));
        assert!(looks_like_spec_url("https://x.io/v3/api-docs"));
        assert!(looks_like_spec_url("https://x.io/swagger/v1/swagger.json?x=1"));
        assert!(!looks_like_spec_url("https://x.io/users/profile"));
        assert!(!looks_like_spec_url("https://x.io/assets/app.json"));
    }

    #[test]
    fn extract_spec_ref_from_swagger_ui() {
        let base = reqwest::Url::parse("https://x.io/docs/").unwrap();
        let html = r##"<script>const ui = SwaggerUIBundle({ url: "/internal/openapi.json", dom_id: "#x" });</script>"##;
        assert_eq!(
            extract_spec_ref(html, &base).as_deref(),
            Some("https://x.io/internal/openapi.json")
        );
        // Redoc spec-url attribute, relative path resolved against the page.
        let redoc = r#"<redoc spec-url='../api/v3/api-docs'></redoc>"#;
        assert_eq!(
            extract_spec_ref(redoc, &base).as_deref(),
            Some("https://x.io/api/v3/api-docs")
        );
        // No spec reference → None.
        assert_eq!(extract_spec_ref("<html>nothing here</html>", &base), None);
    }
}
