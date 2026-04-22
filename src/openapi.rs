//! OpenAPI/Swagger spec scanner.
//!
//! Parses an OpenAPI 3.x or Swagger 2.x spec and generates security checks
//! for every endpoint: auth requirements, input validation, response codes.

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

/// Fetch and parse an OpenAPI spec, then generate security findings.
pub async fn scan_openapi(client: &Client, spec_url: &str, target: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Fetch the spec
    let body = match client.get(spec_url).send().await {
        Ok(resp) if resp.status().is_success() => resp.text().await.unwrap_or_default(),
        _ => {
            // Try common paths
            let paths = ["/openapi.json", "/swagger.json", "/api-docs", "/v3/api-docs"];
            let mut found = String::new();
            for p in &paths {
                let url = format!("{target}{p}");
                if let Ok(r) = client.get(&url).send().await {
                    if r.status().is_success() {
                        if let Ok(body) = r.text().await {
                            if body.contains("paths") || body.contains("swagger") {
                                found = body;
                                break;
                            }
                        }
                    }
                }
            }
            if found.is_empty() {
                return findings;
            }
            found
        }
    };

    // Parse spec (try JSON then YAML)
    let spec: OpenApiSpec = match serde_json::from_str(&body) {
        Ok(s) => s,
        Err(_) => match serde_yaml::from_str(&body) {
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
                });
            }
        }
    }

    findings
}
