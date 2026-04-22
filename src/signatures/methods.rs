//! HTTP method testing — detect dangerous methods enabled on the target.

use super::{Finding, Severity};
use reqwest::Client;

pub async fn check_methods(client: &Client, target: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Check TRACE
    if let Ok(resp) = client.request(reqwest::Method::TRACE, target).send().await {
        if resp.status().is_success() {
            findings.push(Finding {
                id: "CYWEB-MTH-001".into(),
                title: "HTTP TRACE method enabled".into(),
                severity: Severity::Medium,
                category: "HTTP Methods".into(),
                description: "The TRACE method is enabled. This can be exploited for Cross-Site Tracing (XST) attacks to steal credentials.".into(),
                evidence: format!("TRACE {} returned {}", target, resp.status()),
                url: target.into(),
                cwe: Some("CWE-693".into()),
                remediation: "Disable the TRACE method on the web server.".into(),
            });
        }
    }

    // Check OPTIONS for allowed methods
    if let Ok(resp) = client.request(reqwest::Method::OPTIONS, target).send().await {
        if let Some(allow) = resp.headers().get("allow").and_then(|v| v.to_str().ok()) {
            let methods: Vec<&str> = allow.split(',').map(|m| m.trim()).collect();
            let dangerous = ["PUT", "DELETE", "PATCH"];
            for method in &dangerous {
                if methods.iter().any(|m| m.eq_ignore_ascii_case(method)) {
                    findings.push(Finding {
                        id: format!("CYWEB-MTH-002-{method}"),
                        title: format!("{method} method allowed"),
                        severity: Severity::Low,
                        category: "HTTP Methods".into(),
                        description: format!("The {method} method is listed in the Allow header. Ensure this is intentional and properly authenticated."),
                        evidence: format!("Allow: {allow}"),
                        url: target.into(),
                        cwe: Some("CWE-749".into()),
                        remediation: format!("Disable the {method} method if not required, or ensure it requires authentication."),
                    });
                }
            }
        }
    }

    findings
}
