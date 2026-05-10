//! Signature-based detection modules.

pub mod cves;
pub mod headers;
pub mod methods;
pub mod mixed_content;
pub mod passive_html;
pub mod paths;
pub mod rules;
pub mod server;

/// A single finding from a scan.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub category: String,
    pub description: String,
    pub evidence: String,
    pub url: String,
    pub cwe: Option<String>,
    pub remediation: String,
    /// Sprint 76 — modern vuln-class taxonomy. Set by fuzz rules whose
    /// YAML carries a `vuln_class` field. None for legacy / non-fuzz
    /// findings (CVE matches, missing headers, exposed paths).
    ///
    /// Values: http_smuggling | jwt_confusion | prototype_pollution |
    ///         race_condition | cache_poisoning | websocket_hijack |
    ///         grpc_web
    ///
    /// Cybrium platform reads this from the JSON output and surfaces
    /// it as a chip on FindingCard + per-class feature gating.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vuln_class: Option<String>,
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
            Severity::Info => write!(f, "INFO"),
        }
    }
}
