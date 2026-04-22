//! Signature-based detection modules.

pub mod headers;
pub mod methods;
pub mod paths;
pub mod rules;
pub mod server;

/// A single finding from a scan.
#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
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
}

#[derive(Debug, Clone, Copy, serde::Serialize, PartialEq, Eq)]
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
