//! Output formatters — text, JSON, SARIF.

use crate::scanner::ScanResult;
use crate::signatures::Severity;
use colored::Colorize;

/// Pretty-print to terminal.
pub fn print_text(result: &ScanResult) {
    eprintln!();
    eprintln!("{}", "═══════════════════════════════════════════════════".dimmed());
    eprintln!("  {} {}", "SCAN COMPLETE".green().bold(), result.target.white());
    eprintln!(
        "  Duration: {}ms | Requests: {} | Paths checked: {}",
        result.duration_ms, result.summary.requests_made, result.summary.paths_checked
    );
    eprintln!("{}", "═══════════════════════════════════════════════════".dimmed());

    if result.findings.is_empty() {
        eprintln!("\n  {} No issues found.\n", "✓".green().bold());
        return;
    }

    eprintln!(
        "\n  {} findings: {} critical, {} high, {} medium, {} low, {} info\n",
        result.summary.total.to_string().bold(),
        result.summary.critical.to_string().red().bold(),
        result.summary.high.to_string().yellow().bold(),
        result.summary.medium.to_string().blue(),
        result.summary.low.to_string().dimmed(),
        result.summary.info.to_string().dimmed(),
    );

    for finding in &result.findings {
        let sev = match finding.severity {
            Severity::Critical => "CRIT".red().bold().to_string(),
            Severity::High     => "HIGH".yellow().bold().to_string(),
            Severity::Medium   => " MED".blue().to_string(),
            Severity::Low      => " LOW".dimmed().to_string(),
            Severity::Info     => "INFO".dimmed().to_string(),
        };

        eprintln!("  [{}] {} {}", sev, finding.id.dimmed(), finding.title.white().bold());
        eprintln!("         {}", finding.evidence.dimmed());
        if let Some(ref cwe) = finding.cwe {
            eprintln!("         {}", cwe.cyan());
        }
        eprintln!();
    }
}

/// JSON output.
pub fn to_json(result: &ScanResult) -> String {
    serde_json::to_string_pretty(result).unwrap_or_else(|_| "{}".into())
}

/// SARIF 2.1.0 output — compatible with GitHub, Azure DevOps, Cybrium platform.
pub fn to_sarif(result: &ScanResult) -> String {
    let rules: Vec<serde_json::Value> = result
        .findings
        .iter()
        .map(|f| {
            serde_json::json!({
                "id": f.id,
                "shortDescription": { "text": f.title },
                "fullDescription": { "text": f.description },
                "help": { "text": f.remediation },
                "properties": {
                    "security-severity": match f.severity {
                        Severity::Critical => "9.5",
                        Severity::High     => "8.0",
                        Severity::Medium   => "5.5",
                        Severity::Low      => "3.0",
                        Severity::Info     => "1.0",
                    },
                    "tags": ["security", "web-scanner"]
                }
            })
        })
        .collect();

    let results: Vec<serde_json::Value> = result
        .findings
        .iter()
        .map(|f| {
            serde_json::json!({
                "ruleId": f.id,
                "level": match f.severity {
                    Severity::Critical | Severity::High => "error",
                    Severity::Medium => "warning",
                    _ => "note",
                },
                "message": { "text": f.description },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": f.url }
                    }
                }],
                "properties": {
                    "evidence": f.evidence,
                    "category": f.category,
                    "cwe": f.cwe,
                }
            })
        })
        .collect();

    let sarif = serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "cyweb",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/cybrium-ai/cyweb",
                    "rules": rules
                }
            },
            "results": results,
            "invocations": [{
                "executionSuccessful": true,
                "startTimeUtc": result.started_at,
                "endTimeUtc": result.completed_at,
            }]
        }]
    });

    serde_json::to_string_pretty(&sarif).unwrap_or_else(|_| "{}".into())
}
