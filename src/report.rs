//! Output formatters — text, JSON, SARIF.

use crate::scanner::ScanResult;
use crate::signatures::Severity;
use colored::Colorize;

/// Pretty-print to terminal.
pub fn print_text(result: &ScanResult) {
    eprintln!();
    eprintln!("{}", "═══════════════════════════════════════════════════".dimmed());
    eprintln!("  {} {}", "SCAN COMPLETE".green().bold(), result.target.white());
    let duration_display = if result.duration_ms > 1000 {
        format!("{:.1}s", result.duration_ms as f64 / 1000.0)
    } else {
        format!("{}ms", result.duration_ms)
    };
    eprintln!(
        "  Duration: {} | Requests: {} | Paths: {}",
        duration_display.yellow(), result.summary.requests_made, result.summary.paths_checked
    );
    eprintln!("  End Time: {}", chrono::Local::now().format("%Y-%m-%d %H:%M:%S (%Z)").to_string().dimmed());
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

/// CSV output.
pub fn to_csv(result: &ScanResult) -> String {
    let mut lines = vec!["\"ID\",\"Severity\",\"Title\",\"Category\",\"URL\",\"CWE\",\"Evidence\",\"Remediation\"".to_string()];
    for f in &result.findings {
        lines.push(format!(
            "\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"",
            f.id,
            f.severity,
            f.title.replace('"', "\"\""),
            f.category,
            f.url,
            f.cwe.as_deref().unwrap_or(""),
            f.evidence.replace('"', "\"\""),
            f.remediation.replace('"', "\"\""),
        ));
    }
    lines.join("\n")
}

/// XML output.
pub fn to_xml(result: &ScanResult) -> String {
    let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str("<cyweb-report>\n");
    xml.push_str(&format!("  <target>{}</target>\n", escape_xml(&result.target)));
    xml.push_str(&format!("  <started-at>{}</started-at>\n", result.started_at));
    xml.push_str(&format!("  <completed-at>{}</completed-at>\n", result.completed_at));
    xml.push_str(&format!("  <duration-ms>{}</duration-ms>\n", result.duration_ms));
    xml.push_str(&format!("  <summary total=\"{}\" critical=\"{}\" high=\"{}\" medium=\"{}\" low=\"{}\" info=\"{}\" />\n",
        result.summary.total, result.summary.critical, result.summary.high,
        result.summary.medium, result.summary.low, result.summary.info));
    xml.push_str("  <findings>\n");
    for f in &result.findings {
        xml.push_str("    <finding>\n");
        xml.push_str(&format!("      <id>{}</id>\n", f.id));
        xml.push_str(&format!("      <severity>{}</severity>\n", f.severity));
        xml.push_str(&format!("      <title>{}</title>\n", escape_xml(&f.title)));
        xml.push_str(&format!("      <category>{}</category>\n", escape_xml(&f.category)));
        xml.push_str(&format!("      <description>{}</description>\n", escape_xml(&f.description)));
        xml.push_str(&format!("      <evidence>{}</evidence>\n", escape_xml(&f.evidence)));
        xml.push_str(&format!("      <url>{}</url>\n", escape_xml(&f.url)));
        if let Some(ref cwe) = f.cwe {
            xml.push_str(&format!("      <cwe>{}</cwe>\n", cwe));
        }
        xml.push_str(&format!("      <remediation>{}</remediation>\n", escape_xml(&f.remediation)));
        xml.push_str("    </finding>\n");
    }
    xml.push_str("  </findings>\n");
    xml.push_str("</cyweb-report>\n");
    xml
}

/// HTML report.
pub fn to_html(result: &ScanResult) -> String {
    let sev_color = |s: &Severity| match s {
        Severity::Critical => "#ef4444",
        Severity::High     => "#f59e0b",
        Severity::Medium   => "#3b82f6",
        Severity::Low      => "#6b7280",
        Severity::Info     => "#8b5cf6",
    };

    let mut html = format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>cyweb Report — {target}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0a0b0f; color: #e4e4e7; margin: 0; padding: 24px; }}
  .header {{ max-width: 900px; margin: 0 auto 32px; }}
  .header h1 {{ font-size: 24px; color: #a78bfa; margin: 0 0 8px; }}
  .header p {{ color: #71717a; margin: 4px 0; font-size: 14px; }}
  .summary {{ display: flex; gap: 16px; margin: 20px 0; }}
  .stat {{ background: #1a1a2e; border: 1px solid #27273a; border-radius: 12px; padding: 12px 20px; text-align: center; }}
  .stat .num {{ font-size: 28px; font-weight: 700; }}
  .stat .label {{ font-size: 11px; color: #71717a; text-transform: uppercase; letter-spacing: 0.1em; }}
  table {{ width: 100%; max-width: 900px; margin: 0 auto; border-collapse: collapse; }}
  th {{ text-align: left; padding: 10px 12px; border-bottom: 2px solid #27273a; font-size: 12px; color: #71717a; text-transform: uppercase; letter-spacing: 0.05em; }}
  td {{ padding: 10px 12px; border-bottom: 1px solid #1a1a2e; font-size: 13px; vertical-align: top; }}
  tr:hover {{ background: #1a1a2e; }}
  .sev {{ display: inline-block; padding: 2px 8px; border-radius: 6px; font-size: 11px; font-weight: 700; text-transform: uppercase; }}
  .footer {{ max-width: 900px; margin: 32px auto 0; text-align: center; color: #3f3f46; font-size: 12px; }}
  .footer a {{ color: #7c5cfc; text-decoration: none; }}
</style>
</head>
<body>
<div class="header">
  <h1>cyweb Scan Report</h1>
  <p>Target: {target}</p>
  <p>Duration: {duration}ms | Requests: {requests} | {date}</p>
  <div class="summary">
    <div class="stat"><div class="num" style="color:#ef4444">{critical}</div><div class="label">Critical</div></div>
    <div class="stat"><div class="num" style="color:#f59e0b">{high}</div><div class="label">High</div></div>
    <div class="stat"><div class="num" style="color:#3b82f6">{medium}</div><div class="label">Medium</div></div>
    <div class="stat"><div class="num" style="color:#6b7280">{low}</div><div class="label">Low</div></div>
    <div class="stat"><div class="num" style="color:#8b5cf6">{info}</div><div class="label">Info</div></div>
  </div>
</div>
<table>
<thead><tr><th>Severity</th><th>ID</th><th>Finding</th><th>Evidence</th><th>CWE</th></tr></thead>
<tbody>
"#,
        target = escape_xml(&result.target),
        duration = result.duration_ms,
        requests = result.summary.requests_made,
        date = &result.completed_at[..19],
        critical = result.summary.critical,
        high = result.summary.high,
        medium = result.summary.medium,
        low = result.summary.low,
        info = result.summary.info,
    );

    for f in &result.findings {
        html.push_str(&format!(
            "<tr><td><span class=\"sev\" style=\"background:{color}22;color:{color}\">{sev}</span></td><td style=\"font-family:monospace;font-size:11px;color:#71717a\">{id}</td><td><strong>{title}</strong><br><span style=\"color:#71717a;font-size:12px\">{desc}</span></td><td style=\"font-family:monospace;font-size:11px;color:#a1a1aa\">{evidence}</td><td style=\"color:#60a5fa;font-size:12px\">{cwe}</td></tr>\n",
            color = sev_color(&f.severity),
            sev = f.severity,
            id = f.id,
            title = escape_xml(&f.title),
            desc = escape_xml(&f.remediation),
            evidence = escape_xml(&f.evidence),
            cwe = f.cwe.as_deref().unwrap_or(""),
        ));
    }

    html.push_str("</tbody></table>\n");
    html.push_str("<div class=\"footer\">Generated by <a href=\"https://github.com/cybrium-ai/cyweb\">cyweb</a> — Cybrium AI Web Scanner</div>\n");
    html.push_str("</body></html>\n");
    html
}

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}
