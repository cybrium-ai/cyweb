//! Version-specific CVE matching.
//!
//! Maps detected server/technology versions to known CVEs.

use super::{Finding, Severity};
use crate::scanner::ServerInfo;

struct CveEntry {
    product: &'static str,
    version_below: &'static str,
    cve: &'static str,
    severity: Severity,
    title: &'static str,
    description: &'static str,
}

const CVE_DB: &[CveEntry] = &[
    // Apache
    CveEntry { product: "apache", version_below: "2.4.62", cve: "CVE-2024-38476", severity: Severity::High,
        title: "Apache HTTP Server SSRF via mod_rewrite",
        description: "Apache HTTP Server allows SSRF via crafted requests to mod_rewrite configurations." },
    CveEntry { product: "apache", version_below: "2.4.59", cve: "CVE-2024-27316", severity: Severity::High,
        title: "Apache HTTP Server HTTP/2 DoS",
        description: "HTTP/2 CONTINUATION frames can cause unbounded memory consumption." },
    CveEntry { product: "apache", version_below: "2.4.56", cve: "CVE-2023-25690", severity: Severity::Critical,
        title: "Apache mod_proxy HTTP request smuggling",
        description: "HTTP request smuggling vulnerability in mod_proxy." },
    CveEntry { product: "apache", version_below: "2.4.52", cve: "CVE-2021-44790", severity: Severity::Critical,
        title: "Apache mod_lua buffer overflow",
        description: "Buffer overflow in mod_lua r:parsebody may lead to RCE." },

    // Nginx
    CveEntry { product: "nginx", version_below: "1.25.4", cve: "CVE-2024-7347", severity: Severity::Medium,
        title: "Nginx mp4 module vulnerability",
        description: "Buffer over-read in the mp4 module when processing specially crafted mp4 files." },
    CveEntry { product: "nginx", version_below: "1.25.0", cve: "CVE-2023-44487", severity: Severity::High,
        title: "HTTP/2 Rapid Reset (affects nginx)",
        description: "HTTP/2 protocol allows denial of service via rapid stream resets." },
    CveEntry { product: "nginx", version_below: "1.22.0", cve: "CVE-2022-41741", severity: Severity::High,
        title: "Nginx mp4 module memory corruption",
        description: "Memory corruption in the mp4 module when processing crafted files." },

    // PHP
    CveEntry { product: "php", version_below: "8.3.8", cve: "CVE-2024-4577", severity: Severity::Critical,
        title: "PHP CGI argument injection",
        description: "Argument injection via CGI mode allows remote code execution on Windows." },
    CveEntry { product: "php", version_below: "8.2.20", cve: "CVE-2024-2756", severity: Severity::Medium,
        title: "PHP cookie bypass",
        description: "__Host-/__Secure- cookie bypass through partial cookie name matching." },
    CveEntry { product: "php", version_below: "8.1.0", cve: "CVE-2022-31625", severity: Severity::Critical,
        title: "PHP pgsql parameter overflow",
        description: "Uninitialized memory use in pg_query_params() may lead to RCE." },
    CveEntry { product: "php", version_below: "7.4.0", cve: "CVE-2019-11043", severity: Severity::Critical,
        title: "PHP-FPM remote code execution",
        description: "Underflow in fpm_main.c allows remote code execution via crafted URLs." },

    // IIS
    CveEntry { product: "iis", version_below: "10.0", cve: "CVE-2021-31166", severity: Severity::Critical,
        title: "IIS HTTP Protocol Stack RCE",
        description: "HTTP protocol stack wormable RCE vulnerability in IIS." },

    // Express.js
    CveEntry { product: "express", version_below: "4.20.0", cve: "CVE-2024-43796", severity: Severity::Medium,
        title: "Express.js XSS in res.redirect()",
        description: "Cross-site scripting via untrusted input in redirect URLs." },

    // jQuery (client-side but commonly detected)
    CveEntry { product: "jquery", version_below: "3.5.0", cve: "CVE-2020-11022", severity: Severity::Medium,
        title: "jQuery XSS in htmlPrefilter",
        description: "Cross-site scripting in jQuery's HTML sanitization." },

    // WordPress
    CveEntry { product: "wordpress", version_below: "6.4.3", cve: "CVE-2024-25101", severity: Severity::High,
        title: "WordPress POP chain RCE",
        description: "Property-Oriented Programming chain allows remote code execution." },
    CveEntry { product: "wordpress", version_below: "6.2.0", cve: "CVE-2023-22622", severity: Severity::Medium,
        title: "WordPress SSRF via DNS rebinding",
        description: "Server-side request forgery via DNS rebinding in wp-cron." },
];

pub fn match_cves(info: &ServerInfo) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Extract product + version from Server header
    if let Some(ref server) = info.server {
        let lower = server.to_lowercase();
        for entry in CVE_DB {
            if lower.contains(entry.product) {
                if let Some(current_ver) = extract_version(server) {
                    if version_lt(&current_ver, entry.version_below) {
                        findings.push(Finding {
                            id: format!("CYWEB-CVE-{}", entry.cve),
                            title: format!("{} ({})", entry.title, entry.cve),
                            severity: entry.severity,
                            category: "Known CVE".into(),
                            description: entry.description.into(),
                            evidence: format!("Server: {} — vulnerable below {}", server, entry.version_below),
                            url: String::new(),
                            cwe: None,
                            remediation: format!("Update {} to version {} or later.", entry.product, entry.version_below),
                        });
                    }
                }
            }
        }
    }

    // Check X-Powered-By for PHP
    if let Some(ref pb) = info.powered_by {
        let lower = pb.to_lowercase();
        for entry in CVE_DB {
            if entry.product == "php" && lower.contains("php") {
                if let Some(current_ver) = extract_version(pb) {
                    if version_lt(&current_ver, entry.version_below) {
                        findings.push(Finding {
                            id: format!("CYWEB-CVE-{}", entry.cve),
                            title: format!("{} ({})", entry.title, entry.cve),
                            severity: entry.severity,
                            category: "Known CVE".into(),
                            description: entry.description.into(),
                            evidence: format!("X-Powered-By: {} — vulnerable below {}", pb, entry.version_below),
                            url: String::new(),
                            cwe: None,
                            remediation: format!("Update PHP to version {} or later.", entry.version_below),
                        });
                    }
                }
            }
        }
    }

    findings
}

fn extract_version(header: &str) -> Option<String> {
    let re = regex::Regex::new(r"[\w]+/([\d]+\.[\d]+\.?[\d]*)").ok()?;
    re.captures(header).map(|c| c[1].to_string())
}

fn version_lt(current: &str, minimum: &str) -> bool {
    let parse = |v: &str| -> Vec<u32> {
        v.split('.').filter_map(|p| p.parse().ok()).collect()
    };
    let cur = parse(current);
    let min = parse(minimum);
    for i in 0..min.len().max(cur.len()) {
        let c = cur.get(i).copied().unwrap_or(0);
        let m = min.get(i).copied().unwrap_or(0);
        if c < m { return true; }
        if c > m { return false; }
    }
    false
}
