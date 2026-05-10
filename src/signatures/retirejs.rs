//! retire.js-style vulnerable JS library scanner.
//!
//! Bundles the retire.js community DB (`jsrepository.json`) at compile
//! time and matches every cross-origin / same-origin `<script src=>`
//! URL against the URI + filename extractor patterns. When a library
//! name + version pair matches a known-vulnerable entry, emit a
//! finding referencing the CVE / GHSA identifier from retire.js.
//!
//! Coverage today:
//!   - URI pattern match  (e.g. `/(§§version§§)/jquery.min.js`)
//!   - Filename pattern match  (e.g. `jquery-(§§version§§).min.js`)
//!
//! Not yet covered (deferred to v0.8.1+):
//!   - filecontent patterns  (would require fetching every JS file)
//!   - hashes  (full file SHA256 lookup against retire.js cdnjs hashes)
//!   - func patterns  (require executing JS in a runtime)
//!
//! Standard "Vulnerable JS Library" coverage. CWE-1395 (Vulnerable
//! Third-Party Component) / historically CWE-829.

use super::{Finding, Severity};
use regex::Regex;
use reqwest::Client;
use scraper::{Html, Selector};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::OnceLock;
use url::Url;

/// Embed the retire.js DB at compile time. Refresh by re-running:
///   curl -sL https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository.json \
///        -o src/signatures/data/retirejs.json
/// and bumping cyweb's version.
const RETIREJS_DB_RAW: &str = include_str!("data/retirejs.json");

#[derive(Debug, Deserialize)]
struct LibraryEntry {
    #[serde(default)]
    vulnerabilities: Vec<Vulnerability>,
    #[serde(default)]
    extractors: Extractors,
}

#[derive(Debug, Deserialize, Default)]
struct Extractors {
    #[serde(default)]
    uri: Vec<String>,
    #[serde(default)]
    filename: Vec<String>,
    // func / filecontent / hashes / filecontentreplace are intentionally
    // ignored — we only do URL-pattern matching for now.
}

#[derive(Debug, Deserialize, Clone)]
struct Vulnerability {
    /// Vulnerable when `version < below`.
    #[serde(default)]
    below: Option<String>,
    /// Vulnerable when `version >= atOrAbove` (combined with `below`).
    #[serde(default, rename = "atOrAbove")]
    at_or_above: Option<String>,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    cwe: Vec<String>,
    #[serde(default)]
    identifiers: Identifiers,
    #[serde(default)]
    info: Vec<String>,
}

#[derive(Debug, Deserialize, Clone, Default)]
struct Identifiers {
    #[serde(default)]
    summary: Option<String>,
    #[serde(default, rename = "CVE")]
    cve: Vec<String>,
    #[serde(default, rename = "githubID")]
    github_id: Option<String>,
}

/// Compiled extractor — regex with `§§version§§` placeholder replaced
/// by a real version-capture group, paired with the originating
/// library name.
struct CompiledExtractor {
    library: String,
    pattern: Regex,
}

/// Process the raw DB once at startup. Returns:
///   - vec of compiled URI/filename regexes paired with their library name
///   - map library_name → its full LibraryEntry (for vulnerability lookup)
fn compile_db() -> (Vec<CompiledExtractor>, HashMap<String, LibraryEntry>) {
    // The version capture group. Tight enough to NOT swallow trailing
    // `.min` / `.js` etc. The earlier `[\w\-.+]*` tail was too loose
    // and matched `1.6.2.min` for `jquery-1.6.2.min.js`. Now: at
    // least MAJOR.MINOR (with optional .PATCH and optional -rc1 /
    // +build suffix that MUST start with `-` or `+`).
    const VERSION_GROUP: &str = r"(\d+\.\d+(?:\.\d+)?(?:[+\-][\w.]+)?)";

    let parsed: HashMap<String, LibraryEntry> = match serde_json::from_str(RETIREJS_DB_RAW) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("retire.js DB parse failed: {}", e);
            return (Vec::new(), HashMap::new());
        }
    };

    let mut extractors: Vec<CompiledExtractor> = Vec::new();
    for (lib_name, entry) in &parsed {
        // skip retire.js's self-test entry
        if lib_name == "retire-example" {
            continue;
        }
        for raw in entry
            .extractors
            .uri
            .iter()
            .chain(entry.extractors.filename.iter())
        {
            let with_version = raw.replace("§§version§§", VERSION_GROUP);
            // Some retire.js patterns aren't anchored — wrap to avoid
            // matching a substring that's inside another path
            // unintentionally. Pattern compiled case-insensitive
            // since URLs vary.
            let final_pat = format!("(?i){}", with_version);
            if let Ok(re) = Regex::new(&final_pat) {
                extractors.push(CompiledExtractor {
                    library: lib_name.clone(),
                    pattern: re,
                });
            }
        }
    }
    (extractors, parsed)
}

fn db() -> &'static (Vec<CompiledExtractor>, HashMap<String, LibraryEntry>) {
    static DB: OnceLock<(Vec<CompiledExtractor>, HashMap<String, LibraryEntry>)> = OnceLock::new();
    DB.get_or_init(compile_db)
}

/// Compare two dot-separated version strings. Returns:
///   Some(Less) / Some(Equal) / Some(Greater) on success,
///   None if either string isn't parseable.
fn cmp_version(a: &str, b: &str) -> Option<std::cmp::Ordering> {
    fn parts(s: &str) -> Option<Vec<u64>> {
        let head = s.split(|c: char| c == '-' || c == '+').next()?;
        head.split('.').map(|p| p.parse::<u64>().ok()).collect()
    }
    let av = parts(a)?;
    let bv = parts(b)?;
    let len = av.len().max(bv.len());
    for i in 0..len {
        let ai = av.get(i).copied().unwrap_or(0);
        let bi = bv.get(i).copied().unwrap_or(0);
        match ai.cmp(&bi) {
            std::cmp::Ordering::Equal => continue,
            other => return Some(other),
        }
    }
    Some(std::cmp::Ordering::Equal)
}

fn vuln_applies(version: &str, vuln: &Vulnerability) -> bool {
    use std::cmp::Ordering;
    if let Some(ref below) = vuln.below {
        if !matches!(cmp_version(version, below), Some(Ordering::Less)) {
            return false;
        }
    }
    if let Some(ref at) = vuln.at_or_above {
        match cmp_version(version, at) {
            Some(Ordering::Less) => return false,
            Some(_) => (),
            None => return false,
        }
    }
    // No `below` and no `atOrAbove` means the entry is structural-only
    // (rare); be conservative and don't flag.
    vuln.below.is_some() || vuln.at_or_above.is_some()
}

fn map_severity(s: Option<&String>) -> Severity {
    match s.map(|x| x.to_ascii_lowercase()).as_deref() {
        Some("critical") => Severity::Critical,
        Some("high")     => Severity::High,
        Some("medium")   => Severity::Medium,
        Some("low")      => Severity::Low,
        _                 => Severity::Info,
    }
}

/// Extract every <script src=> from the HTML document, return absolute
/// URLs.
fn collect_script_srcs(base: &Url, body: &str) -> Vec<String> {
    let doc = Html::parse_document(body);
    let sel = Selector::parse(r#"script[src]"#).expect("static selector");
    doc.select(&sel)
        .filter_map(|el| el.value().attr("src"))
        .filter_map(|src| base.join(src).ok())
        .map(|u| u.to_string())
        .collect()
}

/// Walk the spider's URL list, fetch each HTML page, extract script
/// URLs, then match each script URL against the retire.js DB. Emit one
/// Finding per vulnerable (library, version, cve) tuple, deduplicated.
pub async fn check_retirejs(client: &Client, target: &str, urls: &[String]) -> Vec<Finding> {
    let mut findings = Vec::new();

    let mut to_check: Vec<String> = urls.to_vec();
    if !to_check.iter().any(|u| u == target) {
        to_check.insert(0, target.to_string());
    }

    let (extractors, lib_db) = db();
    if extractors.is_empty() || lib_db.is_empty() {
        return findings;
    }

    // (library, version, cve_or_summary) → seen flag
    let mut seen: std::collections::HashSet<(String, String, String)> = Default::default();

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
        let base = match Url::parse(url) {
            Ok(b) => b,
            Err(_) => continue,
        };

        for script_url in collect_script_srcs(&base, &body) {
            for ex in extractors.iter() {
                let caps = match ex.pattern.captures(&script_url) {
                    Some(c) => c,
                    None => continue,
                };
                let version = match caps.get(1).map(|m| m.as_str().to_string()) {
                    Some(v) => v,
                    None => continue,
                };
                let entry = match lib_db.get(&ex.library) {
                    Some(e) => e,
                    None => continue,
                };
                for vuln in &entry.vulnerabilities {
                    if !vuln_applies(&version, vuln) {
                        continue;
                    }
                    let cve_or_id = vuln
                        .identifiers
                        .cve
                        .first()
                        .cloned()
                        .or_else(|| vuln.identifiers.github_id.clone())
                        .or_else(|| vuln.identifiers.summary.clone())
                        .unwrap_or_else(|| "(no identifier)".into());
                    let key = (ex.library.clone(), version.clone(), cve_or_id.clone());
                    if !seen.insert(key) {
                        continue;
                    }
                    let cwe = vuln.cwe.first().cloned();
                    let title = format!(
                        "Vulnerable JS library — {} {} ({})",
                        ex.library, version, cve_or_id
                    );
                    let summary = vuln
                        .identifiers
                        .summary
                        .clone()
                        .unwrap_or_else(|| "Known vulnerability in this library version".into());
                    let info_link = vuln.info.first().cloned().unwrap_or_default();
                    let mut description = format!(
                        "Page `{}` loads `{}` version `{}`. retire.js reports `{}` is \
                         affected by: {}",
                        url, ex.library, version, version, summary
                    );
                    if !info_link.is_empty() {
                        description.push_str(&format!(" See {}", info_link));
                    }
                    findings.push(Finding {
                        id: format!("CYWEB-RETIRE-{}", cve_or_id),
                        title,
                        severity: map_severity(vuln.severity.as_ref()),
                        category: "Vulnerable Component".into(),
                        description,
                        evidence: format!("<script src=\"{}\">", script_url),
                        url: url.clone(),
                        cwe,
                        remediation: format!(
                            "Upgrade `{}` to a version not listed in the retire.js advisory \
                             database. Most fixed versions ship in subsequent minor releases — \
                             see https://github.com/RetireJS/retire.js for the latest tracked \
                             advisories.",
                            ex.library
                        ),
                        vuln_class: None,
                    });
                }
            }
        }
    }

    findings
}
