//! v0.8.6 — Two-axis tuning taxonomy.
//!
//! Cyweb's `--tuning` flag has carried a single axis since v0.8.0:
//! the *phase* — which scan stage runs (headers, paths, fuzz, etc.).
//! That model lets you skip phases but doesn't let you say "run
//! everything BUT only emit SQLi findings."
//!
//! v0.8.6 adds a second axis: the **vulnerability class**. The two
//! axes compose:
//!
//!   --tuning paths,sqli      → run only the paths phase, emit only
//!                              findings whose vuln_class matches sqli
//!   --tuning sqli,xss        → run all phases, emit only sqli or xss
//!   --tuning paths           → run only the paths phase (legacy
//!                              behaviour preserved)
//!   --tuning 0,9             → Nikto-style numeric slots (0=upload,
//!                              9=sqli)
//!
//! The taxonomy includes Nikto's full -Tuning surface (slots 0-9 and
//! a-e — 14 categories) plus 6 cyweb-extension categories, for a
//! total of 20 vulnerability classes. Combined with the 13 existing
//! phase categories, that's 33 tuning slots end-to-end.

use crate::signatures::Finding;

/// One row in the tuning taxonomy.
#[derive(Debug, Clone, Copy)]
pub struct TuningEntry {
    /// Canonical name (lowercase, hyphenated). Used in `--tuning`.
    pub name: &'static str,
    /// Axis: phase or class. Phases gate scan stages; classes
    /// filter findings.
    pub axis: TuningAxis,
    /// Nikto numeric / letter slot when one exists. None for cyweb
    /// extensions and phase entries.
    pub nikto_slot: Option<&'static str>,
    /// Short human-readable description (printed by --tuning-list).
    pub description: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TuningAxis {
    /// Gates which scan PHASE runs. Composes with class filters.
    Phase,
    /// Gates which finding vuln_class is emitted. Composes with
    /// phase filters.
    Class,
}

/// The complete v0.8.6 taxonomy. Order = print order in
/// `--tuning-list`.
pub const TAXONOMY: &[TuningEntry] = &[
    // ── Vulnerability classes (Nikto -Tuning + cyweb extensions) ────
    TuningEntry { name: "upload",        axis: TuningAxis::Class, nikto_slot: Some("0"), description: "File upload vulnerabilities" },
    TuningEntry { name: "interesting",   axis: TuningAxis::Class, nikto_slot: Some("1"), description: "Interesting files / logs / backups" },
    TuningEntry { name: "misconfig",     axis: TuningAxis::Class, nikto_slot: Some("2"), description: "Misconfiguration / default files" },
    TuningEntry { name: "infodisc",      axis: TuningAxis::Class, nikto_slot: Some("3"), description: "Information disclosure" },
    TuningEntry { name: "injection-xss", axis: TuningAxis::Class, nikto_slot: Some("4"), description: "XSS / HTML / script injection" },
    TuningEntry { name: "rfi-local",     axis: TuningAxis::Class, nikto_slot: Some("5"), description: "Remote file retrieval (inside web root)" },
    TuningEntry { name: "dos",           axis: TuningAxis::Class, nikto_slot: Some("6"), description: "Denial of service signatures" },
    TuningEntry { name: "rfi-global",    axis: TuningAxis::Class, nikto_slot: Some("7"), description: "Remote file retrieval (server wide)" },
    TuningEntry { name: "rce",           axis: TuningAxis::Class, nikto_slot: Some("8"), description: "Command execution / remote shell" },
    TuningEntry { name: "sqli",          axis: TuningAxis::Class, nikto_slot: Some("9"), description: "SQL injection" },
    TuningEntry { name: "authbypass",    axis: TuningAxis::Class, nikto_slot: Some("a"), description: "Authentication bypass" },
    TuningEntry { name: "softwareid",    axis: TuningAxis::Class, nikto_slot: Some("b"), description: "Software identification" },
    TuningEntry { name: "rsi",           axis: TuningAxis::Class, nikto_slot: Some("c"), description: "Remote source inclusion" },
    TuningEntry { name: "webservice",    axis: TuningAxis::Class, nikto_slot: Some("d"), description: "WebService / SOAP / WSDL" },
    TuningEntry { name: "admin",         axis: TuningAxis::Class, nikto_slot: Some("e"), description: "Administrative console exposure" },
    // cyweb extensions (no Nikto slot)
    TuningEntry { name: "ssrf",          axis: TuningAxis::Class, nikto_slot: None, description: "Server-side request forgery" },
    TuningEntry { name: "xxe",           axis: TuningAxis::Class, nikto_slot: None, description: "XML external entity" },
    TuningEntry { name: "ssti",          axis: TuningAxis::Class, nikto_slot: None, description: "Server-side template injection" },
    TuningEntry { name: "tls",           axis: TuningAxis::Class, nikto_slot: None, description: "TLS / cert / cipher issues" },
    TuningEntry { name: "secrets",       axis: TuningAxis::Class, nikto_slot: None, description: "Leaked secrets / API keys" },

    // ── Phase categories (cyweb scan stages) ────────────────────────
    TuningEntry { name: "headers",       axis: TuningAxis::Phase, nikto_slot: None, description: "Phase: security header analysis" },
    TuningEntry { name: "methods",       axis: TuningAxis::Phase, nikto_slot: None, description: "Phase: HTTP method testing" },
    TuningEntry { name: "paths",         axis: TuningAxis::Phase, nikto_slot: None, description: "Phase: path discovery" },
    TuningEntry { name: "server",        axis: TuningAxis::Phase, nikto_slot: None, description: "Phase: server-specific checks" },
    TuningEntry { name: "ajax-spider",   axis: TuningAxis::Phase, nikto_slot: None, description: "Phase: headless-Chrome JS spider" },
    TuningEntry { name: "passive",       axis: TuningAxis::Phase, nikto_slot: None, description: "Phase: passive HTML analysis" },
    TuningEntry { name: "mixed-content", axis: TuningAxis::Phase, nikto_slot: None, description: "Phase: mixed-content (HTTP-on-HTTPS)" },
    TuningEntry { name: "retirejs",      axis: TuningAxis::Phase, nikto_slot: None, description: "Phase: outdated JS library detection" },
    TuningEntry { name: "mutate",        axis: TuningAxis::Phase, nikto_slot: None, description: "Phase: path mutation" },
    TuningEntry { name: "fuzz",          axis: TuningAxis::Phase, nikto_slot: None, description: "Phase: active payload fuzzing" },
    TuningEntry { name: "templates",     axis: TuningAxis::Phase, nikto_slot: None, description: "Phase: template engine" },
    TuningEntry { name: "race",          axis: TuningAxis::Phase, nikto_slot: None, description: "Phase: race-condition probes" },
    TuningEntry { name: "websocket",     axis: TuningAxis::Phase, nikto_slot: None, description: "Phase: WebSocket hijack probes" },
];

/// Parsed tuning selection. `phases` and `classes` are both
/// case-insensitive HashSets of canonical names. Empty = no filter
/// (run/emit everything on that axis).
#[derive(Debug, Clone, Default)]
pub struct TuningSelection {
    pub phases: std::collections::HashSet<String>,
    pub classes: std::collections::HashSet<String>,
    /// Tokens we couldn't recognise — surfaced to the user as a
    /// warning. We don't error-out so a typo in `--tuning` doesn't
    /// abort a long scan; we just print which slots were ignored.
    pub unknown: Vec<String>,
}

impl TuningSelection {
    /// Parse the comma-separated `--tuning` argument. Accepts:
    ///  - canonical names: "sqli", "paths", "ajax-spider"
    ///  - Nikto numeric/letter slots: "0", "9", "a", "e"
    ///  - mixed: "paths,sqli,9"
    ///  - case-insensitive
    pub fn parse(arg: Option<&str>) -> Self {
        let mut sel = Self::default();
        let raw = match arg {
            Some(s) if !s.trim().is_empty() => s,
            _ => return sel,
        };
        for tok in raw.split(',') {
            let tok = tok.trim().to_lowercase();
            if tok.is_empty() { continue; }

            // Try Nikto numeric/letter slot first
            if let Some(entry) = TAXONOMY.iter().find(|e| e.nikto_slot == Some(tok.as_str())) {
                sel.classes.insert(entry.name.into());
                continue;
            }
            // Then canonical name
            match TAXONOMY.iter().find(|e| e.name == tok) {
                Some(entry) => match entry.axis {
                    TuningAxis::Phase => { sel.phases.insert(entry.name.into()); }
                    TuningAxis::Class => { sel.classes.insert(entry.name.into()); }
                },
                None => sel.unknown.push(tok),
            }
        }
        sel
    }

    /// Should this phase run? Phase tuning is OR-ed across the set;
    /// empty set = run everything (legacy behaviour preserved).
    pub fn run_phase(&self, phase: &str) -> bool {
        self.phases.is_empty() || self.phases.contains(phase)
    }

    /// Should this finding's class pass the filter? Empty set = emit
    /// everything (legacy behaviour preserved). When a class filter
    /// is set, the finding's own `vuln_class` field is checked first;
    /// if absent, `infer_class` heuristically derives one from
    /// `category` / `id` / `title`. Findings that match no class
    /// even after inference are dropped.
    pub fn keep_finding(&self, f: &Finding) -> bool {
        if self.classes.is_empty() {
            return true;
        }
        let cls: Option<&str> = f.vuln_class.as_deref().or_else(|| infer_class(f));
        match cls {
            Some(c) => self.classes.contains(c),
            None => false,
        }
    }
}

/// v0.8.6 — Infer a vuln_class from a Finding's existing category /
/// id / title fields when the producer didn't set one explicitly.
/// This lets the class filter work on legacy emit sites without
/// touching every signature module.
///
/// Returns `None` when nothing matches (the filter then drops the
/// finding, which is the correct behaviour: untagged + class filter
/// active = drop).
pub fn infer_class(f: &Finding) -> Option<&'static str> {
    let c = f.category.to_lowercase();
    let i = f.id.to_lowercase();
    let t = f.title.to_lowercase();

    // Direct category mappings — fast path.
    let direct: &[(&str, &str)] = &[
        ("tls",                "tls"),
        ("ssl",                "tls"),
        ("certificate",        "tls"),
        ("retirejs",           "softwareid"),
        ("retire.js",          "softwareid"),
        ("mixed content",      "infodisc"),
        ("security header",    "infodisc"),
        ("http methods",       "misconfig"),
        ("server",             "softwareid"),
        ("dns",                "misconfig"),
        ("tcp service",        "softwareid"),
        ("blind interaction",  "ssrf"),
        ("oast",               "ssrf"),
        ("websocket",          "infodisc"),
        ("workflow",           "misconfig"),
    ];
    for (needle, cls) in direct {
        if c.contains(needle) { return Some(cls); }
    }

    // Title / id keyword sniff — slower path for path-discovery,
    // CVE, fuzz, and template findings whose category is generic.
    let combined = format!("{} {} {}", i, t, c);
    let kw: &[(&str, &str)] = &[
        // RCE family
        ("rce", "rce"), ("remote code", "rce"), ("command execution", "rce"),
        ("command injection", "rce"), ("shell upload", "rce"),
        // SQLi
        ("sqli", "sqli"), ("sql injection", "sqli"),
        // XSS / injection
        ("xss", "injection-xss"), ("cross-site scripting", "injection-xss"),
        ("html injection", "injection-xss"),
        // SSRF / XXE / SSTI
        ("ssrf", "ssrf"), ("server-side request forgery", "ssrf"),
        ("xxe", "xxe"), ("xml external entity", "xxe"),
        ("ssti", "ssti"), ("template injection", "ssti"),
        // Path / file
        ("path traversal", "rfi-local"), ("directory traversal", "rfi-local"),
        ("lfi", "rfi-local"), ("local file inclusion", "rfi-local"),
        ("rfi", "rfi-global"), ("remote file inclusion", "rfi-global"),
        ("rsi", "rsi"),
        // Auth / admin
        ("auth bypass", "authbypass"), ("authentication bypass", "authbypass"),
        ("default credentials", "authbypass"), ("admin panel", "admin"),
        ("administrative", "admin"), ("/admin", "admin"), ("/manager", "admin"),
        // Webservice
        ("soap", "webservice"), ("wsdl", "webservice"), ("graphql", "webservice"),
        // Upload
        ("file upload", "upload"), ("arbitrary upload", "upload"),
        // DoS
        ("denial of service", "dos"), ("slowloris", "dos"),
        // Secrets
        ("api key", "secrets"), ("aws_access_key", "secrets"),
        ("private key", "secrets"), ("secret leak", "secrets"),
        ("token leak", "secrets"),
        // Backups / interesting
        (".bak", "interesting"), (".backup", "interesting"),
        (".git", "interesting"), (".svn", "interesting"),
        (".env", "interesting"), ("backup file", "interesting"),
        // Information disclosure default
        ("disclosure", "infodisc"), ("exposed", "infodisc"),
        ("leak", "infodisc"),
        // TLS / cert (catches title-only matches when category is blank)
        ("tls ", "tls"), ("ssl ", "tls"), ("certificate", "tls"),
        ("cipher", "tls"), ("heartbleed", "tls"),
    ];
    for (needle, cls) in kw {
        if combined.contains(needle) { return Some(cls); }
    }

    None
}

/// Render the full taxonomy as a printable table.
pub fn render_list() -> String {
    let mut out = String::new();
    out.push_str("Tuning taxonomy — combine any number with --tuning <a>,<b>,...\n\n");
    out.push_str("VULNERABILITY CLASSES (filter findings)\n");
    out.push_str(&format!("  {:<16} {:<6} {}\n", "name", "nikto", "description"));
    out.push_str(&format!("  {:<16} {:<6} {}\n", "----", "-----", "-----------"));
    for e in TAXONOMY.iter().filter(|e| e.axis == TuningAxis::Class) {
        out.push_str(&format!(
            "  {:<16} {:<6} {}\n",
            e.name,
            e.nikto_slot.unwrap_or("-"),
            e.description,
        ));
    }
    out.push_str("\nPHASES (gate scan stages)\n");
    out.push_str(&format!("  {:<16} {}\n", "name", "description"));
    out.push_str(&format!("  {:<16} {}\n", "----", "-----------"));
    for e in TAXONOMY.iter().filter(|e| e.axis == TuningAxis::Phase) {
        out.push_str(&format!("  {:<16} {}\n", e.name, e.description));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signatures::{Finding, Severity};

    fn finding_with_class(class: Option<&str>) -> Finding {
        Finding {
            id: "test".into(),
            title: "t".into(),
            severity: Severity::Info,
            category: "c".into(),
            description: "".into(),
            evidence: "".into(),
            url: "https://x".into(),
            cwe: None,
            remediation: "".into(),
            vuln_class: class.map(|s| s.into()),
        }
    }

    #[test]
    fn empty_input_means_no_filter() {
        let sel = TuningSelection::parse(None);
        assert!(sel.phases.is_empty());
        assert!(sel.classes.is_empty());
        assert!(sel.run_phase("paths"));
        assert!(sel.keep_finding(&finding_with_class(Some("sqli"))));
        assert!(sel.keep_finding(&finding_with_class(None)));
    }

    #[test]
    fn parses_canonical_names() {
        let sel = TuningSelection::parse(Some("sqli,paths"));
        assert!(sel.classes.contains("sqli"));
        assert!(sel.phases.contains("paths"));
    }

    #[test]
    fn parses_nikto_numeric_slots() {
        let sel = TuningSelection::parse(Some("0,9,a"));
        assert!(sel.classes.contains("upload"));
        assert!(sel.classes.contains("sqli"));
        assert!(sel.classes.contains("authbypass"));
    }

    #[test]
    fn case_insensitive() {
        let sel = TuningSelection::parse(Some("SQLI,Paths"));
        assert!(sel.classes.contains("sqli"));
        assert!(sel.phases.contains("paths"));
    }

    #[test]
    fn unknown_tokens_collected_not_errored() {
        let sel = TuningSelection::parse(Some("sqli,bogus,paths"));
        assert!(sel.classes.contains("sqli"));
        assert!(sel.phases.contains("paths"));
        assert_eq!(sel.unknown, vec!["bogus"]);
    }

    #[test]
    fn class_filter_keeps_explicit_match() {
        let sel = TuningSelection::parse(Some("sqli"));
        assert!(sel.keep_finding(&finding_with_class(Some("sqli"))));
    }

    #[test]
    fn class_filter_drops_explicit_mismatch() {
        let sel = TuningSelection::parse(Some("sqli"));
        let mut f = finding_with_class(Some("xss"));
        // Make sure title doesn't accidentally trigger sqli inference
        f.title = "Cross-site scripting in foo".into();
        f.id = "xss-001".into();
        f.category = "Fuzz".into();
        assert!(!sel.keep_finding(&f));
    }

    #[test]
    fn untagged_findings_get_inferred_then_filtered() {
        // A finding with no vuln_class but title=SQL injection should
        // pass the sqli filter via inference.
        let mut f = finding_with_class(None);
        f.title = "SQL injection in /login".into();
        let sel = TuningSelection::parse(Some("sqli"));
        assert!(sel.keep_finding(&f));
        // And the same finding shouldn't pass the xss filter.
        let sel = TuningSelection::parse(Some("injection-xss"));
        assert!(!sel.keep_finding(&f));
    }

    #[test]
    fn infer_class_covers_common_patterns() {
        let cases: &[(&str, &str, &str)] = &[
            ("",          "TLS certificate expired",         "tls"),
            ("Server",    "Apache 2.4.1 EOL",                "softwareid"),
            ("Path",      "/admin panel exposed",            "admin"),
            ("Path",      "/.git/config readable",           "interesting"),
            ("Fuzz",      "SQL injection at /login",         "sqli"),
            ("Fuzz",      "Reflected XSS in q",              "injection-xss"),
            ("Fuzz",      "Server-side request forgery",     "ssrf"),
            ("Headers",   "Missing CSP header (info leak)",  "infodisc"),
        ];
        for (cat, title, expected) in cases {
            let mut f = finding_with_class(None);
            f.category = cat.to_string();
            f.title = title.to_string();
            assert_eq!(
                infer_class(&f),
                Some(*expected),
                "{} / {} should infer {}",
                cat, title, expected,
            );
        }
    }

    #[test]
    fn phase_filter_only_does_not_drop_untagged_findings() {
        let sel = TuningSelection::parse(Some("paths"));
        // Class filter is empty → keep everything regardless of class
        let mut f = finding_with_class(None);
        f.title = "no-keywords-here".into();
        f.category = "generic".into();
        assert!(sel.keep_finding(&f));
        assert!(sel.keep_finding(&finding_with_class(Some("sqli"))));
        // Phase filter applies normally
        assert!(sel.run_phase("paths"));
        assert!(!sel.run_phase("fuzz"));
    }

    #[test]
    fn untagged_finding_with_no_keywords_dropped_by_class_filter() {
        // Class filter active + no inference hits → dropped.
        let sel = TuningSelection::parse(Some("sqli"));
        let mut f = finding_with_class(None);
        f.title = "completely-generic-finding".into();
        f.category = "generic".into();
        f.id = "g-1".into();
        assert!(!sel.keep_finding(&f));
    }

    #[test]
    fn render_list_includes_all_axes() {
        let s = render_list();
        assert!(s.contains("VULNERABILITY CLASSES"));
        assert!(s.contains("PHASES"));
        assert!(s.contains("sqli"));
        assert!(s.contains("paths"));
        // Nikto slot column populated
        assert!(s.contains("9"));
        assert!(s.contains("e"));
    }

    #[test]
    fn taxonomy_has_33_entries() {
        // Sprint contract: 20 classes + 13 phases = 33 slots.
        assert_eq!(TAXONOMY.len(), 33);
        assert_eq!(TAXONOMY.iter().filter(|e| e.axis == TuningAxis::Class).count(), 20);
        assert_eq!(TAXONOMY.iter().filter(|e| e.axis == TuningAxis::Phase).count(), 13);
    }
}
