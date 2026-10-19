//! Shared soft-404 / catch-all fingerprinting.
//!
//! A Single-Page-App (or any catch-all route) returns a `200` `index.html`
//! — a fixed, often byte-identical body — for EVERY unmatched path. A bare
//! `HTTP 200` on a probed path therefore proves nothing: `/requirements.txt`,
//! `/actuator/info`, `/stats.json` and a random `/<uuid>` all come back as the
//! same `index.html`.
//!
//! Before any path/rule "exposed" finding fires on a `200`, we compare the
//! response against a fingerprint captured from deliberately-nonexistent
//! random paths at scan start (one or two cheap requests per host). If the
//! probed path's response is indistinguishable from that catch-all
//! fingerprint, the finding is suppressed. A finding fires only when the
//! response *differs* from the catch-all (different status, or a materially
//! different body length / hash) — i.e. the path actually returned something.

use reqwest::Client;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// Normalised body hash — strips everything but alphanumerics and whitespace
/// so a dynamic nonce / CSRF token embedded in an otherwise-constant page
/// doesn't, on its own, defeat the comparison. (Nonces are alphanumeric, so
/// this is complemented by the length fallback in [`SoftError::matches`].)
pub fn normalized_hash(body: &str) -> u64 {
    let mut h = DefaultHasher::new();
    body.chars()
        .filter(|c| c.is_alphanumeric() || c.is_whitespace())
        .collect::<String>()
        .hash(&mut h);
    h.finish()
}

/// True when the body looks like an HTML document rather than raw config /
/// JSON / SQL / git / binary content. Used as a content-type sanity guard for
/// checks that expect a specific non-HTML file type: a check for `/.env` or
/// `/config.json` that comes back as an HTML page is the SPA shell, not the
/// file.
pub fn looks_like_html(body: &str) -> bool {
    // Inspect a bounded, char-boundary-safe prefix.
    let head: String = body.trim_start().chars().take(1024).collect();
    let lower = head.to_ascii_lowercase();
    lower.starts_with("<!doctype html")
        || lower.starts_with("<html")
        || lower.contains("<head")
        || lower.contains("<body")
        || lower.contains("<script")
        || lower.contains("<div")
        || lower.contains("<title>")
}

/// Two byte-lengths are "close" when they are within a small flat epsilon.
/// A rotating CSRF/nonce token in an otherwise-constant page is almost always
/// fixed-length (so the length barely moves), while a genuinely different file
/// differs by far more. A tight epsilon keeps nonce rotation suppressed
/// without ever mistaking a real small file (e.g. a 130-byte `.git/config`)
/// for the catch-all page.
fn len_close(a: usize, b: usize) -> bool {
    a.abs_diff(b) <= 16
}

fn random_segment() -> String {
    format!("cyweb-nonexistent-{}", uuid::Uuid::new_v4().as_simple())
}

async fn fetch(client: &Client, url: &str) -> Option<(u16, u64, usize)> {
    let resp = client.get(url).send().await.ok()?;
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    Some((status, normalized_hash(&body), body.len()))
}

/// Fingerprint of a host's response to a definitely-nonexistent path.
#[derive(Debug, Clone, Default)]
pub struct SoftError {
    /// Whether the host serves an unconditional `200` catch-all (both random
    /// probes came back `200` with the same, or near-same-length, body). Only
    /// when this is true will [`matches`](Self::matches) ever suppress.
    pub is_catch_all: bool,
    /// Status returned for nonexistent paths.
    pub status: u16,
    /// Normalised hash of the catch-all body.
    pub body_hash: u64,
    /// Length of the catch-all body in bytes.
    pub body_len: usize,
}

impl SoftError {
    /// Probe two distinct random paths (one extension-less, one with a random
    /// extension — some servers serve a static 404 only for extensioned
    /// requests) to capture the catch-all fingerprint. At most two requests
    /// per host. We treat the host as a catch-all only when BOTH probes return
    /// `200` with the same (or near-same-length) body — that is what actually
    /// proves an unconditional 200, as opposed to a one-off.
    pub async fn probe(client: &Client, target: &str) -> Self {
        let base = target.trim_end_matches('/');
        let p1 = format!("{}/{}", base, random_segment());
        let p2 = format!("{}/{}.{}", base, random_segment(), "zzxq");
        let first = fetch(client, &p1).await;
        let second = fetch(client, &p2).await;
        match (first, second) {
            (Some((s1, h1, l1)), Some((s2, h2, l2)))
                if s1 == 200 && s2 == 200 && (h2 == h1 || len_close(l1, l2)) =>
            {
                Self { is_catch_all: true, status: 200, body_hash: h1, body_len: l1 }
            }
            (Some((s1, h1, l1)), _) => {
                // Single usable sample — record it (status is still useful for
                // callers' own comparisons) but do NOT treat as a catch-all,
                // so a lone probe never suppresses a real 200 finding.
                Self { is_catch_all: false, status: s1, body_hash: h1, body_len: l1 }
            }
            _ => Self::default(),
        }
    }

    /// True when `(status, body)` is indistinguishable from the catch-all
    /// soft-404 response — i.e. firing an "exposed" finding on it would be a
    /// false positive. Returns false whenever no catch-all was fingerprinted,
    /// so hosts that return real 404s are never affected.
    pub fn matches(&self, status: u16, body: &str) -> bool {
        if !self.is_catch_all || status != self.status {
            return false;
        }
        normalized_hash(body) == self.body_hash || len_close(body.len(), self.body_len)
    }

    /// Legacy single-value baseline hash consumed by the fuzz / mutate engines
    /// to skip soft-404 bodies.
    pub fn baseline_hash(&self) -> u64 {
        self.body_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPA_INDEX: &str = "<!doctype html><html><head><title>Cybrium</title>\
        <script src=\"/assets/index-a1b2c3.js\"></script></head>\
        <body><div id=\"root\"></div></body></html>";

    fn catch_all(body: &str) -> SoftError {
        SoftError { is_catch_all: true, status: 200, body_hash: normalized_hash(body), body_len: body.len() }
    }

    #[test]
    fn spa_identical_body_is_suppressed() {
        // The reported FP class: /requirements.txt, /actuator/info, /stats.json
        // all return the identical index.html with HTTP 200.
        let soft = catch_all(SPA_INDEX);
        assert!(soft.matches(200, SPA_INDEX), "identical SPA body must match the fingerprint");
    }

    #[test]
    fn genuinely_different_body_still_fires() {
        let soft = catch_all(SPA_INDEX);
        let real_env = "SECRET_KEY=supersecret\nDATABASE_URL=postgres://u:p@db/app\nDEBUG=0\n";
        assert!(!soft.matches(200, real_env), "a real exposed .env must NOT match the SPA fingerprint");
    }

    #[test]
    fn different_status_never_matches() {
        let soft = catch_all(SPA_INDEX);
        // Even with an identical body, a different status means it's not the
        // catch-all response we fingerprinted.
        assert!(!soft.matches(403, SPA_INDEX));
    }

    #[test]
    fn non_catch_all_never_suppresses() {
        // Host returns real 404s — no catch-all captured. matches() must be a
        // no-op so genuine 200 findings are untouched.
        let soft = SoftError { is_catch_all: false, status: 404, body_hash: 123, body_len: 99 };
        assert!(!soft.matches(200, SPA_INDEX));
        assert!(!soft.matches(200, "anything"));
    }

    #[test]
    fn nonce_rotation_still_matches_via_length() {
        // Same page, a rotated alphanumeric nonce → different hash but
        // near-identical length. The length fallback keeps it suppressed.
        let base = format!("<!doctype html><html>…nonce=AAAA1111BBBB2222…{}</html>", "x".repeat(200));
        let rotated = format!("<!doctype html><html>…nonce=CCCC3333DDDD4444…{}</html>", "x".repeat(200));
        let soft = catch_all(&base);
        assert_ne!(normalized_hash(&base), normalized_hash(&rotated));
        assert!(soft.matches(200, &rotated), "near-same-length nonce rotation should still be the catch-all");
    }

    #[test]
    fn looks_like_html_detects_spa_shell() {
        assert!(looks_like_html(SPA_INDEX));
        assert!(looks_like_html("   \n<html><body>hi</body></html>"));
        // Structured non-HTML content is not HTML.
        assert!(!looks_like_html("{\"openapi\":\"3.0.0\"}"));
        assert!(!looks_like_html("[core]\n\trepositoryformatversion = 0\n"));
        assert!(!looks_like_html("SECRET_KEY=abc\nDEBUG=0"));
    }
}
