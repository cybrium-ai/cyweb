//! Sprint 76 Phase 5 — race condition detection.
//!
//! Some state machines that should accept a request exactly once
//! accept it more than once when N concurrent requests arrive within
//! the same TOCTOU (time-of-check to time-of-use) window. Common
//! targets:
//!
//!   - Voucher / discount-code redemption (use-once codes used N times)
//!   - OAuth authorization-code reuse (one-shot codes accepted twice)
//!   - TOTP replay (same code accepted on two devices)
//!   - Wallet transfers (double-spend within the lock window)
//!   - Vote-submission once-per-user
//!
//! Detection is differential: we send N=20 concurrent identical
//! requests via tokio::join! and compare response status codes. A
//! correctly-implemented endpoint shows 1 success + N-1 conflicts
//! (4xx). A vulnerable endpoint shows multiple 2xx in the response
//! distribution.
//!
//! **Intrusive**: a stuck state machine can be left in an inconsistent
//! state. Cybrium platform requires `requires_intrusive_attestation`
//! on the ScanJob before this rule dispatches. This module assumes
//! the gate has already passed; it does not re-check.

use crate::signatures::{Finding, Severity};
use reqwest::Client;
use std::time::Duration;
use tokio::time::timeout;
use futures::future::join_all;

/// Concurrency level for the differential probe. 20 is enough to surface
/// any meaningful race — diminishing returns above this, and the
/// burst can disrupt rate-limited endpoints.
const RACE_CONCURRENCY: usize = 20;

/// Cap on time spent on the burst itself. Servers that return slowly
/// would otherwise stretch the scan; if they're too slow to respond
/// within this window they're not racy in any practical sense.
const RACE_TIMEOUT: Duration = Duration::from_secs(15);

/// Heuristic patterns in URLs that look state-mutating. We only race
/// these — racing a GET / static-asset URL is wasted work.
const STATE_MUTATING_PATTERNS: &[&str] = &[
    "/redeem",
    "/voucher",
    "/coupon",
    "/discount",
    "/transfer",
    "/withdraw",
    "/payment",
    "/checkout",
    "/order",
    "/submit",
    "/vote",
    "/like",
    "/follow",
    "/redirect_uri",   // OAuth code reuse
    "/totp",
    "/2fa",
    "/mfa",
    "/redeem_code",
    "/claim",
    "/booking",
    "/reservation",
];

pub async fn run_race(
    client: &Client,
    target: &str,
    crawled_urls: &[String],
) -> Vec<Finding> {
    let mut out = Vec::new();
    let candidates = pick_candidates(target, crawled_urls);

    for url in candidates {
        if let Some(finding) = race_one(client, &url).await {
            out.push(finding);
        }
    }

    out
}

/// Pick URLs likely to be state-mutating endpoints. Keeps the scan
/// budget proportional to a real attack surface, not the full crawl.
fn pick_candidates(target: &str, crawled_urls: &[String]) -> Vec<String> {
    // Always probe the target itself (bare host) only when it ends in
    // a state-mutating segment — otherwise users would hit homepage
    // races every scan.
    let mut out = Vec::new();
    for url in crawled_urls {
        let lower = url.to_lowercase();
        if STATE_MUTATING_PATTERNS.iter().any(|p| lower.contains(p)) {
            out.push(url.clone());
        }
    }
    // De-dupe + cap. Race probes are expensive (20 requests each); 10
    // candidates is the sane upper bound per scan.
    out.sort();
    out.dedup();
    if out.len() > 10 {
        out.truncate(10);
    }
    // If the crawler didn't find any, try the target with a couple of
    // canonical paths appended. Most apps have at least one.
    if out.is_empty() {
        let target = target.trim_end_matches('/');
        out.push(format!("{target}/redeem"));
        out.push(format!("{target}/checkout"));
    }
    out
}

/// Send N concurrent identical POSTs and look for multiple 2xx where
/// only one should succeed. Idempotency-key header is the same across
/// all bursts — that's the whole point of the race oracle.
async fn race_one(client: &Client, url: &str) -> Option<Finding> {
    let idempotency_key = format!("cyweb-race-{}", short_hash(url));
    let body = serde_json::json!({
        "amount":         1,
        "code":           "CYWEB-RACE-PROBE",
        "_cybrium_probe": true,
    });

    let mut futures = Vec::with_capacity(RACE_CONCURRENCY);
    for _ in 0..RACE_CONCURRENCY {
        let req = client
            .post(url)
            .header("Idempotency-Key", &idempotency_key)
            .header("X-Cybrium-Probe", "race-condition")
            .json(&body)
            .timeout(RACE_TIMEOUT);
        futures.push(async move {
            req.send().await.map(|r| r.status().as_u16()).unwrap_or(0)
        });
    }

    // Wrap the burst in an outer timeout so a single dead endpoint
    // doesn't stall the scan.
    let statuses: Vec<u16> = match timeout(RACE_TIMEOUT, join_all(futures)).await {
        Ok(v) => v,
        Err(_) => return None,
    };

    let success_count = statuses.iter().filter(|s| (200..300).contains(*s)).count();
    let total         = statuses.len();

    // ── Decision rules ──────────────────────────────────────────────────
    //
    // 1. Zero successes — endpoint rejects every variant. Not a race.
    // 2. Exactly one success, rest conflict (409 / 422 / 429) — correct
    //    behaviour. Not a race.
    // 3. Two or more successes — the endpoint accepted the same
    //    idempotent operation more than once. Race finding.
    // 4. All N succeed — same as (3), even higher confidence.
    if success_count >= 2 {
        let severity = if success_count == total {
            Severity::Critical
        } else {
            Severity::High
        };
        return Some(Finding {
            id:          format!("CYWEB-RACE-{}", short_hash(url)),
            title:       "Race condition — idempotent operation accepted multiple times".into(),
            severity,
            category:    "Race Condition".into(),
            description: format!(
                "{success_count}/{total} concurrent identical requests against {url} \
                 returned a 2xx response despite carrying the same Idempotency-Key. \
                 A correctly-implemented state machine should accept this operation \
                 exactly once. Targets vouchers, payments, OAuth code reuse, \
                 vote-submission, draft-publish, etc."
            ),
            evidence:    format!(
                "Status distribution from {RACE_CONCURRENCY} concurrent POSTs: {}",
                summarise(&statuses)
            ),
            url:         url.into(),
            cwe:         Some("CWE-362".into()),
            remediation: "Wrap the state mutation in a SELECT ... FOR UPDATE / advisory lock \
                          / Redis SETNX guarded against the idempotency key. Reject \
                          duplicate requests with 409 Conflict.".into(),
            vuln_class:  Some("race_condition".into()),
        });
    }
    None
}

/// Compress a status-code list into a buyer-friendly summary like
/// `200×3, 409×17`.
fn summarise(statuses: &[u16]) -> String {
    use std::collections::BTreeMap;
    let mut counts: BTreeMap<u16, usize> = BTreeMap::new();
    for s in statuses {
        *counts.entry(*s).or_insert(0) += 1;
    }
    counts.into_iter()
        .map(|(s, n)| format!("{s}×{n}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn short_hash(s: &str) -> String {
    let mut h: u64 = 1469598103934665603;
    for b in s.bytes() {
        h = h.wrapping_mul(1099511628211).wrapping_add(b as u64);
    }
    format!("{:08x}", (h & 0xffffffff) as u32)
}
