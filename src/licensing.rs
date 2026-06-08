//! v0.11.x — Hardware fingerprint + per-host license state.
//!
//! Sprint 127 Phase 1: client-side fingerprint computation + local
//! license-state CRUD. **No network call, no refuse-to-run enforcement
//! in this phase** — that lands in Phase 3 (cy-tls v0.6.0) once the
//! backend `apps/licensing/` endpoint ships.
//!
//! Fingerprint sources (in priority order):
//!   1. TPM EK / Apple Secure Enclave EK — via `hardware_rot::detect()`
//!      from v0.5.71. When present, the fingerprint hashes the ROT
//!      kind + vendor + a stable OS-platform identifier.
//!   2. Firmware UUID — DMI product UUID on Linux, IOPlatformUUID on
//!      macOS, Win32_ComputerSystemProduct UUID on Windows.
//!   3. `/etc/machine-id` (Linux only) as a final fallback.
//!
//! The `host_id_source` field on `HardwareFingerprint` discloses
//! which source produced the identifier — operators MUST be able to
//! distinguish a TPM-bound fingerprint (strong) from a firmware-UUID
//! fallback (weak, defeated by hypervisor cloning).
//!
//! License-state file: `~/.cybrium/cyweb/license.json` on Unix,
//! `%APPDATA%\Cybrium\cyweb\license.json` on Windows. Created with
//! 0o600 permissions when on Unix.

use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hardware_rot::{self, RootOfTrust};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareFingerprint {
    /// Algorithm tag. v1 = SHA-256 over the canonical input string
    /// "<rot_kind>|<rot_vendor>|<host_id_source>|<host_id_value>".
    pub algorithm: String,
    /// Hex-encoded SHA-256 digest. Stable across reboots on the same
    /// host with the same ROT + firmware identifier.
    pub fingerprint: String,
    /// Snapshot of the hardware root-of-trust at fingerprint time.
    pub root_of_trust: RootOfTrust,
    /// Which class of identifier was used. One of:
    ///   "tpm_ek"        — TPM EK or Apple SE key hash (strongest)
    ///   "platform_uuid" — firmware-reported UUID (weaker; clonable)
    ///   "machine_id"    — Linux /etc/machine-id (weakest; per-install)
    pub host_id_source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseState {
    pub schema: u32,
    pub binary: String,
    pub license_id: String,
    pub fingerprint: HardwareFingerprint,
    pub activated_at: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub not_after: Option<String>,
    pub issuer: String,
    /// Ed25519 signature over the canonical JSON of every other
    /// field. Empty in Phase 1 (no backend yet). Phase 3 enforces.
    #[serde(default)]
    pub server_signature: String,
    #[serde(default)]
    pub server_pubkey_id: String,
}

/// Compute the stable hardware fingerprint for this host. Never
/// panics; falls back to weaker identifier sources when stronger
/// ones aren't available. The `host_id_source` field on the output
/// always discloses which source was used.
pub fn fingerprint() -> HardwareFingerprint {
    let rot = hardware_rot::detect();
    let (host_id_source, host_id_value) = collect_host_id();
    let canonical = format!(
        "{rot_kind}|{rot_vendor}|{src}|{val}",
        rot_kind = rot.kind.as_str(),
        rot_vendor = rot.vendor,
        src = host_id_source,
        val = host_id_value,
    );
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let digest = hasher.finalize();
    HardwareFingerprint {
        algorithm: "sha256-v1".into(),
        fingerprint: hex::encode(digest),
        root_of_trust: rot,
        host_id_source: host_id_source.into(),
    }
}

fn collect_host_id() -> (&'static str, String) {
    #[cfg(target_os = "linux")]
    {
        // Prefer DMI product UUID, fall back to machine-id.
        if let Ok(uuid) = std::fs::read_to_string("/sys/class/dmi/id/product_uuid") {
            let trimmed = uuid.trim().to_string();
            if !trimmed.is_empty() {
                return ("platform_uuid", trimmed);
            }
        }
        if let Ok(mid) = std::fs::read_to_string("/etc/machine-id") {
            let trimmed = mid.trim().to_string();
            if !trimmed.is_empty() {
                return ("machine_id", trimmed);
            }
        }
        ("none", String::new())
    }
    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        let out = Command::new("ioreg")
            .args(["-d2", "-c", "IOPlatformExpertDevice"])
            .output();
        if let Ok(o) = out {
            let text = String::from_utf8_lossy(&o.stdout);
            if let Some(line) = text.lines().find(|l| l.contains("IOPlatformUUID")) {
                if let Some(eq) = line.find('=') {
                    let val = line[eq + 1..].trim().trim_matches('"').to_string();
                    if !val.is_empty() {
                        return ("platform_uuid", val);
                    }
                }
            }
        }
        ("none", String::new())
    }
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        let out = Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "(Get-WmiObject Win32_ComputerSystemProduct).UUID",
            ])
            .output();
        if let Ok(o) = out {
            let val = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if !val.is_empty() {
                return ("platform_uuid", val);
            }
        }
        ("none", String::new())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        ("none", String::new())
    }
}

pub fn license_path() -> Result<PathBuf> {
    let base = dirs::home_dir().ok_or_else(|| anyhow!("could not resolve home directory"))?;
    #[cfg(target_os = "windows")]
    let dir = base
        .join("AppData")
        .join("Roaming")
        .join("Cybrium")
        .join("cyweb");
    #[cfg(not(target_os = "windows"))]
    let dir = base.join(".cybrium").join("cyweb");
    Ok(dir.join("license.json"))
}

pub fn load_license() -> Result<Option<LicenseState>> {
    let path = license_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let body =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let state: LicenseState =
        serde_json::from_str(&body).with_context(|| format!("parsing {}", path.display()))?;
    Ok(Some(state))
}

pub fn store_license(state: &LicenseState) -> Result<PathBuf> {
    let path = license_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let body = serde_json::to_string_pretty(state)?;
    std::fs::write(&path, body).with_context(|| format!("writing {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(path)
}

pub fn remove_license() -> Result<bool> {
    let path = license_path()?;
    if !path.exists() {
        return Ok(false);
    }
    std::fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
    Ok(true)
}

/// v0.11.x / Phase 1 — store the license key + current fingerprint
/// locally, with no server signature yet. Phase 2 (backend endpoint)
/// will replace this with a real POST + signed-token return.
pub fn activate_local(license_key: &str) -> Result<LicenseState> {
    let state = LicenseState {
        schema: 1,
        binary: "cyweb".into(),
        license_id: license_key.to_string(),
        fingerprint: fingerprint(),
        activated_at: chrono::Utc::now().to_rfc3339(),
        not_after: None,
        issuer: "local-phase-1".into(),
        server_signature: String::new(),
        server_pubkey_id: String::new(),
    };
    store_license(&state)?;
    Ok(state)
}

/// Re-read the current hardware fingerprint and compare against the
/// stored license. Returns Ok(true) when they match, Ok(false) when
/// they diverge (host has changed or license was copied between
/// machines), Err when no license is stored.
pub fn verify_binding() -> Result<bool> {
    let stored = load_license()?
        .ok_or_else(|| anyhow!("no license stored; run `cyweb license activate <key>` first"))?;
    let current = fingerprint();
    Ok(stored.fingerprint.fingerprint == current.fingerprint)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_deterministic_within_a_run() {
        let a = fingerprint();
        let b = fingerprint();
        assert_eq!(a.fingerprint, b.fingerprint);
        assert_eq!(a.algorithm, "sha256-v1");
        assert_eq!(a.fingerprint.len(), 64);
    }

    #[test]
    fn host_id_source_is_one_of_known_values() {
        let fp = fingerprint();
        assert!(matches!(
            fp.host_id_source.as_str(),
            "tpm_ek" | "platform_uuid" | "machine_id" | "none"
        ));
    }
}
