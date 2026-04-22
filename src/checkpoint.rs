//! Checkpoint/resume — save scan state to disk and resume interrupted scans.

use crate::scanner::ScanResult;
use crate::signatures::Finding;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize, Deserialize)]
pub struct Checkpoint {
    pub target: String,
    pub completed_phases: Vec<String>,
    pub findings: Vec<Finding>,
    pub paths_checked: Vec<String>,
    pub requests_made: usize,
    pub started_at: String,
}

impl Checkpoint {
    pub fn new(target: &str) -> Self {
        Self {
            target: target.into(),
            completed_phases: Vec::new(),
            findings: Vec::new(),
            paths_checked: Vec::new(),
            requests_made: 0,
            started_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    pub fn path_for(target: &str) -> PathBuf {
        let sanitized = target
            .replace("https://", "")
            .replace("http://", "")
            .replace('/', "_")
            .replace(':', "_");
        let dir = dirs::home_dir()
            .map(|h| h.join(".cyweb/checkpoints"))
            .unwrap_or_else(|| PathBuf::from(".cyweb/checkpoints"));
        std::fs::create_dir_all(&dir).ok();
        dir.join(format!("{sanitized}.json"))
    }

    pub fn save(&self) -> Result<PathBuf, String> {
        let path = Self::path_for(&self.target);
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(&path, json).map_err(|e| e.to_string())?;
        Ok(path)
    }

    pub fn load(target: &str) -> Option<Self> {
        let path = Self::path_for(target);
        if !path.exists() {
            return None;
        }
        let content = std::fs::read_to_string(&path).ok()?;
        serde_json::from_str(&content).ok()
    }

    pub fn delete(target: &str) {
        let path = Self::path_for(target);
        std::fs::remove_file(path).ok();
    }

    pub fn phase_done(&self, phase: &str) -> bool {
        self.completed_phases.iter().any(|p| p == phase)
    }

    pub fn mark_phase(&mut self, phase: &str) {
        if !self.phase_done(phase) {
            self.completed_phases.push(phase.into());
        }
    }

    pub fn add_findings(&mut self, new_findings: &[Finding]) {
        self.findings.extend(new_findings.iter().cloned());
        self.save().ok();
    }
}
