//! Playbook configuration for multi-step tool chains.

use serde::{Deserialize, Serialize};

// ── Playbooks ──────────────────────────────────────────────────────────────────

/// Playbook configuration for multi-step tool chains.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PlaybooksConfig {
    /// Enable playbook engine.
    pub enabled: bool,
    /// Directories to load playbook definitions from.
    pub directories: Vec<String>,
}

impl Default for PlaybooksConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            directories: vec!["playbooks".to_string()],
        }
    }
}
