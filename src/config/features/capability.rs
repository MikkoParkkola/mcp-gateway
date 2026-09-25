// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Capability configuration for direct REST API integration.

use serde::{Deserialize, Serialize};

// ── Capability ─────────────────────────────────────────────────────────────────

/// Capability configuration for direct REST API integration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CapabilityConfig {
    /// Enable capability system.
    pub enabled: bool,
    /// Backend name for capabilities (shown in `gateway_list_servers`).
    pub name: String,
    /// Directories to load capability definitions from.
    pub directories: Vec<String>,
}

impl Default for CapabilityConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            name: "gateway".to_string(),
            // Only the bundled catalogue. Any other source is named in config.
            directories: vec!["capabilities".to_string()],
        }
    }
}
