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
            directories: {
                let mut dirs = vec!["capabilities".to_string()];
                if let Some(home) = std::env::var_os("HOME") {
                    let private_dir =
                        std::path::Path::new(&home).join("github/mcp-gateway-private/capabilities");
                    if private_dir.is_dir() {
                        dirs.push(private_dir.to_string_lossy().into_owned());
                    }
                }
                dirs
            },
        }
    }
}
