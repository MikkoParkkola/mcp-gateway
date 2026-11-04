// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The transparency log's resolved runtime configuration, with a `Debug`
//! that redacts its shared secret (moved from `transparency_log.rs`).

use crate::security::audit_rotation_config::RotationConfig;

/// Runtime configuration for the transparency log.
///
/// Serialisation lives in `src/config/features/security.rs` alongside the
/// other security configs; this struct is the "resolved" in-memory copy.
#[derive(Clone)]
pub struct TransparencyLogConfig {
    /// Enable the transparency log.  Default: `false` (opt-in).
    pub enabled: bool,
    /// Path to the NDJSON log file.  `~` is expanded at open time.
    pub path: String,
    /// Key identifier written into `key_id` when signing is active.
    pub key_id: String,
    /// HMAC shared secret.  When empty, the `sig` / `key_id` fields are
    /// omitted from each entry (hash chain still provides tamper evidence).
    pub shared_secret: String,
    /// Segment size, retention and disk-full behaviour (D6).
    pub rotation: RotationConfig,
}

// Manual `Debug` that redacts the HMAC shared secret (CWE-532). A derived
// `Debug` would print the resolved signing secret verbatim into any trace or
// error context; only its presence is surfaced.
impl std::fmt::Debug for TransparencyLogConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransparencyLogConfig")
            .field("enabled", &self.enabled)
            .field("path", &self.path)
            .field("key_id", &self.key_id)
            .field("rotation", &self.rotation)
            .field(
                "shared_secret",
                &if self.shared_secret.is_empty() {
                    "<empty>"
                } else {
                    "<redacted>"
                },
            )
            .finish()
    }
}

impl Default for TransparencyLogConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: "~/.mcp-gateway/transparency/transparency.jsonl".to_string(),
            key_id: "default".to_string(),
            shared_secret: String::new(),
            rotation: RotationConfig::default(),
        }
    }
}

#[cfg(test)]
mod cwe532_debug_redaction {
    use super::*;

    const SENTINEL: &str = "SENTINEL_SECRET_a1b2c3";

    // The resolved in-memory TransparencyLogConfig::Debug must never surface
    // the HMAC shared secret.
    #[test]
    fn transparency_log_config_debug_redacts_shared_secret() {
        let cfg = TransparencyLogConfig {
            shared_secret: SENTINEL.to_string(),
            ..TransparencyLogConfig::default()
        };
        let dbg = format!("{cfg:?}");
        assert!(!dbg.contains(SENTINEL), "leaked shared_secret: {dbg}");
        assert!(
            dbg.contains("<redacted>"),
            "missing redaction marker: {dbg}"
        );
    }
}
