//! Code Mode configuration — the search+execute pattern for minimal context usage.

use serde::{Deserialize, Serialize};

// ── Code Mode ──────────────────────────────────────────────────────────────────

/// Code Mode configuration — the search+execute pattern for minimal context usage.
///
/// When enabled, `tools/list` returns only two meta-tools (`gateway_search` and
/// `gateway_execute`) instead of the full meta-tool set.
///
/// # Example
///
/// ```yaml
/// code_mode:
///   enabled: true
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct CodeModeConfig {
    /// Enable Code Mode.
    pub enabled: bool,
}
