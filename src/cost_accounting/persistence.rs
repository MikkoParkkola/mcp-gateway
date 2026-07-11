// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Cost state persistence.
//!
//! Saves/loads a `PersistedCosts` snapshot to `~/.mcp-gateway/costs.json`.
//! Consistent with the existing `usage.json` and `transitions.json` pattern.

use std::collections::HashMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

// ── PersistedCosts ────────────────────────────────────────────────────────────

/// All-time cumulative cost data persisted across restarts.
#[cfg(feature = "cost-governance")]
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct PersistedCosts {
    /// Unix timestamp (seconds) of the last save.
    pub saved_at: u64,
    /// Per-tool cumulative totals (for historical display in the UI).
    pub tool_totals: HashMap<String, ToolTotal>,
    /// Per-API-key cumulative cost totals.
    pub key_totals: HashMap<String, f64>,
}

/// Cumulative cost data for a single tool (all-time).
#[cfg(feature = "cost-governance")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolTotal {
    /// Total invocations recorded.
    pub call_count: u64,
    /// Total cost in USD (all-time).
    pub total_cost_usd: f64,
    /// Average cost per call (updated on each save).
    pub avg_cost_usd: f64,
}

#[cfg(feature = "cost-governance")]
impl ToolTotal {
    /// Merge an additional invocation into this total.
    pub fn add_invocation(&mut self, cost_usd: f64) {
        self.call_count += 1;
        self.total_cost_usd += cost_usd;
        if self.call_count > 0 {
            #[allow(clippy::cast_precision_loss)]
            let count = self.call_count as f64;
            self.avg_cost_usd = self.total_cost_usd / count;
        }
    }
}

// ── I/O ───────────────────────────────────────────────────────────────────────

/// Save cost state to disk at `path`.
///
/// Creates parent directories if they do not exist.
///
/// # Errors
///
/// Returns an error if the directory cannot be created or the file cannot
/// be written.
#[cfg(feature = "cost-governance")]
pub fn save(path: &Path, costs: &PersistedCosts) -> crate::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| crate::Error::Config(format!("Failed to create cost dir: {e}")))?;
    }
    let json = serde_json::to_string_pretty(costs)
        .map_err(|e| crate::Error::Config(format!("Failed to serialize costs: {e}")))?;
    std::fs::write(path, json)
        .map_err(|e| crate::Error::Config(format!("Failed to write costs: {e}")))?;
    tracing::info!(path = %path.display(), "Saved cost data");
    Ok(())
}

/// Load cost state from `path`.
///
/// Returns `PersistedCosts::default()` when the file does not exist (first
/// run after feature is enabled).
///
/// # Errors
///
/// Returns an error if the file exists but cannot be parsed as valid JSON.
#[cfg(feature = "cost-governance")]
pub fn load(path: &Path) -> crate::Result<PersistedCosts> {
    if !path.exists() {
        return Ok(PersistedCosts::default());
    }
    let json = std::fs::read_to_string(path)
        .map_err(|e| crate::Error::Config(format!("Failed to read costs: {e}")))?;
    let mut costs: PersistedCosts = serde_json::from_str(&json)
        .map_err(|e| crate::Error::Config(format!("Failed to parse costs.json: {e}")))?;
    // Recompute averages defensively (handles files written by older versions)
    for total in costs.tool_totals.values_mut() {
        if total.call_count > 0 {
            #[allow(clippy::cast_precision_loss)]
            let count = total.call_count as f64;
            total.avg_cost_usd = total.total_cost_usd / count;
        }
    }
    tracing::info!(
        path = %path.display(),
        tools = costs.tool_totals.len(),
        "Loaded cost data"
    );
    Ok(costs)
}

/// Return the current Unix timestamp in seconds (for `saved_at`).
#[cfg(feature = "cost-governance")]
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persist_save_and_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("costs.json");

        let mut costs = PersistedCosts {
            saved_at: 1_700_000_000,
            tool_totals: HashMap::new(),
            key_totals: HashMap::new(),
        };
        costs.tool_totals.insert(
            "tavily_search".to_string(),
            ToolTotal {
                call_count: 10,
                total_cost_usd: 0.10,
                avg_cost_usd: 0.01,
            },
        );
        costs.key_totals.insert("dev_key".to_string(), 2.50);

        save(&path, &costs).unwrap();
        let loaded = load(&path).unwrap();

        assert_eq!(loaded.saved_at, 1_700_000_000);
        assert_eq!(loaded.tool_totals.len(), 1);
        let tool = loaded.tool_totals.get("tavily_search").unwrap();
        assert_eq!(tool.call_count, 10);
        assert!((tool.total_cost_usd - 0.10).abs() < 1e-9);
        assert!((loaded.key_totals["dev_key"] - 2.50).abs() < 1e-9);
    }

    #[test]
    fn persist_load_missing_file_returns_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonexistent.json");
        let costs = load(&path).unwrap();
        assert_eq!(costs.saved_at, 0);
        assert!(costs.tool_totals.is_empty());
    }

    #[test]
    fn persist_load_corrupt_file_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("costs.json");
        std::fs::write(&path, b"not valid json {{{").unwrap();
        let result = load(&path);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("parse") || msg.contains("costs"),
            "Error should mention parsing: {msg}"
        );
    }

    #[test]
    fn tool_total_add_invocation_updates_average() {
        let mut t = ToolTotal {
            call_count: 0,
            total_cost_usd: 0.0,
            avg_cost_usd: 0.0,
        };
        t.add_invocation(0.01);
        t.add_invocation(0.03);
        assert_eq!(t.call_count, 2);
        assert!((t.total_cost_usd - 0.04).abs() < 1e-9);
        assert!((t.avg_cost_usd - 0.02).abs() < 1e-9);
    }
}
