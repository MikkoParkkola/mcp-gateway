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

/// Today's spend (UTC) as of `saved_at`, persisted so a restart keeps the
/// daily budgets. Reloaded only on the same UTC day it was saved.
#[cfg(feature = "cost-governance")]
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct PersistedCosts {
    /// Unix timestamp (seconds) of the last save.
    pub saved_at: u64,
    /// Per-tool spend for the day of `saved_at`.
    pub tool_totals: HashMap<String, ToolTotal>,
    /// Per-API-key spend for the day of `saved_at`.
    pub key_totals: HashMap<String, f64>,
    /// Spend of unbudgeted tools past the per-tool day map's cap (MIK-8015).
    #[serde(default)]
    pub tool_overflow_usd: f64,
    /// Spend of unbudgeted keys past the per-key day map's cap (MIK-8015).
    #[serde(default)]
    pub key_overflow_usd: f64,
}

/// Spend for a single tool on the day of `saved_at`.
#[cfg(feature = "cost-governance")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolTotal {
    /// Total invocations recorded.
    pub call_count: u64,
    /// Spend in USD on the day of `saved_at`.
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
    // Numbers each save's scratch file within this process (see below).
    static SAVES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| crate::Error::Config(format!("Failed to create cost dir: {e}")))?;
    }
    let json = serde_json::to_string_pretty(costs)
        .map_err(|e| crate::Error::Config(format!("Failed to serialize costs: {e}")))?;
    // Write then rename, so a crash mid-write leaves the previous file, not a
    // truncated one that fails to parse and restarts the budgets at zero. The
    // scratch name is unique per save: gateways sharing a data directory (and
    // one gateway's periodic and final saves) must never write one file.
    // A name already taken (a file left by a killed process whose id this
    // one reuses) is skipped, never reused or removed: it is not ours.
    let (tmp, mut file) = loop {
        let n = SAVES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let tmp = path.with_extension(format!("json.{}.{n}.tmp", std::process::id()));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
        {
            Ok(file) => break (tmp, file),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(crate::Error::Config(format!("Failed to save costs: {e}"))),
        }
    };
    // Synced and closed before the rename: the renamed file holds the whole
    // snapshot after a power loss, and Windows renames only a closed file.
    let written =
        std::io::Write::write_all(&mut file, json.as_bytes()).and_then(|()| file.sync_all());
    drop(file);
    let saved = written.and_then(|()| std::fs::rename(&tmp, path));
    if let Err(e) = saved {
        // This save created the scratch file, so it is ours to remove.
        let _ = std::fs::remove_file(&tmp);
        return Err(crate::Error::Config(format!("Failed to save costs: {e}")));
    }
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
            ..PersistedCosts::default()
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
        assert!(
            !path.with_extension("json.tmp").exists(),
            "the temp file is renamed away"
        );
        let loaded = load(&path).unwrap();

        assert_eq!(loaded.saved_at, 1_700_000_000);
        assert_eq!(loaded.tool_totals.len(), 1);
        let tool = loaded.tool_totals.get("tavily_search").unwrap();
        assert_eq!(tool.call_count, 10);
        assert!((tool.total_cost_usd - 0.10).abs() < 1e-9);
        assert!((loaded.key_totals["dev_key"] - 2.50).abs() < 1e-9);
    }

    /// Two writers saving one path at once each finish with one whole
    /// snapshot on disk: no save fails and nothing is left half-written.
    /// A shared scratch name lets one writer rename the other's file away
    /// (a failed save) or interleave into it (a torn file).
    #[test]
    fn concurrent_saves_use_distinct_scratch_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = std::sync::Arc::new(dir.path().join("costs.json"));
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let writers: Vec<_> = [1_u64, 2]
            .into_iter()
            .map(|writer| {
                let (path, barrier) = (path.clone(), barrier.clone());
                std::thread::spawn(move || {
                    let mut costs = PersistedCosts {
                        saved_at: writer,
                        ..PersistedCosts::default()
                    };
                    // Enough entries that a write is not one syscall.
                    for i in 0..200 {
                        costs.key_totals.insert(format!("key-{writer}-{i}"), 0.5);
                    }
                    barrier.wait();
                    (0..200)
                        .map(|_| save(&path, &costs).map_err(|e| e.to_string()))
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        for writer in writers {
            for result in writer.join().expect("writer thread") {
                result.expect("a concurrent save failed");
            }
        }
        let loaded = load(&path).expect("the file on disk is one whole snapshot");
        assert!(
            loaded.saved_at == 1 || loaded.saved_at == 2,
            "the file is neither writer's snapshot: saved_at {}",
            loaded.saved_at
        );
        let owner = format!("key-{}-", loaded.saved_at);
        assert!(
            loaded.key_totals.len() == 200
                && loaded.key_totals.keys().all(|k| k.starts_with(&owner)),
            "the file mixes the two writers' snapshots"
        );
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|name| name != "costs.json")
            .collect();
        assert!(
            leftovers.is_empty(),
            "scratch files left behind: {leftovers:?}"
        );
    }

    /// A save that cannot replace the destination reports the error and
    /// leaves no scratch file behind in the user's data directory.
    #[test]
    fn a_failed_rename_removes_its_scratch_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("costs.json");
        // A non-empty directory where the file should go: the rename fails.
        std::fs::create_dir_all(path.join("occupied")).unwrap();
        assert!(save(&path, &PersistedCosts::default()).is_err());
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["costs.json".to_string()], "scratch left behind");
    }

    /// A scratch name already on disk (left by a killed process whose id this
    /// one reuses) is skipped: the save still succeeds and the leftover is
    /// neither overwritten nor removed.
    #[test]
    fn a_leftover_scratch_file_is_neither_reused_nor_deleted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("costs.json");
        // Every name this process can reach before the test's save, with
        // room for the saves other tests make in parallel.
        let leftovers: Vec<_> = (0..5_000)
            .map(|n| path.with_extension(format!("json.{}.{n}.tmp", std::process::id())))
            .collect();
        for leftover in &leftovers {
            std::fs::write(leftover, b"left by an earlier process").unwrap();
        }
        save(&path, &PersistedCosts::default()).expect("a free scratch name is used instead");
        assert!(
            leftovers
                .iter()
                .all(|l| std::fs::read(l).is_ok_and(|b| b == b"left by an earlier process")),
            "a leftover scratch file was overwritten or removed"
        );
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

    #[test]
    fn a_file_saved_before_the_overflow_fields_still_loads() {
        // MIK-8015: the overflow totals default to zero for an older file.
        let old = r#"{"saved_at":1700000000,"tool_totals":{},"key_totals":{"k":1.5}}"#;
        let costs: PersistedCosts = serde_json::from_str(old).expect("older file loads");
        assert!((costs.key_totals["k"] - 1.5).abs() < 1e-9);
        assert!(costs.tool_overflow_usd.abs() < 1e-12);
        assert!(costs.key_overflow_usd.abs() < 1e-12);
    }
}
