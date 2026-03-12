//! Step-level checkpoint persistence using JSONL files.
//!
//! Each chain gets one file: `~/.mcp-gateway/chains/<chain_id>.jsonl`.
//! Every completed step appends one JSON line. On resume, the file is replayed
//! to reconstruct which steps are already done.
//!
//! # Format
//!
//! Each line is a [`ChainCheckpoint`] serialized as compact JSON.
//!
//! # Example
//!
//! ```rust,no_run
//! use mcp_gateway::chains::{ChainCheckpointStore, ChainCheckpoint};
//! use chrono::Utc;
//! use serde_json::json;
//!
//! async fn demo() -> mcp_gateway::Result<()> {
//!     let store = ChainCheckpointStore::new("/tmp/chains")?;
//!     store.append(&ChainCheckpoint {
//!         chain_id: "chain-001".into(),
//!         step_name: "search".into(),
//!         output: json!({"results": []}),
//!         attempts: 1,
//!         completed_at: Utc::now(),
//!         duration_ms: 42,
//!     }).await?;
//!     let checkpoints = store.load("chain-001").await?;
//!     assert_eq!(checkpoints.len(), 1);
//!     Ok(())
//! }
//! ```

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use tokio::fs::{self, OpenOptions};
use tokio::io::AsyncWriteExt;
use tracing::debug;

use crate::chains::types::ChainCheckpoint;
use crate::{Error, Result};

// ============================================================================
// ChainCheckpointStore
// ============================================================================

/// Persists and loads step checkpoints from JSONL files on disk.
#[derive(Clone)]
pub struct ChainCheckpointStore {
    dir: PathBuf,
}

impl ChainCheckpointStore {
    /// Create a store rooted at `dir`, creating it if absent.
    ///
    /// # Errors
    ///
    /// Returns `Error::Io` if the directory cannot be created.
    pub fn new(dir: impl AsRef<Path>) -> Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir)
            .map_err(Error::Io)?;
        Ok(Self { dir })
    }

    /// Default store path: `~/.mcp-gateway/chains/`.
    ///
    /// # Errors
    ///
    /// Returns `Error::Config` if the home directory cannot be determined.
    pub fn default_store() -> Result<Self> {
        let home = dirs::home_dir()
            .ok_or_else(|| Error::Config("Cannot determine home directory".into()))?;
        Self::new(home.join(".mcp-gateway").join("chains"))
    }

    /// Append a completed-step checkpoint to the chain's JSONL file.
    ///
    /// # Errors
    ///
    /// Returns `Error::Io` on filesystem failure.
    pub async fn append(&self, checkpoint: &ChainCheckpoint) -> Result<()> {
        let path = self.chain_path(&checkpoint.chain_id);
        let line = serde_json::to_string(checkpoint)
            .map_err(Error::Json)?;

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await
            .map_err(Error::Io)?;

        file.write_all(line.as_bytes()).await.map_err(Error::Io)?;
        file.write_all(b"\n").await.map_err(Error::Io)?;
        file.flush().await.map_err(Error::Io)?;

        debug!(chain_id = %checkpoint.chain_id, step = %checkpoint.step_name, "Checkpoint written");
        Ok(())
    }

    /// Load all checkpoints for a chain, returning them in append order.
    ///
    /// Returns an empty `Vec` if no checkpoint file exists yet.
    ///
    /// # Errors
    ///
    /// Returns `Error::Io` on read failure (parse errors are skipped with a warning).
    pub async fn load(&self, chain_id: &str) -> Result<Vec<ChainCheckpoint>> {
        let path = self.chain_path(chain_id);

        if !path.exists() {
            return Ok(Vec::new());
        }

        let content = fs::read_to_string(&path).await.map_err(Error::Io)?;
        let checkpoints = parse_jsonl(&content, chain_id);
        debug!(chain_id, count = checkpoints.len(), "Loaded checkpoints");
        Ok(checkpoints)
    }

    /// Build a map of `step_name → checkpoint` for quick lookup.
    ///
    /// The **last** checkpoint wins when a step appears more than once
    /// (idempotent re-runs).
    ///
    /// # Errors
    ///
    /// Propagates errors from [`Self::load`].
    pub async fn load_map(&self, chain_id: &str) -> Result<HashMap<String, ChainCheckpoint>> {
        let checkpoints = self.load(chain_id).await?;
        let map = checkpoints
            .into_iter()
            .map(|c| (c.step_name.clone(), c))
            .collect();
        Ok(map)
    }

    /// Delete the checkpoint file for a chain (used after successful completion
    /// or explicit pruning).
    ///
    /// # Errors
    ///
    /// Returns `Error::Io` if the file exists but cannot be removed.
    pub async fn delete(&self, chain_id: &str) -> Result<()> {
        let path = self.chain_path(chain_id);
        if path.exists() {
            fs::remove_file(&path).await.map_err(Error::Io)?;
            debug!(chain_id, "Checkpoint file deleted");
        }
        Ok(())
    }

    /// List all chain IDs that have checkpoint files in this store.
    ///
    /// # Errors
    ///
    /// Returns `Error::Io` if the directory cannot be read.
    pub async fn list_chain_ids(&self) -> Result<Vec<String>> {
        let mut ids = Vec::new();
        let mut entries = fs::read_dir(&self.dir).await.map_err(Error::Io)?;
        while let Some(entry) = entries.next_entry().await.map_err(Error::Io)? {
            let file_name = entry.file_name();
            let name = file_name.to_string_lossy();
            if let Some(id) = name.strip_suffix(".jsonl") {
                ids.push(id.to_owned());
            }
        }
        Ok(ids)
    }

    fn chain_path(&self, chain_id: &str) -> PathBuf {
        self.dir.join(format!("{chain_id}.jsonl"))
    }
}

// ============================================================================
// Internal helpers
// ============================================================================

/// Parse JSONL content, silently skipping malformed lines.
fn parse_jsonl(content: &str, chain_id: &str) -> Vec<ChainCheckpoint> {
    content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|line| {
            serde_json::from_str::<ChainCheckpoint>(line)
                .map_err(|e| {
                    tracing::warn!(chain_id, error = %e, "Skipping malformed checkpoint line");
                })
                .ok()
        })
        .collect()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use serde_json::{Value, json};
    use tempfile::TempDir;

    fn tmp_store() -> (TempDir, ChainCheckpointStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = ChainCheckpointStore::new(dir.path()).unwrap();
        (dir, store)
    }

    fn make_checkpoint(chain_id: &str, step: &str, output: Value) -> ChainCheckpoint {
        ChainCheckpoint {
            chain_id: chain_id.into(),
            step_name: step.into(),
            output,
            attempts: 1,
            completed_at: Utc::now(),
            duration_ms: 10,
        }
    }

    #[tokio::test]
    async fn load_returns_empty_when_no_file() {
        // GIVEN no checkpoint file
        let (_dir, store) = tmp_store();
        // WHEN loading a chain with no prior checkpoints
        let result = store.load("nonexistent-chain").await.unwrap();
        // THEN an empty vec is returned
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn append_and_load_roundtrip() {
        // GIVEN a checkpoint store
        let (_dir, store) = tmp_store();
        let cp = make_checkpoint("chain-1", "search", json!({"results": ["a", "b"]}));
        // WHEN we append a checkpoint
        store.append(&cp).await.unwrap();
        // THEN loading retrieves it correctly
        let loaded = store.load("chain-1").await.unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].step_name, "search");
        assert_eq!(loaded[0].output, json!({"results": ["a", "b"]}));
    }

    #[tokio::test]
    async fn multiple_steps_preserved_in_order() {
        // GIVEN two steps appended sequentially
        let (_dir, store) = tmp_store();
        store.append(&make_checkpoint("chain-2", "step_a", json!(1))).await.unwrap();
        store.append(&make_checkpoint("chain-2", "step_b", json!(2))).await.unwrap();
        // WHEN loaded
        let loaded = store.load("chain-2").await.unwrap();
        // THEN both are present in order
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].step_name, "step_a");
        assert_eq!(loaded[1].step_name, "step_b");
    }

    #[tokio::test]
    async fn load_map_returns_keyed_by_step_name() {
        // GIVEN two steps for a chain
        let (_dir, store) = tmp_store();
        store.append(&make_checkpoint("chain-3", "alpha", json!("x"))).await.unwrap();
        store.append(&make_checkpoint("chain-3", "beta", json!("y"))).await.unwrap();
        // WHEN loaded as a map
        let map = store.load_map("chain-3").await.unwrap();
        // THEN both keys are present
        assert_eq!(map["alpha"].output, json!("x"));
        assert_eq!(map["beta"].output, json!("y"));
    }

    #[tokio::test]
    async fn delete_removes_file() {
        // GIVEN an existing checkpoint
        let (_dir, store) = tmp_store();
        store.append(&make_checkpoint("chain-4", "step", json!(null))).await.unwrap();
        // WHEN deleted
        store.delete("chain-4").await.unwrap();
        // THEN subsequent load is empty
        let loaded = store.load("chain-4").await.unwrap();
        assert!(loaded.is_empty());
    }

    #[tokio::test]
    async fn delete_nonexistent_is_ok() {
        // GIVEN no file exists
        let (_dir, store) = tmp_store();
        // WHEN deleting a chain that never existed
        let result = store.delete("no-such-chain").await;
        // THEN no error is returned
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn list_chain_ids_returns_all_chains() {
        // GIVEN two different chains with checkpoints
        let (_dir, store) = tmp_store();
        store.append(&make_checkpoint("alpha-chain", "s1", json!(1))).await.unwrap();
        store.append(&make_checkpoint("beta-chain", "s1", json!(2))).await.unwrap();
        // WHEN listing chain IDs
        let mut ids = store.list_chain_ids().await.unwrap();
        ids.sort();
        // THEN both chains appear
        assert_eq!(ids, vec!["alpha-chain", "beta-chain"]);
    }

    #[test]
    fn parse_jsonl_skips_malformed_lines() {
        // GIVEN a JSONL string with one bad line
        let content = "{\"chain_id\":\"c\",\"step_name\":\"s\",\"output\":null,\"attempts\":1,\
            \"completed_at\":\"2024-01-01T00:00:00Z\",\"duration_ms\":5}\nBAD LINE\n";
        // WHEN parsed
        let result = parse_jsonl(content, "c");
        // THEN only the valid line is returned
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].step_name, "s");
    }

    #[tokio::test]
    async fn load_map_last_write_wins_for_duplicate_steps() {
        // GIVEN a step that was checkpointed twice (idempotent retry)
        let (_dir, store) = tmp_store();
        store.append(&make_checkpoint("chain-5", "step", json!("first"))).await.unwrap();
        store.append(&make_checkpoint("chain-5", "step", json!("second"))).await.unwrap();
        // WHEN loaded as map
        let map = store.load_map("chain-5").await.unwrap();
        // THEN the last value wins
        assert_eq!(map["step"].output, json!("second"));
    }
}
