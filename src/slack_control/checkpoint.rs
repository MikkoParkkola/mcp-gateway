//! Instruction checkpoint/resume for restart durability (B3-DURABLE).
//!
//! In-flight instructions are checkpointed to a JSONL file so they can be
//! resumed after a restart. The launchd KeepAlive mechanism ensures the
//! listener process restarts automatically.

use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use chrono::Utc;
use serde::{Deserialize, Serialize};

/// State of a checkpointed instruction.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointState {
    /// Instruction received, not yet dispatched.
    Pending,
    /// Instruction dispatched to agent, awaiting result.
    Dispatched,
    /// Instruction completed successfully.
    Completed,
    /// Instruction failed.
    Failed,
}

/// A checkpointed instruction entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointEntry {
    /// Unique attribution ID linking to the audit log.
    pub attribution_id: String,
    /// ISO 8601 timestamp when the instruction was checkpointed.
    pub timestamp: String,
    /// Slack user ID.
    pub user_id: String,
    /// Slack channel ID.
    pub channel: String,
    /// Slack message timestamp.
    pub slack_ts: String,
    /// The instruction text.
    pub instruction: String,
    /// Current state of the instruction.
    pub state: CheckpointState,
    /// Optional result text (populated when completed).
    pub result: Option<String>,
}

/// Checkpoint store for in-flight instructions.
pub struct CheckpointStore {
    inner: Mutex<CheckpointStoreInner>,
}

struct CheckpointStoreInner {
    writer: BufWriter<File>,
    entries: Vec<CheckpointEntry>,
}

impl CheckpointStore {
    /// Open or create the checkpoint file, recovering any pending entries.
    ///
    /// # Errors
    ///
    /// Returns `io::Error` if the file cannot be opened.
    pub fn open(path: &Path) -> io::Result<Self> {
        let expanded = expand_tilde(path);

        if let Some(parent) = expanded.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }

        let entries = if expanded.exists() {
            recover_checkpoints(&expanded)?
        } else {
            Vec::new()
        };

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&expanded)?;

        Ok(Self {
            inner: Mutex::new(CheckpointStoreInner {
                writer: BufWriter::new(file),
                entries,
            }),
        })
    }

    /// Checkpoint a new pending instruction.
    pub fn checkpoint_pending(
        &self,
        attribution_id: &str,
        user_id: &str,
        channel: &str,
        slack_ts: &str,
        instruction: &str,
    ) -> io::Result<()> {
        let entry = CheckpointEntry {
            attribution_id: attribution_id.to_string(),
            timestamp: Utc::now().to_rfc3339(),
            user_id: user_id.to_string(),
            channel: channel.to_string(),
            slack_ts: slack_ts.to_string(),
            instruction: instruction.to_string(),
            state: CheckpointState::Pending,
            result: None,
        };
        self.write_entry(&entry)
    }

    /// Mark an instruction as dispatched.
    pub fn mark_dispatched(&self, attribution_id: &str) -> io::Result<()> {
        self.update_state(attribution_id, CheckpointState::Dispatched, None)
    }

    /// Mark an instruction as completed with an optional result.
    pub fn mark_completed(&self, attribution_id: &str, result: Option<String>) -> io::Result<()> {
        self.update_state(attribution_id, CheckpointState::Completed, result)
    }

    /// Mark an instruction as failed.
    pub fn mark_failed(&self, attribution_id: &str) -> io::Result<()> {
        self.update_state(attribution_id, CheckpointState::Failed, None)
    }

    /// Return all pending or dispatched (in-flight) entries.
    pub fn pending_entries(&self) -> Vec<CheckpointEntry> {
        let inner = self.inner.lock().expect("checkpoint mutex poisoned");
        inner
            .entries
            .iter()
            .filter(|e| matches!(e.state, CheckpointState::Pending | CheckpointState::Dispatched))
            .cloned()
            .collect()
    }

    fn write_entry(&self, entry: &CheckpointEntry) -> io::Result<()> {
        let mut inner = self.inner.lock().expect("checkpoint mutex poisoned");
        let line = serde_json::to_string(entry).map_err(io::Error::other)?;
        writeln!(inner.writer, "{line}")?;
        inner.writer.flush()?;
        inner.entries.push(entry.clone());
        Ok(())
    }

    fn update_state(
        &self,
        attribution_id: &str,
        state: CheckpointState,
        result: Option<String>,
    ) -> io::Result<()> {
        let mut inner = self.inner.lock().expect("checkpoint mutex poisoned");

        for entry in &mut inner.entries {
            if entry.attribution_id == attribution_id {
                entry.state = state.clone();
                if result.is_some() {
                    entry.result.clone_from(&result);
                }
                entry.timestamp = Utc::now().to_rfc3339();
                break;
            }
        }

        let updated = inner
            .entries
            .iter()
            .find(|e| e.attribution_id == attribution_id)
            .cloned();

        if let Some(entry) = updated {
            let line = serde_json::to_string(&entry).map_err(io::Error::other)?;
            writeln!(inner.writer, "{line}")?;
            inner.writer.flush()?;
        }

        Ok(())
    }
}

fn recover_checkpoints(path: &Path) -> io::Result<Vec<CheckpointEntry>> {
    let content = std::fs::read_to_string(path)?;
    let mut entries: Vec<CheckpointEntry> = Vec::new();
    let mut latest_by_id: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let entry: CheckpointEntry = match serde_json::from_str(trimmed) {
            Ok(e) => e,
            Err(_) => continue,
        };

        if let Some(&idx) = latest_by_id.get(&entry.attribution_id) {
            entries[idx] = entry.clone();
        } else {
            let idx = entries.len();
            latest_by_id.insert(entry.attribution_id.clone(), idx);
            entries.push(entry);
        }
    }

    Ok(entries)
}

fn expand_tilde(path: &Path) -> PathBuf {
    let s = path.to_string_lossy();
    if let Some(rest) = s.strip_prefix("~/")
        && let Some(home) = dirs::home_dir()
    {
        return home.join(rest);
    }
    path.to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn checkpoint_and_recover() {
        let tmp = NamedTempFile::new().unwrap();
        {
            let store = CheckpointStore::open(tmp.path()).unwrap();
            store
                .checkpoint_pending(
                    "attr-1",
                    "U123",
                    "C456",
                    "1234567890.123456",
                    "what is 2+2",
                )
                .unwrap();
            store.mark_dispatched("attr-1").unwrap();
        }

        let store2 = CheckpointStore::open(tmp.path()).unwrap();
        let pending = store2.pending_entries();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].attribution_id, "attr-1");
        assert_eq!(pending[0].state, CheckpointState::Dispatched);
    }

    #[test]
    fn completed_entries_not_pending() {
        let tmp = NamedTempFile::new().unwrap();
        let store = CheckpointStore::open(tmp.path()).unwrap();
        store
            .checkpoint_pending("attr-2", "U123", "C456", "ts1", "list issues")
            .unwrap();
        store.mark_completed("attr-2", Some("42 issues found".to_string())).unwrap();

        let pending = store.pending_entries();
        assert!(pending.is_empty());
    }
}
