//! Checkpoint policy and state types (MIK-NEW.RUNTIME.3 — B3-DURABLE).
//!
//! Defines the checkpoint cadence (30-second periodic + explicit events)
//! and sandbox restore handle used by the scheduler to resume tasks.

use serde::{Deserialize, Serialize};

use super::snapshot::SandboxCheckpoint;

/// Checkpoint cadence configuration.
///
/// AC.3: "Checkpoint cadence: every 30 seconds during active task plus on
/// explicit symphony+ checkpoint event."
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckpointCadence {
    /// Periodic checkpoint interval in seconds (default 30).
    pub interval_secs: u64,
    /// Whether explicit (event-driven) checkpoints are enabled.
    pub explicit_enabled: bool,
}

impl Default for CheckpointCadence {
    fn default() -> Self {
        Self {
            interval_secs: super::DEFAULT_CHECKPOINT_INTERVAL_SECS,
            explicit_enabled: true,
        }
    }
}

/// The current checkpoint state of a sandbox task.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CheckpointState {
    /// No checkpoint exists yet — task starts from zero.
    Empty,
    /// A checkpoint is available for resume.
    Checkpointed(SandboxCheckpoint),
    /// The last checkpoint attempt failed but the task continues.
    Degraded {
        /// The last successful checkpoint, if any.
        last_successful: Option<SandboxCheckpoint>,
        /// Error from the failed checkpoint attempt.
        last_error: String,
    },
}

impl CheckpointState {
    /// Whether the task can resume from a checkpoint.
    #[must_use]
    pub fn can_resume(&self) -> bool {
        matches!(self, Self::Checkpointed(_))
    }

    /// The available checkpoint for resume, if any.
    #[must_use]
    pub fn checkpoint(&self) -> Option<&SandboxCheckpoint> {
        match self {
            Self::Checkpointed(c) => Some(c),
            Self::Degraded {
                last_successful: Some(c),
                ..
            } => Some(c),
            _ => None,
        }
    }
}

/// Handle returned to the scheduler on sandbox restore.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SandboxRestoreHandle {
    /// The sandbox identifier.
    pub sandbox_id: String,
    /// Task UUID being resumed.
    pub task_uuid: String,
    /// Checkpoint state at restore time.
    pub state: CheckpointState,
    /// Sub-steps already completed (skip these on resume).
    pub completed_steps: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox_checkpoint::snapshot::{CheckpointResult, SandboxCheckpoint};

    #[test]
    fn default_cadence_is_30_seconds_with_explicit_enabled() {
        let cadence = CheckpointCadence::default();
        assert_eq!(cadence.interval_secs, 30);
        assert!(cadence.explicit_enabled);
    }

    #[test]
    fn empty_state_cannot_resume() {
        let state = CheckpointState::Empty;
        assert!(!state.can_resume());
        assert!(state.checkpoint().is_none());
    }

    #[test]
    fn checkpointed_state_can_resume() {
        let checkpoint = SandboxCheckpoint {
            result: CheckpointResult {
                sandbox_id: "sb".into(),
                substrate: "gvisor".into(),
                sequence: 1,
                timestamp: "2026-06-12T00:00:00Z".into(),
                artifact_path: "/tmp/ckpt".into(),
                integrity_hash: "abc".into(),
                success: true,
                error: None,
            },
            completed_steps: vec!["step1".into()],
            task_uuid: "task-1".into(),
        };
        let state = CheckpointState::Checkpointed(checkpoint);
        assert!(state.can_resume());
        assert!(state.checkpoint().is_some());
    }

    #[test]
    fn degraded_with_last_successful_provides_checkpoint() {
        let checkpoint = SandboxCheckpoint {
            result: CheckpointResult {
                sandbox_id: "sb".into(),
                substrate: "gvisor".into(),
                sequence: 1,
                timestamp: "t".into(),
                artifact_path: "/tmp/ckpt".into(),
                integrity_hash: "abc".into(),
                success: true,
                error: None,
            },
            completed_steps: vec![],
            task_uuid: "task-1".into(),
        };
        let state = CheckpointState::Degraded {
            last_successful: Some(checkpoint),
            last_error: "checkpoint write failed".into(),
        };
        assert!(!state.can_resume()); // Degraded does not permit resume
        assert!(state.checkpoint().is_some()); // but provides the last good checkpoint
    }

    #[test]
    fn degraded_without_last_successful_is_empty() {
        let state = CheckpointState::Degraded {
            last_successful: None,
            last_error: "first checkpoint failed".into(),
        };
        assert!(!state.can_resume());
        assert!(state.checkpoint().is_none());
    }
}
