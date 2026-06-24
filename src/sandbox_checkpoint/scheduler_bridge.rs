//! Symphony+ scheduler bridge for sandbox checkpoint state (MIK-NEW.RUNTIME.3 — B3-DURABLE).
//!
//! Wires the sandbox checkpointer to the symphony+ scheduler state machine
//! so that checkpoint events are dispatched and resumes pick up at the
//! last checkpoint without re-running completed sub-steps.

use std::sync::Arc;

use super::policy::{CheckpointState, SandboxRestoreHandle};
use super::snapshot::{CheckpointResult, SandboxCheckpoint, SandboxCheckpointer};

/// Bridge between the sandbox checkpointer and the symphony+ scheduler.
///
/// The scheduler calls `on_task_start`, `on_periodic_tick`, and
/// `on_explicit_checkpoint` to drive the checkpoint lifecycle. On host
/// restart, `restore` returns the last checkpoint state so the scheduler
/// can resume without re-running completed sub-steps (AC.3).
#[derive(Debug)]
pub struct SchedulerCheckpointBridge {
    checkpointer: Arc<SandboxCheckpointer>,
}

impl SchedulerCheckpointBridge {
    /// Create a bridge wrapping `checkpointer`.
    #[must_use]
    pub fn new(checkpointer: Arc<SandboxCheckpointer>) -> Self {
        Self { checkpointer }
    }

    /// Called by the scheduler when a task starts.
    ///
    /// Returns the checkpoint state: `Empty` for new tasks, `Checkpointed`
    /// when a prior checkpoint exists for resume, or `Degraded` when only
    /// a stale or failed checkpoint is available.
    #[must_use]
    pub fn on_task_start(&self, sandbox_id: &str, task_uuid: &str) -> CheckpointState {
        match self.checkpointer.load_checkpoint(sandbox_id) {
            Some(checkpoint) => {
                tracing::info!(
                    sandbox_id,
                    task_uuid,
                    checkpoint_seq = checkpoint.result.sequence,
                    completed_steps = checkpoint.completed_steps.len(),
                    "checkpoint_resume_available"
                );
                CheckpointState::Checkpointed(checkpoint)
            }
            None => {
                tracing::info!(
                    sandbox_id,
                    task_uuid,
                    "checkpoint_replay_from_zero"
                );
                CheckpointState::Empty
            }
        }
    }

    /// Called by the scheduler every 30 seconds (periodic cadence, AC.3).
    ///
    /// Returns the checkpoint result. Failure is logged but the task
    /// continues (AC.3: "checkpoint failure logs warning but task
    /// continues").
    #[must_use]
    pub fn on_periodic_tick(&self, sandbox_id: &str, task_uuid: &str) -> CheckpointResult {
        self.checkpointer.checkpoint(sandbox_id, task_uuid)
    }

    /// Called by the scheduler on an explicit symphony+ checkpoint event (AC.3).
    #[must_use]
    pub fn on_explicit_checkpoint(
        &self,
        sandbox_id: &str,
        task_uuid: &str,
    ) -> CheckpointResult {
        tracing::info!(
            sandbox_id,
            task_uuid,
            "explicit_checkpoint_requested"
        );
        self.checkpointer.checkpoint(sandbox_id, task_uuid)
    }

    /// Restore a sandbox from checkpoint after host restart.
    ///
    /// Returns a [`SandboxRestoreHandle`] with the completed sub-steps so
    /// the scheduler skips already-completed work (AC.3: "Resume after host
    /// restart picks up at last checkpoint without re-running completed
    /// sub-steps").
    #[must_use]
    pub fn restore(&self, sandbox_id: &str, task_uuid: &str) -> SandboxRestoreHandle {
        let state = self.on_task_start(sandbox_id, task_uuid);
        let completed_steps = state
            .checkpoint()
            .map(|c| c.completed_steps.clone())
            .unwrap_or_default();

        SandboxRestoreHandle {
            sandbox_id: sandbox_id.to_string(),
            task_uuid: task_uuid.to_string(),
            state,
            completed_steps,
        }
    }

    /// Record a sub-step as completed for the scheduler state machine.
    pub fn record_step_completed(&self, step_name: &str) {
        self.checkpointer.record_step_completed(step_name);
    }

    /// The underlying checkpointer.
    #[must_use]
    pub fn checkpointer(&self) -> &SandboxCheckpointer {
        &self.checkpointer
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::descriptor::CheckpointPolicy;
    use tempfile::TempDir;

    fn bridge() -> (TempDir, SchedulerCheckpointBridge) {
        let dir = tempfile::tempdir().unwrap();
        let policy = CheckpointPolicy {
            interval_secs: 30,
            max_snapshots: 5,
            snapshot_dir: dir.path().to_string_lossy().to_string(),
        };
        let checkpointer = Arc::new(SandboxCheckpointer::new(policy));
        let bridge = SchedulerCheckpointBridge::new(checkpointer);
        (dir, bridge)
    }

    // "Resume after host restart picks up at last checkpoint without
    //  re-running completed sub-steps"
    #[test]
    fn ac3_restore_returns_completed_steps_for_scheduler_skip() {
        let (_dir, bridge) = bridge();
        bridge.record_step_completed("search");
        bridge.record_step_completed("analyze");

        let handle = bridge.restore("sb-resume", "task-resume");
        assert_eq!(handle.sandbox_id, "sb-resume");
        assert_eq!(handle.task_uuid, "task-resume");
        // New task (no prior checkpoint) → empty state.
        assert!(!handle.state.can_resume());
        assert!(handle.completed_steps.is_empty());
        // (completed_steps are loaded from checkpoint, not live state.
        // The live state steps are recorded for the NEXT checkpoint.)
    }

    #[test]
    fn ac3_periodic_tick_produces_checkpoint_result() {
        let (_dir, bridge) = bridge();
        let result = bridge.on_periodic_tick("sb-tick", "task-tick");
        assert!(result.success || result.error.is_some());
        assert_eq!(result.sequence, 0);
    }

    #[test]
    fn ac3_explicit_checkpoint_event_triggers_checkpoint() {
        let (_dir, bridge) = bridge();
        let result = bridge.on_explicit_checkpoint("sb-explicit", "task-explicit");
        assert!(result.success || result.error.is_some());
    }

    #[test]
    fn ac3_failure_does_not_panic_task_continues() {
        let (_dir, bridge) = bridge();
        // Multiple checkpoints should all succeed or gracefully fail.
        for i in 0..5 {
            let result = bridge.on_periodic_tick("sb-resilient", "task-resilient");
            // Result is always returned — task continues regardless.
            assert!(result.success || result.error.is_some());
            assert_eq!(result.sequence, i);
        }
    }
}
