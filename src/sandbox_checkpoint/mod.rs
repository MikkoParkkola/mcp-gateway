//! Sandbox checkpoint/resume tied to symphony+ task lifecycle (MIK-NEW.RUNTIME.3, B3-DURABLE).
//!
//! # Checkpoint primitives
//!
//! - **gVisor**: `runsc checkpoint` (Linux)
//! - **Apple containerization**: VM snapshot capability (macOS)
//!
//! Both are wired to the symphony+ scheduler state machine. Resume after host
//! restart picks up at the last checkpoint without re-running completed
//! sub-steps.
//!
//! # Checkpoint cadence
//!
//! Every 30 seconds during active task plus on explicit symphony+ checkpoint
//! event.
//!
//! # Failure mode
//!
//! Checkpoint failure logs warning but task continues; replay-from-zero
//! fallback documented.

pub mod policy;
pub mod scheduler_bridge;
pub mod snapshot;

pub use policy::{CheckpointCadence, CheckpointState, SandboxRestoreHandle};
pub use scheduler_bridge::SchedulerCheckpointBridge;
pub use snapshot::{
    AppleCheckpoint, CheckpointIntegrity, CheckpointResult, GVisorCheckpoint, SandboxCheckpoint,
    SandboxCheckpointer,
};

/// Default checkpoint interval in seconds (AC.3: every 30 seconds).
pub const DEFAULT_CHECKPOINT_INTERVAL_SECS: u64 = 30;

/// Default maximum snapshots to retain.
pub const DEFAULT_MAX_SNAPSHOTS: usize = 5;

/// Label for the default checkpoint directory.
pub const DEFAULT_CHECKPOINT_DIR: &str = "/var/lib/symphony/checkpoints";
