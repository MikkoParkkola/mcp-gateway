//! Structured observability for chain execution.
//!
//! [`ChainObservability`] emits structured tracing events for every
//! significant lifecycle event in a chain run: start, step complete,
//! step retry, step skip, chain complete, and chain fail.
//!
//! All events carry a consistent set of fields so they can be queried
//! as a structured log in any tracing backend (stdout JSON, Loki, etc.).
//!
//! # Example
//!
//! ```rust
//! use mcp_gateway::chains::ChainObservability;
//!
//! let obs = ChainObservability::new("my-chain-007");
//! obs.chain_started(3);
//! obs.step_started("search", 1, 3);
//! obs.step_completed("search", 1, 1, 42);
//! obs.chain_completed(3, 0, 0, 250);
//! ```

use tracing::{debug, info, warn};

// ============================================================================
// ChainObservability
// ============================================================================

/// Emits structured tracing events for a single chain execution.
///
/// Create one instance per chain run and call the appropriate method at
/// each lifecycle boundary.
#[derive(Debug, Clone)]
pub struct ChainObservability {
    chain_id: String,
}

impl ChainObservability {
    /// Create an observer bound to the given chain ID.
    #[must_use]
    pub fn new(chain_id: impl Into<String>) -> Self {
        Self {
            chain_id: chain_id.into(),
        }
    }

    /// Emit an event when a chain begins execution.
    pub fn chain_started(&self, total_steps: usize) {
        info!(
            chain_id = %self.chain_id,
            total_steps,
            event = "chain_started",
            "Chain execution started"
        );
    }

    /// Emit an event when a chain resumes from a prior checkpoint.
    pub fn chain_resumed(&self, resumed_steps: usize, remaining_steps: usize) {
        info!(
            chain_id = %self.chain_id,
            resumed_steps,
            remaining_steps,
            event = "chain_resumed",
            "Chain resumed from checkpoint"
        );
    }

    /// Emit an event when a step begins.
    pub fn step_started(&self, step_name: &str, step_index: usize, total_steps: usize) {
        debug!(
            chain_id = %self.chain_id,
            step = step_name,
            step_index,
            total_steps,
            event = "step_started",
            "Step started"
        );
    }

    /// Emit an event when a step retries after a failure.
    pub fn step_retrying(&self, step_name: &str, attempt: u32, error: &str) {
        warn!(
            chain_id = %self.chain_id,
            step = step_name,
            attempt,
            error,
            event = "step_retrying",
            "Step retrying after failure"
        );
    }

    /// Emit an event when a step completes successfully.
    pub fn step_completed(
        &self,
        step_name: &str,
        step_index: usize,
        attempts: u32,
        duration_ms: u64,
    ) {
        info!(
            chain_id = %self.chain_id,
            step = step_name,
            step_index,
            attempts,
            duration_ms,
            event = "step_completed",
            "Step completed"
        );
    }

    /// Emit an event when an optional step is skipped after failure.
    pub fn step_skipped(&self, step_name: &str, reason: &str) {
        warn!(
            chain_id = %self.chain_id,
            step = step_name,
            reason,
            event = "step_skipped",
            "Step skipped (optional, failure tolerated)"
        );
    }

    /// Emit an event when a required step fails, aborting the chain.
    pub fn step_failed(&self, step_name: &str, attempts: u32, error: &str) {
        warn!(
            chain_id = %self.chain_id,
            step = step_name,
            attempts,
            error,
            event = "step_failed",
            "Step failed — chain aborted"
        );
    }

    /// Emit an event when a step is restored from a prior checkpoint.
    pub fn step_restored(&self, step_name: &str) {
        debug!(
            chain_id = %self.chain_id,
            step = step_name,
            event = "step_restored",
            "Step restored from checkpoint"
        );
    }

    /// Emit an event when the full chain completes successfully.
    pub fn chain_completed(
        &self,
        steps_done: usize,
        steps_skipped: usize,
        steps_resumed: usize,
        duration_ms: u64,
    ) {
        info!(
            chain_id = %self.chain_id,
            steps_done,
            steps_skipped,
            steps_resumed,
            duration_ms,
            event = "chain_completed",
            "Chain completed successfully"
        );
    }

    /// Emit an event when the chain fails (unrecoverable step failure).
    pub fn chain_failed(&self, failed_step: &str, duration_ms: u64) {
        warn!(
            chain_id = %self.chain_id,
            failed_step,
            duration_ms,
            event = "chain_failed",
            "Chain failed"
        );
    }

    /// Emit an event when the chain exceeds its total timeout.
    pub fn chain_timed_out(&self, timeout_secs: u64, elapsed_ms: u64) {
        warn!(
            chain_id = %self.chain_id,
            timeout_secs,
            elapsed_ms,
            event = "chain_timed_out",
            "Chain timed out"
        );
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke test: all observability methods must compile and not panic.
    /// Actual log output is verified via integration tests with tracing subscribers.
    #[test]
    fn all_methods_execute_without_panic() {
        // GIVEN an observability instance
        let obs = ChainObservability::new("test-chain-obs");
        // WHEN all lifecycle events are emitted
        obs.chain_started(5);
        obs.chain_resumed(2, 3);
        obs.step_started("step_a", 0, 5);
        obs.step_retrying("step_a", 2, "timeout");
        obs.step_completed("step_a", 0, 1, 42);
        obs.step_skipped("step_b", "optional step failed");
        obs.step_failed("step_c", 3, "permanent error");
        obs.step_restored("step_d");
        obs.chain_completed(4, 1, 2, 500);
        obs.chain_failed("step_c", 100);
        obs.chain_timed_out(30, 31_000);
        // THEN no panic occurred
    }

    #[test]
    fn new_stores_chain_id() {
        // GIVEN a chain ID
        let obs = ChainObservability::new("chain-xyz");
        // WHEN accessing the ID
        // THEN it is stored correctly
        assert_eq!(obs.chain_id, "chain-xyz");
    }

    #[test]
    fn clone_is_independent() {
        // GIVEN an observability instance
        let obs = ChainObservability::new("original");
        // WHEN cloned
        let cloned = obs.clone();
        // THEN both have the same chain_id
        assert_eq!(obs.chain_id, cloned.chain_id);
    }
}
