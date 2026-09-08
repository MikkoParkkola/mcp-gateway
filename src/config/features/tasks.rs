// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Durable task-store and worker-pool configuration.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::config::humantime_serde;
use crate::{Error, Result};

/// Default worker cap. Named from the design: a zero cap cannot drain.
pub const DEFAULT_MAX_WORKERS: usize = 16;

/// Default retention: one day, matching `Task::create`.
const DEFAULT_TTL_MS: u64 = 86_400_000;
const DEFAULT_POLL_INTERVAL_MS: u64 = 1_000;
const DEFAULT_MAX_RECORDS: usize = 256;
const DEFAULT_MAX_PER_PRINCIPAL: usize = 32;
const DEFAULT_MAX_RECORD_BYTES: usize = 512 * 1024;
const DEFAULT_LOGICAL_BUDGET_BYTES: usize = 128 * 1024 * 1024;

/// Tasks extension store, worker pool, and later-increment knobs.
///
/// `store_dir` is a durable path. A process that cannot open it does not start;
/// there is no volatile fallback.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TasksConfig {
    /// Directory that holds the exclusive store lease and records.
    /// `~` is expanded at startup.
    pub store_dir: String,
    /// Retention stamped onto a new record. `0` is unlimited (`ttlMs: null`).
    pub default_ttl_ms: u64,
    /// Suggested poll cadence stamped onto a new record. `0` omits the field.
    pub poll_interval_ms: u64,
    /// Store-wide live record cap.
    pub max_records: usize,
    /// Per-principal live record cap.
    pub max_per_principal: usize,
    /// Concurrent dispatched workers. Must be nonzero.
    pub max_workers: usize,
    /// Maximum serialized bytes of one record.
    pub max_record_bytes: usize,
    /// Logical byte budget: `max_records * max_record_bytes` must fit.
    pub logical_budget_bytes: usize,
    /// Period of the gateway's periodic expiry sweep. Must be nonzero: a zero
    /// period is a spin, not a cadence, and the runtime refuses to start one.
    #[serde(with = "humantime_serde")]
    pub expiry_interval: Duration,
    /// I5 trusted recovery adapter names. Empty keeps the conservative branch.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recovery_adapters: Vec<String>,
}

impl Default for TasksConfig {
    fn default() -> Self {
        Self {
            store_dir: "~/.mcp-gateway/tasks".to_string(),
            default_ttl_ms: DEFAULT_TTL_MS,
            poll_interval_ms: DEFAULT_POLL_INTERVAL_MS,
            max_records: DEFAULT_MAX_RECORDS,
            max_per_principal: DEFAULT_MAX_PER_PRINCIPAL,
            max_workers: DEFAULT_MAX_WORKERS,
            max_record_bytes: DEFAULT_MAX_RECORD_BYTES,
            logical_budget_bytes: DEFAULT_LOGICAL_BUDGET_BYTES,
            expiry_interval: Duration::from_secs(60),
            recovery_adapters: Vec::new(),
        }
    }
}

impl TasksConfig {
    /// Finite, nonzero worker/store limits whose product fits the logical budget.
    ///
    /// # Errors
    /// Returns [`Error::ConfigValidation`] for an empty directory, a zero worker
    /// cap, a zero store cap, a zero expiry period, or arithmetic that cannot
    /// represent the budget.
    pub fn validate(&self) -> Result<()> {
        if self.store_dir.trim().is_empty() {
            return Err(Error::ConfigValidation(
                "tasks.store_dir must not be empty".to_string(),
            ));
        }
        if self.max_workers == 0 {
            return Err(Error::ConfigValidation(
                "tasks.max_workers must be nonzero".to_string(),
            ));
        }
        if self.max_records == 0 {
            return Err(Error::ConfigValidation(
                "tasks.max_records must be nonzero".to_string(),
            ));
        }
        if self.max_per_principal == 0 {
            return Err(Error::ConfigValidation(
                "tasks.max_per_principal must be nonzero".to_string(),
            ));
        }
        if self.max_record_bytes == 0 {
            return Err(Error::ConfigValidation(
                "tasks.max_record_bytes must be nonzero".to_string(),
            ));
        }
        // Checked here rather than only at startup: the runtime refuses a zero
        // period, and a config that cannot start is a config to refuse.
        if self.expiry_interval.is_zero() {
            return Err(Error::ConfigValidation(
                "tasks.expiry_interval must be nonzero".to_string(),
            ));
        }
        if self.logical_budget_bytes == 0 {
            return Err(Error::ConfigValidation(
                "tasks.logical_budget_bytes must be nonzero".to_string(),
            ));
        }
        let reserved = self
            .max_records
            .checked_mul(self.max_record_bytes)
            .ok_or_else(|| {
                Error::ConfigValidation(
                    "tasks.max_records * tasks.max_record_bytes overflows".to_string(),
                )
            })?;
        if reserved > self.logical_budget_bytes {
            return Err(Error::ConfigValidation(format!(
                "tasks.max_records * tasks.max_record_bytes ({reserved}) exceeds \
                 tasks.logical_budget_bytes ({})",
                self.logical_budget_bytes
            )));
        }
        if self.max_per_principal > self.max_records {
            return Err(Error::ConfigValidation(
                "tasks.max_per_principal must not exceed tasks.max_records".to_string(),
            ));
        }
        Ok(())
    }
}
