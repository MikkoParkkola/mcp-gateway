//! Cron scheduler and inbound webhook action dispatcher.
//!
//! # Overview
//!
//! ```text
//! CronScheduler  (Arc-wrapped, background tokio task)
//!   ├── entries : Vec<ScheduleEntry>
//!   └── tick()  — checks each entry against current time, fires due jobs
//! ```
//!
//! Each [`ScheduleEntry`] holds a human-readable name, a parsed
//! [`CronExpression`], and a [`ScheduleAction`] (run a playbook or invoke an
//! MCP tool directly).  Execution tracking is kept per-entry so callers can
//! inspect `last_run`, `run_count`, and `last_status`.
//!
//! # Cron expression format
//!
//! Five space-separated fields: `minute hour day-of-month month day-of-week`
//!
//! Each field accepts:
//! - `*`           — match any value
//! - `N`           — match exactly N
//! - `*/N`         — match every N-th value (step)
//! - `N-M`         — match the inclusive range N..=M
//! - `N,M,...`     — match a list of values
//!
//! Examples:
//! - `0 * * * *`   — every hour on the hour
//! - `*/15 * * * *` — every 15 minutes
//! - `0 9 * * 1-5` — 09:00 on weekdays
//! - `30 18 1 * *` — 18:30 on the first of every month

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Datelike, Timelike, Utc};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use crate::{Error, Result};

// ── SchedulerConfig ───────────────────────────────────────────────────────────

/// Top-level scheduler configuration (loaded from gateway config).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct SchedulerConfig {
    /// Enable the cron scheduler.
    pub enabled: bool,
    /// Scheduled job definitions.
    pub jobs: Vec<JobConfig>,
}

/// Configuration for a single scheduled job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobConfig {
    /// Human-readable name (must be unique within the scheduler).
    pub name: String,
    /// Cron expression: `minute hour day month weekday`.
    pub cron: String,
    /// Action to run when the schedule fires.
    pub action: ActionConfig,
    /// Whether this job is active (default true).
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

/// Serialisable action definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ActionConfig {
    /// Execute a named playbook.
    RunPlaybook {
        /// Playbook name or path.
        playbook: String,
    },
    /// Invoke an MCP tool on a specific backend.
    InvokeTool {
        /// Backend server name.
        server: String,
        /// Tool name.
        tool: String,
        /// Tool arguments (arbitrary JSON object).
        #[serde(default)]
        arguments: HashMap<String, serde_json::Value>,
    },
}

// ── CronField ─────────────────────────────────────────────────────────────────

/// A single parsed cron field (minute, hour, etc.).
#[derive(Debug, Clone, PartialEq, Eq)]
enum CronField {
    /// `*` — matches any value.
    Any,
    /// `N` — matches exactly one value.
    Exact(u32),
    /// `*/N` — matches values divisible by the step.
    Step(u32),
    /// `N-M` — matches the inclusive range.
    Range(u32, u32),
    /// `N,M,...` — matches any value in the list.
    List(Vec<u32>),
}

impl CronField {
    /// Parse a single cron field string for values within `[min_val, max_val]`.
    fn parse(s: &str, min_val: u32, max_val: u32) -> Result<Self> {
        if s == "*" {
            return Ok(Self::Any);
        }
        if let Some(step_str) = s.strip_prefix("*/") {
            let step: u32 = step_str
                .parse()
                .map_err(|_| Error::Config(format!("invalid cron step: {s}")))?;
            if step == 0 {
                return Err(Error::Config("cron step cannot be zero".to_string()));
            }
            return Ok(Self::Step(step));
        }
        if s.contains(',') {
            let mut values = Vec::new();
            for part in s.split(',') {
                let v: u32 = part
                    .trim()
                    .parse()
                    .map_err(|_| Error::Config(format!("invalid cron list value: {part}")))?;
                if v < min_val || v > max_val {
                    return Err(Error::Config(format!(
                        "cron value {v} out of range [{min_val}, {max_val}]"
                    )));
                }
                values.push(v);
            }
            return Ok(Self::List(values));
        }
        if s.contains('-') {
            let parts: Vec<&str> = s.splitn(2, '-').collect();
            if parts.len() == 2 {
                let lo: u32 = parts[0]
                    .parse()
                    .map_err(|_| Error::Config(format!("invalid cron range start: {s}")))?;
                let hi: u32 = parts[1]
                    .parse()
                    .map_err(|_| Error::Config(format!("invalid cron range end: {s}")))?;
                if lo > hi {
                    return Err(Error::Config(format!(
                        "cron range start {lo} > end {hi}"
                    )));
                }
                if lo < min_val || hi > max_val {
                    return Err(Error::Config(format!(
                        "cron range {lo}-{hi} out of bounds [{min_val},{max_val}]"
                    )));
                }
                return Ok(Self::Range(lo, hi));
            }
        }
        // Plain number
        let v: u32 = s
            .parse()
            .map_err(|_| Error::Config(format!("invalid cron value: {s}")))?;
        if v < min_val || v > max_val {
            return Err(Error::Config(format!(
                "cron value {v} out of range [{min_val}, {max_val}]"
            )));
        }
        Ok(Self::Exact(v))
    }

    /// Returns `true` if `value` matches this field.
    fn matches(&self, value: u32) -> bool {
        match self {
            Self::Any => true,
            Self::Exact(n) => value == *n,
            Self::Step(n) => value % n == 0,
            Self::Range(lo, hi) => value >= *lo && value <= *hi,
            Self::List(vs) => vs.contains(&value),
        }
    }
}

// ── CronExpression ────────────────────────────────────────────────────────────

/// A fully parsed cron expression with five fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CronExpression {
    minute: CronField,   // 0–59
    hour: CronField,     // 0–23
    day: CronField,      // 1–31
    month: CronField,    // 1–12
    weekday: CronField,  // 0–7 (0 and 7 are both Sunday)
}

impl CronExpression {
    /// Parse a five-field cron expression string.
    ///
    /// # Errors
    ///
    /// Returns an error if the string does not contain exactly five fields or
    /// any field value is out of range.
    pub fn parse(expr: &str) -> Result<Self> {
        let fields: Vec<&str> = expr.split_whitespace().collect();
        if fields.len() != 5 {
            return Err(Error::Config(format!(
                "cron expression must have exactly 5 fields, got {}: {expr:?}",
                fields.len()
            )));
        }
        Ok(Self {
            minute: CronField::parse(fields[0], 0, 59)?,
            hour: CronField::parse(fields[1], 0, 23)?,
            day: CronField::parse(fields[2], 1, 31)?,
            month: CronField::parse(fields[3], 1, 12)?,
            weekday: CronField::parse(fields[4], 0, 7)?,
        })
    }

    /// Returns `true` if this expression matches the given `DateTime<Utc>`.
    ///
    /// Seconds are ignored; matching is minute-granular.  Weekday 0 and 7 are
    /// both treated as Sunday (same as POSIX cron).
    pub fn matches(&self, now: &DateTime<Utc>) -> bool {
        let minute = now.minute();
        let hour = now.hour();
        let day = now.day();
        let month = now.month();
        // chrono weekday: Mon=0..Sun=6 — we convert to Sun=0..Sat=6 (POSIX)
        let weekday = (now.weekday().num_days_from_sunday()) % 7;

        self.minute.matches(minute)
            && self.hour.matches(hour)
            && self.day.matches(day)
            && self.month.matches(month)
            && (self.weekday.matches(weekday) || self.weekday.matches(weekday + 7))
    }
}

// ── ScheduleAction ────────────────────────────────────────────────────────────

/// Action executed when a schedule fires.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ScheduleAction {
    /// Run a named playbook.
    RunPlaybook(String),
    /// Invoke an MCP tool on a named backend server.
    InvokeTool {
        /// Backend server name.
        server: String,
        /// Tool name.
        tool: String,
        /// Tool arguments.
        arguments: HashMap<String, serde_json::Value>,
    },
}

impl From<ActionConfig> for ScheduleAction {
    fn from(cfg: ActionConfig) -> Self {
        match cfg {
            ActionConfig::RunPlaybook { playbook } => Self::RunPlaybook(playbook),
            ActionConfig::InvokeTool {
                server,
                tool,
                arguments,
            } => Self::InvokeTool {
                server,
                tool,
                arguments,
            },
        }
    }
}

// ── JobStatus ─────────────────────────────────────────────────────────────────

/// Outcome of the last execution of a scheduled job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum JobStatus {
    /// Job has never been run.
    Never,
    /// Last execution succeeded.
    Ok,
    /// Last execution returned an error message.
    Error(String),
}

// ── ScheduleEntry ─────────────────────────────────────────────────────────────

/// A single scheduled job with its expression, action, and execution tracking.
#[derive(Debug)]
pub struct ScheduleEntry {
    /// Unique name for this job.
    pub name: String,
    /// Parsed cron expression.
    pub expression: CronExpression,
    /// Action to perform when the schedule fires.
    pub action: ScheduleAction,
    /// Whether this entry is active.
    pub enabled: bool,

    // --- Execution tracking (behind a mutex for interior mutability) ---
    tracking: Mutex<EntryTracking>,
}

#[derive(Debug, Default)]
struct EntryTracking {
    last_run: Option<DateTime<Utc>>,
    next_run: Option<DateTime<Utc>>,
    run_count: u64,
    last_status: JobStatus,
}

impl Default for JobStatus {
    fn default() -> Self {
        Self::Never
    }
}

impl ScheduleEntry {
    /// Create a new entry from config.
    ///
    /// # Errors
    ///
    /// Returns an error if the cron expression cannot be parsed.
    pub fn from_config(cfg: JobConfig) -> Result<Self> {
        let expression = CronExpression::parse(&cfg.cron)?;
        Ok(Self {
            name: cfg.name,
            expression,
            action: ScheduleAction::from(cfg.action),
            enabled: cfg.enabled,
            tracking: Mutex::new(EntryTracking::default()),
        })
    }

    /// Returns `true` if this entry should fire at `now` (minute-granular).
    pub fn is_due(&self, now: &DateTime<Utc>) -> bool {
        self.enabled && self.expression.matches(now)
    }

    /// Snapshot of current tracking state.
    pub fn snapshot(&self) -> EntrySnapshot {
        let t = self.tracking.lock();
        EntrySnapshot {
            name: self.name.clone(),
            enabled: self.enabled,
            last_run: t.last_run,
            next_run: t.next_run,
            run_count: t.run_count,
            last_status: t.last_status.clone(),
        }
    }

    /// Record a successful execution at `when`.
    fn record_success(&self, when: DateTime<Utc>) {
        let mut t = self.tracking.lock();
        t.last_run = Some(when);
        t.run_count += 1;
        t.last_status = JobStatus::Ok;
    }

    /// Record a failed execution at `when`.
    fn record_failure(&self, when: DateTime<Utc>, err: &str) {
        let mut t = self.tracking.lock();
        t.last_run = Some(when);
        t.run_count += 1;
        t.last_status = JobStatus::Error(err.to_string());
    }

    /// Advance `next_run` to the next minute that matches the expression,
    /// searching up to `horizon_minutes` ahead of `after`.
    fn update_next_run(&self, after: &DateTime<Utc>, horizon_minutes: u32) {
        let mut t = self.tracking.lock();
        t.next_run = find_next_match(&self.expression, after, horizon_minutes);
    }
}

/// Serialisable snapshot of a single entry's state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntrySnapshot {
    /// Job name.
    pub name: String,
    /// Whether the entry is active.
    pub enabled: bool,
    /// Timestamp of the last execution, if any.
    pub last_run: Option<DateTime<Utc>>,
    /// Computed next fire time, if determinable within the search horizon.
    pub next_run: Option<DateTime<Utc>>,
    /// Total successful + failed executions.
    pub run_count: u64,
    /// Status of the most recent execution.
    pub last_status: JobStatus,
}

// ── CronScheduler ─────────────────────────────────────────────────────────────

/// Central cron scheduler managing all registered jobs.
///
/// Designed to be wrapped in [`Arc`] and shared with a background
/// [`tokio::task`] that calls [`CronScheduler::tick`] every minute.
pub struct CronScheduler {
    entries: Vec<Arc<ScheduleEntry>>,
}

impl CronScheduler {
    /// Construct a scheduler from a [`SchedulerConfig`].
    ///
    /// # Errors
    ///
    /// Returns an error if any job has an invalid cron expression or if names
    /// are not unique.
    pub fn from_config(cfg: SchedulerConfig) -> Result<Self> {
        let mut entries = Vec::with_capacity(cfg.jobs.len());
        let mut seen_names = std::collections::HashSet::new();

        for job in cfg.jobs {
            if !seen_names.insert(job.name.clone()) {
                return Err(Error::Config(format!(
                    "duplicate scheduler job name: {:?}",
                    job.name
                )));
            }
            entries.push(Arc::new(ScheduleEntry::from_config(job)?));
        }

        Ok(Self { entries })
    }

    /// Construct an empty scheduler (no jobs).
    pub fn empty() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Number of registered entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if no entries are registered.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns all entries that are due at `now`.
    ///
    /// The caller is responsible for dispatching the returned entries.
    pub fn due_entries(&self, now: &DateTime<Utc>) -> Vec<Arc<ScheduleEntry>> {
        self.entries
            .iter()
            .filter(|e| e.is_due(now))
            .cloned()
            .collect()
    }

    /// Tick the scheduler at `now`, collecting due jobs.
    ///
    /// For each due entry the method invokes `executor` with the entry.  The
    /// executor should be an async-capable closure; since `CronScheduler` is
    /// not itself async, callers typically wrap the tick call in a
    /// `tokio::spawn` loop.
    ///
    /// Returns the list of entries that fired (regardless of outcome).
    pub fn tick<F>(&self, now: &DateTime<Utc>, mut executor: F) -> Vec<String>
    where
        F: FnMut(&ScheduleEntry),
    {
        let mut fired = Vec::new();
        for entry in &self.entries {
            if entry.is_due(now) {
                executor(entry);
                fired.push(entry.name.clone());
            }
        }
        fired
    }

    /// Snapshot all entries.
    pub fn snapshots(&self) -> Vec<EntrySnapshot> {
        self.entries.iter().map(|e| e.snapshot()).collect()
    }

    /// Snapshot a single entry by name.
    pub fn snapshot_by_name(&self, name: &str) -> Option<EntrySnapshot> {
        self.entries.iter().find(|e| e.name == name).map(|e| e.snapshot())
    }

    /// Record a successful run for the named entry.
    pub fn record_success(&self, name: &str, when: DateTime<Utc>) {
        if let Some(entry) = self.entries.iter().find(|e| e.name == name) {
            entry.record_success(when);
            entry.update_next_run(&when, 60 * 24 * 7); // search up to 1 week
        }
    }

    /// Record a failed run for the named entry.
    pub fn record_failure(&self, name: &str, when: DateTime<Utc>, err: &str) {
        if let Some(entry) = self.entries.iter().find(|e| e.name == name) {
            entry.record_failure(when, err);
            entry.update_next_run(&when, 60 * 24 * 7);
        }
    }

    /// Pre-compute `next_run` for all entries starting from `after`.
    pub fn precompute_next_runs(&self, after: &DateTime<Utc>) {
        for entry in &self.entries {
            entry.update_next_run(after, 60 * 24 * 7);
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Walk forward minute-by-minute from `after` to find the next time `expr`
/// matches, searching at most `horizon_minutes` ahead.
fn find_next_match(
    expr: &CronExpression,
    after: &DateTime<Utc>,
    horizon_minutes: u32,
) -> Option<DateTime<Utc>> {
    // Start one minute ahead (next schedulable slot)
    let mut candidate = after
        .with_second(0)
        .and_then(|t| t.with_nanosecond(0))
        .unwrap_or(*after)
        + chrono::Duration::minutes(1);

    for _ in 0..horizon_minutes {
        if expr.matches(&candidate) {
            return Some(candidate);
        }
        candidate = candidate + chrono::Duration::minutes(1);
    }
    None
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
