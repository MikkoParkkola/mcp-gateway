// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What a failed start leaves behind for classifying it (#1759).
//!
//! A package manager that cannot use its install tree says so on stderr and
//! dies before it can answer anything, so the child's stderr is the only place
//! that failure is visible: it is what tells a failed install apart from a
//! backend that is merely dead. The tail is the one `early_exit` already reads;
//! this keeps a handle to it, raw, for the repair in `backend::package_cache`.
//!
//! The raw text stays in memory and is read only to pick a needle out of it.
//! It is never handed to a caller, and the next start of this backend drops it.

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize};

use parking_lot::RwLock;
use tokio::sync::Mutex;

use super::early_exit::{self, StderrTail};
use super::{DEFAULT_MAX_FRAME_BYTES, StdioTransport, cache::CACHE_ENV};

/// How long a failed start waits for a child that is still dying.
///
/// Only the exit status is wanted here, and only a child that has already
/// exited has one. A child still alive after this is one the caller was about
/// to be told about anyway, and it is killed on the failure path either way.
const EXIT_DRAIN_GRACE: std::time::Duration = std::time::Duration::from_millis(500);

/// How long a failed start waits for the child's stderr to be drained.
const STDERR_DRAIN_GRACE: std::time::Duration = std::time::Duration::from_millis(500);

/// The last start's stderr tail and exit status, once a failure saw them.
#[derive(Default)]
pub(super) struct FailureRecord {
    tail: parking_lot::Mutex<Option<StderrTail>>,
    exit_status: parking_lot::Mutex<Option<std::process::ExitStatus>>,
}

impl FailureRecord {
    /// Drops what the previous attempt said, so each start is judged on its own.
    pub(super) fn begin(&self) {
        *self.tail.lock() = None;
        *self.exit_status.lock() = None;
    }

    /// Keeps a handle to this start's stderr tail.
    pub(super) fn track(&self, tail: &StderrTail) {
        *self.tail.lock() = Some(Arc::clone(tail));
    }

    /// Records how the child of this start exited.
    pub(super) fn record_exit(&self, status: Option<std::process::ExitStatus>) {
        *self.exit_status.lock() = status;
    }
}

impl StdioTransport {
    /// [`StdioTransport::new`], telling the transport which cache this gateway
    /// assigned.
    ///
    /// The caller that built the environment is the only one that knows, and
    /// the repair reads it rather than the environment: a path the operator
    /// configured has the same shape as one the gateway assigned.
    #[must_use]
    pub(crate) fn new_with_assigned_cache(
        command: &str,
        env: HashMap<String, String>,
        cwd: Option<String>,
        request_timeout: std::time::Duration,
        protocol_version: Option<String>,
        assigned_cache: Option<PathBuf>,
    ) -> Arc<Self> {
        Arc::new(Self {
            child: Mutex::new(None),
            pending: dashmap::DashMap::new(),
            request_id: AtomicU64::new(1),
            connected: AtomicBool::new(false),
            command: command.to_string(),
            env,
            cwd,
            request_timeout,
            writer: Mutex::new(None),
            protocol_version: RwLock::new(protocol_version),
            progress_destinations: dashmap::DashMap::new(),
            start: early_exit::StartState::default(),
            taps: crate::transport::upstream_tap::Taps::default(),
            max_frame_bytes: AtomicUsize::new(DEFAULT_MAX_FRAME_BYTES),
            failure: FailureRecord::default(),
            assigned_cache,
        })
    }

    /// The per-request timeout, which also bounds the cache repair's waits.
    pub(crate) fn request_timeout(&self) -> std::time::Duration {
        self.request_timeout
    }

    /// The cache directory this gateway assigned, if it assigned one.
    pub(crate) fn assigned_package_cache_dir(&self) -> Option<&Path> {
        self.assigned_cache.as_deref()
    }

    /// The cache directory the child is given, whoever chose it. The assigned
    /// cache is set from the path itself at spawn, so it is the one reported.
    pub(crate) fn package_cache_dir(&self) -> Option<PathBuf> {
        self.exact_assigned_cache()
            .map(Path::to_path_buf)
            .or_else(|| self.env.get(CACHE_ENV).map(PathBuf::from))
    }

    /// The assigned cache, when the environment still carries the gateway's own
    /// rendering of it: then spawn hands the child the path itself (MIK-7990).
    /// Any other value, or none, is left as the environment says, so the repair
    /// still clears only a cache the child was actually given.
    pub(super) fn exact_assigned_cache(&self) -> Option<&Path> {
        let dir = self.assigned_cache.as_deref()?;
        (self.env.get(CACHE_ENV).map(String::as_str) == Some(&*dir.to_string_lossy()))
            .then_some(dir)
    }

    /// How the child exited, if a failed start saw it exit.
    ///
    /// `None` covers both "the child is still running" and "no failed start
    /// has looked yet", which is all a caller can do anything with: the status
    /// is only ever read to classify a failure.
    pub(crate) fn exit_status(&self) -> Option<std::process::ExitStatus> {
        *self.failure.exit_status.lock()
    }

    /// The child's last lines on stderr, as one block.
    ///
    /// For classifying a failure, never for a log: see the module docs.
    pub(crate) fn stderr_tail(&self) -> String {
        self.failure
            .tail
            .lock()
            .as_ref()
            .map(|tail| joined(&tail.lock()))
            .unwrap_or_default()
    }

    /// Waits, briefly, for a child that is on its way out, and records how it
    /// went.
    ///
    /// A process that fails at startup writes its reason and exits; the order
    /// those two become visible here is not fixed, and a status read before
    /// the exit is reaped is `None`. This is only called on a failed start, so
    /// the wait can never delay a backend that is working.
    pub(super) async fn settle_child_exit(&self) {
        let mut guard = self.child.lock().await;
        let Some(child) = guard.as_mut() else {
            return;
        };
        if let Ok(Ok(status)) = tokio::time::timeout(EXIT_DRAIN_GRACE, child.wait()).await {
            self.failure.record_exit(Some(status));
        }
    }

    /// Waits, briefly, for the stderr reader to finish.
    ///
    /// The reader is its own task, so a child that dies mid-handshake is
    /// visible to the failure path before the last thing it said has been
    /// read. A child that has exited closes the pipe, so this returns as soon
    /// as there is nothing left to read.
    pub(super) async fn settle_stderr_tail(reader: tokio::task::JoinHandle<()>) {
        let abort = reader.abort_handle();
        if tokio::time::timeout(STDERR_DRAIN_GRACE, reader)
            .await
            .is_err()
        {
            // Something still holds the pipe; keep what was read so far.
            abort.abort();
        }
    }
}

/// The raw tail as text, one line per entry.
fn joined(tail: &VecDeque<Vec<u8>>) -> String {
    tail.iter()
        .map(|line| {
            String::from_utf8_lossy(line)
                .trim_end_matches(['\r', '\n'])
                .to_string()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

// Unix-only: the dying child is a `sh` script.
#[cfg(all(test, unix))]
#[path = "stdio_start_failure_tests.rs"]
mod tests;
