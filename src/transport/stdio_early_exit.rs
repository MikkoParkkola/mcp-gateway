// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A stdio child that dies before `initialize` (#526).
//!
//! Such a child used to be reported after the full request timeout, as a
//! timeout, while its stderr, which named the cause, had already been read and
//! dropped. Now the start notices stdout closing, and reports the exit status.
//!
//! The child's stderr reaches neither an MCP client nor the gateway log: it is
//! another program's output and can hold a secret no redaction pattern knows
//! (MIK-7978). The bounded tail is only matched against a fixed list of
//! needles; the error and the log record carry the exit status, the class and
//! the matched needle, all text of ours. `doctor --start-stdio` shows the
//! error.

use std::collections::VecDeque;

use tokio::io::{AsyncBufReadExt, AsyncReadExt as _, BufReader};
use tokio::process::ChildStderr;
use tracing::{debug, warn};

use super::StdioTransport;
use crate::{Error, Result};

/// Lines of stderr kept; the tail, since the cause is usually printed last.
const TAIL_LINES: usize = 20;
/// Bytes read of one line; the rest of an overlong line is discarded unread
/// into memory, so the reader is bounded whatever the child writes.
const RAW_LINE_BYTES: usize = 4096;
/// How long the start waits for the exit status and the last stderr bytes.
const DRAIN: std::time::Duration = std::time::Duration::from_secs(1);

/// The last [`TAIL_LINES`] raw stderr lines, shared so a reader that never
/// finishes (a grandchild holding the pipe) can still be read after abort.
pub(super) type StderrTail = std::sync::Arc<parking_lot::Mutex<VecDeque<Vec<u8>>>>;

/// The read loop over one start's stderr, shared between the task that
/// drives it while the start runs and a failed start that drives it itself.
type ReadLoop = futures::future::Shared<futures::future::BoxFuture<'static, ()>>;

/// One start's stderr reader.
///
/// A failed start does not wait for the task: a loaded host may not run it in
/// time. It polls the same read loop itself, so whatever the child wrote is
/// read before the window can close. The loop is never cancelled mid-read,
/// so a partial line and the key-block state stay inside it.
pub(super) struct StderrReader {
    task: tokio::task::JoinHandle<()>,
    read_loop: ReadLoop,
    pub(super) tail: StderrTail,
}

impl StderrReader {
    /// Read the child's stderr to its end, within `window`; past it, something
    /// still holds the pipe, and what was read is kept.
    ///
    /// The task lets go of the loop first, so the drain is its only reader: a
    /// poll in flight on another worker ends before the drain's first poll,
    /// and nothing reads into the tail once this returns.
    pub(super) async fn drain(self, window: std::time::Duration) {
        self.task.abort();
        let _ = self.task.await;
        // `timeout` polls the read loop before its clock, so the clock wins
        // only once a read has found the pipe empty.
        let _ = tokio::time::timeout(window, self.read_loop).await;
    }
}

/// Test-only: where the reader task is held on an OS thread, and for how long,
/// as a loaded host can hold it. The read loop itself is never held.
#[cfg(all(test, unix))]
#[derive(Clone, Copy)]
pub(super) enum ReaderHold {
    /// Before it first polls the loop: it has never run.
    BeforeFirstRead(std::time::Duration),
    /// Once the loop has stored a line and waits for more: it ran, then starved.
    AfterFirstLine(std::time::Duration),
}

#[cfg(all(test, unix))]
thread_local! {
    /// The hold for a stderr reader spawned on this thread.
    pub(super) static STDERR_READER_HOLD: std::cell::Cell<Option<ReaderHold>> =
        const { std::cell::Cell::new(None) };
}

/// Holds the task on an OS thread, so its runtime keeps running.
#[cfg(all(test, unix))]
async fn hold_reader(hold: std::time::Duration) {
    let _ = tokio::task::spawn_blocking(move || std::thread::sleep(hold)).await;
}

/// The task's side of [`ReaderHold`]: returns once the task should drive the
/// loop as usual, or `true` if the loop already ended while it was watched.
#[cfg(all(test, unix))]
async fn held_task(hold: Option<ReaderHold>, read_loop: &mut ReadLoop, tail: &StderrTail) -> bool {
    use futures::FutureExt as _;
    match hold {
        None => false,
        Some(ReaderHold::BeforeFirstRead(hold)) => {
            hold_reader(hold).await;
            false
        }
        Some(ReaderHold::AfterFirstLine(hold)) => {
            let ended = std::future::poll_fn(|cx| {
                if read_loop.poll_unpin(cx).is_ready() {
                    return std::task::Poll::Ready(true);
                }
                if tail.lock().is_empty() {
                    std::task::Poll::Pending
                } else {
                    std::task::Poll::Ready(false)
                }
            })
            .await;
            if !ended {
                hold_reader(hold).await;
            }
            ended
        }
    }
}

/// Read stderr to its end into a bounded tail.
///
/// `read_until`, not `lines()`: a child killed mid-write leaves a last line
/// with no newline, and that is often the one that names the cause.
pub(super) fn spawn_stderr_tail(stderr: ChildStderr, command: String) -> StderrReader {
    use futures::FutureExt as _;
    let tail = StderrTail::default();
    let read_loop = read_to_end(stderr, command, std::sync::Arc::clone(&tail))
        .boxed()
        .shared();
    #[cfg(all(test, unix))]
    let hold = STDERR_READER_HOLD.with(std::cell::Cell::get);
    // Mutable only for the test hold, which polls it in place.
    #[cfg_attr(not(all(test, unix)), allow(unused_mut))]
    let mut driven = read_loop.clone();
    #[cfg(all(test, unix))]
    let watched = std::sync::Arc::clone(&tail);
    let task = tokio::spawn(async move {
        #[cfg(all(test, unix))]
        if held_task(hold, &mut driven, &watched).await {
            return;
        }
        driven.await;
    });
    StderrReader {
        task,
        read_loop,
        tail,
    }
}

/// The read loop: every line into `shared`, until EOF or an error.
async fn read_to_end(stderr: ChildStderr, command: String, shared: StderrTail) {
    let mut reader = BufReader::new(stderr);
    let mut buf = Vec::with_capacity(RAW_LINE_BYTES);
    let mut in_block = false;
    loop {
        buf.clear();
        let limit = RAW_LINE_BYTES as u64;
        match (&mut reader).take(limit).read_until(b'\n', &mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                debug!(command = %command, line_len = n, "Received line from stderr");
                {
                    let mut tail = shared.lock();
                    if tail.len() == TAIL_LINES {
                        tail.pop_front();
                    }
                    tail.push_back(sanitize::captured_line(&mut in_block, &buf));
                }
                // Published first, so a held pipe cannot lose the prefix.
                if n == RAW_LINE_BYTES && !buf.ends_with(b"\n") {
                    discard_rest_of_line(&mut reader, &mut in_block, &buf).await;
                }
            }
        }
    }
}

/// Skip to the end of an overlong line in bounded chunks, still tracking key
/// block markers in it: a `-----BEGIN` past the limit masks the body after it.
async fn discard_rest_of_line(
    reader: &mut BufReader<ChildStderr>,
    in_block: &mut bool,
    stored: &[u8],
) {
    let carry = sanitize::MARKER_CARRY;
    let mut scratch = Vec::with_capacity(carry + RAW_LINE_BYTES);
    scratch.extend_from_slice(&stored[stored.len().saturating_sub(carry)..]);
    loop {
        match (&mut *reader)
            .take(RAW_LINE_BYTES as u64)
            .read_until(b'\n', &mut scratch)
            .await
        {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                sanitize::track_block(in_block, &scratch);
                if n < RAW_LINE_BYTES || scratch.ends_with(b"\n") {
                    return;
                }
                scratch.drain(..scratch.len() - carry);
            }
        }
    }
}

/// Known causes, as (needle, class). The first needle found, scanning from
/// the last line back, names the cause; the needle is logged, never the line.
const NEEDLES: &[(&str, &str)] = &[
    ("Cannot find module", "missing_module"),
    ("ERR_MODULE_NOT_FOUND", "missing_module"),
    ("ModuleNotFoundError", "missing_module"),
    ("command not found", "missing_file"),
    ("No such file or directory", "missing_file"),
    ("EACCES", "permission_denied"),
    ("Permission denied", "permission_denied"),
    ("EADDRINUSE", "address_in_use"),
    ("address already in use", "address_in_use"),
];

/// Class used when no needle matches.
const UNCLASSIFIED: &str = "unclassified";

/// The early exit's class and the needle that chose it, from the raw tail.
pub(super) fn classify(tail: &VecDeque<Vec<u8>>) -> (&'static str, Option<&'static str>) {
    for line in tail.iter().rev() {
        for &(needle, class) in NEEDLES {
            if line.windows(needle.len()).any(|w| w == needle.as_bytes()) {
                return (class, Some(needle));
            }
        }
    }
    (UNCLASSIFIED, None)
}

/// The reply, or `None` if stdout closed first. A reply read before EOF has
/// resolved its request already, so the reply wins a tie: a child that
/// answered and then exited has still answered.
pub(super) async fn reply_or_eof<T>(
    reply: impl std::future::Future<Output = T>,
    eof: impl std::future::Future<Output = ()>,
) -> Option<T> {
    tokio::select! {
        biased;
        reply = reply => Some(reply),
        () = eof => None,
    }
}

/// Trips a start's stdout-closed latch when dropped. The reader task holds it,
/// so the latch trips however the task ends: at EOF, on an early return, or in
/// a panic. A handshake or request racing the latch then never waits out its
/// timeout behind a reader that is gone, though `StartState` keeps the sender.
pub(super) struct TripOnDrop(pub(super) std::sync::Arc<tokio::sync::watch::Sender<bool>>);

impl Drop for TripOnDrop {
    fn drop(&mut self) {
        self.0.send_replace(true);
    }
}

/// Per-start state: the stdout-closed latch (fresh each start, so a previous
/// generation's exit cannot answer this one) and whether the race saw it. Tests
/// also keep the class and needle of the last early exit.
#[derive(Default)]
pub(super) struct StartState {
    eof: parking_lot::Mutex<Option<std::sync::Arc<tokio::sync::watch::Sender<bool>>>>,
    exited: std::sync::atomic::AtomicBool,
    /// The last early exit's stderr tail, already sanitized: the raw bytes
    /// never outlive `early_exit_error`.
    shown_stderr: parking_lot::Mutex<Vec<String>>,
    // Unix-only (W-L5): recorded only for the `sh`-script tests in `stdio_early_exit_tests.rs`.
    #[cfg(all(test, unix))]
    failure: parking_lot::Mutex<Option<(&'static str, Option<&'static str>)>>,
}

impl StartState {
    /// Forget the last start's shown stderr, before anything can fail: a
    /// start that cannot even spawn must not show an older exit's tail.
    pub(super) fn forget_shown_stderr(&self) {
        self.shown_stderr.lock().clear();
    }

    pub(super) fn begin(&self, eof: std::sync::Arc<tokio::sync::watch::Sender<bool>>) {
        *self.eof.lock() = Some(eof);
        // A class describes the last start only.
        // Unix-only (W-L5): recorded only for the `sh`-script tests in `stdio_early_exit_tests.rs`.
        #[cfg(all(test, unix))]
        {
            *self.failure.lock() = None;
        }
        self.exited
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }

    /// This start's stdout-closed latch, or `None` before the first start.
    pub(super) fn eof_receiver(&self) -> Option<tokio::sync::watch::Receiver<bool>> {
        self.eof.lock().as_ref().map(|eof| eof.subscribe())
    }

    /// Trip this start's stdout-closed latch now, as the reader does at EOF
    /// (MIK-7923, design P5): a retire fails waiting requests at once.
    /// Sync; a second trip is a no-op for watchers.
    pub(super) fn trip_eof(&self) {
        if let Some(eof) = self.eof.lock().as_ref() {
            eof.send_replace(true);
        }
    }

    pub(super) fn exited_early(&self) -> bool {
        self.exited.swap(false, std::sync::atomic::Ordering::SeqCst)
    }
}

impl StdioTransport {
    /// The class and needle of the last start that ended in an early exit, as
    /// the log record carried them.
    // Unix-only (W-L5): recorded only for the `sh`-script tests in `stdio_early_exit_tests.rs`.
    #[cfg(all(test, unix))]
    pub(super) fn start_failure_class(&self) -> Option<(&'static str, Option<&'static str>)> {
        *self.start.failure.lock()
    }

    /// The last early exit's stderr tail, sanitized, for
    /// `doctor --start-stdio --show-stderr` only (MIK-7978): never logged and
    /// never in an error. Empty unless the last start exited early.
    #[doc(hidden)]
    #[must_use]
    pub fn last_failure_stderr(&self) -> Vec<String> {
        self.start.shown_stderr.lock().clone()
    }

    /// The `initialize` request, raced against this start's stdout closing.
    pub(super) async fn init_request(
        &self,
        params: serde_json::Value,
    ) -> Result<crate::protocol::JsonRpcResponse> {
        use crate::transport::Transport as _;
        let Some(mut eof) = self.start.eof_receiver() else {
            return self.request("initialize", Some(params)).await;
        };
        // `wait_for` reads the current value first, so the clone sees an EOF
        // the select arm already saw.
        let mut after_error = eof.clone();
        let closed = async move {
            let _ = eof.wait_for(|closed| *closed).await;
        };
        let Some(response) = reply_or_eof(self.request("initialize", Some(params)), closed).await
        else {
            self.start
                .exited
                .store(true, std::sync::atomic::Ordering::SeqCst);
            return Err(Error::Transport(
                "stdout closed before initialize".to_string(),
            ));
        };
        // A child that died before reading fails the write (EPIPE) before its
        // stdout closes; stdout closing within the drain window makes that the
        // same early exit. Awaited after the select, whose watch futures are
        // not `Send`, and `matches!` drops the guard at once.
        if response.is_err()
            && matches!(
                tokio::time::timeout(self.exit_window(), after_error.wait_for(|closed| *closed))
                    .await,
                Ok(Ok(_))
            )
        {
            self.start
                .exited
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
        response
    }

    /// How long the start waits for stdout to close after a failed write,
    /// and for the leader's exit: [`DRAIN`], or the test-only slow-host bound
    /// (MIK-8360).
    #[cfg_attr(not(test), allow(clippy::unused_self))]
    fn exit_window(&self) -> std::time::Duration {
        #[cfg(test)]
        if let Some(bound) = *self.slow_host_bound.lock() {
            return bound;
        }
        DRAIN
    }

    /// How long a failed start reads the child's last stderr bytes: `path`'s
    /// window ([`DRAIN`] here, a shorter one on the late path), or the
    /// test-only stderr bound. Separate from [`Self::exit_window`] so a row
    /// can keep this window real (a grandchild holding the pipe) while the
    /// exit wait stays long (MIK-8360).
    #[cfg_attr(not(test), allow(clippy::unused_self))]
    pub(super) fn stderr_window(&self, path: std::time::Duration) -> std::time::Duration {
        #[cfg(test)]
        if let Some(bound) = *self.stderr_bound.lock() {
            return bound;
        }
        path
    }

    /// Turn an early exit into its report: the exit status, class and needle,
    /// for the caller and the log alike. Kills a child that closed stdout but
    /// is still running.
    pub(super) async fn early_exit_error(&self, stderr: StderrReader) -> Error {
        // Wait for the exit without reaping, then end the group (any
        // descendant left in it) and reap, in that order (MIK-8080). The tree
        // stays in the slot while waiting, so a retire can still reach it, and
        // leaves it only for the reaper (MIK-7923).
        let had_tree = self.child.lock().tree.is_some();
        let status = if had_tree {
            let exited = self.wait_exited_in_slot(self.exit_window()).await;
            let status = self.end_tree().await;
            exited.then_some(status).flatten()
        } else {
            None
        };
        // Kept for classifying the failure (#1759).
        self.failure.record_exit(status);
        let tail = std::sync::Arc::clone(&stderr.tail);
        stderr.drain(self.stderr_window(DRAIN)).await;
        let (class, needle) = {
            let tail = tail.lock();
            *self.start.shown_stderr.lock() = sanitize::sanitize(&tail);
            classify(&tail)
        };
        let command = self.diagnostic_command();
        let what = match status {
            Some(status) => format!("exited before initialize ({status})"),
            None => "closed its stdout before initialize".to_string(),
        };
        let cause = match needle {
            Some(needle) => format!("{class}, stderr matched \"{needle}\""),
            None => class.to_string(),
        };
        // Never the stderr text itself: no redaction pattern list is complete.
        warn!(command = %command, class, needle = needle.unwrap_or("none"), "stdio backend {what}");
        // Unix-only (W-L5): recorded only for the `sh`-script tests in `stdio_early_exit_tests.rs`.
        #[cfg(all(test, unix))]
        {
            *self.start.failure.lock() = Some((class, needle));
        }
        Error::Transport(format!("stdio backend {command} {what}: {cause}"))
    }
}

#[path = "stdio_stderr_sanitize.rs"]
mod sanitize;

// Unix-only (W-L5): the tests drive `sh -c` scripts as stdio backends.
#[cfg(all(test, unix))]
#[path = "stdio_early_exit_tests.rs"]
mod tests;
