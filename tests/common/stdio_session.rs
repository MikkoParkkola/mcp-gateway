// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The shipped binary over stdio, for suites that need a real serve loop.
//!
//! Included by `#[path]` from each suite that drives one, so an item only one
//! suite uses is dead in the other; that is the layout, not a defect.
#![allow(dead_code)]

#[path = "gateway_bin.rs"]
pub(crate) mod gateway_bin;

use std::path::Path;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::timeout;

/// Bound on one read. It starts once the child is ready (every read waits for
/// that first), so it times an answer, never the child's start. Far below the
/// shipped bridge's 30s/120s bounds, which nothing here should ever wait on.
pub const READ_TIMEOUT: Duration = Duration::from_secs(10);

/// The shipped binary, spawned the way a stdio client spawns it.
pub struct StdioSession {
    child: Child,
    /// Taken by [`Self::close_stdin`]: EOF is the stimulus of the drain row,
    /// and the session has to outlive it to read what the drain writes.
    stdin: Option<ChildStdin>,
    stdout: Lines<BufReader<ChildStdout>>,
    /// Fires when the child logs [`READY_LINE`]; taken by the first read.
    ready: Option<oneshot::Receiver<()>>,
}

impl StdioSession {
    pub fn spawn(home: &Path) -> Self {
        let command = gateway_bin::command(home, gateway_bin::Inherit::Environment);
        Self::serve(command, home, StderrSink::Forward).0
    }

    /// As [`Self::spawn`], with the binary started through `wrapper` (see
    /// `gateway_bin::wrapped`): a launcher that delays or replaces the start,
    /// for rows about the wait for ready.
    pub fn spawn_through(wrapper: &[&str], home: &Path) -> Self {
        let command = gateway_bin::wrapped(wrapper, home, gateway_bin::Inherit::Environment);
        Self::serve(command, home, StderrSink::Forward).0
    }

    /// Start `serve --stdio` with every stream piped. The stderr drain feeds
    /// `sink` and fires the ready signal the reads wait for.
    fn serve(
        command: std::process::Command,
        home: &Path,
        sink: StderrSink,
    ) -> (Self, JoinHandle<()>) {
        let mut command = Command::from(command);
        command.arg("serve").arg("--stdio").current_dir(home);
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // The kill that survives a panicking assertion. `shutdown` is the
            // orderly path; this is the one that runs when a row fails.
            .kill_on_drop(true)
            .spawn()
            .expect("spawn gateway over stdio");
        let stdin = child.stdin.take().expect("child stdin");
        let stdout = BufReader::new(child.stdout.take().expect("child stdout")).lines();
        let (ready, drain) = drain_stderr(child.stderr.take().expect("child stderr"), sink);
        let session = Self {
            child,
            stdin: Some(stdin),
            stdout,
            ready: Some(ready),
        };
        (session, drain)
    }

    /// Wait, once, for the child to log [`READY_LINE`], so the bound of every
    /// read after it times an answer and not the start, which a loaded machine
    /// stretches past [`READ_TIMEOUT`] (see [`READY_CAP`]).
    async fn wait_ready(&mut self) {
        assert!(
            self.wait_ready_for(READY_CAP).await,
            "the gateway never became ready: no ready line within {READY_CAP:?}"
        );
    }

    /// `true` once the child has logged [`READY_LINE`] or exited (the read
    /// that follows an exit then sees stdout end, as it did before), `false`
    /// if `window` passes first. Every read calls it through `wait_ready`
    /// with [`READY_CAP`]; a row about a start that never finishes calls it
    /// with a short window, which only has to pass without a ready line.
    pub async fn wait_ready_for(&mut self, window: Duration) -> bool {
        let Some(mut ready) = self.ready.take() else {
            return true;
        };
        let child = &mut self.child;
        let settled = timeout(window, async {
            tokio::select! {
                _ = &mut ready => {}
                _ = child.wait() => {}
            }
        })
        .await
        .is_ok();
        if !settled {
            self.ready = Some(ready);
        }
        settled
    }

    pub async fn send(&mut self, message: &Value) {
        let stdin = self.stdin.as_mut().expect("child stdin still open");
        stdin
            .write_all(format!("{message}\n").as_bytes())
            .await
            .expect("write to child stdin");
        stdin.flush().await.expect("flush child stdin");
    }

    /// Send EOF and keep the session: the child's reader loop leaves its
    /// `while let Ok(Some(line))` and enters the drain.
    pub fn close_stdin(&mut self) {
        drop(self.stdin.take());
    }

    /// Read lines until one carries `id`, or the bound expires.
    ///
    /// Returns every line consumed on the way, so a caller can still assert on
    /// what the child wrote before the reply it was waiting for.
    pub async fn read_until_id(&mut self, id: i64) -> (Vec<String>, Option<Value>) {
        self.wait_ready().await;
        let mut seen = Vec::new();
        loop {
            let Ok(Ok(Some(line))) = timeout(READ_TIMEOUT, self.stdout.next_line()).await else {
                return (seen, None);
            };
            let matched = serde_json::from_str::<Value>(&line)
                .ok()
                .filter(|value| value.get("id").and_then(Value::as_i64) == Some(id));
            seen.push(line);
            if let Some(value) = matched {
                return (seen, Some(value));
            }
        }
    }

    /// Drain stdout for a fixed window and return the raw lines, for a row
    /// that asserts something did NOT arrive.
    ///
    /// A positive assert on this result is a race (MIK-8295): whatever must
    /// arrive has to beat the window, which a loaded runner does not promise.
    /// Wait for it with [`Self::collect_lines_until`] instead. The whole drain
    /// is under one timeout, so a chatty child cannot keep it alive.
    pub async fn collect_for_absence(&mut self, window: Duration) -> Vec<String> {
        self.wait_ready().await;
        let mut lines = Vec::new();
        let _ = timeout(window, async {
            while let Ok(Some(line)) = self.stdout.next_line().await {
                lines.push(line);
            }
        })
        .await;
        lines
    }

    /// Collect until `enough` holds, then keep reading for `settle`.
    ///
    /// A fixed window asserts a timing coincidence: every admitted request has
    /// to have written its question before the window closes, which a loaded CI
    /// runner does not guarantee. Waiting for the count removes that race
    /// without weakening the row -- `budget` still bounds a parked reader into a
    /// failure, and `settle` still lets an over-admitted extra arrive and redden
    /// the assertion.
    ///
    /// `enough` sees each line parsed once (MIK-7553): re-parsing every 96 KiB
    /// question per line spent ~200 MB of debug-build parsing inside `budget`.
    pub async fn collect_lines_until(
        &mut self,
        budget: Duration,
        settle: Duration,
        enough: impl Fn(&[Value]) -> bool,
    ) -> Vec<String> {
        self.wait_ready().await;
        let mut lines = Vec::new();
        let mut frames = Vec::new();
        let ended = timeout(budget, async {
            while let Ok(Some(line)) = self.stdout.next_line().await {
                frames.extend(serde_json::from_str::<Value>(&line).ok());
                lines.push(line);
                if enough(&frames) {
                    break;
                }
            }
        })
        .await;
        // Which of the three ways collection ended is what separates a budget cut
        // too fine from a question that never arrived, and the count alone does
        // not say which. Printed rather than returned: cargo surfaces it for the
        // run that failed and swallows it for the runs that did not.
        eprintln!(
            "collect_lines_until: {} after {} lines",
            match ended {
                Err(_) => "the budget expired",
                Ok(()) if enough(&frames) => "the expected count arrived",
                Ok(()) => "stdout ended",
            },
            lines.len()
        );
        let _ = timeout(settle, async {
            while let Ok(Some(line)) = self.stdout.next_line().await {
                lines.push(line);
            }
        })
        .await;
        lines
    }

    pub async fn shutdown(mut self) {
        drop(self.stdin.take());
        let _ = self.child.kill().await;
    }

    /// As [`Self::spawn`], but the child's stderr is captured rather than
    /// forwarded, for rows whose evidence is a log line.
    ///
    /// `RUST_LOG` is set explicitly because the child's
    /// `EnvFilter::try_from_default_env()` wins over its `--log-level`, so an
    /// ambient value in the test environment could silence the lines read here.
    pub fn spawn_capturing_stderr(home: &Path) -> (Self, CapturedStderr) {
        Self::capturing(
            gateway_bin::command(home, gateway_bin::Inherit::Environment),
            home,
        )
    }

    /// As [`Self::spawn_capturing_stderr`], started through `wrapper` (see
    /// [`Self::spawn_through`]): for a row whose launcher leaves a process behind.
    pub fn spawn_capturing_through(wrapper: &[&str], home: &Path) -> (Self, CapturedStderr) {
        Self::capturing(
            gateway_bin::wrapped(wrapper, home, gateway_bin::Inherit::Environment),
            home,
        )
    }

    fn capturing(mut command: std::process::Command, home: &Path) -> (Self, CapturedStderr) {
        command.env("RUST_LOG", "info");
        let lines: Arc<Mutex<Vec<String>>> = Arc::default();
        let (session, drain) = Self::serve(command, home, StderrSink::Capture(Arc::clone(&lines)));
        (session, CapturedStderr { lines, drain })
    }

    /// One stdout line: `Err` when `bound` expires, `Ok(None)` when stdout ended.
    pub async fn next_line(
        &mut self,
        bound: Duration,
    ) -> Result<Option<String>, tokio::time::error::Elapsed> {
        self.wait_ready().await;
        timeout(bound, self.stdout.next_line())
            .await
            .map(|read| read.ok().flatten())
    }

    /// End a capturing session and return every stderr line it wrote.
    ///
    /// Order matters: stdin closes first and the child is killed only after it
    /// has logged `EOF_LINE` (or `EOF_WAIT` passes), because a kill that lands
    /// before the child reads EOF suppresses the one line that proves the
    /// capture works. The drain is then joined through EOF, for at most
    /// `EOF_WAIT`, so no count read from the result races a line still in the
    /// pipe.
    pub async fn finish_capturing(mut self, captured: CapturedStderr) -> Vec<String> {
        // A row that never read still gets its start covered here, not by
        // the EOF waits below.
        self.wait_ready().await;
        drop(self.stdin.take());
        let _ = timeout(EOF_WAIT, async {
            while !captured.contains(EOF_LINE) {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await;
        // The EOF line precedes the child's drain of outstanding work, so it
        // is given the same bound to exit on its own before the kill.
        let _ = timeout(EOF_WAIT, self.child.wait()).await;
        let _ = self.child.kill().await;
        // Bounded, outcome ignored: a grandchild that inherited stderr keeps
        // the pipe open after the kill, and the row judges what arrived anyway.
        let _ = timeout(EOF_WAIT, captured.drain).await;
        std::mem::take(&mut *captured.lines.lock().expect("stderr sink poisoned"))
    }
}

impl Drop for StdioSession {
    /// A row that ends without `shutdown` or `finish_capturing` (a panicking assertion) still kills the child here, and
    /// waits for it for a bounded time: `kill_on_drop` alone only sends the kill, and a caller's temp directory is
    /// removed right after, while the child can still be writing into it.
    fn drop(&mut self) {
        if self.child.id().is_none() {
            return; // already reaped by an orderly end
        }
        let _ = self.child.start_kill();
        // A killed process is reaped within milliseconds; the long bound is only for a stuck host, and it says so.
        let started = std::time::Instant::now();
        while matches!(self.child.try_wait(), Ok(None)) {
            if started.elapsed() > Duration::from_secs(30) {
                eprintln!("stdio_session: the gateway child was still running 30 s after the kill");
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

/// The child's own log line on reaching EOF (`gateway/server/mod.rs`): a fixed
/// string whose absence from a capture names a broken capture, not a quiet child.
pub const EOF_LINE: &str = "stdio: EOF reached, shutting down";

/// The child's own log line once it reads stdin (`gateway/server/stdio_loop.rs`;
/// a row pins that the source still logs it). `gateway_bin` keeps its target at
/// `info` under any inherited `RUST_LOG`.
pub const READY_LINE: &str = "MCP Gateway stdio mode ready — reading JSON-RPC from stdin";

/// How long the first read waits for [`READY_LINE`]. Not a timing bound on a
/// healthy start: it only turns a start that never finishes into a failure.
/// Sized from Windows int-a logs (2026-11-19): a healthy start-to-ready is
/// 0.15-0.37 s, and on the saturated runner that lost train 56a the first
/// ready line came 11.1 s after the first start, with three more gateways not
/// ready about 10 s after theirs. 120 s is about ten times the slowest start
/// on record.
const READY_CAP: Duration = Duration::from_secs(120);

/// How long [`StdioSession::finish_capturing`] waits for [`EOF_LINE`].
const EOF_WAIT: Duration = Duration::from_secs(10);

/// Where the child's stderr lines go.
enum StderrSink {
    /// To this process's stderr, where an inherited stream went. Through
    /// tokio's writer, not `eprintln!` (the test harness captures that) and
    /// not a blocking write (a slow reader of this process's stderr would
    /// stall the test's one runtime thread, and every bound with it).
    Forward,
    /// Into the lines a [`CapturedStderr`] returns.
    Capture(Arc<Mutex<Vec<String>>>),
}

/// Drain the child's stderr on its own task into `sink`, and fire the receiver
/// once the child logs [`READY_LINE`]. Drained continuously, and past a line
/// that is not UTF-8: an undrained stderr pipe deadlocks the child once its
/// logs fill the buffer.
fn drain_stderr(stderr: ChildStderr, sink: StderrSink) -> (oneshot::Receiver<()>, JoinHandle<()>) {
    let (ready_tx, ready_rx) = oneshot::channel();
    let mut ready_tx = Some(ready_tx);
    let mut reader = BufReader::new(stderr);
    let drain = tokio::spawn(async move {
        let mut forward = tokio::io::stderr();
        let mut raw = Vec::new();
        while matches!(reader.read_until(b'\n', &mut raw).await, Ok(read) if read > 0) {
            let line = String::from_utf8_lossy(&raw)
                .trim_end_matches(['\r', '\n'])
                .to_owned();
            raw.clear();
            if line.contains(READY_LINE)
                && let Some(ready) = ready_tx.take()
            {
                let _ = ready.send(());
            }
            match &sink {
                StderrSink::Forward => {
                    let _ = forward.write_all(format!("{line}\n").as_bytes()).await;
                }
                StderrSink::Capture(lines) => {
                    lines.lock().expect("stderr sink poisoned").push(line);
                }
            }
        }
    });
    (ready_rx, drain)
}

/// The stderr of a [`StdioSession::spawn_capturing_stderr`] child.
pub struct CapturedStderr {
    lines: Arc<Mutex<Vec<String>>>,
    drain: JoinHandle<()>,
}

impl CapturedStderr {
    fn contains(&self, needle: &str) -> bool {
        self.lines
            .lock()
            .expect("stderr sink poisoned")
            .iter()
            .any(|line| line.contains(needle))
    }
}
