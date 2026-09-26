// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The shipped binary over stdio, for suites that need a real serve loop.
//!
//! Included by `#[path]` from each suite that drives one, so an item only one
//! suite uses is dead in the other; that is the layout, not a defect.
#![allow(dead_code)]

use std::path::Path;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::time::timeout;

/// Bound on one read. Generous enough for a cold child, far below the shipped
/// bridge's 30s/120s bounds, which nothing here should ever wait on.
pub const READ_TIMEOUT: Duration = Duration::from_secs(10);

/// The shipped binary, spawned the way a stdio client spawns it.
pub struct StdioSession {
    child: Child,
    /// Taken by [`Self::close_stdin`]: EOF is the stimulus of the drain row,
    /// and the session has to outlive it to read what the drain writes.
    stdin: Option<ChildStdin>,
    stdout: Lines<BufReader<ChildStdout>>,
}

impl StdioSession {
    pub fn spawn(home: &Path) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_mcp-gateway"));
        command
            .arg("serve")
            .arg("--stdio")
            .current_dir(home)
            .env("HOME", home);
        // The developer's own environment must not decide what this child
        // connects to.
        for (name, _) in std::env::vars() {
            if name.starts_with("MCP_GATEWAY_") {
                command.env_remove(name);
            }
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // Inherited rather than piped: an undrained stderr pipe deadlocks
            // the child once its logs fill the buffer.
            .stderr(Stdio::inherit())
            // The kill that survives a panicking assertion. `shutdown` is the
            // orderly path; this is the one that runs when a row fails.
            .kill_on_drop(true)
            .spawn()
            .expect("spawn gateway over stdio");
        let stdin = child.stdin.take().expect("child stdin");
        let stdout = BufReader::new(child.stdout.take().expect("child stdout")).lines();
        Self {
            child,
            stdin: Some(stdin),
            stdout,
        }
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

    /// Drain stdout for a fixed window and return the raw lines.
    ///
    /// The whole drain is under one timeout rather than each read, so a chatty
    /// child cannot keep this alive indefinitely: the window expires, the
    /// caller gets what arrived, and the row asserts on it.
    pub async fn collect_lines(&mut self, window: Duration) -> Vec<String> {
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
    /// inherited, for rows whose evidence is a log line.
    ///
    /// The pipe is drained continuously on its own task: an undrained stderr
    /// pipe deadlocks the child once its logs fill the buffer (the reason
    /// `spawn` inherits). `RUST_LOG` is set explicitly because the child's
    /// `EnvFilter::try_from_default_env()` wins over its `--log-level`, so an
    /// ambient value in the test environment could silence the lines read here.
    pub fn spawn_capturing_stderr(home: &Path) -> (Self, CapturedStderr) {
        let mut command = Command::new(env!("CARGO_BIN_EXE_mcp-gateway"));
        command
            .arg("serve")
            .arg("--stdio")
            .current_dir(home)
            .env("HOME", home)
            .env("RUST_LOG", "info");
        for (name, _) in std::env::vars() {
            if name.starts_with("MCP_GATEWAY_") {
                command.env_remove(name);
            }
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn gateway over stdio");
        let stdin = child.stdin.take().expect("child stdin");
        let stdout = BufReader::new(child.stdout.take().expect("child stdout")).lines();
        let mut stderr = BufReader::new(child.stderr.take().expect("child stderr")).lines();
        let lines: Arc<Mutex<Vec<String>>> = Arc::default();
        let sink = Arc::clone(&lines);
        let drain = tokio::spawn(async move {
            while let Ok(Some(line)) = stderr.next_line().await {
                sink.lock().expect("stderr sink poisoned").push(line);
            }
        });
        let session = Self {
            child,
            stdin: Some(stdin),
            stdout,
        };
        (session, CapturedStderr { lines, drain })
    }

    /// One stdout line: `Err` when `bound` expires, `Ok(None)` when stdout ended.
    pub async fn next_line(
        &mut self,
        bound: Duration,
    ) -> Result<Option<String>, tokio::time::error::Elapsed> {
        timeout(bound, self.stdout.next_line())
            .await
            .map(|read| read.ok().flatten())
    }

    /// End a capturing session and return every stderr line it wrote.
    ///
    /// Order matters: stdin closes first and the child is killed only after it
    /// has logged `EOF_LINE` (or `EOF_WAIT` passes), because a kill that lands
    /// before the child reads EOF suppresses the one line that proves the
    /// capture works. The drain is then joined through EOF, so no count read
    /// from the result races a line still in the pipe.
    pub async fn finish_capturing(mut self, captured: CapturedStderr) -> Vec<String> {
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
        let _ = captured.drain.await;
        std::mem::take(&mut *captured.lines.lock().expect("stderr sink poisoned"))
    }
}

/// The child's own log line on reaching EOF (`gateway/server/mod.rs`): a fixed
/// string whose absence from a capture names a broken capture, not a quiet child.
pub const EOF_LINE: &str = "stdio: EOF reached, shutting down";

/// How long [`StdioSession::finish_capturing`] waits for [`EOF_LINE`].
const EOF_WAIT: Duration = Duration::from_secs(10);

/// The stderr of a [`StdioSession::spawn_capturing_stderr`] child.
pub struct CapturedStderr {
    lines: Arc<Mutex<Vec<String>>>,
    drain: tokio::task::JoinHandle<()>,
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
