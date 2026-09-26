// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A stdio child that dies before `initialize` (#526).
//!
//! Such a child used to be reported after the full request timeout, as a
//! timeout, while its stderr, which named the cause, had already been read and
//! dropped. Now the start notices stdout closing, and reports the exit status.
//!
//! The child's stderr never reaches an MCP client: it is another program's
//! output and can hold secrets, and a transport error travels to the client
//! verbatim. The returned error names the exit status and points at the
//! gateway log; the bounded, redacted tail goes to that log and to
//! `doctor --start-stdio`, through [`StdioTransport::start_failure_excerpt`].

use std::collections::{HashMap, VecDeque};

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::ChildStderr;
use tracing::{debug, warn};

use super::StdioTransport;
use crate::{Error, Result};

/// Lines of stderr kept; the tail, since the cause is usually printed last.
const TAIL_LINES: usize = 20;
/// Characters kept of one line.
const LINE_CHARS: usize = 256;
/// Bytes kept of the whole excerpt.
const EXCERPT_BYTES: usize = 2048;
/// How long the start waits for the exit status and the last stderr bytes.
const DRAIN: std::time::Duration = std::time::Duration::from_secs(1);

/// Read stderr to its end, keeping the last [`TAIL_LINES`] lines.
///
/// `read_until`, not `lines()`: a child killed mid-write leaves a last line
/// with no newline, and that is often the one that names the cause.
pub(super) fn spawn_stderr_tail(
    stderr: ChildStderr,
    command: String,
) -> tokio::task::JoinHandle<VecDeque<String>> {
    tokio::spawn(async move {
        let mut reader = BufReader::new(stderr);
        let mut tail = VecDeque::with_capacity(TAIL_LINES);
        let mut buf = Vec::new();
        loop {
            buf.clear();
            match reader.read_until(b'\n', &mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    debug!(command = %command, line_len = n, "Received line from stderr");
                    if tail.len() == TAIL_LINES {
                        tail.pop_front();
                    }
                    tail.push_back(clean_line(&buf));
                }
            }
        }
        tail
    })
}

/// One line, lossy UTF-8, control characters dropped, cut to [`LINE_CHARS`].
fn clean_line(raw: &[u8]) -> String {
    String::from_utf8_lossy(raw)
        .chars()
        .filter(|c| !c.is_control())
        .take(LINE_CHARS)
        .collect()
}

/// The tail as one excerpt, with every secret the gateway handed the child
/// (argv arguments, `env:` values) and every recognisable credential replaced,
/// capped at [`EXCERPT_BYTES`] from the end.
pub(super) fn excerpt(
    tail: &VecDeque<String>,
    argv: &[String],
    env: &HashMap<String, String>,
) -> String {
    let mut text = tail.iter().cloned().collect::<Vec<_>>().join("\n");
    let secrets = argv.iter().chain(env.values()).filter(|s| s.len() >= 4);
    for secret in secrets {
        text = text.replace(secret.as_str(), "[REDACTED]");
    }
    #[cfg(feature = "firewall")]
    {
        let mut value = serde_json::Value::String(text);
        crate::security::firewall::redactor::Redactor::new().scan_and_redact(&mut value);
        text = value.as_str().unwrap_or_default().to_string();
    }
    if text.len() > EXCERPT_BYTES {
        let mut cut = text.len() - EXCERPT_BYTES;
        while !text.is_char_boundary(cut) {
            cut += 1;
        }
        text = text[cut..].to_string();
    }
    text
}

/// Per-start state: the stdout-closed latch (fresh each start, so a previous
/// generation's exit cannot answer this one), whether the race saw it, and the
/// excerpt of the last early exit.
#[derive(Default)]
pub(super) struct StartState {
    eof: parking_lot::Mutex<Option<tokio::sync::watch::Receiver<bool>>>,
    exited: std::sync::atomic::AtomicBool,
    failure: parking_lot::Mutex<Option<String>>,
}

impl StartState {
    pub(super) fn begin(&self, eof: tokio::sync::watch::Receiver<bool>) {
        *self.eof.lock() = Some(eof);
        self.exited
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }

    pub(super) fn exited_early(&self) -> bool {
        self.exited.swap(false, std::sync::atomic::Ordering::SeqCst)
    }
}

impl StdioTransport {
    /// The redacted stderr tail of the last start that ended in an early exit.
    ///
    /// For the gateway log and `doctor`, never for an MCP client.
    #[must_use]
    pub(crate) fn start_failure_excerpt(&self) -> Option<String> {
        self.start.failure.lock().clone()
    }

    /// The `initialize` request, raced against this start's stdout closing.
    pub(super) async fn init_request(
        &self,
        params: serde_json::Value,
    ) -> Result<crate::protocol::JsonRpcResponse> {
        use crate::transport::Transport as _;
        let Some(mut eof) = self.start.eof.lock().clone() else {
            return self.request("initialize", Some(params)).await;
        };
        tokio::select! {
            // A reply read before EOF has resolved its request already, so the
            // request wins a tie: a child that answered and then exited has
            // still answered.
            biased;
            response = self.request("initialize", Some(params)) => response,
            _ = eof.wait_for(|closed| *closed) => {
                self.start.exited.store(true, std::sync::atomic::Ordering::SeqCst);
                Err(Error::Transport("stdout closed before initialize".to_string()))
            }
        }
    }

    /// Turn an early exit into its report: the exit status for the caller,
    /// the redacted stderr tail for the log. Kills a child that closed stdout
    /// but is still running.
    pub(super) async fn early_exit_error(
        &self,
        stderr_tail: tokio::task::JoinHandle<VecDeque<String>>,
        argv: &[String],
    ) -> Error {
        let child = self.child.lock().await.take();
        let status = match child {
            Some(mut child) => {
                if let Ok(Ok(status)) = tokio::time::timeout(DRAIN, child.wait()).await {
                    Some(status)
                } else {
                    let _ = child.kill().await;
                    None
                }
            }
            None => None,
        };
        let abort = stderr_tail.abort_handle();
        let tail = if let Ok(Ok(tail)) = tokio::time::timeout(DRAIN, stderr_tail).await {
            tail
        } else {
            abort.abort();
            VecDeque::new()
        };
        let excerpt = excerpt(&tail, argv, &self.env);
        let command = self.diagnostic_command();
        let what = match status {
            Some(status) => format!("exited before initialize ({status})"),
            None => "closed its stdout before initialize".to_string(),
        };
        warn!(command = %command, stderr = %excerpt, "stdio backend {what}");
        *self.start.failure.lock() = Some(excerpt);
        Error::Transport(format!(
            "stdio backend {command} {what}; its stderr is in the gateway log"
        ))
    }
}

#[cfg(all(test, unix))]
#[path = "stdio_early_exit_tests.rs"]
mod tests;
