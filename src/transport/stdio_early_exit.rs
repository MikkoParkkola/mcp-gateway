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
//! gateway log; the bounded, redacted tail goes to that log record, as its
//! `stderr` field, which is where `doctor --start-stdio` reads it too.

use std::collections::{HashMap, VecDeque};

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
/// Characters kept of one line, cut after redaction.
const LINE_CHARS: usize = 256;
/// Bytes kept of the whole excerpt.
const EXCERPT_BYTES: usize = 2048;
/// How long the start waits for the exit status and the last stderr bytes.
const DRAIN: std::time::Duration = std::time::Duration::from_secs(1);

/// The last [`TAIL_LINES`] raw stderr lines, shared so a reader that never
/// finishes (a grandchild holding the pipe) can still be read after abort.
pub(super) type StderrTail = std::sync::Arc<parking_lot::Mutex<VecDeque<Vec<u8>>>>;

/// Read stderr to its end into a bounded tail.
///
/// `read_until`, not `lines()`: a child killed mid-write leaves a last line
/// with no newline, and that is often the one that names the cause.
pub(super) fn spawn_stderr_tail(
    stderr: ChildStderr,
    command: String,
) -> (tokio::task::JoinHandle<()>, StderrTail) {
    let tail = StderrTail::default();
    let shared = std::sync::Arc::clone(&tail);
    let task = tokio::spawn(async move {
        let mut reader = BufReader::new(stderr);
        let mut buf = Vec::with_capacity(RAW_LINE_BYTES);
        loop {
            buf.clear();
            let limit = RAW_LINE_BYTES as u64;
            match (&mut reader).take(limit).read_until(b'\n', &mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    debug!(command = %command, line_len = n, "Received line from stderr");
                    if n == RAW_LINE_BYTES && !buf.ends_with(b"\n") {
                        discard_rest_of_line(&mut reader).await;
                    }
                    let mut tail = shared.lock();
                    if tail.len() == TAIL_LINES {
                        tail.pop_front();
                    }
                    tail.push_back(buf.clone());
                }
            }
        }
    });
    (task, tail)
}

/// Skip to the end of an overlong line in bounded chunks.
async fn discard_rest_of_line(reader: &mut BufReader<ChildStderr>) {
    let mut scratch = Vec::with_capacity(RAW_LINE_BYTES);
    loop {
        scratch.clear();
        match (&mut *reader)
            .take(RAW_LINE_BYTES as u64)
            .read_until(b'\n', &mut scratch)
            .await
        {
            Ok(n) if n == RAW_LINE_BYTES && !scratch.ends_with(b"\n") => {}
            _ => return,
        }
    }
}

/// The tail as one excerpt. Each line is redacted whole (every secret the
/// gateway handed the child: argv arguments, `env:` values, and every
/// recognisable credential) BEFORE it is cut, so a cut can never split a
/// secret out of the reach of its match. A line cut at [`RAW_LINE_BYTES`] on
/// read can still end in the head of a secret; that fragment is masked too.
pub(super) fn excerpt(
    tail: &VecDeque<Vec<u8>>,
    argv: &[String],
    env: &HashMap<String, String>,
) -> String {
    let secrets: Vec<&String> = argv
        .iter()
        .chain(env.values())
        .filter(|s| s.len() >= 4)
        .collect();
    let lines: Vec<String> = tail
        .iter()
        .map(|raw| {
            let cut_on_read = raw.len() == RAW_LINE_BYTES && !raw.ends_with(b"\n");
            let mut line: String = String::from_utf8_lossy(raw).chars().take(LINE_CHARS).collect();
            for secret in &secrets {
                line = line.replace(secret.as_str(), "[REDACTED]");
                if cut_on_read {
                    mask_secret_head(&mut line, secret);
                }
            }
            #[cfg(feature = "firewall")]
            {
                let mut value = serde_json::Value::String(line);
                crate::security::firewall::redactor::Redactor::new().scan_and_redact(&mut value);
                line = value.as_str().unwrap_or_default().to_string();
            }
            line.chars()
                .filter(|c| !c.is_control())
                .take(LINE_CHARS)
                .collect()
        })
        .collect();
    let mut text = lines.join("\n");
    if text.len() > EXCERPT_BYTES {
        let mut cut = text.len() - EXCERPT_BYTES;
        while !text.is_char_boundary(cut) {
            cut += 1;
        }
        text = text[cut..].to_string();
    }
    text
}

/// Replace the end of a line cut at the read limit when it is the first bytes
/// of `secret`: the fragment the cut left behind.
fn mask_secret_head(line: &mut String, secret: &str) {
    let body = line.len();
    let longest = (1..secret.len().min(body + 1))
        .rev()
        .find(|&k| secret.is_char_boundary(k) && line[..body].ends_with(&secret[..k]));
    if let Some(k) = longest {
        line.replace_range(body - k..body, "[REDACTED]");
    }
}

/// Per-start state: the stdout-closed latch (fresh each start, so a previous
/// generation's exit cannot answer this one) and whether the race saw it. Tests
/// also keep the excerpt of the last early exit.
#[derive(Default)]
pub(super) struct StartState {
    eof: parking_lot::Mutex<Option<tokio::sync::watch::Receiver<bool>>>,
    exited: std::sync::atomic::AtomicBool,
    #[cfg(all(test, unix))]
    failure: parking_lot::Mutex<Option<String>>,
}

impl StartState {
    pub(super) fn begin(&self, eof: tokio::sync::watch::Receiver<bool>) {
        *self.eof.lock() = Some(eof);
        // An excerpt describes the last start only.
        #[cfg(all(test, unix))]
        {
            *self.failure.lock() = None;
        }
        self.exited
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }

    pub(super) fn exited_early(&self) -> bool {
        self.exited.swap(false, std::sync::atomic::Ordering::SeqCst)
    }
}

impl StdioTransport {
    /// The redacted stderr tail of the last start that ended in an early exit,
    /// as the log record carried it.
    #[cfg(all(test, unix))]
    pub(super) fn start_failure_excerpt(&self) -> Option<String> {
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
        // `wait_for` reads the current value first, so the clone sees an EOF
        // the select arm already saw.
        let mut after_error = eof.clone();
        let response = tokio::select! {
            // A reply read before EOF has resolved its request already, so the
            // request wins a tie: a child that answered and then exited has
            // still answered.
            biased;
            response = self.request("initialize", Some(params)) => response,
            _ = eof.wait_for(|closed| *closed) => {
                self.start.exited.store(true, std::sync::atomic::Ordering::SeqCst);
                return Err(Error::Transport("stdout closed before initialize".to_string()));
            }
        };
        // A child that died before reading fails the write (EPIPE) before its
        // stdout closes; stdout closing within the drain window makes that the
        // same early exit. Awaited after the select, whose watch futures are
        // not `Send`, and `matches!` drops the guard at once.
        if response.is_err()
            && matches!(
                tokio::time::timeout(DRAIN, after_error.wait_for(|closed| *closed)).await,
                Ok(Ok(_))
            )
        {
            self.start
                .exited
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
        response
    }

    /// Turn an early exit into its report: the exit status for the caller,
    /// the redacted stderr tail for the log. Kills a child that closed stdout
    /// but is still running.
    pub(super) async fn early_exit_error(
        &self,
        stderr_tail: (tokio::task::JoinHandle<()>, StderrTail),
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
        let (reader, tail) = stderr_tail;
        let abort = reader.abort_handle();
        if tokio::time::timeout(DRAIN, reader).await.is_err() {
            // Something still holds the pipe; keep what was read so far.
            abort.abort();
        }
        let excerpt = excerpt(&tail.lock(), argv, &self.env);
        let command = self.diagnostic_command();
        let what = match status {
            Some(status) => format!("exited before initialize ({status})"),
            None => "closed its stdout before initialize".to_string(),
        };
        // `doctor --start-stdio` reads this record's `stderr` field.
        warn!(command = %command, stderr = %excerpt, "stdio backend {what}");
        #[cfg(all(test, unix))]
        {
            *self.start.failure.lock() = Some(excerpt);
        }
        Error::Transport(format!(
            "stdio backend {command} {what}; its stderr is in the gateway log"
        ))
    }
}

#[cfg(all(test, unix))]
#[path = "stdio_early_exit_tests.rs"]
mod tests;
