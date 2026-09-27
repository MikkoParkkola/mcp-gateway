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
                    {
                        let mut tail = shared.lock();
                        if tail.len() == TAIL_LINES {
                            tail.pop_front();
                        }
                        tail.push_back(buf.clone());
                    }
                    // Published first, so a held pipe cannot lose the prefix.
                    if n == RAW_LINE_BYTES && !buf.ends_with(b"\n") {
                        discard_rest_of_line(&mut reader).await;
                    }
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
    // Matched line by line, so a multi-line value (a PEM key) is matched by
    // each of its own lines, and normalised as the lines are, so a value with
    // its own control characters still matches; longest first, so a value
    // that is a prefix of another cannot break the longer one's match.
    let mut secrets: Vec<String> = argv
        .iter()
        .chain(env.values())
        .flat_map(|s| s.lines())
        .map(|s| s.chars().filter(|c| !c.is_control()).collect::<String>())
        .map(|s| s.trim().to_string())
        .filter(|s| s.len() >= 4)
        .collect();
    secrets.sort_by_key(|s| std::cmp::Reverse(s.len()));
    secrets.dedup();
    let secrets: Vec<&str> = secrets.iter().map(String::as_str).collect();
    let lines: Vec<String> = tail.iter().map(|raw| redact_line(raw, &secrets)).collect();
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

/// One stderr line, normalised first (lossy UTF-8, control characters out, a
/// character split by the read limit dropped) so redaction sees what the log
/// will show, then redacted, then cut to [`LINE_CHARS`]. Without the `firewall`
/// feature there is no credential recogniser, so the line is withheld.
fn redact_line(raw: &[u8], secrets: &[&str]) -> String {
    let cut_on_read = raw.len() == RAW_LINE_BYTES && !raw.ends_with(b"\n");
    let whole = if cut_on_read {
        without_split_char(raw)
    } else {
        raw
    };
    let mut line: String = String::from_utf8_lossy(whole)
        .chars()
        .filter(|c| !c.is_control())
        .collect();
    for secret in secrets {
        line = line.replace(secret, "[REDACTED]");
        if cut_on_read {
            mask_secret_head(&mut line, secret);
        }
    }
    recognise(line, RECOGNISER)
        .chars()
        .take(LINE_CHARS)
        .collect()
}

/// Whether this build can recognise credential-shaped text in stderr.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Recogniser {
    /// The firewall redactor masks what it recognises.
    Firewall,
    /// No recogniser is built in, so the text is withheld outright.
    Absent,
}

/// This build's recogniser: a value, so both arms are testable in any build.
pub(super) const RECOGNISER: Recogniser = if cfg!(feature = "firewall") {
    Recogniser::Firewall
} else {
    Recogniser::Absent
};

/// Placeholder for a line no recogniser could vet.
pub(super) const WITHHELD: &str = "[stderr withheld: built without the firewall redactor]";

/// Mask credential-shaped text, or withhold the line when nothing can.
pub(super) fn recognise(line: String, recogniser: Recogniser) -> String {
    match recogniser {
        Recogniser::Firewall => firewall_redact(line),
        Recogniser::Absent => WITHHELD.to_string(),
    }
}

#[cfg(feature = "firewall")]
fn firewall_redact(line: String) -> String {
    let mut value = serde_json::Value::String(line);
    crate::security::firewall::redactor::Redactor::new().scan_and_redact(&mut value);
    value.as_str().unwrap_or_default().to_string()
}

/// Never selected without the feature (see [`RECOGNISER`]); withholds if it were.
#[cfg(not(feature = "firewall"))]
fn firewall_redact(_line: String) -> String {
    WITHHELD.to_string()
}

/// `raw` without a trailing incomplete UTF-8 sequence, whatever precedes it:
/// a character the read limit split would otherwise decode to U+FFFD and hide
/// the secret head before it from [`mask_secret_head`].
fn without_split_char(raw: &[u8]) -> &[u8] {
    for back in 1..=3.min(raw.len()) {
        let byte = raw[raw.len() - back];
        let width = match byte {
            0xC0..=0xDF => 2,
            0xE0..=0xEF => 3,
            0xF0..=0xF7 => 4,
            0x80..=0xBF => continue,
            _ => return raw,
        };
        return if width > back {
            &raw[..raw.len() - back]
        } else {
            raw
        };
    }
    raw
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
