// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The command preview's transport: one child's stdin and stdout, used for a
//! handful of sequential calls and then dropped.
//!
//! A preview asks one question at a time, so there is no reader task and no
//! table of waiting calls: a request writes its line and reads frames until
//! its own answer arrives. What the server sends besides that answer is
//! answered (its own requests get a fixed refusal) or dropped, and nothing of
//! it is kept. The first failure ends the pipe for good and is kept as a
//! closed kind, so a caller can say what went wrong without repeating
//! anything the server wrote.
#![cfg_attr(
    not(all(test, unix)),
    expect(dead_code, reason = "the preview route calls it")
)]

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use async_trait::async_trait;
use serde_json::Value;
use tokio::io::{AsyncWriteExt as _, BufReader};
use tokio::process::{ChildStdin, ChildStdout};

use super::Transport;
use super::stdio::read_frame;
use crate::gateway::health_metrics::clock::{backend_request, backend_wait};
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::{Error, Result};

/// Longest single frame the preview reads.
const FRAME_CAP: usize = 4 * 1024 * 1024;
/// Most bytes the preview reads from one server, over all its frames.
const TOTAL_CAP: usize = 8 * 1024 * 1024;

/// Why a preview pipe stopped. Closed set: none of these carries anything the
/// server sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PipeFailure {
    /// End of the server's output before the answer.
    OutputEnded,
    /// A write to the server failed.
    InputClosed,
    /// A frame that is no JSON-RPC message.
    NotJsonRpc,
    /// One frame longer than [`FRAME_CAP`].
    FrameOverCap,
    /// More than [`TOTAL_CAP`] read in all.
    OverBudget,
}

impl std::fmt::Display for PipeFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::OutputEnded => "the server's output ended before it answered",
            Self::InputClosed => "the server stopped reading its input",
            Self::NotJsonRpc => "the server sent a frame that is not JSON-RPC",
            Self::FrameOverCap => "a frame over the preview's 4 MiB limit",
            Self::OverBudget => "more than the preview's 8 MiB in total",
        })
    }
}

/// The two pipes and what a request needs between calls, under one lock.
struct Wire {
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    next_id: i64,
    left: usize,
    frame: Vec<u8>,
}

/// A [`Transport`] over a preview child's stdin and stdout.
pub(crate) struct PreviewPipe {
    wire: tokio::sync::Mutex<Wire>,
    failure: parking_lot::Mutex<Option<PipeFailure>>,
    closed: AtomicBool,
    refused: AtomicU64,
}

impl PreviewPipe {
    /// A pipe over a child's two standard streams.
    pub(crate) fn new(stdin: ChildStdin, stdout: ChildStdout) -> Self {
        Self {
            wire: tokio::sync::Mutex::new(Wire {
                stdin: Some(stdin),
                stdout: BufReader::new(stdout),
                next_id: 1,
                left: TOTAL_CAP,
                frame: Vec::new(),
            }),
            failure: parking_lot::Mutex::new(None),
            closed: AtomicBool::new(false),
            refused: AtomicU64::new(0),
        }
    }

    /// The first failure, once there is one.
    pub(crate) fn failure(&self) -> Option<PipeFailure> {
        *self.failure.lock()
    }

    /// How many of the server's own requests got the fixed refusal.
    pub(crate) fn client_requests_refused(&self) -> u64 {
        self.refused.load(Ordering::Relaxed)
    }

    /// Keeps `kind` unless an earlier failure is already kept, and returns
    /// the error every later call gets too.
    fn fail(&self, kind: PipeFailure) -> Error {
        let kept = *self.failure.lock().get_or_insert(kind);
        Error::Transport(kept.to_string())
    }

    /// Refuses a call on a pipe that already failed or was closed.
    fn still_open(&self) -> Result<()> {
        match self.failure() {
            Some(kind) => Err(Error::Transport(kind.to_string())),
            None if self.closed.load(Ordering::Relaxed) => {
                Err(Error::Transport("the preview pipe is closed".to_string()))
            }
            None => Ok(()),
        }
    }

    async fn write_line(&self, wire: &mut Wire, line: String) -> Result<()> {
        let Some(stdin) = wire.stdin.as_mut() else {
            return Err(self.fail(PipeFailure::InputClosed));
        };
        let mut bytes = line.into_bytes();
        bytes.push(b'\n');
        if stdin.write_all(&bytes).await.is_err() || stdin.flush().await.is_err() {
            return Err(self.fail(PipeFailure::InputClosed));
        }
        Ok(())
    }

    /// The next frame, counted against the total before it is parsed.
    async fn read_value(&self, wire: &mut Wire) -> Result<Value> {
        let Wire {
            stdout,
            frame,
            left,
            ..
        } = wire;
        let line = match read_frame(stdout, frame, FRAME_CAP).await {
            Ok(Some(line)) => line,
            Err(error) if error.kind() == std::io::ErrorKind::InvalidData => {
                let not_utf8 = matches!(
                    error.get_ref(),
                    Some(inner) if inner.is::<std::string::FromUtf8Error>()
                );
                return Err(self.fail(if not_utf8 {
                    PipeFailure::NotJsonRpc
                } else {
                    PipeFailure::FrameOverCap
                }));
            }
            // The end of the stream, or a read that failed: either way the
            // output ended before the answer.
            Ok(None) | Err(_) => return Err(self.fail(PipeFailure::OutputEnded)),
        };
        let Some(rest) = left.checked_sub(line.len()) else {
            return Err(self.fail(PipeFailure::OverBudget));
        };
        *left = rest;
        serde_json::from_str(&line).map_err(|_| self.fail(PipeFailure::NotJsonRpc))
    }
}

/// The fixed answer to a server's own request, echoing its id as sent.
fn refusal_line(id: &Value) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":{id},"error":{{"code":-32601,"message":"the preview does not serve client methods"}}}}"#
    )
}

impl PreviewPipe {
    /// One request: its line out, then frames until its own answer.
    async fn exchange(&self, method: &str, params: Option<Value>) -> Result<JsonRpcResponse> {
        let mut wire = self.wire.lock().await;
        self.still_open()?;
        let id = wire.next_id;
        wire.next_id += 1;
        let mut call = serde_json::json!({"jsonrpc": "2.0", "id": id, "method": method});
        if let Some(params) = params {
            call["params"] = params;
        }
        self.write_line(&mut wire, call.to_string()).await?;
        loop {
            let value = self.read_value(&mut wire).await?;
            if let Some(named) = value.get("method") {
                // Only a string names a method: anything else in that member
                // is neither a request nor a notification.
                if !named.is_string() {
                    return Err(self.fail(PipeFailure::NotJsonRpc));
                }
                // A request gets the refusal; a notification is dropped.
                if let Some(their_id) = value.get("id") {
                    let line = refusal_line(their_id);
                    self.write_line(&mut wire, line).await?;
                    self.refused.fetch_add(1, Ordering::Relaxed);
                }
                continue;
            }
            let answer: JsonRpcResponse =
                serde_json::from_value(value).map_err(|_| self.fail(PipeFailure::NotJsonRpc))?;
            // An answer to an id this pipe never sent is dropped.
            if answer.id == Some(RequestId::Number(id)) {
                return Ok(answer);
            }
        }
    }

    /// One notification's line out.
    async fn send_note(&self, method: &str, params: Option<Value>) -> Result<()> {
        let mut wire = self.wire.lock().await;
        self.still_open()?;
        let mut note = serde_json::json!({"jsonrpc": "2.0", "method": method});
        if let Some(params) = params {
            note["params"] = params;
        }
        self.write_line(&mut wire, note.to_string()).await
    }
}

// Each send is measured as a wait on the server, as for every transport.
#[async_trait]
impl Transport for PreviewPipe {
    async fn request(&self, method: &str, params: Option<Value>) -> Result<JsonRpcResponse> {
        backend_request(self.exchange(method, params)).await
    }

    async fn notify(&self, method: &str, params: Option<Value>) -> Result<()> {
        backend_wait(self.send_note(method, params)).await
    }

    fn is_connected(&self) -> bool {
        !self.closed.load(Ordering::Relaxed) && self.failure().is_none()
    }

    async fn close(&self) -> Result<()> {
        self.closed.store(true, Ordering::Relaxed);
        self.wire.lock().await.stdin = None;
        Ok(())
    }
}

#[cfg(tp5)]
#[cfg(all(test, unix))]
#[path = "preview_pipe_tests.rs"]
mod tests;
