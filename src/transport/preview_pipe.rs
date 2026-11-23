// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The command preview's transport: one child's stdin and stdout, used for a
//! handful of sequential calls and then dropped.
//!
//! STUB for the rows commit: it takes the first frame as the answer, keeps no
//! failure and has no size limits. The next commit replaces it.
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
use crate::protocol::JsonRpcResponse;
use crate::{Error, Result};

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
    /// One frame longer than the preview's frame limit.
    FrameOverCap,
    /// More than the preview's total read in all.
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
    frame: Vec<u8>,
}

/// A [`Transport`] over a preview child's stdin and stdout.
pub(crate) struct PreviewPipe {
    wire: tokio::sync::Mutex<Wire>,
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
                frame: Vec::new(),
            }),
            closed: AtomicBool::new(false),
            refused: AtomicU64::new(0),
        }
    }

    /// The first failure, once there is one (stub: never).
    pub(crate) fn failure(&self) -> Option<PipeFailure> {
        let _ = self;
        None
    }

    /// How many of the server's own requests got the fixed refusal.
    pub(crate) fn client_requests_refused(&self) -> u64 {
        self.refused.load(Ordering::Relaxed)
    }

    async fn write_line(wire: &mut Wire, line: String) -> Result<()> {
        let Some(stdin) = wire.stdin.as_mut() else {
            return Err(Error::Transport("stub".to_string()));
        };
        let mut bytes = line.into_bytes();
        bytes.push(b'\n');
        stdin
            .write_all(&bytes)
            .await
            .map_err(|_| Error::Transport("stub".to_string()))
    }
}

#[async_trait]
impl Transport for PreviewPipe {
    async fn request(&self, method: &str, params: Option<Value>) -> Result<JsonRpcResponse> {
        let mut wire = self.wire.lock().await;
        let id = wire.next_id;
        wire.next_id += 1;
        let mut call = serde_json::json!({"jsonrpc": "2.0", "id": id, "method": method});
        if let Some(params) = params {
            call["params"] = params;
        }
        Self::write_line(&mut wire, call.to_string()).await?;
        let Wire { stdout, frame, .. } = &mut *wire;
        let line = read_frame(stdout, frame, 16 * 1024 * 1024)
            .await
            .ok()
            .flatten()
            .ok_or_else(|| Error::Transport("stub".to_string()))?;
        serde_json::from_str(&line).map_err(|_| Error::Transport("stub".to_string()))
    }

    async fn notify(&self, method: &str, params: Option<Value>) -> Result<()> {
        let mut wire = self.wire.lock().await;
        let mut note = serde_json::json!({"jsonrpc": "2.0", "method": method});
        if let Some(params) = params {
            note["params"] = params;
        }
        Self::write_line(&mut wire, note.to_string()).await
    }

    fn is_connected(&self) -> bool {
        !self.closed.load(Ordering::Relaxed)
    }

    async fn close(&self) -> Result<()> {
        self.closed.store(true, Ordering::Relaxed);
        self.wire.lock().await.stdin = None;
        Ok(())
    }
}

#[cfg(all(test, unix))]
#[path = "preview_pipe_tests.rs"]
mod tests;
