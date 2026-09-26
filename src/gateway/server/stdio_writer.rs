// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The single stdout writer the stdio serve loop queues every frame on.

use tokio::io::AsyncWriteExt;
use tracing::{debug, warn};

use super::Gateway;

impl Gateway {
    pub(super) async fn run_stdout_writer_prio<W: tokio::io::AsyncWrite + Unpin>(
        mut sink: W,
        mut queue: tokio::sync::mpsc::Receiver<serde_json::Value>,
        mut bridge: tokio::sync::mpsc::Receiver<serde_json::Value>,
    ) {
        loop {
            let frame = tokio::select! {
                biased;
                Some(frame) = bridge.recv() => frame,
                Some(frame) = queue.recv() => frame,
                else => break,
            };
            if !Self::write_response(&mut sink, &frame).await {
                queue.close();
                break;
            }
        }
    }

    /// Drain `queue` onto `sink`, closing the queue once the sink is gone.
    ///
    /// A dead sink ends the writer: staying open would let the dispatch tasks
    /// keep executing requests whose answers are already being thrown away.
    /// Closing the queue makes every producer's `send` fail and `is_closed`
    /// true, which is the signal the read loop stops admitting on.
    pub(super) async fn run_stdout_writer<W: tokio::io::AsyncWrite + Unpin>(
        mut sink: W,
        mut queue: tokio::sync::mpsc::Receiver<serde_json::Value>,
    ) {
        while let Some(frame) = queue.recv().await {
            if !Self::write_response(&mut sink, &frame).await {
                queue.close();
                break;
            }
        }
    }

    /// Write a JSON-RPC response to stdout followed by a newline.
    /// `false` when the frame did not reach `stdout`, which the stdio writer
    /// reads as "the pipe is gone" rather than "this one frame was lost".
    async fn write_response<W: tokio::io::AsyncWrite + Unpin>(
        stdout: &mut W,
        value: &serde_json::Value,
    ) -> bool {
        let serialized = match serde_json::to_string(value) {
            Ok(s) => s,
            Err(e) => {
                // Serialisation is this frame's problem, not the pipe's.
                warn!(error = %e, "Failed to serialize response");
                return true;
            }
        };
        debug!(response_len = serialized.len(), "stdio: writing response");
        if let Err(e) = stdout.write_all(serialized.as_bytes()).await {
            warn!(error = %e, "Failed to write to stdout");
            return false;
        }
        if let Err(e) = stdout.write_all(b"\n").await {
            warn!(error = %e, "Failed to write newline to stdout");
            return false;
        }
        if let Err(e) = stdout.flush().await {
            warn!(error = %e, "Failed to flush stdout");
            return false;
        }
        true
    }
}
