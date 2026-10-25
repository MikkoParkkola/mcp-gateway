// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! How a stdio session writes its answers and how it ends (moved out of
//! `server/mod.rs` with MIK-8895, which added the shutdown half).
//!
//! - [`Gateway::run_stdout_writer`]: the one task that owns stdout.
//! - [`Gateway::stdio_stop_signal`]: Ctrl+C and SIGTERM, registered early.
//! - [`Gateway::join_stdout_writer`]: the writer's bounded join at the end.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tracing::{debug, warn};

use super::Gateway;

impl Gateway {
    /// Ctrl+C and SIGTERM end stdio the way stdin EOF does: stop reading,
    /// drain what was accepted, then `stop_all`. Without this a signal killed
    /// stdio outright, and since each backend leads its own process group
    /// (MIK-8895) nothing else would end the backends' trees. The release line
    /// does the same (MIK-8364).
    ///
    /// Polled once here, before any backend can start, so the OS handlers are
    /// registered from the call on rather than from the read loop's first
    /// poll. `true` when a signal had already arrived.
    pub(super) fn stdio_stop_signal() -> (Pin<Box<dyn Future<Output = ()> + Send>>, bool) {
        let (signal_tx, _) = tokio::sync::broadcast::channel(1);
        let mut stop_signal: Pin<Box<dyn Future<Output = ()> + Send>> =
            Box::pin(super::support::shutdown_signal(signal_tx));
        let signalled = futures::FutureExt::now_or_never(stop_signal.as_mut()).is_some();
        (stop_signal, signalled)
    }

    /// Join the stdout writer within `bound`, aborting it past the bound: a
    /// client that stopped reading leaves a write pending on a full pipe, and
    /// an unbounded join would never reach the backend teardown after it.
    pub(super) async fn join_stdout_writer(
        mut writer: tokio::task::JoinHandle<()>,
        bound: Duration,
    ) {
        match tokio::time::timeout(bound, &mut writer).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => warn!(%error, "stdio: the stdout writer did not finish cleanly"),
            Err(_) => {
                warn!(timeout = ?bound, "stdio: stdout writer stuck; aborting it");
                writer.abort();
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
