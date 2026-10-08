// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Writing one frame to a stdio child's stdin (split from `stdio.rs` for the
//! file-size ceiling).

use std::sync::atomic::{AtomicBool, Ordering};

use tokio::io::AsyncWriteExt;
use tracing::debug;

use super::StdioTransport;
use crate::{Error, Result};

/// The writer, held for one frame. Dropped before the frame is complete (a
/// write error or a cancelled caller), it retires stdin: the next frame would
/// otherwise be appended to half of this one, and later writes get
/// "Not connected" instead.
struct FrameWriter<'a> {
    writer: tokio::sync::MutexGuard<'a, Option<tokio::process::ChildStdin>>,
    connected: &'a AtomicBool,
    complete: bool,
}

impl Drop for FrameWriter<'_> {
    fn drop(&mut self) {
        if !self.complete {
            *self.writer = None;
            self.connected.store(false, Ordering::Relaxed);
        }
    }
}

impl StdioTransport {
    /// Write a message to stdin
    pub(super) async fn write_message(&self, message: &str) -> Result<()> {
        self.write_frame(message, &AtomicBool::new(false)).await
    }

    /// [`Self::write_message`], recording in `began` the moment a byte may
    /// leave: a call that fails before it sent nothing (MIK-7979).
    pub(super) async fn write_frame(&self, message: &str, began: &AtomicBool) -> Result<()> {
        debug!(message_len = message.len(), "Writing to stdin");
        let mut frame = FrameWriter {
            writer: self.writer.lock().await,
            connected: &self.connected,
            complete: false,
        };
        let Some(stdin) = frame.writer.as_mut() else {
            // Nothing was written, so there is nothing to retire, and the
            // failure is pre-send (MIK-7979).
            frame.complete = true;
            return Err(Error::TransportConnect("Not connected".to_string()));
        };
        began.store(true, Ordering::Relaxed);
        stdin
            .write_all(message.as_bytes())
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;
        stdin
            .write_all(b"\n")
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;
        stdin
            .flush()
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;
        frame.complete = true;
        // Drop the lock before yielding to allow concurrent reads
        drop(frame);
        // Yield to give the runtime a chance to process the I/O
        tokio::task::yield_now().await;
        debug!("Write complete and flushed");
        Ok(())
    }
}

/// The error for a call that ended without a reply. Before its first byte
/// could leave (`began` unset) nothing was sent, so it is pre-send
/// (`TransportConnect`, MIK-7979) and frees an idempotency key for the retry;
/// after, the round may have reached the backend, so it is `sent(message)`.
pub(super) fn unsent_or(began: &AtomicBool, message: &str, sent: fn(String) -> Error) -> Error {
    if began.load(Ordering::Relaxed) {
        sent(message.to_string())
    } else {
        Error::TransportConnect(format!("{message} before anything was sent"))
    }
}
