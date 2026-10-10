// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Writing frames to a stdio child, and what a call that got no reply was
//! (MIK-7871, MIK-7979). Included by `#[path]` from `stdio.rs`.

use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::oneshot;
use tracing::debug;

use super::{StdioTransport, tree};
use crate::protocol::JsonRpcResponse;
use crate::transport::write_claim::WriteClaim;
use crate::{Error, Result};

impl StdioTransport {
    /// Write one frame to stdin, cancel-safely: see [`tree::write_frame`].
    pub(super) async fn write_message(&self, message: String) -> Result<()> {
        self.write_frame(message, &AtomicBool::new(false), None)
            .await
    }

    /// [`Self::write_message`], recording in `began` the moment the frame is
    /// committed to go out whole: a call that fails before it sent nothing.
    pub(super) async fn write_frame(
        &self,
        message: String,
        began: &AtomicBool,
        claim: Option<&WriteClaim>,
    ) -> Result<()> {
        debug!(message_len = message.len(), "Writing to stdin");
        tree::write_frame(&self.writer, &self.shutdown, message, began, claim).await?;
        tokio::task::yield_now().await;
        debug!("Write complete and flushed");
        Ok(())
    }

    /// One request's write and reply under one `request_timeout`, raced
    /// against this start's stdout-closed latch: a request never waits on a
    /// child whose stdout is gone (MIK-7871).
    pub(super) async fn exchange(
        &self,
        message: String,
        mut rx: oneshot::Receiver<JsonRpcResponse>,
        claim: Option<&WriteClaim>,
    ) -> Result<JsonRpcResponse> {
        // MIK-7871: stdout may have closed, and `pending` been cleared, before
        // the caller registered this reply. The reader trips the latch before it clears, so
        // either this sees it, or the clear drops the entry. Nothing is written
        // yet, so the refusal is pre-send (MIK-7979).
        let eof = self.start.eof_receiver();
        if eof.as_ref().is_some_and(|eof| *eof.borrow()) {
            return Err(Error::TransportConnect("stdout closed".to_string()));
        }
        let began = AtomicBool::new(false);
        // One deadline for the write and the reply: a child that stopped
        // reading stdin cannot hold the call past it.
        let exchange = tokio::time::timeout(self.request_timeout(), async {
            self.write_frame(message, &began, claim).await?;
            (&mut rx)
                .await
                .map_err(|_| Error::Transport("Response channel closed".to_string()))
        });
        let outcome = match eof {
            None => Some(exchange.await),
            Some(mut eof) => {
                // Not `wait_for`: its future is not `Send`, and this one has
                // to be. A dropped sender means this start's reader is gone.
                let closed = async move {
                    loop {
                        // Separate statements: the borrow must end before
                        // the await, or the read lock is held across it.
                        if *eof.borrow_and_update() {
                            break;
                        }
                        if eof.changed().await.is_err() {
                            break;
                        }
                    }
                };
                super::early_exit::reply_or_eof(exchange, closed).await
            }
        };
        match outcome {
            Some(Ok(reply)) => reply,
            Some(Err(_)) => Err(unsent_or(
                &began,
                "Request timed out",
                Error::BackendTimeout,
            )),
            // A reply routed while the write was still yielding is the answer.
            None => rx
                .try_recv()
                .map_err(|_| unsent_or(&began, "stdout closed", Error::Transport)),
        }
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
