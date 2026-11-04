// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! [`Transport`] for the WebSocket transport: a request and its answer, a
//! notification, and close (moved from `websocket.rs`).

use std::sync::atomic::Ordering;

use async_trait::async_trait;
use serde_json::Value;
use tokio::sync::oneshot;

use super::{McpFrame, ProgressRegistration, WebSocketTransport, cancel};
use crate::gateway::health_metrics::clock::{backend_request, backend_wait};
use crate::protocol::{JsonRpcRequest, JsonRpcResponse};
use crate::transport::write_claim::WriteClaim;
use crate::transport::{PendingRequestGuard, Transport};
use crate::{Error, Result};

#[async_trait]
impl Transport for WebSocketTransport {
    fn redacts_injected_values(&self) -> bool {
        self.inner.needles.get().is_some()
    }

    async fn request(&self, method: &str, params: Option<Value>) -> Result<JsonRpcResponse> {
        backend_request(async move {
            let id = self.next_id();
            let request = JsonRpcRequest {
                jsonrpc: "2.0".to_string(),
                id: id.clone(),
                method: method.to_string(),
                params,
            };

            // Register before the send: the I/O task can route progress back
            // before `send_message` returns, and an unregistered token is dropped.
            let _progress_cleanup = ProgressRegistration::register(
                &self.inner.progress_destinations,
                request.params.as_ref(),
            );

            let (tx, rx) = oneshot::channel();
            self.inner.pending.insert(id.to_string(), tx);
            // See StdioTransport::request: removing the entry is the guard's job
            // so a request future dropped by an OUTER timeout or task abort does
            // not strand its `pending` entry.
            let _cleanup = PendingRequestGuard::new(&self.inner.pending, &id.to_string());
            // Declared after `_cleanup`, so it drops first and still finds the
            // entry of a request nobody answered.
            let claim = WriteClaim::new();
            let mut cancel = cancel::CancelUnanswered::arm(&self.inner, &request, &claim);

            let msg = McpFrame::Request(request).to_ws_message()?;
            // The timeout covers the enqueue too: a full queue behind a stalled
            // writer must not outlast the configured backend timeout.
            let exchange = async {
                self.enqueue((msg, Some(claim))).await?;
                Ok::<_, Error>(rx.await)
            };
            let outcome = tokio::time::timeout(self.timeout, exchange).await;
            // Finished, answered or failed: the transport's own timeout is not a
            // cancel (design Q1).
            cancel.disarm();
            let answer = match outcome {
                Ok(Ok(Ok(response))) => Ok(response),
                Ok(Err(e)) => Err(e),
                Ok(Ok(Err(_))) => Err(Error::Transport(
                    "WebSocket connection closed before the response arrived".to_string(),
                )),
                Err(_) => Err(Error::BackendTimeout(
                    "WebSocket request timed out".to_string(),
                )),
            };
            // Scrubbed on the call's own task (the reader routes the answer as
            // sent), as the body's last step: a redacted answer stays the
            // backend's, and a refusal is an error `Error::origin` counts as
            // the gateway's.
            match self.inner.needles.get() {
                Some(needles) => crate::security::needles::scrub_answer(needles, answer),
                None => answer,
            }
        })
        .await
    }

    async fn notify(&self, method: &str, params: Option<Value>) -> Result<()> {
        backend_wait(async move {
            let msg = McpFrame::Notification {
                method: method.to_string(),
                params,
            }
            .to_ws_message()?;
            self.send_message(msg).await
        })
        .await
    }

    fn is_connected(&self) -> bool {
        self.inner.connected.load(Ordering::Relaxed)
    }

    async fn close(&self) -> Result<()> {
        self.inner.connected.store(false, Ordering::Relaxed);

        // Dropping the sender closes the outbound channel, which causes the I/O
        // task to send a WebSocket close frame and exit cleanly.
        self.inner.outbound_tx.lock().await.take();

        // Abort the task (safe to call even after it has already exited).
        if let Some(h) = self.inner.task.lock().take() {
            h.abort();
        }

        // The aborted task skips its own cleanup: fail in-flight calls here so
        // they do not wait out their timeouts.
        self.inner.pending.clear();
        self.inner.taps.clear();

        Ok(())
    }
}
