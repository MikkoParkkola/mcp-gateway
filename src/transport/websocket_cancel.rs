// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `MIK-7642.PR.B`: a websocket request dropped before its answer cancels the
//! backend's call, if its frame was written, by the id the backend received.

use std::sync::Arc;

use tracing::debug;

use super::{Inner, McpFrame};
use crate::protocol::{JsonRpcRequest, RequestId};
use crate::transport::write_claim::WriteClaim;

/// Armed for one request; disarmed once the request finished, answered or
/// failed. Owns clones only, so it can send after its caller is gone.
pub(super) struct CancelUnanswered {
    inner: Arc<Inner>,
    key: String,
    id: RequestId,
    claim: Arc<WriteClaim>,
    armed: bool,
}

impl CancelUnanswered {
    /// Never armed for `initialize`, which the protocol forbids cancelling.
    pub(super) fn arm(
        inner: &Arc<Inner>,
        request: &JsonRpcRequest,
        claim: &Arc<WriteClaim>,
    ) -> Self {
        Self {
            inner: Arc::clone(inner),
            key: request.id.to_string(),
            id: request.id.clone(),
            claim: Arc::clone(claim),
            armed: request.method != "initialize",
        }
    }

    pub(super) fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for CancelUnanswered {
    fn drop(&mut self) {
        // Removing the entry is the arbitration with the reader, which removes
        // it before delivering: exactly one of {answer, cancel} wins.
        if !self.armed || self.inner.pending.remove(&self.key).is_none() || !self.claim.abandon() {
            return;
        }
        let frame = McpFrame::Notification {
            method: "notifications/cancelled".to_string(),
            params: Some(serde_json::json!({
                "requestId": self.id,
                "reason": "the gateway's caller abandoned the request",
            })),
        };
        let (Ok(message), Ok(runtime)) =
            (frame.to_ws_message(), tokio::runtime::Handle::try_current())
        else {
            debug!("websocket: cancel not sent; the backend finishes the call");
            return;
        };
        let inner = Arc::clone(&self.inner);
        // Queued behind the request frame on the one writer, so never ahead
        // of it and never inside it.
        runtime.spawn(async move {
            let sender = inner.outbound_tx.lock().await.clone();
            if let Some(sender) = sender {
                drop(sender.send((message, None)).await);
            }
        });
    }
}
