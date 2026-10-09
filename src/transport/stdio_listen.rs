// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The events listener's side of a stdio child (MIK-7630 I5 design §4): a
//! modern `subscriptions/listen` written as a request that is not a pending
//! request (no timeout fires on it), and the legacy out-of-request stream.

use std::sync::{Arc, Weak};

use serde_json::{Value, json};

use super::StdioTransport;
use crate::transport::Transport;
use crate::transport::http::modern_listen_params;
use crate::transport::upstream_tap::{
    FrameStream, LegacyPin, Refused, Requested, UpstreamListen, Watched, interest_method,
    listen_filter,
};

/// Ends a listen upstream when its stream is dropped: stop routing to it and
/// tell the peer with `notifications/cancelled`.
struct CancelListen {
    transport: Weak<StdioTransport>,
    id: Value,
}

impl Drop for CancelListen {
    fn drop(&mut self) {
        let (transport, id) = (self.transport.clone(), self.id.clone());
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                if let Some(transport) = transport.upgrade() {
                    transport.taps.forget(&id);
                    let _ = transport
                        .notify("notifications/cancelled", Some(json!({"requestId": id})))
                        .await;
                }
            });
        }
    }
}

#[async_trait::async_trait]
impl UpstreamListen for StdioTransport {
    async fn listen(self: Arc<Self>, requested: Requested) -> Result<FrameStream, Refused> {
        let id = self.next_id();
        let id_value =
            serde_json::to_value(&id).map_err(|e| crate::Error::Protocol(e.to_string()))?;
        let params = modern_listen_params(
            "subscriptions/listen",
            Some(listen_filter(requested.kinds, &requested.uris)),
        )?;
        let rx = self.taps.listen(&id_value, requested);
        // Installed before the write: a cancelled open still forgets the tap
        // and tells the peer.
        let guard = CancelListen {
            transport: Arc::downgrade(&self),
            id: id_value,
        };
        let message = serde_json::to_string(&json!({
            "jsonrpc": "2.0", "id": id, "method": "subscriptions/listen", "params": params,
        }))
        .map_err(crate::Error::from)?;
        self.write_message(message).await?;
        Ok(FrameStream::guarded(rx, guard))
    }

    async fn unsolicited(self: Arc<Self>, watched: Watched) -> Result<FrameStream, Refused> {
        Ok(FrameStream::new(self.taps.unsolicited(watched)))
    }

    /// The process is the holder: a call on it lands nowhere else.
    async fn legacy_interest(
        self: Arc<Self>,
        _pin: LegacyPin,
        uri: &str,
        subscribe: bool,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        self.request(interest_method(subscribe), Some(json!({ "uri": uri })))
            .await
    }
}
