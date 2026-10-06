// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The events listener's side of a WebSocket (MIK-7630 I5 design §3): the
//! peer is legacy only, so there is no `subscriptions/listen`; the reader's
//! out-of-request notifications are the stream.

use std::sync::Arc;

use super::WebSocketTransport;
use crate::transport::Transport;
use crate::transport::upstream_tap::{
    FrameStream, LegacyPin, Refused, Requested, UpstreamListen, Watched, interest_method,
};

#[async_trait::async_trait]
impl UpstreamListen for WebSocketTransport {
    async fn listen(self: Arc<Self>, _requested: Requested) -> Result<FrameStream, Refused> {
        Err(Refused::Unsupported)
    }

    async fn unsolicited(self: Arc<Self>, watched: Watched) -> Result<FrameStream, Refused> {
        Ok(FrameStream::new(self.inner.taps.unsolicited(watched)))
    }

    /// The connection is the holder: a call on it lands nowhere else.
    async fn legacy_interest(
        self: Arc<Self>,
        _pin: LegacyPin,
        uri: &str,
        subscribe: bool,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        self.request(
            interest_method(subscribe),
            Some(serde_json::json!({ "uri": uri })),
        )
        .await
    }
}
