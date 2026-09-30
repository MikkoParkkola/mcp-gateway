// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `Deserialize` for [`JsonRpcResponse`], written by hand: a frame carrying
//! `method` is a request or a notification, never a response. Its own file to
//! keep `messages.rs` under the file-size ratchet.

use serde::Deserialize;
use serde_json::Value;

use super::{JsonRpcError, JsonRpcResponse, RequestId};

impl<'de> Deserialize<'de> for JsonRpcResponse {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        /// Mirrors [`JsonRpcResponse`] and additionally observes `method`, the
        /// field that marks a frame as a request or a notification.
        #[derive(Deserialize)]
        struct Shadow {
            jsonrpc: String,
            id: Option<RequestId>,
            result: Option<Value>,
            error: Option<JsonRpcError>,
            method: Option<serde::de::IgnoredAny>,
        }

        let shadow = Shadow::deserialize(deserializer)?;
        if shadow.method.is_some() {
            return Err(serde::de::Error::custom(
                "frame carries `method`: a request or notification, not a response",
            ));
        }
        Ok(Self {
            jsonrpc: shadow.jsonrpc,
            id: shadow.id,
            result: shadow.result,
            error: shadow.error,
            confirmation_refusal: false,
            delivery_refusal: false,
            discovery_inspected: false,
        })
    }
}
