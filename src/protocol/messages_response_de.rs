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
            /// `Some(Value::Null)` when the peer sent `"result": null`: that is
            /// a result (JSON-RPC 2.0 section 5), unlike an absent member.
            #[serde(default, deserialize_with = "present")]
            result: Option<Value>,
            error: Option<JsonRpcError>,
            /// Present, `null` included: a plain `Option` maps null to `None`,
            /// which let `"method": null` through as a response (MIK-8019).
            #[serde(default, deserialize_with = "present")]
            method: Option<Value>,
        }

        let shadow = Shadow::deserialize(deserializer)?;
        if shadow.method.is_some() {
            return Err(serde::de::Error::custom(
                "frame carries `method`: a request or notification, not a response",
            ));
        }
        // A `null` beside an error is the peer spelling "no result": an error
        // response carries no `result`, so it stays absent.
        let result = match (shadow.result, &shadow.error) {
            (Some(Value::Null), Some(_)) => None,
            (result, _) => result,
        };
        Ok(Self {
            jsonrpc: shadow.jsonrpc,
            ..Self::envelope(shadow.id, result, shadow.error)
        })
    }
}

/// A member that is present, `null` included; `#[serde(default)]` supplies
/// `None` only when it is absent.
fn present<'de, D>(deserializer: D) -> std::result::Result<Option<Value>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Value::deserialize(deserializer).map(Some)
}
