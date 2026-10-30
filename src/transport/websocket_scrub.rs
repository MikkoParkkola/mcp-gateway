// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What a WebSocket transport does with backend text: a frame is scrubbed of
//! the backend's injected values before it is routed, and a close reason is
//! logged by its length.

use tracing::debug;

use super::McpFrame;
use crate::protocol::JsonRpcNotification;

/// Logs a close frame by its code and the length of its reason: the reason
/// is backend text.
pub(super) fn log_close(frame: Option<&tokio_tungstenite::tungstenite::protocol::CloseFrame>) {
    debug!(
        code = ?frame.map(|f| f.code),
        reason_len = frame.map_or(0, |f| f.reason.len()),
        "WebSocket close frame received"
    );
}

/// Removes the injected values from `frame`; `false` when it is withheld. A
/// refused answer is replaced with the fixed refusal under its own `id`, so
/// the call still gets its answer.
pub(super) fn scrub_frame(
    needles: &crate::security::needles::NeedleSet,
    frame: &mut McpFrame,
) -> bool {
    use crate::protocol::JsonRpcMessage;
    use crate::security::needles::{
        Scrubbed, ingress_scrub, refused_response, scrub_response_with,
    };
    match frame {
        McpFrame::Response(response) => {
            if scrub_response_with(needles, response) == Scrubbed::Refuse {
                *response = refused_response(needles, response.id.clone());
            }
            true
        }
        McpFrame::Notification { method, params } => {
            let mut message = JsonRpcMessage::Notification(JsonRpcNotification {
                jsonrpc: "2.0".to_string(),
                method: std::mem::take(method),
                params: params.take(),
            });
            let outcome = ingress_scrub(needles, &mut message);
            if let JsonRpcMessage::Notification(notification) = message {
                *method = notification.method;
                *params = notification.params;
            }
            matches!(outcome, Scrubbed::Clean | Scrubbed::Redacted)
        }
        // A server-initiated request is only logged, never relayed.
        McpFrame::Request(_) | McpFrame::Ping | McpFrame::Pong => true,
    }
}
