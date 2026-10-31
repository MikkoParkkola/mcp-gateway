// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What a WebSocket transport does with backend text: a notification is
//! scrubbed of the backend's injected values before it is published (an
//! answer is scrubbed by its call), and a close reason is logged by its
//! length.

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

/// Removes the injected values from a notification `frame`; `false` when it
/// is withheld. An answer passes as sent, for its call to scrub.
pub(super) fn scrub_frame(
    needles: &crate::security::needles::NeedleSet,
    frame: &mut McpFrame,
) -> bool {
    use crate::protocol::JsonRpcMessage;
    use crate::security::needles::{Scrubbed, ingress_scrub};
    match frame {
        // An answer goes to its call as sent: the call scrubs it on its own
        // task, so a rewrite lands on that call's delivery record.
        McpFrame::Response(_) => true,
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
