// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Progress routing for the WebSocket transport (stdio parity), split out
//! of `websocket.rs` to keep that file under the size ceiling.

use serde_json::Value;
use tracing::{debug, warn};

use super::Inner;
use crate::protocol::JsonRpcNotification;
use crate::transport::notification_sink::DeliveryHandle;

/// Deliver a `notifications/progress` to the call that supplied its token.
///
/// Same rules as `StdioTransport::capture_notification`: progress only (a
/// token stamped on `notifications/message` must not bypass the caller's level
/// filter), and a frame with no token, or a token no live call registered, is
/// dropped rather than given an invented owner.
pub(super) fn route_progress(inner: &Inner, notification: JsonRpcNotification) {
    let token = (notification.method == "notifications/progress")
        .then(|| {
            notification
                .params
                .as_ref()
                .and_then(|p| p.get("progressToken"))
                .and_then(progress_token_string)
        })
        .flatten();
    // `deliver` uses `try_send`: this runs on the I/O task, which must never
    // park on a slow caller.
    if let Some(destination) = token.and_then(|t| inner.progress_destinations.get(&t)) {
        destination.deliver(notification);
    } else {
        debug!(method = %notification.method, "Ignoring WebSocket notification");
    }
}

/// A progress token is a string or a number on the wire; the map is keyed by
/// its string form so both spellings of one token agree.
fn progress_token_string(token: &Value) -> Option<String> {
    match token {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// Hold a call's progress registration exactly as long as its request future,
/// so success, error, timeout and cancellation all retire it.
///
/// Vacant-only: a token already live belongs to another call, and overwriting
/// it would reroute that call's progress here. The loser owns nothing and
/// must remove nothing. Mirrors stdio's `ProgressRegistrationGuard`.
pub(super) struct ProgressRegistration<'a> {
    destinations: &'a dashmap::DashMap<String, DeliveryHandle>,
    token: Option<String>,
}

impl<'a> ProgressRegistration<'a> {
    /// Register the token under `params._meta.progressToken`, if any.
    ///
    /// Must run on the caller's task: `DeliveryHandle::capture` reads the
    /// caller's task-locals, which the I/O task does not have.
    pub(super) fn register(
        destinations: &'a dashmap::DashMap<String, DeliveryHandle>,
        params: Option<&Value>,
    ) -> Self {
        let wanted = params
            .and_then(|p| p.get("_meta"))
            .and_then(|meta| meta.get("progressToken"))
            .and_then(progress_token_string);
        let token = match wanted {
            None => None,
            Some(token) => match destinations.entry(token.clone()) {
                dashmap::mapref::entry::Entry::Vacant(slot) => {
                    slot.insert(DeliveryHandle::capture(&token));
                    Some(token)
                }
                dashmap::mapref::entry::Entry::Occupied(_) => {
                    // ci-allow-secret-log: a minted progress token is a correlation id, not a credential
                    warn!(
                        token = %token,
                        "progress token is already registered to a live call; refusing to reroute it"
                    );
                    None
                }
            },
        };
        Self {
            destinations,
            token,
        }
    }
}

impl Drop for ProgressRegistration<'_> {
    fn drop(&mut self) {
        if let Some(token) = &self.token {
            self.destinations.remove(token);
        }
    }
}
