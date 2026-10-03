// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Progress-token bookkeeping of the stdio transport, split out of
//! `stdio.rs` to keep that file under the size ceiling.

use serde_json::Value;

use super::StdioTransport;
/// A progress token is a string or a number on the wire; the capture map is
/// keyed by its string form so both spellings of one token agree.
pub(super) fn progress_token_string(token: &Value) -> Option<String> {
    match token {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// The caller's progress token as an outgoing request carries it.
///
/// Note the asymmetry with `capture_notification`: a request carries the token
/// under `params._meta`, while an incoming `notifications/progress` carries it
/// as a direct member of `params`. Reading the wrong shape here leaves the
/// stdio leg dead while the HTTP one still looks green.
pub(super) fn request_progress_token(params: Option<&Value>) -> Option<String> {
    params
        .and_then(|p| p.get("_meta"))
        .and_then(|meta| meta.get("progressToken"))
        .and_then(progress_token_string)
}

/// Keep a progress-token registration alive exactly as long as its request,
/// and drain it wherever that request ends.
///
/// `register_progress_token` inserts and only a drain removes, so every exit
/// path has to reach one. A drain written as a statement after the await
/// reaches three of them -- success, a write error, the internal timeout --
/// and misses the fourth: an OUTER timeout or a task abort drops the in-flight
/// request future mid-await, the statement never runs, and the entry lives for
/// the transport's lifetime. That is growth rather than misrouting, because
/// `gw-<uuid>` keys never collide and a stranded entry cannot capture another
/// call's notifications, but it is unbounded growth.
///
/// This is `crate::transport::PendingRequestGuard`'s counterpart: same problem,
/// same shape, the other map. Drop publishes what was captured, so all four
/// paths drain through one place. Publishing outside a notification scope is a
/// no-op, which is what a cancelled request wants.
pub(super) struct ProgressRegistrationGuard<'a> {
    transport: &'a StdioTransport,
    token: String,
    /// Whether this guard's registration is the one in the map.
    ///
    /// `false` when the token was already registered to a live call. The
    /// guard still exists -- construction has no failure mode the request
    /// path can act on -- but it owns nothing and must retire nothing.
    owns_registration: bool,
}

impl<'a> ProgressRegistrationGuard<'a> {
    /// Register `token` on `transport` and hold it for the guard's lifetime.
    #[must_use]
    pub(super) fn register(transport: &'a StdioTransport, token: &str) -> Self {
        let owns_registration = transport.register_progress_token(token);
        Self {
            transport,
            token: token.to_string(),
            owns_registration,
        }
    }
}

impl Drop for ProgressRegistrationGuard<'_> {
    fn drop(&mut self) {
        if self.owns_registration {
            self.transport.deregister_progress_token(&self.token);
        }
    }
}
