// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Explicit client cancels of in-flight backend calls (MIK-7642 PR.C; design
//! r5 D3 and D5, r4 R4.2).
//!
//! A call is registered under the caller's own key while it runs, and a
//! client's `notifications/cancelled` aborts only the call registered under
//! that same key. Aborting drops the backend dispatch, and the transport's
//! own guard then cancels the call on the backend by the backend's id (PR.B):
//! the client's id is never forwarded.
//!
//! The key is (scope, owner, session, client request id). The scope is the
//! backend name on the direct route, or the `/mcp` route itself. The owner is
//! the resolved authorized subject, or the credential principal when there is
//! no subject; a caller with neither is never registered, so its cancels are
//! always dropped. The session is the validated MCP session id, or none for a
//! sessionless caller.

use std::collections::HashMap;
use std::sync::Arc;

use futures::future::{AbortHandle, AbortRegistration};
use parking_lot::Mutex;
use serde_json::Value;

/// Whose call, where, and which of their requests.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct CallKey {
    scope: String,
    owner: String,
    session: Option<String>,
    /// The client's JSON-RPC id in its wire form, so `7` and `"7"` differ.
    client_id: String,
}

impl CallKey {
    /// `None` without an owner: such a caller's call is never registered.
    pub(crate) fn new(
        scope: &str,
        owner: Option<&str>,
        session: Option<&str>,
        client_id: &Value,
    ) -> Option<Self> {
        let owner = owner.filter(|owner| !owner.is_empty())?;
        Some(Self {
            scope: scope.to_owned(),
            owner: owner.to_owned(),
            session: session.map(str::to_owned),
            client_id: client_id.to_string(),
        })
    }
}

/// The calls that can be cancelled right now.
#[derive(Default)]
pub(crate) struct InFlightCalls {
    calls: Mutex<HashMap<CallKey, AbortHandle>>,
}

impl InFlightCalls {
    /// Register a call. `None` when a live call already holds this key (D5):
    /// JSON-RPC forbids reusing a live id, so the second call cannot be
    /// cancelled explicitly, and the first stays untouched.
    pub(crate) fn register(
        self: &Arc<Self>,
        key: CallKey,
    ) -> Option<(Registered, AbortRegistration)> {
        let mut calls = self.calls.lock();
        if calls.contains_key(&key) {
            return None;
        }
        let (handle, registration) = AbortHandle::new_pair();
        calls.insert(key.clone(), handle);
        Some((
            Registered {
                calls: Arc::clone(self),
                key,
            },
            registration,
        ))
    }

    /// Abort the call registered under `key`. `false` when none is: the
    /// cancel is dropped.
    pub(crate) fn cancel(&self, key: &CallKey) -> bool {
        self.calls.lock().get(key).map(AbortHandle::abort).is_some()
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.calls.lock().len()
    }
}

/// A live registration, dropped when the call finishes however it finishes.
/// Only a registered call holds one, so a refused duplicate can never
/// unregister the live call (D5), and a key is reused only after its holder
/// has dropped.
pub(crate) struct Registered {
    calls: Arc<InFlightCalls>,
    key: CallKey,
}

impl Drop for Registered {
    fn drop(&mut self) {
        self.calls.calls.lock().remove(&self.key);
    }
}

#[cfg(test)]
#[path = "inflight_calls_tests.rs"]
mod tests;
