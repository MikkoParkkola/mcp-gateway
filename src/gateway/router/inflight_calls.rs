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
//! the router's caller key (`identity::caller_key`): the authorized subject,
//! re-derived from a certificate rather than its display-name fallback, else
//! the authenticated credential. A caller with neither is never registered,
//! so its cancels are always dropped. The session is the validated MCP
//! session id, or none for a sessionless caller.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use futures::future::{AbortHandle, AbortRegistration};
use parking_lot::Mutex;
use serde_json::Value;

/// The JSON-RPC code a call aborted by its caller's own cancel is answered
/// with: the request was cancelled (MCP's `RequestCancelled`).
pub(crate) const CLIENT_CANCELLED_CODE: i32 = -32800;
/// Its message.
pub(crate) const CLIENT_CANCELLED_MESSAGE: &str = "Request cancelled by the client";

/// The dispatch, aborted by its caller's own explicit cancel. Aborting drops
/// it, and the transport's guard cancels the call on the backend by the
/// backend's id. An abort becomes the [`is_client_cancelled`] error, which
/// the direct route answers -32800 and settles an idempotency key on as it
/// does any error that may follow a committed side effect (ADR-012
/// consequence 1).
pub(crate) async fn explicitly_cancellable<T>(
    cancel_on: Option<CancelOn>,
    dispatch: impl std::future::Future<Output = crate::Result<T>>,
) -> crate::Result<T> {
    let Some(cancel_on) = cancel_on else {
        return dispatch.await;
    };
    cancel_on.run(dispatch).await.unwrap_or_else(|| {
        Err(crate::Error::JsonRpc {
            code: CLIENT_CANCELLED_CODE,
            message: CLIENT_CANCELLED_MESSAGE.to_owned(),
            data: None,
        })
    })
}

/// Whether a call failed because its own caller cancelled it: its dispatch
/// was actually aborted (not merely asked to be, after it had finished), and
/// `error` is the one [`explicitly_cancellable`] answers that abort with. So
/// a backend that returns the same error is never mistaken for the caller's
/// cancel, even when a cancel lands just after its answer.
pub(crate) fn cancelled_by_caller(
    entry: Option<&Registered>,
    error: Option<&crate::Error>,
) -> bool {
    entry.is_some_and(Registered::cancelled) && error.is_some_and(is_client_cancelled)
}

/// Whether `e` is the error [`explicitly_cancellable`] answers an abort with.
fn is_client_cancelled(e: &crate::Error) -> bool {
    matches!(e, crate::Error::JsonRpc { code, message, data: None }
        if *code == CLIENT_CANCELLED_CODE && message == CLIENT_CANCELLED_MESSAGE)
}

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
    /// `None` without an owner (an empty caller key): such a caller's call is
    /// never registered.
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
    pub(crate) fn register(self: &Arc<Self>, key: CallKey) -> Option<(Registered, CancelOn)> {
        let mut calls = self.calls.lock();
        if calls.contains_key(&key) {
            return None;
        }
        let (handle, registration) = AbortHandle::new_pair();
        calls.insert(key.clone(), handle);
        let aborted = Arc::new(AtomicBool::new(false));
        Some((
            Registered {
                calls: Arc::clone(self),
                key,
                aborted: Arc::clone(&aborted),
            },
            CancelOn {
                registration,
                aborted,
            },
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
    aborted: Arc<AtomicBool>,
}

impl Registered {
    /// Whether the caller's own cancel aborted this call's dispatch: its
    /// failure is then the client's choice, not the backend's or the
    /// gateway's. Set only when the dispatch yielded to the abort, never by a
    /// cancel that arrived after it finished.
    pub(crate) fn cancelled(&self) -> bool {
        self.aborted.load(Ordering::SeqCst)
    }
}

/// The abort half of a registration, taken by the one dispatch the call
/// makes.
pub(crate) struct CancelOn {
    registration: AbortRegistration,
    aborted: Arc<AtomicBool>,
}

impl CancelOn {
    /// Run `call` until it finishes or the caller's own cancel aborts it
    /// (`None`), recording an abort for [`Registered::cancelled`].
    pub(crate) async fn run<F: std::future::Future>(self, call: F) -> Option<F::Output> {
        let outcome = futures::future::Abortable::new(call, self.registration).await;
        if outcome.is_err() {
            self.aborted.store(true, Ordering::SeqCst);
        }
        outcome.ok()
    }
}

impl Drop for Registered {
    fn drop(&mut self) {
        self.calls.calls.lock().remove(&self.key);
    }
}

#[cfg(test)]
#[path = "inflight_calls_tests.rs"]
mod tests;
