// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Request-scoped sink for a backend's notifications (`MIK-7272.SUB.2b`).
//!
//! A task-local rather than a registry keyed by progress token, for two
//! reasons. The invocation funnel between the router and the transport cannot
//! be widened -- `Transport::request` returns a bare `JsonRpcResponse` -- and no
//! channel exists from `AppState` down to a live transport: the `attach_era`
//! collaborator is built per backend inside the lifecycle, not threaded from
//! the gateway.
//!
//! The task-local also *is* the request scoping: two concurrent POSTs are two
//! tasks, so a notification can only ever be appended to the sink of the call
//! that provoked it. Nothing propagates across `tokio::spawn`, and nothing
//! between the router and the per-call transport code spawns.

use std::sync::{Arc, Mutex};

use crate::protocol::JsonRpcNotification;

/// Buffer one in-flight request collects its backend notifications into.
type Sink = Arc<Mutex<Vec<JsonRpcNotification>>>;

tokio::task_local! {
    static SINK: Sink;
}

/// Run `fut` with a fresh sink installed, yielding its output and whatever the
/// backend published while it ran.
pub(crate) async fn collect<F: Future>(fut: F) -> (F::Output, Vec<JsonRpcNotification>) {
    let sink: Sink = Arc::new(Mutex::new(Vec::new()));
    let out = SINK.scope(Arc::clone(&sink), fut).await;
    let mut guard = sink
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    (out, std::mem::take(&mut *guard))
}

/// Append notifications to the in-flight request's sink. A no-op outside one,
/// which covers every backend call that did not arrive on `POST /mcp` --
/// health probes, warm-up handshakes and the reaper all run outside a scope.
pub(crate) fn publish(notifications: Vec<JsonRpcNotification>) {
    if notifications.is_empty() {
        return;
    }
    let _ = SINK.try_with(|sink| {
        sink.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend(notifications);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn note(method: &str) -> JsonRpcNotification {
        JsonRpcNotification {
            jsonrpc: "2.0".to_string(),
            method: method.to_string(),
            params: None,
        }
    }

    #[tokio::test]
    async fn publish_outside_a_scope_is_dropped_not_panicked() {
        publish(vec![note("notifications/progress")]);
    }

    /// S-03 in miniature: the isolation is structural, so two concurrent
    /// scopes cannot see each other's notifications even under the same
    /// progress token.
    #[tokio::test]
    async fn concurrent_scopes_do_not_cross() {
        let left = collect(async {
            publish(vec![note("left")]);
            tokio::task::yield_now().await;
        });
        let right = collect(async {
            publish(vec![note("right")]);
            tokio::task::yield_now().await;
        });
        let ((), l) = tokio::spawn(left).await.unwrap();
        let ((), r) = tokio::spawn(right).await.unwrap();
        assert_eq!(l.len(), 1);
        assert_eq!(l[0].method, "left");
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].method, "right");
    }
}
