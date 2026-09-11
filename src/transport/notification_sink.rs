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
//!
//! The payload is a **bounded channel, not a buffer** (ADR-014 §1). A `Vec`
//! drained after the future resolves preserves wire ordering but cannot
//! deliver a notification while the call that raised it is still in flight,
//! which is the whole requirement. [`scope`] therefore hands the receiving end
//! back to the caller so a consumer can drain it *concurrently* with the
//! request.

use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::mpsc;

use crate::protocol::JsonRpcNotification;

/// Notifications one in-flight request may have outstanding before the sink
/// starts shedding them (ADR-014 §5 overflow policy).
const REQUEST_NOTIFICATION_DEPTH: usize = 64;

tokio::task_local! {
    static SINK: mpsc::Sender<JsonRpcNotification>;
}

/// Notifications dropped because a request's sink was full. Monotonic for the
/// life of the process; overflow is a symptom worth seeing in aggregate.
static DROPPED: AtomicU64 = AtomicU64::new(0);

/// Install a fresh sink around `fut` and hand back its receiving end.
///
/// The returned future owns the sending end, so the receiver observes close
/// exactly when the request finishes. Drain the receiver concurrently with
/// polling the future -- that concurrency is what makes a notification
/// reachable while its call is still running.
pub(crate) fn scope<F: Future>(
    fut: F,
) -> (
    impl Future<Output = F::Output>,
    mpsc::Receiver<JsonRpcNotification>,
) {
    let (tx, rx) = mpsc::channel(REQUEST_NOTIFICATION_DEPTH);
    (SINK.scope(tx, fut), rx)
}

/// Run `fut` under a sink, draining alongside it, and yield its output with
/// everything the backend published while it ran.
///
/// The drain runs concurrently rather than after, so this is a convenience
/// over [`scope`] for callers that have nowhere to stream to -- not a return
/// to collect-then-emit.
pub(crate) async fn collect<F: Future>(fut: F) -> (F::Output, Vec<JsonRpcNotification>) {
    let (scoped, mut rx) = scope(fut);
    let mut drained = Vec::new();
    tokio::pin!(scoped);
    let out = loop {
        tokio::select! {
            Some(notification) = rx.recv() => drained.push(notification),
            out = &mut scoped => break out,
        }
    };
    while let Ok(notification) = rx.try_recv() {
        drained.push(notification);
    }
    (out, drained)
}

/// Publish notifications to the in-flight request's sink. A no-op outside one,
/// which covers every backend call that did not arrive on `POST /mcp` --
/// health probes, warm-up handshakes and the reaper all run outside a scope.
///
/// Never blocks and never awaits: a full sink drops and counts, because
/// stalling a backend response to buffer a progress update inverts the
/// priority the notification exists to serve.
pub(crate) fn publish(notifications: Vec<JsonRpcNotification>) {
    if notifications.is_empty() {
        return;
    }
    let _ = SINK.try_with(|tx| {
        for notification in notifications {
            if tx.try_send(notification).is_err() {
                let total = DROPPED.fetch_add(1, Ordering::Relaxed) + 1;
                tracing::warn!(
                    dropped_total = total,
                    capacity = REQUEST_NOTIFICATION_DEPTH,
                    "request notification sink full; dropping notification"
                );
            }
        }
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

    /// The liveness property the `Vec` payload could not offer: a notification
    /// is readable while the future that raised it is still pending.
    #[tokio::test]
    async fn a_notification_is_readable_before_its_request_finishes() {
        let gate = std::sync::Arc::new(tokio::sync::Semaphore::new(0));
        let backend_gate = std::sync::Arc::clone(&gate);
        let (scoped, mut rx) = scope(async move {
            publish(vec![note("notifications/progress")]);
            let _permit = backend_gate.acquire().await.unwrap();
            "result"
        });
        tokio::pin!(scoped);

        let early = tokio::select! {
            received = rx.recv() => received,
            _ = &mut scoped => panic!("the request resolved before the gate was released"),
        };

        assert_eq!(early.unwrap().method, "notifications/progress");
        gate.add_permits(1);
        assert_eq!(scoped.await, "result");
    }

    /// ADR-014 §5: past capacity the sink sheds rather than stalling the call.
    #[tokio::test]
    async fn an_overfull_sink_drops_and_counts_instead_of_blocking() {
        let before = DROPPED.load(Ordering::Relaxed);
        let ((), drained) = collect(async {
            publish(
                (0..REQUEST_NOTIFICATION_DEPTH + 8)
                    .map(|_| note("flood"))
                    .collect(),
            );
        })
        .await;

        assert_eq!(drained.len(), REQUEST_NOTIFICATION_DEPTH);
        assert_eq!(DROPPED.load(Ordering::Relaxed) - before, 8);
    }
}
