// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Deadline helpers for the Try-a-tool rows, and the row that stalls the path to the send.

use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use serde_json::Value;

use super::ui_tool_call_tests::{
    ADMIN, Fx, SERVER, SLOW_GATE_BOUND, Stub, call, fixture, post, sent,
};
use crate::backend::Backend;
use crate::config::{BackendConfig, FailsafeConfig};

/// The deadline the deadline rows give the route; how long `slow` waits for
/// its gate at most; how long a row waits for the route's answer. Each is
/// shorter than the next: with the route's deadline broken, `slow` answers
/// 200 inside the post bound, so the row fails on its 504 check, never hangs.
pub(super) const ROW_DEADLINE: Duration = Duration::from_secs(2);
pub(super) const POST_BOUND: Duration = Duration::from_secs(10);
const _: () = {
    assert!(ROW_DEADLINE.as_millis() < SLOW_GATE_BOUND.as_millis());
    assert!(SLOW_GATE_BOUND.as_millis() < POST_BOUND.as_millis());
};

/// Gives the route a test deadline until dropped. Dropping clears it, so a
/// row that panics mid-way leaves no short deadline on a reused thread.
pub(super) struct TestDeadline;

impl TestDeadline {
    pub(super) fn set(deadline: Duration) -> Self {
        crate::gateway::ui::DEADLINE_FOR_TEST.with(|d| d.set(Some(deadline)));
        Self
    }
}

impl Drop for TestDeadline {
    fn drop(&mut self) {
        crate::gateway::ui::DEADLINE_FOR_TEST.with(|d| d.set(None));
    }
}

/// Puts `alpha` back with `stub` answering it. Its catalogue stays cold.
pub(super) fn install(fx: &Fx, stub: Stub) {
    let backend = Arc::new(Backend::new(
        SERVER,
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    backend.set_transport_for_test(Arc::new(stub));
    assert!(fx.state.backends.register(backend), "registration");
}

/// [`install`]s a stub whose `slow` waits on the returned gate, then fills
/// its catalogue, so the call reaches its send without a list fetch.
pub(super) async fn install_slow_gated(fx: &Fx) -> Arc<tokio::sync::Notify> {
    let gate = Arc::new(tokio::sync::Notify::new());
    install(
        fx,
        Stub {
            calls: Arc::clone(&fx.calls),
            declares_read: true,
            list_gate: None,
            list_entered: None,
            slow_gate: Some(Arc::clone(&gate)),
        },
    );
    fx.state
        .backends
        .get(SERVER)
        .expect("alpha is registered")
        .get_tools_shared()
        .await
        .expect("the catalogue is warm");
    gate
}

/// Posts `slow` as the admin under [`ROW_DEADLINE`] and returns the answer.
/// The stub's `slow_gate` opens only once that answer is in hand, so the
/// deadline fires before the tool can answer; whether the call was sent by
/// then is what the row checks. No answer within [`POST_BOUND`] fails here.
pub(super) async fn deadline_after_send(
    fx: &Fx,
    slow_gate: &Arc<tokio::sync::Notify>,
) -> (StatusCode, Value) {
    let answer = {
        let _deadline = TestDeadline::set(ROW_DEADLINE);
        tokio::time::timeout(POST_BOUND, post(fx, ADMIN, call("slow", false))).await
    };
    let answer = answer.expect("the route answered within the post bound");
    // A stored permit: the tool gets it even if it is not waiting yet.
    slow_gate.notify_one();
    answer
}

/// The deadline row holds on a slow path to the send: the catalogue is cold
/// and its list is released 300 ms after the call reaches it, which is after
/// the route armed its deadline. Under a 100 ms deadline this read `not_run`.
/// Mutants: the timeout removed (`slow` answers 200 after the gate bound, the
/// 504 check fails); the disposition always `not_run` (the `may_have_run` check
/// fails).
#[tokio::test]
async fn the_deadline_row_survives_a_slow_path_to_the_send() {
    let fx = fixture().await;
    let list_gate = Arc::new(tokio::sync::Notify::new());
    let entered = Arc::new(tokio::sync::Notify::new());
    let slow_gate = Arc::new(tokio::sync::Notify::new());
    install(
        &fx,
        Stub {
            calls: Arc::clone(&fx.calls),
            declares_read: true,
            list_gate: Some(Arc::clone(&list_gate)),
            list_entered: Some(Arc::clone(&entered)),
            slow_gate: Some(Arc::clone(&slow_gate)),
        },
    );
    // Runs beside the post: waits until the call is inside its list fetch,
    // holds it there 300 ms, then lets it through.
    let stall = tokio::spawn(async move {
        tokio::time::timeout(POST_BOUND, entered.notified())
            .await
            .expect("the call reached the catalogue's list");
        // timing: lower-bound
        tokio::time::sleep(Duration::from_millis(300)).await;
        list_gate.notify_one();
    });
    let (status, body) = deadline_after_send(&fx, &slow_gate).await;
    stall.await.expect("the stall ran to its release");
    assert_eq!(status, StatusCode::GATEWAY_TIMEOUT, "{body}");
    assert_eq!(body["disposition"], "may_have_run", "{body}");
    assert_eq!(sent(&fx), 1, "the call was sent before the deadline");
}
