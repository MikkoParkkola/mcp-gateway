// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A `subscriptions/listen` stream opened under a held adapter assertion
//! closes when that assertion's window passes, instead of delivering the
//! next wanted task frame to a dead held identity.
//!
//! The `AdapterAssertion::for_test` receipt rides the real authenticated
//! route as a request extension beside `key-a`'s verified `alice` identity,
//! so this row proves held-window custody on the genuine listen path — not
//! new `OpenWebUI` ingress signature verification. The window is the old
//! A-EXPIRE one: 120 seconds plus 30 of skew, inclusive at `issued + 150`
//! and dead at `issued + 151`; the 24-hour task TTL dwarfs both.
//!
//! A child of `notifications`, declared there with `#[path]`, so it reads
//! the same bounded stream reader.
use super::super::super::*;
use super::super::support::*;
use super::helpers::{
    ARRIVES_WITHIN, EventStream, ReleasedOnDrop, SUBSCRIPTION_ID_META, StreamEvent,
    TASK_NOTIFICATION, expect_message,
};

const SUBSCRIPTION: i64 = 7811;

/// Two tasks `key-a` owns, both dispatched to the holding backend and both
/// still held there, so both ids exist and are owned before the listen
/// filter names them.
pub(super) async fn two_owned_tasks(
    state: &Arc<AppState>,
    gate: &mut ReleasedOnDrop,
) -> (String, String) {
    let first = task_id(
        &post(
            state,
            "key-a",
            task_invoke(7801, "adapter-expiry-1", json!({ "q": "a" })),
        )
        .await,
    );
    let second = task_id(
        &post(
            state,
            "key-a",
            task_invoke(7802, "adapter-expiry-2", json!({ "q": "b" })),
        )
        .await,
    );
    gate.0.wait_for_dispatch().await;
    gate.0.wait_for_dispatch().await;
    (first, second)
}

/// Open the listen stream as `key-a` under an adapter assertion expiring at
/// `expires_at` (120-second lifetime, 30 of skew), and consume its
/// acknowledgement. Built with the suite's own `http_request`, so the
/// Bearer [REDACTED] and the verified `alice` identity are the real ones;
/// only the held assertion receipt is added.
async fn open_listen_asserted(
    state: &Arc<AppState>,
    first: &str,
    second: &str,
    expires_at: u64,
) -> EventStream {
    let body = task_method(
        SUBSCRIPTION,
        "subscriptions/listen",
        json!({ "taskIds": [first, second] }),
    );
    let mut request = http_request(Some("key-a"), &body);
    request
        .extensions_mut()
        .insert(crate::gateway::openwebui_adapter::AdapterAssertion::for_test(expires_at, 30));
    let response = create_router(Arc::clone(state))
        .oneshot(request)
        .await
        .expect("the router must answer");
    let status = response.status();
    if status != StatusCode::OK {
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("a refusal body ends");
        panic!(
            "the asserted listen stream must be admitted before anything can \
             be observed on it, got {status}: {}",
            String::from_utf8_lossy(&bytes)
        );
    }
    let mut stream = EventStream::from_response(response);
    let ack = expect_message(&mut stream, "the acknowledgement that opens the stream").await;
    std::assert_eq!(
        ack["method"],
        "notifications/subscriptions/acknowledged",
        "{ack}"
    );
    std::assert_eq!(
        ack["params"]["_meta"][SUBSCRIPTION_ID_META],
        json!(SUBSCRIPTION),
        "the subscription id is the listen request's own id: {ack}"
    );
    stream
}

/// At the assertion window's last inclusive second the wanted task frame is
/// delivered; one second later the same stream's FIRST observable outcome
/// for the remaining wanted task is its close, never that task's frame.
///
/// Non-vacuity is the healthy half: one permit releases one of the two held
/// dispatches (whichever the semaphore wakes), and the first frame on the
/// stream must be that dispatch's own completed notification — a real
/// owned id, the acknowledged subscription, the backend's result — while
/// the other task is provably still `working`. Only then does the clock
/// pass the window, the remaining dispatch completes for real (polled
/// terminal, carrying the backend result, two counted calls), and the held
/// stream is read once: `Closed` passes, a `Message` fails this row's own
/// closure assertion with the leaked frame printed, and `Silent` is a VOID
/// premise failure, never closure evidence.
#[tokio::test]
async fn a_wanted_task_listener_closes_at_its_held_adapter_assertion_expiry() {
    let (mock, gate) = MockBackend::holding(Answer::ok());
    let mut gate = ReleasedOnDrop(gate);
    let (state, _store) = state_with(&mock).await;
    let issued = crate::clock::unix_secs().expect("clock after 1970");

    let (first, second) = two_owned_tasks(&state, &mut gate).await;
    let mut stream = open_listen_asserted(&state, &first, &second, issued + 120).await;

    // Live boundary: 120 + 30 inclusive. Exactly one permit, so exactly one
    // of the two held dispatches answers — the frame itself says which.
    let last_live = crate::clock::test_clock::at_secs(issued + 150);
    gate.0.release();
    let frame = expect_message(&mut stream, "the first completed task notification").await;
    std::assert_eq!(frame["method"], json!(TASK_NOTIFICATION), "{frame}");
    std::assert_eq!(frame["params"]["status"], json!("completed"), "{frame}");
    std::assert_eq!(
        frame["params"]["_meta"][SUBSCRIPTION_ID_META],
        json!(SUBSCRIPTION),
        "{frame}"
    );
    std::assert_eq!(
        frame["params"].pointer("/result/structuredContent/marker"),
        Some(&json!("mock-backend-answered")),
        "the healthy frame carries the full task, result included: {frame}"
    );
    let delivered = frame["params"]["taskId"]
        .as_str()
        .unwrap_or_else(|| panic!("the healthy frame names no task id: {frame}"))
        .to_string();
    std::assert!(
        delivered == first || delivered == second,
        "the healthy frame must name one of the two owned tasks: {frame}"
    );
    let other = if delivered == first { &second } else { &first };
    assert_carries_the_backend_result(&poll_until_terminal(&state, "key-a", &delivered).await);
    let other_now = get_task(&state, "key-a", other).await;
    std::assert_eq!(
        status_of(&other_now),
        "working",
        "the unreleased task must still be working before expiry: {other_now}"
    );
    drop(last_live);

    // One second past the window: the remaining dispatch genuinely
    // completes into this held generation, then the stream is read once.
    let _past = crate::clock::test_clock::at_secs(issued + 151);
    gate.0.release();
    assert_carries_the_backend_result(&poll_until_terminal(&state, "key-a", other).await);
    std::assert_eq!(
        mock.calls(),
        2,
        "both tasks must reach the backend once, or the transitions the \
         stream was judged on did not happen; the backend saw {:?}",
        mock.seen()
    );
    let leaked: Option<Value> = match stream.next(ARRIVES_WITHIN).await {
        StreamEvent::Closed => None,
        StreamEvent::Message(frame) => Some(frame),
        StreamEvent::Silent => panic!(
            "VOID: the expired stream stayed silently open for \
             {ARRIVES_WITHIN:?}, which is a premise failure, not closure"
        ),
    };
    std::assert!(
        leaked.is_none(),
        "a wanted-task listener must close at its held adapter assertion \
         expiry, yet the expired stream carried a further frame: {leaked:?}"
    );
}
