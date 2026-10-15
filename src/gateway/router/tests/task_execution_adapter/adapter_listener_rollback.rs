// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8350 C0b: a held adapter listener closes when a clock rollback
//! moves its held issuance into the future beyond skew.
use super::super::super::*;
use super::super::support::*;
use super::adapter_listener_expiry::two_owned_tasks;
use super::helpers::{
    ARRIVES_WITHIN, EventStream, ReleasedOnDrop, SUBSCRIPTION_ID_META, StreamEvent,
    TASK_NOTIFICATION, expect_message,
};
use crate::gateway::openwebui_adapter::AdapterAssertion;

const SUBSCRIPTION: i64 = 7812;

async fn open_listen_verified(
    state: &Arc<AppState>,
    first: &str,
    second: &str,
    receipt: AdapterAssertion,
) -> EventStream {
    let body = task_method(
        SUBSCRIPTION,
        "subscriptions/listen",
        json!({ "taskIds": [first, second] }),
    );
    let mut request = http_request(Some("key-a"), &body);
    request.extensions_mut().insert(receipt);
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
            "VOID: asserted listen must be admitted, got {status}: {}",
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
        "{ack}"
    );
    stream
}

fn genuine_receipt(t0: u64) -> AdapterAssertion {
    let iat = i64::try_from(t0).expect("test clock fits i64");
    AdapterAssertion::verified_for_test(iat, iat + 120, 30)
        .unwrap_or_else(|| panic!("VOID: genuine signed capture refused at issuance"))
}

fn fresh_verifies(t0: u64) -> bool {
    let iat = i64::try_from(t0).expect("test clock fits i64");
    AdapterAssertion::verified_for_test(iat, iat + 120, 30).is_some()
}

#[tokio::test(flavor = "current_thread")]
async fn a_wanted_task_listener_closes_when_its_held_adapter_issuance_moves_into_the_future() {
    let (mock, gate) = MockBackend::holding(Answer::ok());
    let mut gate = ReleasedOnDrop(gate);
    let (state, _store) = state_with(&mock).await;
    let t0 = crate::clock::unix_secs().expect("clock after 1970");
    let capture = crate::clock::test_clock::at_secs(t0);
    let receipt = genuine_receipt(t0);
    let (first, second) = two_owned_tasks(&state, &mut gate).await;
    let mut stream = open_listen_verified(&state, &first, &second, receipt).await;
    drop(capture);
    let live = crate::clock::test_clock::at_secs(t0 - 30);
    std::assert!(
        fresh_verifies(t0),
        "VOID: same signed claims must freshly verify at t0-30"
    );
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
        "{frame}"
    );
    let delivered = frame["params"]["taskId"]
        .as_str()
        .unwrap_or_else(|| panic!("VOID: healthy frame names no task id: {frame}"))
        .to_string();
    std::assert!(
        delivered == first || delivered == second,
        "VOID: healthy frame must name an owned task: {frame}"
    );
    let other = if delivered == first { &second } else { &first };
    assert_carries_the_backend_result(&poll_until_terminal(&state, "key-a", &delivered).await);
    let other_now = get_task(&state, "key-a", other).await;
    std::assert_eq!(
        status_of(&other_now),
        "working",
        "VOID: unreleased task must still be working: {other_now}"
    );
    drop(live);
    let _past = crate::clock::test_clock::at_secs(t0 - 31);
    std::assert!(
        !fresh_verifies(t0),
        "VOID: fresh verification must refuse at t0-31"
    );
    gate.0.release();
    assert_carries_the_backend_result(&poll_until_terminal(&state, "key-a", other).await);
    std::assert_eq!(
        mock.calls(),
        2,
        "VOID: both tasks must reach backend once; saw {:?}",
        mock.seen()
    );
    let leaked: Option<Value> = match stream.next(ARRIVES_WITHIN).await {
        StreamEvent::Closed => None,
        StreamEvent::Message(frame) => Some(frame),
        StreamEvent::Silent => {
            panic!("VOID: rolled-back stream stayed silently open for {ARRIVES_WITHIN:?}")
        }
    };
    std::assert!(
        leaked.is_none(),
        "a wanted-task listener must close when its held adapter issuance \
         moves into the future, yet it carried a further frame: {leaked:?}"
    );
}
