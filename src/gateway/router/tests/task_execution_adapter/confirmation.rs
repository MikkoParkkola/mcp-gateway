// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! X14b: real modern confirmation on an annotated, surfaced outer tool name.
//! No wrapper hint changes, SSE session, or invented acceptance key.
use super::super::*;
use super::support::*;
mod backend_domain;
mod fixture;
use fixture::*;

#[tokio::test]
async fn x14b_confirmation_accepts_once_and_committed_retry_reuses_task() {
    let (mock, mut gate) = MockBackend::holding(Answer::ok());
    let (state, _store) = fixture(&mock).await;
    let original = request("confirm-once");
    let challenge = post(&state, "key-a", original.clone()).await;
    let accepted = retry(&original, &challenge, "accept");
    std::assert_eq!(mock.calls(), 0, "challenge must precede dispatch");
    let created = post(&state, "key-a", accepted.clone()).await;
    let id = task_id(&created);
    gate.wait_for_dispatch().await;
    std::assert_eq!(status_of(&get_task(&state, "key-a", &id).await), "working");
    let replay = post(&state, "key-a", accepted.clone()).await;
    std::assert_eq!(task_id(&replay), id);
    std::assert_eq!(mock.calls(), 1);
    let sent = mock.seen();
    assert!(
        sent[0].get("requestState").is_none(),
        "gateway grant leaked upstream"
    );
    assert!(
        sent[0].get("inputResponses").is_none(),
        "gateway answer leaked upstream"
    );
    gate.release();
    assert_carries_the_backend_result(&poll_until_terminal(&state, "key-a", &id).await);
    let completed_replay = post(&state, "key-a", accepted).await;
    std::assert_eq!(task_id(&completed_replay), id);
    std::assert_eq!(mock.calls(), 1);
}

#[tokio::test]
async fn x14_confirmation_refusals_do_not_dispatch_or_reserve_original_key() {
    for case in [
        "bare",
        "decline",
        "cancel",
        "tamper",
        "owner",
        "name",
        "arguments",
        "task",
        "key",
    ] {
        let mock = MockBackend::answering(Answer::ok());
        let (state, _store) = fixture(&mock).await;
        let original = request("refusal-key");
        let challenge = post(&state, "key-a", original.clone()).await;
        let mut denied = retry(&original, &challenge, "accept");
        let mut principal = "key-a";
        match case {
            "bare" => {
                denied["params"]
                    .as_object_mut()
                    .unwrap()
                    .remove("requestState");
            }
            "decline" | "cancel" => denied = retry(&original, &challenge, case),
            "tamper" => denied["params"]["requestState"] = json!("invalid-sealed-grant"),
            "owner" => principal = "key-b",
            "name" => denied["params"]["name"] = json!(TOOL),
            "arguments" => denied["params"]["arguments"]["record"] = json!("another-record"),
            "task" => denied["params"]["task"] = json!({"ttl": 60000}),
            "key" => denied = keyed(denied, "different-key"),
            _ => unreachable!(),
        }
        let refused = post(&state, principal, denied).await;
        assert!(
            refused.pointer("/result/taskId").is_none(),
            "{case}: {refused}"
        );
        std::assert_eq!(mock.calls(), 0, "{case}: must not reach backend");
        // Same owner and key, DIFFERENT allowed operation: succeeds only if
        // neither the challenge nor the refusal claimed the admission key.
        let created = post(
            &state,
            "key-a",
            task_invoke(3, "refusal-key", json!({"read": true})),
        )
        .await;
        let id = task_id(&created);
        assert_carries_the_backend_result(&poll_until_terminal(&state, "key-a", &id).await);
        std::assert_eq!(
            mock.calls(),
            1,
            "{case}: only the allowed operation dispatched"
        );
    }
}

#[tokio::test]
async fn x14_expired_authentic_grant_cannot_dispatch_or_reserve_key() {
    use crate::protocol::continuation::{ContinuationError, now_unix_secs};
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = fixture(&mock).await;
    let original = request("expired-grant");
    let challenge = post(&state, "key-a", original.clone()).await;
    let mut accepted = retry(&original, &challenge, "accept");
    let continuation = state.meta_mcp.continuation();
    let keyring = continuation.keyring();
    let now = now_unix_secs();
    let mut payload = keyring
        .open(accepted["params"]["requestState"].as_str().unwrap(), now)
        .expect("the real challenge is authentic before altering only its time window");
    // Preserve the issued operation, owner, challenge and purpose. Re-sealing
    // is confined to this negative fixture: the positive test uses the exact
    // issued envelope. No sleep and no production clock override are needed.
    payload.issued_at = now.saturating_sub(301);
    payload.expires_at = now.saturating_sub(1);
    let expired = keyring
        .mint(&payload)
        .expect("validly sealed expired window");
    assert!(matches!(
        keyring.open(&expired, now),
        Err(ContinuationError::Expired)
    ));
    accepted["params"]["requestState"] = json!(expired);
    let refused = post(&state, "key-a", accepted).await;
    assert!(refused.pointer("/result/taskId").is_none(), "{refused}");
    std::assert_eq!(mock.calls(), 0);
    let created = post(
        &state,
        "key-a",
        task_invoke(3, "expired-grant", json!({"read": true})),
    )
    .await;
    let id = task_id(&created);
    assert_carries_the_backend_result(&poll_until_terminal(&state, "key-a", &id).await);
    std::assert_eq!(mock.calls(), 1);
}

#[tokio::test]
async fn x14_backend_input_purpose_cannot_authorize_destructive_task() {
    use crate::protocol::continuation::{Payload, now_unix_secs};
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = fixture(&mock).await;
    let original = request("wrong-purpose");
    let challenge = post(&state, "key-a", original.clone()).await;
    let mut accepted = retry(&original, &challenge, "accept");
    let continuation = state.meta_mcp.continuation();
    let keyring = continuation.keyring();
    let now = now_unix_secs();
    let issued = keyring
        .open(accepted["params"]["requestState"].as_str().unwrap(), now)
        .expect("authentic gateway-issued confirmation");
    let mut encoded = serde_json::to_value(&issued).unwrap();
    std::assert_eq!(encoded["purpose"], json!("destructive_confirm"));
    encoded["purpose"] = json!("backend_input");
    let wrong: Payload =
        serde_json::from_value(encoded).expect("backend purpose is a supported domain");
    // This assertion prevents an absent/ignored purpose field from masquerading
    // as a tested domain boundary. All other issued bindings remain identical.
    std::assert_eq!(
        serde_json::to_value(&wrong).unwrap()["purpose"],
        json!("backend_input")
    );
    accepted["params"]["requestState"] = json!(keyring.mint(&wrong).unwrap());
    let refused = post(&state, "key-a", accepted).await;
    assert!(refused.pointer("/result/taskId").is_none(), "{refused}");
    std::assert_eq!(mock.calls(), 0);
    let created = post(
        &state,
        "key-a",
        task_invoke(3, "wrong-purpose", json!({"read": true})),
    )
    .await;
    let id = task_id(&created);
    assert_carries_the_backend_result(&poll_until_terminal(&state, "key-a", &id).await);
    std::assert_eq!(mock.calls(), 1);
}
