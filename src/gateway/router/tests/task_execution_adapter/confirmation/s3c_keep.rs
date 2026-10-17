// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8353 slice 3c, K-x14-sealed (KEEP; green on base and after): a task
//! call whose X14 confirmation grant was consumed, then refused at submit
//! (sealed), keeps its nonce spent. Something acted (the grant), so a fresh,
//! non-destructive request carrying the same nonce is refused as a replay.
//! Kills a give-back at the submit refusal that bypasses the witness.
use super::*;
use crate::security::message_signing::MessageSigner;

const NONCE: &str = "s3c-x14-sealed-nonce";

fn with_nonce(mut body: Value) -> Value {
    body["params"]["_meta"]["io.mcp-gateway/nonce"] = json!(NONCE);
    body
}

#[tokio::test]
async fn s3c_a_consumed_grant_then_a_sealed_submit_keeps_the_nonce() {
    let mock = MockBackend::answering(Answer::ok());
    let mut config = crate::config::Config::default();
    config.security.posture = crate::security::SecurityPosture::Hardened;
    let (state, _store) = fixture_with(&mock, config, |meta| {
        meta.enable_message_signing(
            MessageSigner::new(
                b"s3c-x14-sealed-signing-secret-of-32-bytes".to_vec(),
                None,
                "s3c-x14".to_owned(),
            ),
            Duration::from_secs(300),
            false,
        );
    })
    .await;
    let original = with_nonce(request("s3c-x14-sealed"));
    let challenge = post(&state, "key-a", original.clone()).await;
    let accepted = retry(&original, &challenge, "accept");

    let admission = state.task_executor.service.admission();
    admission.adjust_sealed(0, 1);
    let refused = post(&state, "key-a", accepted.clone()).await;
    std::assert_eq!(
        refused.pointer("/error/code"),
        Some(&json!(409)),
        "premise: the grant was redeemed and the submit refused sealed: {refused}"
    );
    std::assert_eq!(mock.calls(), 0, "premise: the refusal dispatched nothing");
    let spent = post(&state, "key-a", accepted).await;
    assert!(
        spent.get("error").is_some(),
        "premise: the grant was consumed, so it cannot be redeemed again: {spent}"
    );
    admission.adjust_sealed(1, 0);

    let fresh = post(
        &state,
        "key-a",
        with_nonce(task_invoke(3, "s3c-x14-fresh", json!({ "q": "fresh" }))),
    )
    .await;
    assert!(
        fresh.to_string().contains("Nonce replay detected"),
        "the nonce was given back after the grant was consumed: {fresh}"
    );
    std::assert_eq!(mock.calls(), 0, "the replay dispatched nothing");
}
