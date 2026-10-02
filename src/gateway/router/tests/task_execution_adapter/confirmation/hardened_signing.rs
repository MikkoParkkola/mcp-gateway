// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7699: under `hardened`, the task-augmented destructive gate answers
//! before nonce admission. Its challenge goes out unsigned and leaves the nonce
//! unspent, so the follow-up carrying the same nonce is admitted, runs once and
//! is signed over it. Moving admission ahead of the gate reddens this row.
use super::*;
use crate::security::message_signing::MessageSigner;

const NONCE: &str = "task-gate-follow-up-nonce";

async fn hardened(mock: &Arc<MockBackend>) -> (Arc<AppState>, tempfile::TempDir) {
    let mut config = crate::config::Config::default();
    config.security.posture = crate::security::SecurityPosture::Hardened;
    fixture_with(mock, config, |meta| {
        // The production entry point, as `signing_joint` installs it.
        meta.enable_message_signing(
            MessageSigner::new(
                b"task-gate-signing-secret-of-32-bytes-or-more".to_vec(),
                None,
                "task-gate-key".to_owned(),
            ),
            Duration::from_secs(300),
            false,
        );
    })
    .await
}

fn with_nonce(mut body: Value) -> Value {
    body["params"]["_meta"]["io.mcp-gateway/nonce"] = json!(NONCE);
    body
}

#[tokio::test]
async fn the_task_gate_challenge_is_unsigned_and_its_follow_up_spends_the_nonce() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = hardened(&mock).await;
    let original = with_nonce(request("hardened-task-gate"));

    let challenge = post(&state, "key-a", original.clone()).await;
    std::assert_eq!(
        challenge.pointer("/result/resultType"),
        Some(&json!("input_required")),
        "{challenge}"
    );
    assert!(
        challenge.pointer("/result/_signature").is_none(),
        "the challenge is answered before admission, unsigned: {challenge}"
    );
    std::assert_eq!(mock.calls(), 0, "the challenge dispatches nothing");

    let accepted = retry(&original, &challenge, "accept");
    let created = post(&state, "key-a", accepted.clone()).await;
    std::assert_eq!(
        created.pointer("/result/_signature/nonce"),
        Some(&json!(NONCE)),
        "the follow-up is admitted on the challenge's nonce and signed over it: {created}"
    );
    let id = task_id(&created);
    poll_until_terminal(&state, "key-a", &id).await;
    std::assert_eq!(mock.calls(), 1, "the follow-up runs once");

    let replay = post(&state, "key-a", accepted).await;
    assert!(
        replay.get("error").is_some(),
        "the nonce is now spent: {replay}"
    );
}
