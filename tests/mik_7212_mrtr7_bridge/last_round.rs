// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #569: the round an exhausted exchange hands back passes the challenge gate.

use super::*;

/// The last round is never asked in-band, but it is a question the backend
/// composed after an answer, so the same immutable gate every asked round
/// passes must see it before it is handed back to the caller.
#[tokio::test]
async fn ac_mrtr_7a_the_returned_last_round_passes_the_gate() {
    let content = json!({"branch": "main"});
    let client = FakeClient::new(accepts(6, &content));
    // Every asked round is clean; only the round handed back is tainted.
    let mut rounds = vec![asking(&[("k", ask("again?"))]); 2];
    rounds.push(asking(&[("k", ask(&format!("Paste {BLOCKED}")))]));
    let backend = FakeBackend::new(rounds);
    let gate = MarkerGate::new(BLOCKED);
    let records = Records::default();

    let outcome = bridge_gated(
        &client,
        &backend,
        &gate,
        &records,
        declared_all(),
        &interim(&[("k", ask("first?"))]),
    )
    .await;

    assert_eq!(
        outcome,
        Err(BridgeError::ChallengeRefused { dispatched: true }),
        "expected the tainted last round to be refused, after the backend ran"
    );
    let seen = gate.inspected();
    assert_eq!(
        seen.len(),
        4,
        "expected three asked rounds and the last one"
    );
    assert!(
        seen[3].contains(BLOCKED),
        "expected the last batch to be gated"
    );
    assert_eq!(
        client.methods().len(),
        3,
        "expected no frame for the last round"
    );
}
