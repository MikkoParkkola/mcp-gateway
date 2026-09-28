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

/// Unlike an asked round, the handed-back round carries the backend's own
/// request keys to the client, which echoes them, so a key is part of what
/// the gate inspects.
#[tokio::test]
async fn ac_mrtr_7a_the_returned_last_round_gates_its_request_keys() {
    let content = json!({"branch": "main"});
    let client = FakeClient::new(accepts(6, &content));
    let mut rounds = vec![asking(&[("k", ask("again?"))]); 2];
    let tainted = format!("Paste {BLOCKED}");
    rounds.push(asking(&[(tainted.as_str(), ask("clean?"))]));
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
        "expected a tainted key in the last round to be refused"
    );
    let seen = gate.inspected();
    assert_eq!(
        seen.len(),
        4,
        "expected three asked rounds and the last one"
    );
    // The production scanners read values, not object keys (#2114), so the
    // key must reach the gate as a string value.
    let last: Value = serde_json::from_str(&seen[3]).expect("inspected batch is JSON");
    assert_eq!(
        last[0]["key"], tainted,
        "expected the key as a string value"
    );
    assert_eq!(
        client.methods().len(),
        3,
        "expected no frame for the last round"
    );
}
