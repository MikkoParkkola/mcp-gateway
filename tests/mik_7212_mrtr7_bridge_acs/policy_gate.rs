// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MRTR.7a: the policy gate on the client-visible batch.

use super::*;

// ── MRTR.7a — the policy gate on the client-visible batch ────────────────────

/// The gate runs on every round, not only the first.
///
/// `run` loops, and each round's prompts are built from a backend result the
/// bridge had not seen when the exchange opened. A gate placed before `run`
/// would admit this exchange: its first batch is clean, and only the question
/// the backend asks *after* the first answer carries blocked content. Both
/// independent reviewers of the design raised exactly this, which is why the
/// row asserts on the second round rather than the first.
#[tokio::test]
async fn ac_mrtr_7a_the_gate_inspects_every_round_not_only_the_first() {
    let client = FakeClient::new(vec![accepted(&json!({"ok": true}))]);
    // The first retry answers with a second question, and that one is tainted.
    let backend = FakeBackend::new(vec![asking(&[("k2", ask(&format!("Paste {BLOCKED}")))])]);
    let gate = MarkerGate::new(BLOCKED);
    let records = Records(Mutex::new(Vec::new()));

    let outcome = bridge_gated(
        &client,
        &backend,
        &gate,
        &records,
        declared_all(),
        &interim(&[("k1", ask("Which branch?"))]),
    )
    .await;

    assert_eq!(
        outcome,
        Err(BridgeError::ChallengeRefused { dispatched: true }),
        "a blocked second-round batch must refuse the exchange, and it must say \
         the backend already ran — the caller settles the key on that fact"
    );
    assert_eq!(
        gate.inspected().len(),
        2,
        "the gate must be consulted once per round, not once per exchange"
    );
    assert!(
        gate.inspected()[1].contains(BLOCKED),
        "the second batch is the one carrying the blocked content"
    );
    // One frame, from the clean first round. The tainted question never
    // reached the wire, which is the property a refusal after `ask` would lose.
    assert_eq!(client.methods().len(), 1, "frames: {:?}", client.frames());
}

/// The backend's opaque state is neither scanned nor delivered.
///
/// The control for the row above. A gate fed the whole interim result would
/// pass the refusal test just as well while reading `requestState` — server-
/// owned bytes the client must never see, and which MRTR.2 seals into a
/// gateway-minted continuation instead. Asserting only that blocked content is
/// refused cannot tell the two implementations apart; this asserts on the
/// canary's absence from both the gate's view and the wire.
#[tokio::test]
async fn ac_mrtr_7a_opaque_state_is_neither_scanned_nor_delivered() {
    let client = FakeClient::new(vec![accepted(&json!({"ok": true}))]);
    let backend = FakeBackend::new(vec![completed()]);
    let gate = MarkerGate::new(BLOCKED);
    let records = Records(Mutex::new(Vec::new()));
    let mut pending = interim(&[("k1", ask("Which branch?"))]);
    pending.request_state = Some(format!("state-{STATE_CANARY}"));

    let outcome = bridge_gated(&client, &backend, &gate, &records, declared_all(), &pending).await;

    assert!(outcome.is_ok(), "a clean batch is carried: {outcome:?}");
    for seen in gate.inspected() {
        assert!(
            !seen.contains(STATE_CANARY),
            "the gate was shown the backend's opaque state: {seen}"
        );
    }
    for frame in client.frames() {
        let rendered = frame.params.map(|p| p.to_string()).unwrap_or_default();
        assert!(
            !rendered.contains(STATE_CANARY),
            "the opaque state reached the client: {rendered}"
        );
    }
}

/// A refusal says whether the backend already ran, because the key turns on it.
///
/// The paired control for the multi-round row above, which refuses on round two
/// and reports `dispatched: true`. Round one has dispatched nothing, so its
/// refusal releases the idempotency key and the caller may retry once the
/// refusal lifts. Collapsing the two into one untagged refusal is what ADR-012
/// consequence 1 forbids: the caller cannot then tell a call that never ran
/// from one whose side effect may already have taken effect, and releasing the
/// key on the second readmits a retry of that side effect.
#[tokio::test]
async fn ac_mrtr_7a_a_first_round_refusal_reports_that_nothing_was_dispatched() {
    let client = FakeClient::new(Vec::new());
    let backend = FakeBackend::never();
    let gate = MarkerGate::new(BLOCKED);
    let records = Records(Mutex::new(Vec::new()));

    let outcome = bridge_gated(
        &client,
        &backend,
        &gate,
        &records,
        declared_all(),
        &interim(&[("k1", ask(&format!("Paste {BLOCKED}")))]),
    )
    .await;

    assert_eq!(
        outcome,
        Err(BridgeError::ChallengeRefused { dispatched: false }),
        "a round-one refusal must report that nothing reached the backend"
    );
    assert!(
        backend.calls().is_empty(),
        "the backend was re-invoked after a round-one refusal: {:?}",
        backend.calls()
    );
}

/// The backend's own request key is neither scanned nor delivered.
///
/// The second control on the challenge artifact, alongside the opaque-state row.
/// `ask` mints its own wire id per frame and files the answer under the backend's
/// key afterwards, so that key is backend-facing bookkeeping no client can read.
/// A gate shown it refuses exchanges over content that was never exposed, which
/// is a denial of service on legacy clients dressed as a security control.
#[tokio::test]
async fn ac_mrtr_7a_the_backend_request_key_is_neither_scanned_nor_delivered() {
    let client = FakeClient::new(vec![accepted(&json!({"ok": true}))]);
    let backend = FakeBackend::new(vec![completed()]);
    let gate = MarkerGate::new(BLOCKED);
    let records = Records(Mutex::new(Vec::new()));
    let tainted = format!("k-{BLOCKED}");

    let outcome = bridge_gated(
        &client,
        &backend,
        &gate,
        &records,
        declared_all(),
        &interim(&[(tainted.as_str(), ask("Which branch?"))]),
    )
    .await;

    assert!(
        outcome.is_ok(),
        "a clean batch under a tainted backend key is carried: {outcome:?}"
    );
    for seen in gate.inspected() {
        assert!(
            !seen.contains(BLOCKED),
            "the gate was shown the backend's own request key: {seen}"
        );
    }
    for frame in client.frames() {
        let rendered = frame.params.map(|p| p.to_string()).unwrap_or_default();
        assert!(
            !rendered.contains(BLOCKED),
            "the backend's request key reached the client: {rendered}"
        );
    }
}
