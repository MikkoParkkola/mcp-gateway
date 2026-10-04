// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MRTR.7b: what comes back.

use super::*;

// ── MRTR.7b — what comes back ────────────────────────────────────────────────

/// Row 313 — an accepted answer reaches the backend under the backend's own
/// key.
///
/// The key is the assertion. `InputRequired::requests` is collected from a JSON
/// map, so the backend's authoring order is already lost before the bridge sees
/// it and the key is the only correlation between a question and its answer. A
/// test asserting only that a retry happened passes against a bridge that files
/// every answer under a key it invented.
#[tokio::test]
async fn ac_mrtr_7b_an_accepted_answer_is_filed_under_the_backend_key() {
    let content = json!({"branch": "main"});
    let client = FakeClient::new(vec![accepted(&content)]);
    let backend = FakeBackend::new(vec![completed()]);
    let records = Records::default();

    let outcome = bridge(
        &client,
        &backend,
        &records,
        declared_all(),
        None,
        &interim(&[(
            "server-chose-this",
            entry(
                "elicitation/create",
                &json!({"mode": "form", "message": "Which branch?"}),
            ),
        )]),
    )
    .await;

    assert!(outcome.is_ok(), "accepted round failed: {outcome:?}");
    let calls = backend.calls();
    assert_eq!(calls.len(), 1, "one answered round, one retry");
    assert_eq!(
        calls[0].pointer("/inputResponses/server-chose-this"),
        Some(&content),
        "the answer must arrive under the key the backend assigned"
    );
    assert_eq!(
        calls[0].get("requestState").and_then(Value::as_str),
        Some("state-1"),
        "the backend's opaque state must be echoed back untouched"
    );
}

/// Row 314 — a decline fails the call, and says a person declined rather than
/// that something broke.
///
/// A successful JSON-RPC result carrying a decline arrives through the door a
/// transport-error path does not cover. The reason is the load-bearing half: a
/// test asserting only "no retry" passes against a bridge that maps every
/// non-accept onto a transport fault, which is exactly the distinction the
/// `phase` label was added to preserve.
#[tokio::test]
async fn ac_mrtr_7b_a_decline_fails_the_call_as_a_refusal_by_a_person() {
    let client = FakeClient::new(vec![result(&json!({"action": "decline"}))]);
    let backend = FakeBackend::never();
    let records = Records::default();

    let outcome = bridge(
        &client,
        &backend,
        &records,
        declared_all(),
        None,
        &interim(&[(
            "k1",
            entry(
                "elicitation/create",
                &json!({"mode": "form", "message": "Deploy?"}),
            ),
        )]),
    )
    .await;

    assert_eq!(
        outcome,
        Err(BridgeError::Delivery {
            key: "k1".to_string(),
            error: DeliveryError::Declined {
                action: "decline".to_string(),
            },
        }),
        "a decline must not be reported as a transport fault"
    );
    assert!(backend.calls().is_empty(), "backend must not be retried");
}

/// Row 315 — a JSON-RPC `error` reply fails the call carrying the client's own
/// code.
///
/// The shipped elicitation helper resolves an error reply through its success
/// arm, so an error envelope is read as an answer today. Both the code and the
/// message are asserted: a bridge that reports "the client refused" without the
/// client's own code leaves an operator with nothing to look up.
#[tokio::test]
async fn ac_mrtr_7b_an_error_reply_fails_the_call_as_a_client_refusal() {
    let client = FakeClient::new(vec![Reply::Now(json!({
        "jsonrpc": "2.0",
        "error": {"code": -32601, "message": "elicitation not supported"},
    }))]);
    let backend = FakeBackend::never();
    let records = Records::default();

    let outcome = bridge(
        &client,
        &backend,
        &records,
        declared_all(),
        None,
        &interim(&[(
            "k1",
            entry(
                "elicitation/create",
                &json!({"mode": "form", "message": "Deploy?"}),
            ),
        )]),
    )
    .await;

    assert_eq!(
        outcome,
        Err(BridgeError::Delivery {
            key: "k1".to_string(),
            error: DeliveryError::ClientRefused {
                code: -32601,
                message: "elicitation not supported".to_string(),
            },
        }),
    );
    assert!(backend.calls().is_empty(), "backend must not be retried");
}

/// Row 316 — an accept whose body cannot be read as an answer fails as
/// `Malformed`.
///
/// Both shapes, because they fail differently: `content` absent is a client
/// that accepted and said nothing, and a `content` that is not an object is a
/// client that said something unusable. Either forwarded to the backend files
/// an answer nobody gave under a key the backend will read.
///
/// The non-object half runs every scalar JSON admits, not only a string and an
/// array. A check written as "is it a map, or is it a string" reads `null`,
/// `true` and `0` as neither and falls through to the accept path, and `null`
/// is what a client emits for a field it chose not to fill.
#[tokio::test]
async fn ac_mrtr_7b_an_unusable_accept_fails_as_malformed() {
    for body in [
        json!({"action": "accept"}),
        json!({"action": "accept", "content": "not an object"}),
        json!({"action": "accept", "content": ["nor", "this"]}),
        json!({"action": "accept", "content": null}),
        json!({"action": "accept", "content": true}),
        json!({"action": "accept", "content": 0}),
    ] {
        let client = FakeClient::new(vec![result(&body)]);
        let backend = FakeBackend::never();
        let records = Records::default();

        let outcome = bridge(
            &client,
            &backend,
            &records,
            declared_all(),
            None,
            &interim(&[(
                "k1",
                entry(
                    "elicitation/create",
                    &json!({"mode": "form", "message": "Deploy?"}),
                ),
            )]),
        )
        .await;

        assert_eq!(
            outcome,
            Err(BridgeError::Delivery {
                key: "k1".to_string(),
                error: DeliveryError::Malformed,
            }),
            "unusable accept {body} must fail as malformed"
        );
        assert!(
            backend.calls().is_empty(),
            "backend must not be retried for {body}"
        );
    }
}

/// Row 317 — an accepted `content` that does not satisfy the backend's own
/// `requestedSchema` is forwarded unchanged.
///
/// Deliberately the opposite of the row above, and written next to it for that
/// reason: an implementer who reads `Malformed` alone adds a validator, and the
/// validator rejects an answer the backend asked for and would have accepted.
/// The gateway does not second-guess a contract between a backend and its
/// client — a shape it cannot read is a bridge failure, a shape it can read and
/// disagrees with is not the bridge's business.
#[tokio::test]
async fn ac_mrtr_7b_content_violating_the_requested_schema_is_forwarded_unchanged() {
    let content = json!({"branch": 7, "unasked": true});
    let client = FakeClient::new(vec![accepted(&content)]);
    let backend = FakeBackend::new(vec![completed()]);
    let records = Records::default();

    let outcome = bridge(
        &client,
        &backend,
        &records,
        declared_all(),
        None,
        &interim(&[(
            "k1",
            entry(
                "elicitation/create",
                &json!({
                    "mode": "form",
                    "message": "Which branch?",
                    "requestedSchema": {
                        "type": "object",
                        "properties": {"branch": {"type": "string"}},
                        "required": ["branch"],
                    },
                }),
            ),
        )]),
    )
    .await;

    assert!(
        outcome.is_ok(),
        "a schema mismatch is not the bridge's to refuse: {outcome:?}"
    );
    let calls = backend.calls();
    assert_eq!(calls.len(), 1, "the round must still complete");
    assert_eq!(
        calls[0].pointer("/inputResponses/k1"),
        Some(&content),
        "the answer must reach the backend byte for byte, wrong type and extra field included"
    );
}
