// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! C6 killer (`BRIDGE_UNDECLARED`): the opening batch is held to the session's
//! declaration on its own, with no per-request slice.

use super::*;

/// Every other undeclared-entry row runs under a slice that names
/// `elicitation`, and the slice refuses `sampling` too, so those rows pass
/// with the declaration check gone. With no slice, the declaration is the
/// only thing between the backend's opening batch and the client.
#[tokio::test]
async fn ac_mrtr_7a_an_undeclared_opening_entry_is_refused_without_a_slice() {
    let client = FakeClient::mute();
    let backend = FakeBackend::never();
    let records = Records::default();
    let elicitation_only = declared(&json!({"elicitation": {"form": {}}}));

    let outcome = bridge(
        &client,
        &backend,
        &records,
        elicitation_only,
        None,
        &interim(&[
            (
                "k1",
                entry(
                    "elicitation/create",
                    &json!({"mode": "form", "message": "Which branch?"}),
                ),
            ),
            (
                "k2",
                entry(
                    "sampling/createMessage",
                    &json!({"messages": [], "maxTokens": 1}),
                ),
            ),
        ]),
    )
    .await;

    assert_eq!(
        outcome,
        Err(BridgeError::Refused {
            key: "k2".to_string(),
            reason: Refusal::Capability("sampling"),
        })
    );
    assert!(
        client.frames().is_empty(),
        "a refused batch sends no frame: {:?}",
        client.methods()
    );
    assert!(backend.calls().is_empty(), "backend must not be retried");
}
