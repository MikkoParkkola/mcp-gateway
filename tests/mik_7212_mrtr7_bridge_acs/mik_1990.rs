// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #1990 rows of `mik_7212_mrtr7_bridge_acs`, kept in a child module so the
//! parent file stays within its recorded size baseline. They reuse the
//! parent's fakes through `super`.

use super::*;

/// #1990 — a retry round that still claims `input_required` in a shape the
/// gateway cannot carry is an upstream fault, not a completed call.
///
/// `from_result` folds "completed" and "asked badly" into one `None`; the
/// bridge used to read that as success and hand the broken body back as the
/// terminal result, which the caller then settles under the idempotency key.
/// Both unusable shapes are pinned: a non-object `inputRequests`, and a round
/// with neither a question nor a state.
#[tokio::test]
async fn mik_1990_a_malformed_input_required_round_is_not_a_completed_call() {
    let content = json!({"branch": "main"});
    for malformed in [
        json!({"resultType": "input_required", "inputRequests": "x"}),
        json!({"resultType": "input_required", "inputRequests": {}}),
    ] {
        let client = FakeClient::new(accepts(1, &content));
        let backend = FakeBackend::new(vec![malformed.clone()]);
        let records = Records::default();
        let outcome = bridge(
            &client,
            &backend,
            &records,
            declared_all(),
            None,
            &interim(&[("k", ask("first?"))]),
        )
        .await;

        assert_eq!(backend.calls().len(), 1, "one retry reached the backend");
        assert!(
            matches!(outcome, Err(BridgeError::MalformedInterim)),
            "a body that claims input_required and cannot be carried must fail the \
             exchange, not return as the terminal result: {malformed} -> {outcome:?}"
        );
    }
}
