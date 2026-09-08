// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::*;

/// A confirmation-purpose envelope must not continue a backend exchange, even
/// when its owner, operation digest, hold and lifetime all match that exchange.
#[tokio::test]
async fn confirmation_purpose_cannot_redeem_backend_input_or_spend_its_hold() {
    use crate::protocol::continuation::{Payload, now_unix_secs};
    let mock = MockBackend::answering(Answer::Result(json!({
        "resultType": "input_required", "requestState": "opaque-backend-state"
    })));
    let (state, _store) = fixture(&mock).await;
    // A surfaced tool preserves the backend's native interim envelope; the
    // gateway_invoke meta-tool wraps its payload as text for discovery clients.
    let original = keyed(
        declaring_elicitation(modern(
            10,
            "tools/call",
            json!({"name": TOOL, "arguments": {"record": "fixture"}}),
            true,
        )),
        "backend-domain-control",
    );
    let first = post(&state, "key-a", original.clone()).await;
    std::assert_eq!(
        first.pointer("/result/resultType"),
        Some(&json!("input_required"))
    );
    std::assert_eq!(mock.calls(), 1);
    let token = first
        .pointer("/result/requestState")
        .and_then(Value::as_str)
        .expect("production backend continuation envelope");
    let continuation = state.meta_mcp.continuation();
    let keyring = continuation.keyring();
    let issued = keyring
        .open(token, now_unix_secs())
        .expect("authentic backend envelope");
    let mut encoded = serde_json::to_value(&issued).unwrap();
    std::assert_eq!(encoded["purpose"], json!("backend_input"));
    encoded["purpose"] = json!("destructive_confirm");
    let wrong: Payload = serde_json::from_value(encoded).unwrap();
    std::assert_eq!(
        serde_json::to_value(&wrong).unwrap()["purpose"],
        json!("destructive_confirm")
    );
    let mut retry = original.clone();
    retry["params"]["requestState"] = json!(keyring.mint(&wrong).unwrap());
    retry["params"]["inputResponses"] = json!({});
    let refused = post(&state, "key-a", retry.clone()).await;
    assert!(
        refused.get("error").is_some(),
        "wrong domain must be refused: {refused}"
    );
    std::assert_eq!(mock.calls(), 1, "wrong purpose must not retry backend");

    // The legitimate exchange still works: wrong-domain refusal must happen
    // before the hold or consumed ledger is changed.
    retry["params"]["requestState"] = json!(token);
    let continued = post(&state, "key-a", retry).await;
    assert!(
        continued.get("error").is_none(),
        "valid grant was spent by refusal: {continued}"
    );
    std::assert_eq!(mock.calls(), 2, "valid backend grant reaches its backend");
}
