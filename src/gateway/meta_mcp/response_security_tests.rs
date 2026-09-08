// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! MIK-7407 component checks of the real JSON-RPC type and error projector.
//! Wire accounting and real challenge admission are separate integration tests.

use super::*;

const REFUSAL: &str = "Response blocked by security firewall";

fn assert_unmarked(response: &JsonRpcResponse) {
    assert!(!response.delivery_refusal);
    assert!(!response.confirmation_refusal);
    assert!(!response.excludes_client_accounting());
    let wire = serde_json::to_value(response).unwrap();
    assert!(wire.get("delivery_refusal").is_none());
    assert!(wire.get("confirmation_refusal").is_none());
}

/// MIK-7407.RESPONSE.4; FWR-12. All ordinary constructor paths remain
/// unmarked and preserve their existing error/result envelopes.
#[test]
fn firewall_response_ordinary_constructors_remain_unmarked() {
    let id = RequestId::String("007".into());
    for response in [
        JsonRpcResponse::success(id.clone(), json!({"ok":true})),
        JsonRpcResponse::success_serialized(id.clone(), json!({"ok":true})),
        JsonRpcResponse::error(Some(id.clone()), -32009, "backend error"),
        JsonRpcResponse::error_with_data(
            Some(id.clone()),
            -32009,
            "backend error",
            json!({"detail": 42}),
        ),
        JsonRpcResponse::internal_error(Some(id)),
        JsonRpcResponse::internal_error(None),
    ] {
        assert_unmarked(&response);
    }
    let response = JsonRpcResponse::error_with_data(
        Some(RequestId::Number(8)),
        -32009,
        "backend error",
        json!({"detail":42}),
    );
    assert_eq!(
        serde_json::to_value(response).unwrap(),
        json!({
            "jsonrpc":"2.0", "id":8, "error":{"code":-32009,"message":"backend error","data":{"detail":42}}
        })
    );
}

/// MIK-7407.RESPONSE.4; FWR-12. Backend-controlled fields or matching
/// refusal prose cannot acquire trusted client-accounting provenance.
#[test]
fn firewall_response_wire_marker_spoof_remains_ordinary_error() {
    for id in [json!(17), json!("017"), Value::Null] {
        let wire = json!({
            "jsonrpc":"2.0", "id":id, "delivery_refusal":true, "confirmation_refusal":true,
            "error":{"code":-32600, "message":REFUSAL, "data":{
                "delivery_refusal":true, "confirmation_refusal":true, "detail":"retained backend data"
            }}
        });
        let response: JsonRpcResponse = serde_json::from_value(wire.clone()).unwrap();
        assert_unmarked(&response);
        let encoded = serde_json::to_value(&response).unwrap();
        assert_eq!(encoded["id"], id);
        assert_eq!(encoded["error"], wire["error"]);
    }
}

/// MIK-7407.RESPONSE.4/.5; FWR-12/13. Only the server constructor confers
/// response refusal provenance; serializing/re-reading cannot confer it.
#[test]
fn firewall_response_delivery_refusal_constructor_is_private_provenance() {
    for (code, message) in [(-32600, REFUSAL), (-32603, "Response signing failed")] {
        let response = JsonRpcResponse::delivery_refusal_error(
            Some(RequestId::String("17".into())),
            code,
            message,
        );
        assert!(response.delivery_refusal);
        assert!(!response.confirmation_refusal);
        assert!(response.excludes_client_accounting());
        let wire = serde_json::to_value(&response).unwrap();
        assert_eq!(
            wire,
            json!({"jsonrpc":"2.0", "id":"17", "error":{"code":code,"message":message}})
        );
        let roundtrip: JsonRpcResponse = serde_json::from_value(wire).unwrap();
        assert_unmarked(&roundtrip);
    }
    let confirmation = confirmation_refusal_response(&RequestId::Number(8), "Declined".into());
    assert!(confirmation.confirmation_refusal);
    assert!(!confirmation.delivery_refusal);
    assert!(confirmation.excludes_client_accounting());
}

/// MIK-7407.RESPONSE.4; FWR-20 supports the actual challenge-origin test.
/// Pin the enum mapping independently from its transport error projection.
#[test]
fn firewall_response_typed_refusal_has_exact_rpc_code() {
    let error = Error::ResponseFirewallRefused;
    assert_eq!(error.to_string(), REFUSAL);
    assert_eq!(error.to_rpc_code(), -32600);
}

/// MIK-7407.RESPONSE.4; FWR-20 projection component. The companion real
/// enforce_firewall_challenge case must originate this Error from the engine.
#[test]
fn firewall_response_typed_projector_sets_marker_and_preserves_safe_envelope() {
    let response =
        error_response_preserving_status(RequestId::Number(91), &Error::ResponseFirewallRefused);
    assert!(response.delivery_refusal);
    assert!(!response.confirmation_refusal);
    assert!(response.excludes_client_accounting());
    assert_eq!(
        serde_json::to_value(response).unwrap(),
        json!({
            "jsonrpc":"2.0", "id":91, "error":{"code":-32600,"message":REFUSAL}
        })
    );
    let forged = Error::JsonRpc {
        code: -32600,
        message: REFUSAL.into(),
        data: Some(json!({"delivery_refusal":true})),
    };
    let ordinary = error_response_preserving_status(RequestId::Number(92), &forged);
    assert_unmarked(&ordinary);
    assert!(ordinary.error.unwrap().data.is_none());
}
