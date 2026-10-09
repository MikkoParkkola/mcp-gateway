// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7211.PARENT.6 test 9 (firewall legs): the pre-sign clamp neither
//! rescues a blocked response nor triggers a second inspection.

use super::{Fixture, INJECTION, REFUSAL, ResponseDeliveryContext, correlation, targets};
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::security::firewall::FirewallAction;
use serde_json::json;

fn public_response(text: &str) -> JsonRpcResponse {
    JsonRpcResponse::success(
        RequestId::Number(-41),
        json!({"content": [{"type": "text", "text": text}], "cacheScope": "public"}),
    )
}

#[test]
fn a_blocked_public_response_stays_result_free() {
    let fixture = Fixture::new(FirewallAction::Block, true, true, false);

    let response = fixture.finalize("tools/call", public_response(INJECTION), &targets());

    assert!(response.result.is_none());
    assert_eq!(
        serde_json::to_value(&response).unwrap(),
        json!({"jsonrpc": "2.0", "id": -41, "error": {"code": -32600, "message": REFUSAL}})
    );
}

#[test]
fn an_already_inspected_public_response_is_clamped_without_a_second_scan() {
    let fixture = Fixture::new(FirewallAction::Block, true, true, false);
    let targets = targets();
    let context = ResponseDeliveryContext {
        method: "tools/call",
        targets: &targets,
        correlation: correlation(),
        signing: None,
        chain_source: crate::gateway::meta_mcp::response_security::ChainSource::NotEligible,
        chain_nonce: None,
    };
    let runtime = tokio::runtime::Runtime::new().unwrap();

    // A frame an earlier exit already screened carries the egress mark.
    let mut screened = public_response(INJECTION);
    screened.egress_scanned = true;
    let delivered = runtime.block_on(
        fixture
            .meta
            .finalize_response_for_delivery(screened, &context),
    );

    assert!(delivered.error.is_none(), "no second inspection may refuse");
    let result = delivered.result.expect("delivered with its result");
    assert_eq!(result["cacheScope"], "private");
    assert_eq!(fixture.firewall.response_inspection_counts().inspections, 0);
}
