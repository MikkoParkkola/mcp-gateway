// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8488 PR-A (INVOKE.6), site 18's key half (mutant s18a): a keyed
//! `gateway_invoke` refused by relay detection releases its idempotency key at
//! the refusal, so the reservation's drop never releases it as abandoned.
//! Red against the release removed (the drop then logs the abandoned
//! release), green on the code it pins.

use serde_json::{Value, json};

use super::direct_guards_fixture::{Answer, Fx, fixture_signed_relayed, send_with_headers};

/// Prose a backend answer carries and a later call relays (relay detection).
const PROSE: &str = "The orchard ledger for the north slope records seven rows of late \
    pears, the grafting dates for each rootstock, the hours the drip lines ran during the \
    dry weeks of August, and which crew pruned the older trees after the second frost.";

/// A signed `gateway_invoke read` on `alpha` as `key` under `nonce`, with
/// `meta` merged into the request's `_meta`.
async fn signed_invoke(fx: &Fx, key: &str, nonce: &str, args: Value, meta: Value) -> Value {
    let mut params = json!({
        "name": "gateway_invoke",
        "arguments": {"server": "alpha", "tool": "read", "arguments": args, "nonce": nonce},
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {"elicitation": {"form": {}}}
        }
    });
    if let (Some(into), Some(extra)) = (params["_meta"].as_object_mut(), meta.as_object()) {
        into.extend(extra.clone());
    }
    let headers = [
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "tools/call"),
        ("mcp-name", "gateway_invoke"),
    ];
    send_with_headers(fx, "/mcp", key, "tools/call", params, None, &headers)
        .await
        .1
}

#[test]
fn a_keyed_relay_refusal_releases_its_key_at_the_refusal() {
    let records = crate::test_log_capture::records(|| {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let fx = fixture_signed_relayed(Answer::Text(PROSE)).await;
            let read = signed_invoke(&fx, "k-std", "a1", json!({}), json!({})).await;
            assert!(read.get("error").is_none(), "premise: the read ran: {read}");
            let keyed = json!({(crate::protocol::mrtr::IDEMPOTENCY_KEY_META): "k-8488-relay"});
            let relayed =
                signed_invoke(&fx, "k-budget", "b1", json!({ "cmd": PROSE }), keyed).await;
            assert_eq!(
                relayed["error"]["code"], -32002,
                "premise: the relay refusal: {relayed}"
            );
        });
    });
    let abandoned = crate::test_log_capture::count(
        &records,
        "DEBUG",
        "Released abandoned idempotency reservation",
    );
    assert_eq!(
        abandoned, 0,
        "the relay refusal left its key for the drop to release"
    );
}
