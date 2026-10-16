// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8406 bridged managed-account rows: a bridged caller's connected vault
//! account, revoked after a keyed plan ran. Its live call answers the
//! reconnect offer with data, so these rows carry the offer oracle.

use std::sync::atomic::Ordering;

use super::*;
use crate::personal_accounts::AccountKey;
use crate::personal_accounts::revoke_fixture::{Seed, grant};

/// The issuer [`config`]'s descriptor names, which the account key carries.
const DESCRIPTOR_ISSUER: &str = "https://issuer.fixture.test";

/// The bridged caller `alice`'s key on [`ACCOUNT`].
fn alice_key() -> AccountKey {
    AccountKey {
        principal_authority: "openwebui-adapter:20:fixture-installation".into(),
        principal_subject: "alice".into(),
        backend_id: ACCOUNT.into(),
        resource: RESOURCE.into(),
        oauth_issuer: DESCRIPTOR_ISSUER.into(),
    }
}

/// The gateway with `alice` connected on [`ACCOUNT`] at the descriptor's
/// own revision, so her dispatch mints and reaches her per-user slot.
async fn connected() -> Gateway {
    let config = config(std::path::Path::new("/unused"), Shape::Bridged);
    let descriptors = config
        .accounts
        .as_ref()
        .and_then(|a| a.descriptors.as_ref());
    let descriptor = &descriptors.expect("descriptors")[ACCOUNT];
    let mut seeded = grant("alice");
    seeded.descriptor_revision = crate::personal_accounts::descriptor_revision(descriptor)
        .expect("the descriptor has a revision");
    gateway_seeded(Shape::Bridged, &[(alice_key(), seeded, Seed::Connected)]).await
}

/// Revoke `alice`'s grant through the custody the dispatch reads.
async fn revoke(gw: &Gateway) {
    gw.fixture
        .handles()
        .revocation
        .invalidate(&alice_key())
        .await
        .expect("the seeded grant revokes");
}

/// A `tools/call` of `name` with `arguments`, keyed by `key` when given.
fn keyed(name: &str, arguments: &Value, key: Option<&str>) -> Value {
    let mut meta = json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {},
    });
    if let Some(key) = key {
        meta[crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!(key);
    }
    call(
        "tools/call",
        &json!({"name": name, "arguments": arguments, "_meta": meta}),
    )
}

/// [`rpc`] at `/mcp` as the bridged `alice`, with the protocol header the
/// 2026-07-28 `_meta` needs.
async fn send(gw: &Gateway, body: &Value) -> Value {
    let request = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("authorization", format!("Bearer {API_KEY}"))
        .header("x-openwebui-assertion", assertion(HMAC, "alice"))
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header(
            "mcp-name",
            body["params"]["name"].as_str().unwrap_or_default(),
        )
        .body(Body::from(body.to_string()))
        .unwrap();
    let response = gw.router.clone().oneshot(request).await.unwrap();
    let bytes = axum::body::to_bytes(response.into_body(), 256 * 1024)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).expect("a JSON-RPC body")
}

/// The single `gateway_execute` form: one `list_files` on [`BACKEND`].
fn single() -> Value {
    json!({"tool": format!("{BACKEND}:list_files"), "arguments": {}})
}

/// F0 (fixture check, not a MIK-8406 row): a connected bridged caller's
/// keyed `gateway_execute` mints, reaches her slot once and enters the plan
/// executor once; once revoked, her live call answers the reconnect offer
/// with data.
#[tokio::test]
async fn f0_a_seeded_bridged_caller_dispatches_then_is_offered_after_revoke() {
    let gw = Box::pin(connected()).await;
    let entered = crate::gateway::meta_mcp::plan_entries::count(&gw.meta);
    let first = send(&gw, &keyed("gateway_execute", &single(), Some("f0"))).await;
    assert!(
        first.to_string().contains(SLOT_MARKER),
        "the plan did not dispatch: {first}"
    );
    assert_eq!(gw.sends.load(Ordering::SeqCst), 1, "{first}");
    assert_eq!(
        crate::gateway::meta_mcp::plan_entries::count(&gw.meta) - entered,
        1,
        "the served Meta-MCP did not count the plan"
    );
    revoke(&gw).await;
    let live = send(&gw, &keyed("gateway_execute", &single(), None)).await;
    assert_eq!(live["error"]["code"], -32001, "{live}");
    assert_eq!(live["error"]["data"]["account_id"], ACCOUNT, "{live}");
    assert_eq!(
        live["error"]["data"]["error"]["code"], "reconnect_required",
        "{live}"
    );
    assert_eq!(gw.sends.load(Ordering::SeqCst), 1, "the live call sent");
}
