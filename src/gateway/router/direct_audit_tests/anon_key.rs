// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8154.ANON.1 (design r3 D2, r3.1 F8/F9/F11): a keyed `tools/call` from
//! a caller with no execution principal (no verified identity, credential or
//! proven subject) is answered alike on `/mcp` and `/mcp/{name}`: refused
//! -32003 with HTTP 400, the backend not run. An unkeyed call still runs on
//! both. The gateway here is the plain auth-off one, `idempotency_key:
//! optional` (the default; under `required` an unkeyed modern call is the
//! pre-existing key-mode difference, out of scope).

use super::*;

const KEY: &str = "anon-k";
const NO_PRINCIPAL: &str = "JSON-RPC error -32003: A verified execution principal is required";

fn idempotent() -> Setup {
    Setup {
        meta_mode: MetaMode::Idempotent,
        ..Setup::default()
    }
}

/// `gateway_invoke` of `alpha/t` on `/mcp`, keyed when `key` is given.
fn invoke_call(key: Option<&str>) -> String {
    let mut params = json!({
        "name": "gateway_invoke",
        "arguments": {"server": "alpha", "tool": "t", "arguments": {"customer_id": "c"}},
    });
    if let Some(key) = key {
        params["_meta"] = json!({(crate::protocol::mrtr::IDEMPOTENCY_KEY_META): key});
    }
    json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": params}).to_string()
}

fn message(body: &Value) -> &str {
    body.pointer("/error/message")
        .and_then(Value::as_str)
        .unwrap_or("")
}

/// AN1: the direct route refuses a principal-less keyed call as `/mcp` does:
/// -32003, HTTP 400, the backend not run. The refusal holds nothing: the same
/// call is refused the same way again (never "in flight"), and the same key
/// from a caller who has a principal then runs, once. RED on the PR 1 head,
/// where the direct route guarded such a call with its cache alone.
#[tokio::test]
async fn an1_the_direct_route_refuses_a_principal_less_keyed_call() {
    let fx = fixture(idempotent()).await;
    for attempt in ["first", "again"] {
        let (status, body) = post(
            &fx,
            "alpha",
            &direct_call("c", Some(KEY)),
            &Caller::Anonymous,
        )
        .await;
        assert_eq!(message(&body), NO_PRINCIPAL, "an1 {attempt}: {body}");
        assert_eq!(status, StatusCode::BAD_REQUEST, "an1 {attempt}: {body}");
        assert_eq!(
            fx.calls.load(Ordering::SeqCst),
            0,
            "an1 {attempt}: dispatched"
        );
    }
    let (_, body) = post(&fx, "alpha", &direct_call("c", Some(KEY)), &Caller::Oidc).await;
    assert!(
        body.get("error").is_none(),
        "an1: a caller with a principal: {body}"
    );
    assert_eq!(
        fx.calls.load(Ordering::SeqCst),
        1,
        "an1: the released key did not run once"
    );
}

/// AN2 CONTROL: `/mcp` refuses the same principal-less keyed call: -32003,
/// HTTP 400, the backend not run. Green on the PR 1 head; pins the parity.
#[tokio::test]
async fn an2_mcp_refuses_a_principal_less_keyed_call() {
    let fx = fixture(idempotent()).await;
    let (status, body) = post_to(&fx, "/mcp", &invoke_call(Some(KEY)), &Caller::Session).await;
    assert_eq!(message(&body), NO_PRINCIPAL, "an2: {body}");
    assert_eq!(status, StatusCode::BAD_REQUEST, "an2: {body}");
    assert_eq!(fx.calls.load(Ordering::SeqCst), 0, "an2: dispatched");
}

/// AN3 CONTROL: an unkeyed principal-less call runs on both routes.
#[tokio::test]
async fn an3_an_unkeyed_principal_less_call_runs_on_both_routes() {
    let fx = fixture(idempotent()).await;
    let (_, body) = post(&fx, "alpha", &direct_call("c", None), &Caller::Anonymous).await;
    assert!(body.get("error").is_none(), "an3 direct: {body}");
    let (_, body) = post_to(&fx, "/mcp", &invoke_call(None), &Caller::Session).await;
    assert!(body.get("error").is_none(), "an3 /mcp: {body}");
    assert_eq!(fx.calls.load(Ordering::SeqCst), 2, "an3: not both ran");
}
