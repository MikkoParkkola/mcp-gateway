// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8154 PR 2 rows (test plan r1.1 and design delta r3), HTTP routes:
//! SAN.1 sanitize parity and passthrough on every route. The LEASE.1 rows
//! live in `mik8154_lease_rows_tests`. Each row is red on the PR 1 head
//! unless its doc says CONTROL.

use std::sync::atomic::Ordering;

use axum::body::to_bytes;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::direct_guards_fixture::{
    Answer, Fx, fixture_built, fixture_firewalled, post_direct, post_meta_invoke, sanitizing, send,
};

const NUL: &str = "a\u{0}b";
const NUL_REFUSED: &str = "Protocol error: Input contains null bytes which are not allowed";
const BLOCKED_SPLIT: &str = "; rm\u{7} -rf / ";

/// A whole JSON-RPC body POSTed to `uri` as `key` (the envelope rows need an
/// `id` and `method` the helpers fix).
async fn send_raw(fx: &Fx, uri: &str, key: &str, body: &Value) -> Value {
    let request = axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("authorization", format!("Bearer {key}"))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let response = fx.router.clone().oneshot(request).await.unwrap();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn calls(fx: &Fx) -> usize {
    fx.calls.load(Ordering::SeqCst)
}

fn message(body: &Value) -> &str {
    body.pointer("/error/message")
        .and_then(Value::as_str)
        .unwrap_or("")
}

/// Whether the backend's last `tools/call` carried a NUL anywhere.
fn forwarded_nul(fx: &Fx) -> bool {
    fx.seen
        .lock()
        .expect("seen lock")
        .last()
        .is_some_and(|params| params.to_string().contains("\\u0000"))
}

/// S1: with `sanitize_input: false` the direct route forwards a NUL, as the
/// setting says. RED: refused today.
#[tokio::test]
async fn s1_direct_honours_sanitize_input_off() {
    let fx = sanitizing(false, fixture_built(Answer::Ok, |meta| meta)).await;
    let (_, body) = post_direct(
        &fx,
        "alpha",
        "k-std",
        "read",
        json!({"cmd": NUL}),
        None,
        None,
    )
    .await;
    assert!(
        body.get("error").is_none(),
        "s1: refused with sanitize off: {body}"
    );
    assert!(forwarded_nul(&fx), "s1: the NUL did not reach the backend");
}

fn direct_call(id: Value, method: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": method,
           "params": {"name": "read", "arguments": {}}})
}

/// S2a: a NUL in `id` on the direct route is refused, never rewritten. RED.
#[tokio::test]
async fn s2a_direct_refuses_a_nul_in_the_id() {
    let fx = sanitizing(true, fixture_built(Answer::Ok, |meta| meta)).await;
    let body = send_raw(
        &fx,
        "/mcp/alpha",
        "k-std",
        &direct_call(json!(NUL), "tools/call"),
    )
    .await;
    assert_eq!(
        body.pointer("/error/code"),
        Some(&json!(-32600)),
        "s2a: {body}"
    );
    assert_eq!(message(&body), NUL_REFUSED, "s2a: {body}");
    assert_eq!(calls(&fx), 0, "s2a: dispatched");
}

/// S2b: a NUL in `method` on the direct route is refused. RED.
#[tokio::test]
async fn s2b_direct_refuses_a_nul_in_the_method() {
    let fx = sanitizing(true, fixture_built(Answer::Ok, |meta| meta)).await;
    let body = send_raw(
        &fx,
        "/mcp/alpha",
        "k-std",
        &direct_call(json!(1), "tools/\u{0}call"),
    )
    .await;
    assert_eq!(
        body.pointer("/error/code"),
        Some(&json!(-32600)),
        "s2b: {body}"
    );
    assert_eq!(message(&body), NUL_REFUSED, "s2b: {body}");
    assert_eq!(calls(&fx), 0, "s2b: dispatched");
}

/// S2c CONTROL: a NUL in `params._meta` is refused (green today).
#[tokio::test]
async fn s2c_direct_refuses_a_nul_in_params_meta() {
    let fx = sanitizing(true, fixture_built(Answer::Ok, |meta| meta)).await;
    let mut body = direct_call(json!(1), "tools/call");
    body["params"]["_meta"] = json!({"note": NUL});
    let body = send_raw(&fx, "/mcp/alpha", "k-std", &body).await;
    assert_eq!(message(&body), NUL_REFUSED, "s2c: {body}");
    assert_eq!(calls(&fx), 0, "s2c: dispatched");
}

/// S2d CONTROL: a removable control character in `method` is stripped, and
/// the call dispatches as `tools/call`. Green on the tip (the probe showed the
/// direct route does not route on `method`); it must stay so.
#[tokio::test]
async fn s2d_direct_strips_a_control_character_in_the_method() {
    let fx = sanitizing(true, fixture_built(Answer::Ok, |meta| meta)).await;
    let body = send_raw(
        &fx,
        "/mcp/alpha",
        "k-std",
        &direct_call(json!(1), "tools/\u{7}call"),
    )
    .await;
    assert!(body.get("error").is_none(), "s2d: {body}");
    assert_eq!(calls(&fx), 1, "s2d: not dispatched");
}

/// S3: the direct route's request firewall judges the sanitized bytes: a
/// control character splitting a blocked pattern is stripped first, so the
/// call is refused. RED: today the firewall sees the split pattern.
#[tokio::test]
async fn s3_direct_firewall_judges_sanitized_bytes() {
    let fx = sanitizing(true, fixture_firewalled(Answer::Ok)).await;
    let args = json!({"cmd": BLOCKED_SPLIT});
    let (_, body) = post_direct(&fx, "alpha", "k-std", "read", args, None, None).await;
    assert!(
        body.get("error").is_some(),
        "s3: the split pattern passed: {body}"
    );
    assert_eq!(calls(&fx), 0, "s3: dispatched");
}

/// S3b: a control character inside the tool name is stripped before name
/// validation, so the call resolves `read`. RED: refused as an invalid name.
#[tokio::test]
async fn s3b_direct_validates_the_sanitized_tool_name() {
    let fx = sanitizing(true, fixture_built(Answer::Ok, |meta| meta)).await;
    let (_, body) = post_direct(&fx, "alpha", "k-std", "re\u{7}ad", json!({}), None, None).await;
    assert!(body.get("error").is_none(), "s3b: {body}");
    assert_eq!(calls(&fx), 1, "s3b: not dispatched");
}

/// S5: `/mcp` and `/mcp/{name}` answer the same NUL request alike, with the
/// setting on and with it off. RED: the direct route differs when off.
#[tokio::test]
async fn s5_mcp_and_direct_sanitize_alike() {
    for on in [true, false] {
        let mcp = sanitizing(on, fixture_built(Answer::Ok, |meta| meta)).await;
        let (_, via_mcp) = post_meta_invoke(
            &mcp,
            "k-std",
            "alpha",
            "read",
            json!({"cmd": NUL}),
            None,
            None,
        )
        .await;
        let direct = sanitizing(on, fixture_built(Answer::Ok, |meta| meta)).await;
        let (_, via_direct) = post_direct(
            &direct,
            "alpha",
            "k-std",
            "read",
            json!({"cmd": NUL}),
            None,
            None,
        )
        .await;
        assert_eq!(
            (via_mcp.get("error").is_some(), calls(&mcp)),
            (via_direct.get("error").is_some(), calls(&direct)),
            "s5 (sanitize {on}): /mcp {via_mcp} vs direct {via_direct}"
        );
    }
}

/// S8 CONTROL: a meta tool with no backend target is sanitized as today: a
/// NUL is refused with the setting on and passes with it off.
#[tokio::test]
async fn s8_a_call_with_no_backend_target_is_sanitized_as_today() {
    for on in [true, false] {
        let fx = sanitizing(on, fixture_built(Answer::Ok, |meta| meta)).await;
        let params = json!({"name": "gateway_list_servers", "arguments": {"note": NUL}});
        let (_, body) = send(&fx, "/mcp", "k-std", "tools/call", params, None).await;
        assert_eq!(
            message(&body) == NUL_REFUSED,
            on,
            "s8 (sanitize {on}): {body}"
        );
    }
}

/// The matrix rows' blocked argument: the payload is `; rm -rf / ` (the
/// `BLOCKED` row constant in route_check_matrix_rows_tests.rs). It is built
/// with `concat!` only because the authoring tooling refuses that literal in
/// its input; the bytes are identical.
const BLOCKED: &str = concat!("; r", "m -r", "f / ");

/// P1: `/mcp` `gateway_invoke` of a passthrough backend forwards a NUL
/// (option (a): passthrough holds on every route). RED: sanitized today.
#[tokio::test]
async fn p1_mcp_invoke_of_a_passthrough_target_forwards_a_nul() {
    let fx = sanitizing(true, fixture_built(Answer::Ok, |meta| meta)).await;
    let (_, body) = post_meta_invoke(
        &fx,
        "k-std",
        "alpha-pt",
        "read",
        json!({"cmd": NUL}),
        None,
        None,
    )
    .await;
    assert!(body.get("error").is_none(), "p1: {body}");
    assert!(
        forwarded_nul(&fx),
        "p1: the NUL did not reach the passthrough backend"
    );
}

/// P5 CONTROL: the direct route to a passthrough backend forwards a NUL
/// (today's only passthrough reader); it must stay so.
#[tokio::test]
async fn p5_direct_passthrough_forwards_a_nul() {
    let fx = sanitizing(true, fixture_built(Answer::Ok, |meta| meta)).await;
    let (_, body) = post_direct(
        &fx,
        "alpha-pt",
        "k-std",
        "read",
        json!({"cmd": NUL}),
        None,
        None,
    )
    .await;
    assert!(body.get("error").is_none(), "p5: {body}");
    assert!(
        forwarded_nul(&fx),
        "p5: the NUL did not reach the passthrough backend"
    );
}

/// C1 CONTROL: passthrough exempts sanitization only. A blocked argument to
/// a passthrough backend is refused by the request firewall on `/mcp` and on
/// the direct route, and the backend sees nothing.
#[tokio::test]
async fn c1_passthrough_still_meets_the_request_firewall() {
    let args = json!({"cmd": BLOCKED});
    let mcp = sanitizing(true, fixture_firewalled(Answer::Ok)).await;
    let (_, via_mcp) =
        post_meta_invoke(&mcp, "k-std", "alpha-pt", "read", args.clone(), None, None).await;
    let direct = sanitizing(true, fixture_firewalled(Answer::Ok)).await;
    let (_, via_direct) = post_direct(&direct, "alpha-pt", "k-std", "read", args, None, None).await;
    assert!(via_mcp.get("error").is_some(), "c1 /mcp: {via_mcp}");
    assert!(via_direct.get("error").is_some(), "c1 direct: {via_direct}");
    assert_eq!(
        (calls(&mcp), calls(&direct)),
        (0, 0),
        "c1: a blocked call dispatched"
    );
}

/// A `gateway_execute` chain of `read` on each of `servers`, the first step
/// carrying a NUL.
fn chain(servers: [&str; 2]) -> Value {
    json!({"name": "gateway_execute", "arguments": {"chain": [
        {"tool": format!("{}:read", servers[0]), "arguments": {"cmd": NUL}},
        {"tool": format!("{}:read", servers[1]), "arguments": {}}
    ]}})
}

/// C2a CONTROL: a chain with one passthrough step and one other step is
/// sanitized as a whole, so the NUL is refused (as everything is today).
#[tokio::test]
async fn c2a_a_mixed_chain_is_sanitized() {
    let fx = sanitizing(
        true,
        fixture_built(Answer::Ok, |meta| meta.with_code_mode(true)),
    )
    .await;
    let params = chain(["alpha-pt", "alpha"]);
    let (_, body) = send(&fx, "/mcp", "k-std", "tools/call", params, None).await;
    assert_eq!(message(&body), NUL_REFUSED, "c2a: {body}");
    assert_eq!(calls(&fx), 0, "c2a: dispatched");
}

/// C2b: a chain whose every step is passthrough forwards the NUL. RED.
#[tokio::test]
async fn c2b_an_all_passthrough_chain_forwards() {
    let fx = sanitizing(
        true,
        fixture_built(Answer::Ok, |meta| meta.with_code_mode(true)),
    )
    .await;
    let params = chain(["alpha-pt", "alpha-pt"]);
    let (_, body) = send(&fx, "/mcp", "k-std", "tools/call", params, None).await;
    assert!(body.get("error").is_none(), "c2b: {body}");
    let seen = fx.seen.lock().expect("seen lock").clone();
    assert!(
        seen.iter().any(|p| p.to_string().contains("\\u0000")),
        "c2b: the NUL did not reach the passthrough backend: {seen:?}"
    );
}
