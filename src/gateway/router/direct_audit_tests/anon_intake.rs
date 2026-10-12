// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8382 (design r2 R2-8, test plan r2): a keyed `tools/call` from a
//! caller with no execution principal is refused at intake, -32003 with HTTP
//! 400, before any backend work and before the backend lookup, so the answer
//! is the same whatever the tool or backend name. Rows B1-B9 of the plan
//! (direct route); the `/mcp` rows sit beside AN2. The gateway is the plain
//! auth-off one in idempotent mode, as in `anon_key`.

use super::*;

const KEY: &str = "intake-k";
const NO_PRINCIPAL: &str = "JSON-RPC error -32003: A verified execution principal is required";

fn idempotent() -> Setup {
    Setup {
        meta_mode: MetaMode::Idempotent,
        ..Setup::default()
    }
}

/// A direct `tools/call` of `tool` with `meta` as its `_meta`.
fn call_with_meta(tool: &str, meta: Value) -> String {
    json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {
        "name": tool, "arguments": {"customer_id": "c"}, "_meta": meta}})
    .to_string()
}

fn keyed(tool: &str) -> String {
    call_with_meta(
        tool,
        json!({(crate::protocol::mrtr::IDEMPOTENCY_KEY_META): KEY}),
    )
}

fn message(body: &Value) -> &str {
    body.pointer("/error/message")
        .and_then(Value::as_str)
        .unwrap_or("")
}

/// `idp_mint` rows in the fixture's transparency log: an identity mint for
/// the call (propagation) leaves one.
fn mint_rows(fx: &Fixture) -> usize {
    std::fs::read_to_string(&fx.path)
        .unwrap_or_default()
        .matches("\"idp_mint\"")
        .count()
}

/// B1 (ORDER.1): a keyed call with no principal does no backend work at all:
/// -32003 and HTTP 400, no `tools/call`, no `tools/list`, no identity mint,
/// whether the backend answers or its transport fails. RED: the cold call
/// lists the backend first (the schema key check), so a reachable backend
/// sees a `tools/list` and an unreachable one answers 500 before the
/// principal is ever judged.
#[tokio::test]
async fn b1_keyed_no_principal_does_no_backend_work() {
    for list_fail in [false, true] {
        let fx = fixture(Setup {
            list_fail,
            ..idempotent()
        })
        .await;
        let (status, body) = post(&fx, "alpha", &keyed("t"), &Caller::Anonymous).await;
        assert_eq!(
            message(&body),
            NO_PRINCIPAL,
            "b1 list_fail={list_fail}: {body}"
        );
        assert_eq!(status, StatusCode::BAD_REQUEST, "b1 list_fail={list_fail}");
        assert_eq!(fx.calls.load(Ordering::SeqCst), 0, "b1: tools/call sent");
        assert_eq!(
            fx.lists.load(Ordering::SeqCst),
            0,
            "b1 list_fail={list_fail}: tools/list sent"
        );
        assert_eq!(mint_rows(&fx), 0, "b1: an identity was minted");
    }
}

/// B2 (ORDER.2, UNIFY.1a′): the refusal is byte-identical whatever the tool
/// or backend name: an existing tool, a missing tool, an existing backend
/// whose transport fails, and a backend that does not exist. RED: the missing
/// backend answers -32001 / 404, and the failing backend 500.
#[tokio::test]
async fn b2_keyed_no_principal_is_name_independent() {
    let fx = fixture(idempotent()).await;
    let failing = fixture(Setup {
        list_fail: true,
        ..idempotent()
    })
    .await;
    let answers = [
        (
            "existing tool",
            post_to_raw(&fx, "/mcp/alpha", &keyed("t"), &Caller::Anonymous).await,
        ),
        (
            "missing tool",
            post_to_raw(&fx, "/mcp/alpha", &keyed("nope"), &Caller::Anonymous).await,
        ),
        (
            "failing backend",
            post_to_raw(&failing, "/mcp/alpha", &keyed("t"), &Caller::Anonymous).await,
        ),
        (
            "missing backend",
            post_to_raw(&fx, "/mcp/nope", &keyed("t"), &Caller::Anonymous).await,
        ),
    ];
    let (_, (_, first)) = &answers[0];
    for (case, (status, bytes)) in &answers {
        assert_eq!(*status, StatusCode::BAD_REQUEST, "b2 {case}: {bytes:?}");
        assert_eq!(bytes, first, "b2 {case} differs from the existing tool");
    }
    let body: Value = serde_json::from_slice(first).expect("JSON");
    assert_eq!(message(&body), NO_PRINCIPAL, "b2: {body}");
}

/// B4: a malformed key (empty, or not a string) from a caller with no
/// principal is refused at intake too: the caller asked for keyed handling
/// (lead ruling on R2-7). RED: today preflight answers -32602.
#[tokio::test]
async fn b4_malformed_key_without_principal_is_refused_at_intake() {
    for key in [json!(""), json!(7)] {
        let fx = fixture(idempotent()).await;
        let body = call_with_meta(
            "t",
            json!({(crate::protocol::mrtr::IDEMPOTENCY_KEY_META): key}),
        );
        let (status, answer) = post(&fx, "alpha", &body, &Caller::Anonymous).await;
        assert_eq!(message(&answer), NO_PRINCIPAL, "b4 {key}: {answer}");
        assert_eq!(status, StatusCode::BAD_REQUEST, "b4 {key}");
        assert_eq!(fx.lists.load(Ordering::SeqCst), 0, "b4 {key}: listed");
    }
}

/// B5 CONTROL: the same malformed keys from a caller WITH a principal keep
/// today's refusal, -32602 from the retry fields.
#[tokio::test]
async fn b5_malformed_key_with_principal_keeps_its_refusal() {
    for key in [json!(""), json!(7)] {
        let fx = fixture(idempotent()).await;
        let body = call_with_meta(
            "t",
            json!({(crate::protocol::mrtr::IDEMPOTENCY_KEY_META): key}),
        );
        let (_, answer) = post(&fx, "alpha", &body, &Caller::Oidc).await;
        assert_eq!(
            answer.pointer("/error/code"),
            Some(&json!(-32602)),
            "b5 {key}: {answer}"
        );
        assert_eq!(fx.calls.load(Ordering::SeqCst), 0, "b5 {key}: dispatched");
    }
}

/// B7 CONTROL: a keyed `tools/call` with no `id` keeps today's answer,
/// -32600 "Missing id" with a null id (MIK-8396 owns any change).
#[tokio::test]
async fn b7_id_less_tools_call_keeps_missing_id() {
    let fx = fixture(idempotent()).await;
    let body = json!({"jsonrpc": "2.0", "method": "tools/call", "params": {
        "name": "t", "arguments": {},
        "_meta": {(crate::protocol::mrtr::IDEMPOTENCY_KEY_META): KEY}}})
    .to_string();
    let (_, answer) = post(&fx, "alpha", &body, &Caller::Anonymous).await;
    assert_eq!(
        answer.pointer("/error/code"),
        Some(&json!(-32600)),
        "b7: {answer}"
    );
    assert_eq!(message(&answer), "Missing id", "b7: {answer}");
    assert_eq!(answer.get("id"), Some(&Value::Null), "b7: {answer}");
}

fn sanitizing() -> Setup {
    Setup {
        sanitize: true,
        beta_passthrough: true,
        ..idempotent()
    }
}

/// A keyed direct call whose arguments carry a NUL.
fn keyed_nul(tool: &str) -> String {
    json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {
        "name": tool, "arguments": {"customer_id": "a\u{0}b"},
        "_meta": {(crate::protocol::mrtr::IDEMPOTENCY_KEY_META): KEY}}})
    .to_string()
}

/// B3 (UNIFY.1a′): with sanitizing on, a keyed no-principal call carrying a
/// NUL gets the same bytes from a passthrough backend (`beta`, exempt from
/// sanitizing) as from a backend that does not exist (sanitized). Otherwise
/// the sanitize step would tell the caller which backend is passthrough, or
/// exists. RED: `nope` answers -32001 / 404, `beta` -32003.
/// Control half: the same NUL from a caller WITH a principal to the
/// non-passthrough `alpha` is refused by the sanitizer, so moving the check
/// after the sanitize step is observable (M4's killer is B8a).
#[tokio::test]
async fn b3_sanitize_cannot_tell_backends_apart() {
    let fx = fixture(sanitizing()).await;
    let passthrough = post_to_raw(&fx, "/mcp/beta", &keyed_nul("t"), &Caller::Anonymous).await;
    let missing = post_to_raw(&fx, "/mcp/nope", &keyed_nul("t"), &Caller::Anonymous).await;
    assert_eq!(
        passthrough, missing,
        "b3: passthrough vs missing backend differ"
    );
    let (_, body) = post(&fx, "alpha", &keyed_nul("t"), &Caller::Oidc).await;
    assert!(
        message(&body).contains("null bytes"),
        "b3 control: a principal's NUL was not refused by the sanitizer: {body}"
    );
    assert_eq!(fx.calls.load(Ordering::SeqCst), 0, "b3: dispatched");
}

/// B8: for a keyed no-principal `tools/call`, the intake refusal answers
/// before refusals that come later on the direct route today. Each case's
/// "before" is the answer recorded from the release line (red run); "after"
/// is -32003, HTTP 400, the request's id (None where unrecognised).
#[tokio::test]
async fn b8_intake_answers_before_later_refusals() {
    let fx = fixture(sanitizing()).await;
    let key = json!({(crate::protocol::mrtr::IDEMPOTENCY_KEY_META): KEY});
    let cases: Vec<(&str, String)> = vec![
        // a: the sanitize step's NUL refusal (a non-protocol byte).
        ("a sanitize NUL", keyed_nul("t")),
        // b: an invalid `jsonrpc` version (`parse_request`).
        (
            "b jsonrpc",
            json!({"jsonrpc": "1.0", "id": 5, "method": "tools/call",
                "params": {"name": "t", "arguments": {}, "_meta": key}})
            .to_string(),
        ),
        // c: an `id` present but not a string or number ("Missing id").
        (
            "c id object",
            json!({"jsonrpc": "2.0", "id": {"x": 1}, "method": "tools/call",
                "params": {"name": "t", "arguments": {}, "_meta": key}})
            .to_string(),
        ),
        (
            "c id float",
            json!({"jsonrpc": "2.0", "id": 1.5, "method": "tools/call",
                "params": {"name": "t", "arguments": {}, "_meta": key}})
            .to_string(),
        ),
        // h: a missing tool name.
        (
            "h no name",
            json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                "params": {"arguments": {}, "_meta": key}})
            .to_string(),
        ),
    ];
    for (case, body) in cases {
        let (status, answer) = post(&fx, "alpha", &body, &Caller::Anonymous).await;
        assert_eq!(message(&answer), NO_PRINCIPAL, "b8 {case}: {answer}");
        assert_eq!(status, StatusCode::BAD_REQUEST, "b8 {case}: {answer}");
    }
    assert_eq!(fx.calls.load(Ordering::SeqCst), 0, "b8: dispatched");
}

/// B9 CONTROL: protocol-field refusals stay first, before the intake check: a
/// control character in `method` (so not `tools/call` either) and a NUL in a
/// string `id` answer today's -32600 with a null id.
#[tokio::test]
async fn b9_protocol_field_refusals_stay_first() {
    let fx = fixture(sanitizing()).await;
    let key = json!({(crate::protocol::mrtr::IDEMPOTENCY_KEY_META): KEY});
    for (case, body) in [
        (
            "method",
            json!({"jsonrpc": "2.0", "id": 5, "method": "tools/\u{7}call",
                "params": {"name": "t", "arguments": {}, "_meta": key}}),
        ),
        (
            "id",
            json!({"jsonrpc": "2.0", "id": "a\u{0}b", "method": "tools/call",
                "params": {"name": "t", "arguments": {}, "_meta": key}}),
        ),
    ] {
        let (_, answer) = post(&fx, "alpha", &body.to_string(), &Caller::Anonymous).await;
        assert_eq!(
            answer.pointer("/error/code"),
            Some(&json!(-32600)),
            "b9 {case}: {answer}"
        );
        assert_eq!(answer.get("id"), Some(&Value::Null), "b9 {case}: {answer}");
        assert_ne!(
            message(&answer),
            NO_PRINCIPAL,
            "b9 {case}: intake answered first"
        );
    }
}
