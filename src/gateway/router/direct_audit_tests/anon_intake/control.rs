// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8382 CONTROL rows: answers the intake check must leave as they are
//! (B5-B7, B9, B9b, C5). Green before and after the fix.

use super::*;

/// B5 CONTROL: the same malformed keys from a caller WITH a principal keep
/// today's refusal, -32602 from the retry fields.
#[tokio::test]
async fn b5_malformed_key_with_principal_keeps_its_refusal() {
    for key in [json!(""), json!(7)] {
        let fx = fixture(idempotent()).await;
        let body = call_with_meta(
            "t",
            &json!({(crate::protocol::mrtr::IDEMPOTENCY_KEY_META): key}),
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

/// C5 CONTROL (D1, routed admission owner): with auth off and a trusted proxy
/// naming a subject, a keyed direct call has a principal (the routed owner)
/// and runs; the intake check must not refuse it. As `delivery_who` sets it.
#[tokio::test]
async fn c5_trusted_proxy_subject_is_a_principal() {
    let fx = fixture(Setup {
        caller_identity: Some(crate::security::caller_identity::CallerIdentityConfig {
            mode: crate::security::caller_identity::CallerIdentityMode::TrustedProxy,
            trusted_proxies: vec!["10.0.0.5".parse().expect("a literal IP parses")],
            authority: "corp-sso".to_string(),
            ..crate::security::caller_identity::CallerIdentityConfig::default()
        }),
        ..idempotent()
    })
    .await;
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp/alpha")
        .header("content-type", "application/json")
        .header("x-gateway-identity-subject", "alice")
        .body(axum::body::Body::from(keyed("t")))
        .expect("a static request builds");
    request.extensions_mut().insert(axum::extract::ConnectInfo(
        "10.0.0.5:4000".parse::<std::net::SocketAddr>()
            .expect("a literal socket address parses"),
    ));
    let response = fx.router.clone().oneshot(request)
        .await
        .expect("the router is infallible");
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("an in-memory body reads");
    assert_eq!(
        status,
        StatusCode::OK,
        "c5: {}",
        String::from_utf8_lossy(&body)
    );
    assert_eq!(
        fx.calls.load(Ordering::SeqCst),
        1,
        "c5: the call did not run"
    );
}

/// B6 CONTROL: a key scoped to `alpha` calling `beta` keeps its own scope
/// refusal (403). A scoped key is a credential, so its caller has a principal
/// and passes the intake check: the scope check can't flip.
#[tokio::test]
async fn b6_scoped_key_outside_its_backends_keeps_403() {
    let fx = fixture(Setup {
        auth: Some(key_for_alpha(None)),
        ..idempotent()
    })
    .await;
    let (status, body) = post(&fx, "beta", &keyed("t"), &Caller::Key).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "b6: {body}");
    assert_ne!(message(&body), NO_PRINCIPAL, "b6: intake answered: {body}");
    assert_eq!(fx.calls.load(Ordering::SeqCst), 0, "b6: dispatched");
}

/// B9b CONTROL (i): with `sanitize_input` off, protocol-field validation does
/// not run, today and after the fix (the intake check moves it but keeps its
/// guard): a control character in a keyed call's `method` gets no -32600
/// validation answer. Half (ii), a clean keyed call with sanitizing off, is
/// B1, whose fixture runs with sanitizing off.
#[tokio::test]
async fn b9b_sanitize_off_runs_no_protocol_field_validation() {
    let fx = fixture(idempotent()).await;
    assert!(!fx.state.sanitize_input, "b9b premise: sanitizing is on");
    let body = json!({"jsonrpc": "2.0", "id": 5, "method": "tools/\u{7}call",
        "params": {"name": "t", "arguments": {},
            "_meta": {(crate::protocol::mrtr::IDEMPOTENCY_KEY_META): KEY}}});
    let (_, answer) = post(&fx, "alpha", &body.to_string(), &Caller::Anonymous).await;
    // The validation answer's shape (B9): -32600 with a null id.
    assert_ne!(
        (answer.pointer("/error/code"), answer.get("id")),
        (Some(&json!(-32600)), Some(&Value::Null)),
        "b9b: validation answered with sanitizing off: {answer}"
    );
    assert_ne!(message(&answer), NO_PRINCIPAL, "b9b: not a tools/call: {answer}");
}
