// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8382 direct-route rows (B1-B4, B8, B8d-f): a keyed no-principal
//! `tools/call` on `/mcp/{name}` is refused at intake, before any backend work
//! and before every later refusal.

use super::*;

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
            extras: if list_fail { &[Extra::ListFail] } else { &[] },
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
        extras: &[Extra::ListFail],
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
            &json!({(crate::protocol::mrtr::IDEMPOTENCY_KEY_META): key}),
        );
        let (status, answer) = post(&fx, "alpha", &body, &Caller::Anonymous).await;
        assert_eq!(message(&answer), NO_PRINCIPAL, "b4 {key}: {answer}");
        assert_eq!(status, StatusCode::BAD_REQUEST, "b4 {key}");
        assert_eq!(fx.lists.load(Ordering::SeqCst), 0, "b4 {key}: listed");
    }
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
    // Every case runs; the failures are listed together, so the red run
    // records each case's "before".
    let mut wrong = Vec::new();
    for (case, body) in cases {
        let (status, answer) = post(&fx, "alpha", &body, &Caller::Anonymous).await;
        if message(&answer) != NO_PRINCIPAL || status != StatusCode::BAD_REQUEST {
            wrong.push(format!("{case}: {status} {answer}"));
        }
    }
    assert!(
        wrong.is_empty(),
        "b8 answered before intake:\n{}",
        wrong.join("\n")
    );
    assert_eq!(fx.calls.load(Ordering::SeqCst), 0, "b8: dispatched");
}

/// B8d: `direct_refusal` (the protocol checks `/mcp` shares) and
/// `DirectRouteGuards::run` (the kill switch) answer after the intake check
/// for a keyed no-principal call. Before: each answers its own code (the red
/// run records them); after: -32003, HTTP 400, id 5.
#[tokio::test]
async fn b8d_direct_refusals_answer_after_intake() {
    let modern = crate::protocol::meta::MODERN_VERSIONS[0];
    let mirrors = |name: &'static str| {
        vec![
            ("mcp-protocol-version", modern),
            ("mcp-method", "tools/call"),
            ("mcp-name", name),
        ]
    };
    let twice = |header: &'static str, value: &'static str| {
        let mut headers = mirrors("t");
        headers.push((header, value));
        headers
    };
    let cases: Vec<Case> = vec![
        // A modern header set over a legacy body: Malformed (-32602).
        ("d malformed shape", keyed_body(None), mirrors("t")),
        // A legacy body naming a revision served in neither era (-32022).
        (
            "d unserved header",
            keyed_body(None),
            vec![("mcp-protocol-version", "1999-01-01")],
        ),
        // A modern body at a revision this build cannot serve (-32022).
        (
            "d unsupported modern",
            keyed_body(Some("2099-01-01")),
            vec![],
        ),
        // A mirrored header twice (-32020).
        (
            "d duplicated name",
            keyed_body(Some(modern)),
            twice("mcp-name", "t"),
        ),
        // A mirrored header contradicting the body.
        (
            "d mirrored name",
            keyed_body(Some(modern)),
            mirrors("other"),
        ),
    ];
    let fx = fixture(idempotent()).await;
    let mut wrong = Vec::new();
    for (case, body, headers) in cases {
        let (status, answer) = post_with_headers(&fx, &body, &headers).await;
        if message(&answer) != NO_PRINCIPAL || status != StatusCode::BAD_REQUEST {
            wrong.push(format!("{case}: {status} {answer}"));
        }
    }
    // The kill switch (`DirectRouteGuards::run`): a disabled backend.
    fx.state.meta_mcp.kill_switch().kill("alpha");
    let (status, answer) = post_with_headers(&fx, &keyed_body(None), &[]).await;
    if message(&answer) != NO_PRINCIPAL || status != StatusCode::BAD_REQUEST {
        wrong.push(format!("d kill switch: {status} {answer}"));
    }
    // Hardened: a legacy call that declares no elicitation (403, id None).
    let hardened = fixture(Setup {
        extras: &[Extra::Hardened],
        ..idempotent()
    })
    .await;
    let (status, answer) = post_with_headers(&hardened, &keyed_body(None), &[]).await;
    if message(&answer) != NO_PRINCIPAL || status != StatusCode::BAD_REQUEST {
        wrong.push(format!("d hardened: {status} {answer}"));
    }
    assert!(
        wrong.is_empty(),
        "b8d answered before intake:\n{}",
        wrong.join("\n")
    );
    let calls = fx.calls.load(Ordering::SeqCst) + hardened.calls.load(Ordering::SeqCst);
    assert_eq!(calls, 0, "b8d: dispatched");
}

/// B8e: the direct preflight's refusals answer after the intake check for a
/// keyed no-principal call. Covered here: malformed `inputResponses` and
/// `requestState` (`RetryFields`), an arguments string that does not parse,
/// and a missing attestation token under enforce. Not flips, so not rows: the
/// chain nonce (its parse error is dropped, never answered) and the chain
/// challenge (it fails only on non-object params or `_meta`, which a keyed
/// call cannot have). The signing nonce is hardened-only, where the hardened
/// refusal (B8d) answers first.
#[tokio::test]
async fn b8e_preflight_refusals_answer_after_intake() {
    let with = |field: &str, value: Value| {
        let mut body = keyed_body(None);
        body["params"][field] = value;
        body
    };
    let cases = [
        ("e inputResponses", with("inputResponses", json!([1]))),
        ("e requestState", with("requestState", json!(7))),
        ("e arguments parse", with("arguments", json!("{not json"))),
    ];
    let fx = fixture(idempotent()).await;
    let mut wrong = Vec::new();
    for (case, body) in cases {
        let (status, answer) = post_with_headers(&fx, &body, &[]).await;
        if message(&answer) != NO_PRINCIPAL || status != StatusCode::BAD_REQUEST {
            wrong.push(format!("{case}: {status} {answer}"));
        }
    }
    let attested = fixture(Setup {
        extras: &[Extra::Attestation],
        ..idempotent()
    })
    .await;
    let (status, answer) = post_with_headers(&attested, &keyed_body(None), &[]).await;
    if message(&answer) != NO_PRINCIPAL || status != StatusCode::BAD_REQUEST {
        wrong.push(format!("e attestation: {status} {answer}"));
    }
    assert!(
        wrong.is_empty(),
        "b8e answered before intake:\n{}",
        wrong.join("\n")
    );
    let calls = fx.calls.load(Ordering::SeqCst) + attested.calls.load(Ordering::SeqCst);
    assert_eq!(calls, 0, "b8e: dispatched");
}

/// B8f: identity propagation's refusal (a required passthrough backend, a
/// caller with no credential to pass, a shared slot) answers after the intake
/// check for a keyed no-principal call. Before: its own refusal (the red run
/// records it); after: -32003, HTTP 400, id 5.
#[tokio::test]
async fn b8f_propagation_refusal_answers_after_intake() {
    let fx = fixture(Setup {
        extras: &[Extra::AlphaRequiresIdentity],
        ..idempotent()
    })
    .await;
    let (status, answer) = post_with_headers(&fx, &keyed_body(None), &[]).await;
    assert_eq!(message(&answer), NO_PRINCIPAL, "b8f: {status} {answer}");
    assert_eq!(status, StatusCode::BAD_REQUEST, "b8f: {answer}");
    assert_eq!(fx.calls.load(Ordering::SeqCst), 0, "b8f: dispatched");
    assert_eq!(mint_rows(&fx), 0, "b8f: identity minted");
}
